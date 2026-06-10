//! Image management: create, list, and remove rootfs images.
//!
//! Images are stored at `$XDG_DATA_HOME/redan/images/<name>/`.
//! Base images (Alpine minirootfs) are cached at `$XDG_CACHE_HOME/redan/`.

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, io};

use crate::ca::MitmCa;
use crate::image_meta::{ImageMeta, ImageSource};
use crate::{proxy, vm};

const ALPINE_VERSION: &str = "3.21.3";
const ALPINE_MINOR: &str = "3.21";

fn home_dir() -> PathBuf {
    std::env::var("HOME").map_or_else(
        |_| {
            eprintln!("$HOME not set -- cannot determine config directories");
            std::process::exit(1);
        },
        PathBuf::from,
    )
}

/// Where images are stored.
pub fn image_dir() -> PathBuf {
    let base = std::env::var("XDG_DATA_HOME")
        .map_or_else(|_| home_dir().join(".local/share"), PathBuf::from);
    base.join("redan/images")
}

/// Where downloaded base images are cached.
fn cache_dir() -> PathBuf {
    let base =
        std::env::var("XDG_CACHE_HOME").map_or_else(|_| home_dir().join(".cache"), PathBuf::from);
    base.join("redan")
}

/// Path to a named image's rootfs.
///
/// Validates that the name contains only safe characters to prevent
/// path traversal (e.g., `../../etc`).
pub fn image_path(name: &str) -> io::Result<PathBuf> {
    if !is_valid_image_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid image name: must be alphanumeric, hyphens, or underscores",
        ));
    }
    Ok(image_dir().join(name))
}

fn is_valid_image_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// List all local images.
pub fn list() -> Vec<String> {
    let dir = image_dir();
    let Ok(entries) = fs::read_dir(&dir) else {
        return vec![];
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("bin").is_dir()) // must have bin/ to be a rootfs
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

/// Remove a named image.
pub fn remove(name: &str) -> io::Result<()> {
    let path = image_path(name)?;
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("image '{name}' not found"),
        ));
    }
    fs::remove_dir_all(path)
}

/// Download the Alpine minirootfs tarball if not cached. Returns path to tarball.
fn ensure_base_cached() -> io::Result<PathBuf> {
    let cache = cache_dir();
    fs::create_dir_all(&cache)?;

    let tarball = cache.join(format!("alpine-minirootfs-{ALPINE_VERSION}-x86_64.tar.gz"));
    if tarball.exists() {
        log::info!("using cached base image: {}", tarball.display());
        return Ok(tarball);
    }

    eprintln!("downloading Alpine {ALPINE_VERSION} minirootfs...");
    let url = format!(
        "https://dl-cdn.alpinelinux.org/alpine/v{ALPINE_MINOR}/releases/x86_64/alpine-minirootfs-{ALPINE_VERSION}-x86_64.tar.gz"
    );
    let status = std::process::Command::new("curl")
        .args(["-fSL", "-o"])
        .arg(&tarball)
        .arg(&url)
        .status()
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("curl: {e}")))?;

    if !status.success() {
        let _ = fs::remove_file(&tarball);
        return Err(io::Error::other("failed to download Alpine minirootfs"));
    }

    eprintln!(
        "downloaded {} ({} bytes)",
        tarball.display(),
        fs::metadata(&tarball).map(|meta| meta.len()).unwrap_or(0)
    );
    Ok(tarball)
}

/// Extract a tarball into a directory.
fn extract_tarball(tarball: &Path, dest: &Path) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    let status = std::process::Command::new("tar")
        .args(["xzf"])
        .arg(tarball)
        .arg("-C")
        .arg(dest)
        .status()?;
    if !status.success() {
        return Err(io::Error::other("tar extraction failed"));
    }
    Ok(())
}

/// Create a new image by booting a VM and running setup commands.
///
/// Steps:
/// 1. Extract Alpine minirootfs as the base
/// 2. Boot a redan VM with that rootfs
/// 3. Run `apk update && apk add <packages>` + custom commands
/// 4. The modified rootfs is the image
pub fn create(name: &str, packages: &[String], run_commands: &[String]) -> io::Result<PathBuf> {
    let dest = image_path(name)?;
    if dest.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("image '{name}' already exists (use `redan image remove {name}` first)"),
        ));
    }

    // Step 1: get base tarball
    let tarball = ensure_base_cached()?;

    // Step 2: extract
    eprintln!("extracting base image...");
    extract_tarball(&tarball, &dest)?;

    // From here, clean up dest on any error.
    match build_image(&dest, packages, run_commands) {
        Ok(()) => {
            let meta = ImageMeta::new(ImageSource::Create {
                packages: packages.to_vec(),
                run_commands: run_commands.to_vec(),
            });
            if let Err(e) = meta.save(&dest) {
                log::warn!("cannot save image metadata: {e}");
            }
            eprintln!("image '{name}' created at {}", dest.display());
            Ok(dest)
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&dest);
            Err(e)
        }
    }
}

/// Inner build logic. Separated so `create` can clean up on failure.
fn build_image(dest: &Path, packages: &[String], run_commands: &[String]) -> io::Result<()> {
    // Step 3: build setup command
    let mut setup_parts: Vec<String> = Vec::new();

    // Configure Alpine repos (use HTTPS)
    setup_parts.push(
        "echo 'https://dl-cdn.alpinelinux.org/alpine/v3.21/main' > /etc/apk/repositories; \
         echo 'https://dl-cdn.alpinelinux.org/alpine/v3.21/community' >> /etc/apk/repositories"
            .into(),
    );

    if !packages.is_empty() {
        let pkg_list = packages.join(" ");
        // apk exits non-zero on chown failures (guest UID != root on host).
        // The packages install fine, just with host-user ownership.
        // Filter the "Failed to set ownership" stderr noise so the
        // terminal stays readable, and || true so subsequent commands
        // still execute regardless of apk's exit code.
        setup_parts.push(format!(
            "apk update && (apk add --no-cache {pkg_list} 2>&1 | grep -v 'Failed to set ownership' || true)"
        ));
    }

    for cmd in run_commands {
        setup_parts.push(cmd.clone());
    }

    // Write sentinel file as last step. If any prior command fails
    // (the chain uses &&), this file won't be created and we detect
    // the failure after the VM exits.
    setup_parts.push("touch /tmp/.redan-build-ok".into());

    let full_command = setup_parts.join(" && ");

    // Step 4: boot VM with network, run setup
    eprintln!("building image (this boots a VM with network)...");
    let ca = MitmCa::generate();
    vm::install_ca_cert(dest, ca.ca_cert_pem())?;

    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);
    let ca_update = vm::ca_update_commands();
    let vm_command = format!("{net_setup}; {ca_update}; {full_command}");

    let config = vm::VmConfig {
        rootfs: dest.to_string_lossy().into_owned(),
        vcpus: 2,
        ram_mib: 512,
        command: vm_command,
        env: vec![
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
            "SSL_CERT_FILE=/etc/ssl/certs/redan-ca.pem".into(),
        ],
        virtiofs_mounts: vec![],
        interactive: false,
    };

    let vm_handle = vm::Vm::boot(config);

    // Run proxy until VM completes (generous timeout for package installation)
    let _ = proxy::run(proxy::ProxyConfig {
        host_sock: vm_handle.net_sock.try_clone()?,
        ca: std::sync::Arc::new(std::sync::Mutex::new(ca)),
        secrets: &[],                      // no secrets during build
        timeout: Duration::from_secs(600), // 10 min for builds
        allowed_hosts: None,               // unrestricted during build
        audit_log_path: None,
        discover: false,
        forwards: &[],
    });

    // Reap the build VM (kills it if the proxy timed out instead).
    // The sentinel file is the source of truth for build success.
    let _ = vm_handle.shutdown();

    // Verify the build completed successfully by checking for the
    // sentinel file written as the last build step.
    let sentinel = dest.join("tmp/.redan-build-ok");
    if !sentinel.exists() {
        return Err(io::Error::other(
            "image build failed: setup commands did not complete successfully",
        ));
    }
    // Remove sentinel -- it served its purpose
    let _ = fs::remove_file(sentinel);

    Ok(())
}

/// Import a rootfs from an existing Docker image.
///
/// Runs the image (to flatten layers), exports the filesystem,
/// and stores it as a redan image.
pub fn import_docker(name: &str, docker_image: &str) -> io::Result<PathBuf> {
    import_docker_inner(name, docker_image, true)
}

fn import_docker_inner(name: &str, docker_image: &str, pull: bool) -> io::Result<PathBuf> {
    let dest = image_path(name)?;
    if dest.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("image '{name}' already exists"),
        ));
    }

    if pull {
        eprintln!("pulling {docker_image}...");
        let status = std::process::Command::new("docker")
            .args(["pull", "-q", docker_image])
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "docker pull failed for {docker_image}"
            )));
        }
    }

    eprintln!("exporting rootfs...");
    fs::create_dir_all(&dest)?;

    // Run the image with a no-op command, then export.
    let cid_output = std::process::Command::new("docker")
        .args(["create", docker_image, "true"])
        .output()?;
    if !cid_output.status.success() {
        let _ = fs::remove_dir_all(&dest);
        return Err(io::Error::other("docker create failed"));
    }
    let cid = String::from_utf8_lossy(&cid_output.stdout)
        .trim()
        .to_string();

    let export = std::process::Command::new("sh")
        .args([
            "-c",
            &format!("docker export {cid} | tar xf - -C {}", dest.display()),
        ])
        .status();
    let _ = std::process::Command::new("docker")
        .args(["rm", &cid])
        .status();

    match export {
        Ok(s) if s.success() => {}
        _ => {
            let _ = fs::remove_dir_all(&dest);
            return Err(io::Error::other("docker export failed"));
        }
    }

    // Verify it looks like a rootfs
    if !dest.join("bin").is_dir() {
        let _ = fs::remove_dir_all(&dest);
        return Err(io::Error::other(
            "exported image has no /bin -- not a valid rootfs",
        ));
    }

    let meta = ImageMeta::new(ImageSource::Docker {
        image: docker_image.into(),
    });
    if let Err(e) = meta.save(&dest) {
        log::warn!("cannot save image metadata: {e}");
    }

    eprintln!("image '{name}' imported from {docker_image}");
    eprintln!("  {}", dest.display());
    Ok(dest)
}

/// Build a Dockerfile, then import the result as a redan image.
pub fn import_dockerfile(name: &str, dockerfile_path: &str) -> io::Result<PathBuf> {
    let df = Path::new(dockerfile_path);
    if !df.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Dockerfile not found: {dockerfile_path}"),
        ));
    }

    // Build with a temporary tag
    let tag = format!("redan-build-{name}");
    let context = df
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    eprintln!("building Dockerfile...");
    let build = std::process::Command::new("docker")
        .env("DOCKER_BUILDKIT", "1")
        .args(["build", "-t", &tag, "-f"])
        .arg(df)
        .arg(context)
        .status()?;
    if !build.success() {
        return Err(io::Error::other("docker build failed"));
    }

    // Skip pull -- image was just built locally.
    let result = import_docker_inner(name, &tag, false);

    // Clean up the temporary image
    let _ = std::process::Command::new("docker")
        .args(["rmi", &tag])
        .status();

    // Save build metadata after successful import
    if let Ok(ref dest) = result {
        let meta = ImageMeta::new(ImageSource::Dockerfile {
            path: dockerfile_path.into(),
        });
        if let Err(e) = meta.save(dest) {
            log::warn!("cannot save image metadata: {e}");
        }
    }

    result
}

/// Build from a devcontainer.json spec.
///
/// Supports two modes:
/// - `build.dockerfile`: builds from the referenced Dockerfile
/// - `image`: imports the specified Docker image
///
/// The devcontainer.json can live at `.devcontainer/devcontainer.json`
/// or `.devcontainer.json` (per the spec).
#[allow(clippy::too_many_lines)] // Devcontainer has 3 code paths (dockerfile, image, compose)
pub fn import_devcontainer(name: &str, config_path: &str) -> io::Result<PathBuf> {
    let result = import_devcontainer_inner(name, config_path)?;
    let meta = ImageMeta::new(ImageSource::Devcontainer {
        path: config_path.into(),
    });
    if let Err(e) = meta.save(&result) {
        log::warn!("cannot save image metadata: {e}");
    }
    Ok(result)
}

fn import_devcontainer_inner(name: &str, config_path: &str) -> io::Result<PathBuf> {
    let config_file = Path::new(config_path);
    if !config_file.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("devcontainer config not found: {config_path}"),
        ));
    }

    let raw = fs::read_to_string(config_file)?;
    // Strip JSON comments (// and /* */) since devcontainer.json allows them
    let stripped = strip_jsonc_comments(&raw);
    let config: serde_json::Value = serde_json::from_str(&stripped)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid JSON: {e}")))?;

    let config_dir = config_file.parent().unwrap_or_else(|| Path::new("."));

    // Try build.dockerfile first, then image
    if let Some(build) = config.get("build")
        && let Some(dockerfile) = build.get("dockerfile").and_then(|v| v.as_str())
    {
        let context = build.get("context").and_then(|v| v.as_str()).unwrap_or(".");
        let df_path = config_dir.join(dockerfile);
        let ctx_path = config_dir.join(context);

        eprintln!("building from devcontainer: {dockerfile}");
        let tag = format!("redan-build-{name}");
        let build_status = std::process::Command::new("docker")
            .env("DOCKER_BUILDKIT", "1")
            .args(["build", "-t", &tag, "-f"])
            .arg(&df_path)
            .arg(&ctx_path)
            .status()?;
        if !build_status.success() {
            return Err(io::Error::other("docker build failed"));
        }

        let result = import_docker_inner(name, &tag, false);
        let _ = std::process::Command::new("docker")
            .args(["rmi", &tag])
            .status();
        return result;
    }

    if let Some(image) = config.get("image").and_then(|v| v.as_str()) {
        eprintln!("importing devcontainer image: {image}");
        return import_docker(name, image);
    }

    // dockerComposeFile: build the target service with docker compose
    if let Some(compose_file) = config.get("dockerComposeFile").and_then(|v| v.as_str()) {
        let service = config
            .get("service")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "devcontainer.json has 'dockerComposeFile' but no 'service'",
                )
            })?;
        let compose_path = config_dir.join(compose_file);
        let tag = format!("redan-build-{name}");

        eprintln!("building from docker-compose: {compose_file} (service: {service})");
        let build_status = std::process::Command::new("docker")
            .env("DOCKER_BUILDKIT", "1")
            .args(["compose", "-f"])
            .arg(&compose_path)
            .args(["build", service])
            .status()?;
        if !build_status.success() {
            return Err(io::Error::other("docker compose build failed"));
        }

        // Find the image name compose assigned to the service.
        let config_output = std::process::Command::new("docker")
            .args(["compose", "-f"])
            .arg(&compose_path)
            .args(["config", "--format", "json"])
            .output()?;
        let config_json: serde_json::Value = serde_json::from_slice(&config_output.stdout)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot parse compose config: {e}"),
                )
            })?;
        let source_tag = config_json
            .get("services")
            .and_then(|services| services.get(service))
            .and_then(|svc| svc.get("image"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if source_tag.is_empty() {
            return Err(io::Error::other(format!(
                "cannot determine image name for service '{service}' after build"
            )));
        }

        eprintln!("importing image: {source_tag}");

        // Tag it so we can export with a known name, then import
        let _ = std::process::Command::new("docker")
            .args(["tag", &source_tag, &tag])
            .status();

        let result = import_docker_inner(name, &tag, false);
        let _ = std::process::Command::new("docker")
            .args(["rmi", &tag])
            .status();
        return result;
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "devcontainer.json has no 'build.dockerfile', 'image', or 'dockerComposeFile' field",
    ))
}

/// Strip // and /* */ comments from JSONC (JSON with Comments).
/// Devcontainer.json allows comments per the spec.
fn strip_jsonc_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;

    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    out.push(next);
                    chars.next();
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                chars.next(); // consume second /
                // Skip until end of line
                for c in chars.by_ref() {
                    if c == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next(); // consume *
                // Skip until */
                loop {
                    match chars.next() {
                        Some('*') if chars.peek() == Some(&'/') => {
                            chars.next();
                            break;
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn valid_image_names() {
        assert!(is_valid_image_name("claude-code"));
        assert!(is_valid_image_name("my_image"));
        assert!(is_valid_image_name("test123"));
        assert!(is_valid_image_name("a"));
    }

    #[test]
    fn invalid_image_names() {
        assert!(!is_valid_image_name(""));
        assert!(!is_valid_image_name("../etc"));
        assert!(!is_valid_image_name("../../passwd"));
        assert!(!is_valid_image_name("foo/bar"));
        assert!(!is_valid_image_name("foo bar"));
        assert!(!is_valid_image_name(".hidden"));
        assert!(!is_valid_image_name("name.with.dots"));
    }

    #[test]
    fn image_path_rejects_traversal() {
        let err = image_path("../../etc/passwd").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("invalid image name"));
    }

    #[test]
    fn strip_jsonc_line_comments() {
        let input = r#"{
            // This is a comment
            "image": "ubuntu" // inline
        }"#;
        let stripped = strip_jsonc_comments(input);
        let v: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(v["image"], "ubuntu");
    }

    #[test]
    fn strip_jsonc_block_comments() {
        let input = r#"{
            /* multi
               line */
            "image": "alpine"
        }"#;
        let stripped = strip_jsonc_comments(input);
        let v: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(v["image"], "alpine");
    }

    #[test]
    fn strip_jsonc_preserves_strings() {
        let input = r#"{"url": "https://example.com // not a comment"}"#;
        let stripped = strip_jsonc_comments(input);
        let v: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(v["url"], "https://example.com // not a comment");
    }
}
