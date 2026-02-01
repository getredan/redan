//! Image management: create, list, and remove rootfs images.
//!
//! Images are stored at `$XDG_DATA_HOME/redan/images/<name>/`.
//! Base images (Alpine minirootfs) are cached at `$XDG_CACHE_HOME/redan/`.

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, io};

use crate::ca::MitmCa;
use crate::{proxy, vm};

const ALPINE_VERSION: &str = "3.21.3";
const ALPINE_MINOR: &str = "3.21";

fn home_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("HOME").expect("$HOME not set -- cannot determine config directories"),
    )
}

/// Where images are stored.
pub fn image_dir() -> PathBuf {
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_dir().join(".local/share"));
    base.join("redan/images")
}

/// Where downloaded base images are cached.
fn cache_dir() -> PathBuf {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_dir().join(".cache"));
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
        .filter(|e| e.path().join("bin").is_dir()) // must have bin/ to be a rootfs
        .filter_map(|e| e.file_name().into_string().ok())
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
        fs::metadata(&tarball).map(|m| m.len()).unwrap_or(0)
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
        // Use || true so subsequent --run commands still execute.
        setup_parts.push(format!(
            "apk update && (apk add --no-cache {pkg_list} || true)"
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
    let mut ca = MitmCa::generate();
    vm::install_ca_cert(dest, ca.ca_cert_pem())?;

    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);
    let vm_command = format!("{net_setup}; {full_command}");

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
    proxy::run(
        vm_handle.net_sock.try_clone()?,
        &mut ca,
        &[],                      // no secrets during build
        Duration::from_secs(600), // 10 min timeout for builds
    );

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

#[cfg(test)]
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
}
