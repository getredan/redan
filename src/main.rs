use std::path::Path;
use std::time::Duration;

use clap::Parser;
use env_logger::Env;

use redan::ca::MitmCa;
use redan::config;
use redan::image;
use redan::proxy;
use redan::secret::SecretBinding;
use redan::session;
use redan::vm;

fn redan_banner() -> &'static str {
    // Red banner with dim taglines. Only colorize if stderr is a terminal.
    // clap prints help to stdout, so check that.
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        "\x1b[1;31m\
  ┌──────────────────────────────────────────────────┐\n\
  │                                                  │\n\
  │   ██████  ███████ ██████   █████  ███    ██      │\n\
  │   ██   ██ ██      ██   ██ ██   ██ ████   ██      │\n\
  │   ██████  █████   ██   ██ ███████ ██ ██  ██      │\n\
  │   ██   ██ ██      ██   ██ ██   ██ ██  ██ ██      │\n\
  │   ██   ██ ███████ ██████  ██   ██ ██   ████      │\n\
  │                                                  │\n\
  │\x1b[0m\x1b[2m Your agents run free. Your secrets stay put.     \x1b[0m\x1b[1;31m│\n\
  │                                                  │\n\
  └──────────────────────────────────────────────────┘\x1b[0m\n"
    } else {
        "\
  redan -- secure execution environment for AI agents\n\
  Your agents run free. Your secrets stay put.\n"
    }
}

fn init_logging(log_file: Option<&str>) {
    let env = Env::default().default_filter_or("info");
    let mut builder = env_logger::Builder::from_env(env);
    if let Some(path) = log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| panic!("cannot open log file {path}: {e}"));
        // Redirect stderr to the log file. libkrun writes directly
        // to stderr (bypassing the Rust log crate), so Target::Pipe
        // alone isn't enough.
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO);
        }
        builder.target(env_logger::Target::Pipe(Box::new(file)));
    }
    builder.init();
}

#[derive(Parser)]
#[command(
    name = "redan",
    about = redan_banner(),
    long_about = redan_banner(),
)]
enum Cli {
    /// Check system readiness and validate configs
    Doctor {
        /// Validate a secret spec (same format as `redan exec --secret`)
        #[arg(long = "secret", value_name = "SPEC")]
        secrets: Vec<String>,

        /// Read secret specs from a file for validation
        #[arg(long, value_name = "PATH")]
        secret_file: Option<String>,

        /// Check that a named image exists
        #[arg(long)]
        image: Option<String>,
    },

    /// Run a command in a sandboxed microVM
    Exec {
        /// Named image to use (from `redan image create`).
        /// Mutually exclusive with --rootfs.
        #[arg(long, conflicts_with = "rootfs")]
        image: Option<String>,

        /// Root filesystem path (for manual rootfs management).
        #[arg(long)]
        rootfs: Option<String>,

        /// Shell command to run in the guest.
        /// If omitted in interactive mode, defaults to /bin/sh.
        #[arg(long)]
        command: Option<String>,

        /// Interactive mode: attach terminal to guest console.
        #[arg(long, short = 'i')]
        interactive: bool,

        /// Proxy timeout in seconds (0 = no timeout, wait for VM exit).
        /// Default: 3600
        #[arg(long)]
        timeout: Option<u64>,

        /// Inject a secret: ENV_VAR=real_value:host1,host2
        ///
        /// Multiple hosts: separate with commas (not colons).
        /// Values may contain colons (last colon separates value from hosts).
        /// Visible in ps output; prefer --secret-file for sensitive environments.
        /// The real value is replaced with a placeholder in the guest.
        /// The proxy injects the real value only for requests to allowed hosts.
        #[arg(long = "secret", value_name = "SPEC")]
        secrets: Vec<String>,

        /// Read secret specs from a file (one per line, same format as --secret).
        /// Lines starting with # are comments. Empty lines are skipped.
        /// Avoids exposing secrets in process listings.
        #[arg(long, value_name = "PATH")]
        secret_file: Option<String>,

        /// Allow outbound HTTPS to a host. Default: deny all.
        /// Hosts from --secret specs are included automatically.
        /// Use '*' to allow all outbound connections.
        #[arg(long = "allow-host", value_name = "HOST")]
        allow_hosts: Vec<String>,

        /// Mount a host directory into the guest via virtio-fs.
        /// Format: /host/path:/guest/path (default guest path: /workspace)
        #[arg(long = "mount", value_name = "HOST:GUEST")]
        mounts: Vec<String>,

        /// Write structured audit events to a JSON-lines file.
        /// Records: connections, injections, scrubs, rejections.
        #[arg(long, value_name = "PATH")]
        audit_log: Option<String>,

        /// Write proxy/VM logs to a file instead of stderr.
        /// Useful in interactive mode where stderr interleaves with the TUI.
        #[arg(long, value_name = "PATH")]
        log_file: Option<String>,
    },

    /// Build and manage VM images
    Image {
        #[command(subcommand)]
        action: ImageAction,
    },

    /// Show past execution sessions
    #[command(name = "sessions")]
    Sessions,

    /// Set up redan for the current project
    Init,
}

#[derive(clap::Subcommand)]
enum ImageAction {
    /// Create a new image from Alpine base
    Create {
        /// Image name
        name: String,

        /// Packages to install via apk (space-separated)
        #[arg(long, value_delimiter = ' ', num_args = 1..)]
        packages: Vec<String>,

        /// Additional commands to run during build
        #[arg(long = "run", value_name = "CMD")]
        run_commands: Vec<String>,
    },

    /// Import a rootfs from a Docker image or Dockerfile
    Import {
        /// Image name (for redan)
        name: String,

        /// Docker image to import (e.g. ubuntu:24.04)
        #[arg(long, conflicts_with = "dockerfile")]
        from: Option<String>,

        /// Path to a Dockerfile to build and import
        #[arg(long, conflicts_with = "from")]
        dockerfile: Option<String>,
    },

    /// List local images
    List,

    /// Remove an image
    Remove {
        /// Image name
        name: String,
    },
}

fn main() {
    // rustls needs an explicit crypto provider when both ring and
    // aws-lc-rs are in the dependency tree (via rcgen and ureq).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Initialize logging. --log-file redirects to a file (useful for
    // interactive mode where stderr interleaves with the guest TUI).
    let log_file = match &cli {
        Cli::Exec { log_file, .. } => log_file.clone(),
        _ => None,
    };
    init_logging(log_file.as_deref());

    match cli {
        Cli::Doctor {
            secrets,
            secret_file,
            image,
        } => {
            let all_secrets = collect_secret_specs(&secrets, secret_file.as_deref());
            doctor(&all_secrets, image.as_deref());
        }
        Cli::Exec {
            image: image_name,
            rootfs,
            command,
            interactive,
            timeout,
            secrets,
            secret_file,
            allow_hosts,
            mounts,
            audit_log,
            log_file: _,
        } => {
            // Load config file (redan.toml), merge with CLI args.
            // CLI flags take precedence over config file values.
            let cfg = config::find_and_load();
            if let Some((path, _)) = &cfg {
                log::info!("loaded config from {}", path.display());
            }
            let cfg = cfg.map(|(_, c)| c).unwrap_or_default();

            // Merge secrets: CLI + --secret-file + config file
            let mut all_secrets = collect_secret_specs(&secrets, secret_file.as_deref());
            all_secrets.extend(cfg.secret_specs());
            let secrets = all_secrets;

            // Merge image: CLI > config
            let image_name = image_name.or(cfg.image.clone());
            let rootfs = rootfs.or(cfg.rootfs.clone());

            // Merge exec options: CLI > config
            let command = command.or(cfg.command.clone());
            let timeout = timeout.or(cfg.timeout).unwrap_or(3600);
            let interactive = if interactive {
                true
            } else {
                cfg.interactive.unwrap_or(false)
            };
            let audit_log = audit_log.or(cfg.audit_log.clone());

            // Merge allow_hosts: CLI + config
            let mut allow_hosts = allow_hosts;
            allow_hosts.extend(cfg.network.allow.clone());

            // Merge mounts: CLI + config
            let mut mounts = mounts;
            mounts.extend(cfg.mount_specs());
            let rootfs_path = match (&image_name, &rootfs) {
                (Some(name), _) => {
                    let p = match image::image_path(name) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    if !p.exists() {
                        eprintln!("image '{name}' not found. Run: redan image create {name} ...");
                        std::process::exit(1);
                    }
                    p.to_string_lossy().into_owned()
                }
                (_, Some(path)) => path.clone(),
                (None, None) => {
                    eprintln!("specify --image <name> or --rootfs <path>");
                    std::process::exit(1);
                }
            };
            let command = command.unwrap_or_else(|| {
                if interactive {
                    "/bin/sh".to_string()
                } else {
                    "echo 'no --command specified'".to_string()
                }
            });
            exec(
                &rootfs_path,
                &command,
                interactive,
                timeout,
                &secrets,
                &allow_hosts,
                &mounts,
                audit_log.as_deref(),
                image_name.as_deref(),
            );
        }

        Cli::Image { action } => match action {
            ImageAction::Create {
                name,
                packages,
                run_commands,
            } => match image::create(&name, &packages, &run_commands) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("image create failed: {e}");
                    std::process::exit(1);
                }
            },
            ImageAction::List => {
                let images = image::list();
                if images.is_empty() {
                    eprintln!(
                        "no images. Create one with: redan image create <name> --packages 'nodejs npm'"
                    );
                } else {
                    for name in images {
                        let path = image::image_path(&name).expect("listed image has invalid name");
                        let size = dir_size(&path).unwrap_or(0);
                        println!("{name:20} {}", humanize_bytes(size));
                    }
                }
            }
            ImageAction::Remove { name } => match image::remove(&name) {
                Ok(()) => eprintln!("removed image \'{name}\'"),
                Err(e) => {
                    eprintln!("remove failed: {e}");
                    std::process::exit(1);
                }
            },
            ImageAction::Import {
                name,
                from,
                dockerfile,
            } => {
                let result = if let Some(docker_image) = from {
                    image::import_docker(&name, &docker_image)
                } else if let Some(path) = dockerfile {
                    image::import_dockerfile(&name, &path)
                } else {
                    eprintln!("specify --from <image> or --dockerfile <path>");
                    std::process::exit(1);
                };
                match result {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("import failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },
        Cli::Init => init(),
        Cli::Sessions => {
            let sessions = session::list_sessions();
            if sessions.is_empty() {
                eprintln!("no sessions. Run: redan exec --image <name> --command <cmd>");
            } else {
                for s in &sessions {
                    let status = match &s.status {
                        session::SessionStatus::Running => "running",
                        session::SessionStatus::Finished => "finished",
                        session::SessionStatus::Failed => "failed",
                    };
                    println!(
                        "{}  {:10} {:20} {}",
                        s.id,
                        status,
                        s.image.as_deref().unwrap_or("-"),
                        s.started_at,
                    );
                }
            }
        }
    }
}

fn init() {
    if Path::new("redan.toml").exists() {
        eprintln!("redan.toml already exists. Remove it first to re-initialize.");
        std::process::exit(1);
    }

    let mut cfg = config::Config::default();

    // Detect project type and suggest defaults
    let detections = detect_project();
    let mut packages: Vec<String> = vec![
        "curl".into(),
        "ca-certificates".into(),
        "git".into(),
    ];

    if detections.is_empty() {
        eprintln!("no project type detected. Generating minimal config.");
    } else {
        for d in &detections {
            eprintln!("detected: {}", d.description);
            for host in &d.hosts {
                if !cfg.network.allow.contains(host) {
                    cfg.network.allow.push(host.clone());
                }
            }
            for pkg in &d.packages {
                if !packages.contains(pkg) {
                    packages.push(pkg.clone());
                }
            }
        }
    }

    // Image name from current directory name (same convention as docker-compose)
    let image_name = std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "dev".into());
    cfg.image = Some(image_name);
    cfg.command = Some("/bin/sh".into());

    // Default mount: current directory
    cfg.mount.insert(
        "workspace".into(),
        config::MountConfig {
            source: ".".into(),
            target: Some("/workspace".into()),
        },
    );

    // Write
    let toml = cfg.to_toml().unwrap_or_else(|e| {
        eprintln!("error serializing config: {e}");
        std::process::exit(1);
    });

    let content = format!(
        "# redan.toml -- generated by `redan init`\n\
         # See: https://github.com/getredan/redan\n\
         \n\
         {toml}"
    );

    std::fs::write("redan.toml", &content).unwrap_or_else(|e| {
        eprintln!("cannot write redan.toml: {e}");
        std::process::exit(1);
    });

    eprintln!("wrote redan.toml");
    let img = cfg.image.as_deref().unwrap_or("dev");

    // Check if a Dockerfile exists for a better suggestion
    let dockerfile = ["Dockerfile", "dockerfile", "Containerfile"]
        .iter()
        .find(|f| Path::new(f).exists());

    eprintln!("\nnext steps:");
    if let Some(df) = dockerfile {
        eprintln!("  1. Build the image from your {df}:");
        eprintln!("     redan image import {img} --dockerfile {df}");
    } else {
        let pkg_str = packages.join(" ");
        eprintln!("  1. Create the image:");
        eprintln!("     redan image create {img} --packages '{pkg_str}'");
    }
    eprintln!("  2. Add secrets to redan.toml (if needed):");
    eprintln!("     [secrets.API_KEY]");
    eprintln!("     value = \"your-key\"");
    eprintln!("     hosts = [\"api.example.com\"]");
    eprintln!("  3. Run:");
    eprintln!("     redan exec");
}

struct ProjectDetection {
    description: String,
    hosts: Vec<String>,
    packages: Vec<String>,
}

fn detect_project() -> Vec<ProjectDetection> {
    let mut detections = Vec::new();

    // Detection table: file -> description + hosts + packages
    let rules: &[(&str, &str, &[&str], &[&str])] = &[
        (
            "package.json",
            "Node.js (package.json)",
            &["registry.npmjs.org"],
            &["nodejs", "npm"],
        ),
        (
            "yarn.lock",
            "Yarn (yarn.lock)",
            &["registry.yarnpkg.com", "registry.npmjs.org"],
            &["nodejs", "npm"],
        ),
        (
            "pnpm-lock.yaml",
            "pnpm (pnpm-lock.yaml)",
            &["registry.npmjs.org"],
            &["nodejs", "npm"],
        ),
        (
            "requirements.txt",
            "Python (requirements.txt)",
            &["pypi.org", "files.pythonhosted.org"],
            &["python3", "py3-pip"],
        ),
        (
            "pyproject.toml",
            "Python (pyproject.toml)",
            &["pypi.org", "files.pythonhosted.org"],
            &["python3", "py3-pip"],
        ),
        (
            "Cargo.toml",
            "Rust (Cargo.toml)",
            &["crates.io", "static.crates.io"],
            &["cargo", "rust"],
        ),
        (
            "go.mod",
            "Go (go.mod)",
            &["proxy.golang.org", "sum.golang.org"],
            &["go"],
        ),
        ("Gemfile", "Ruby (Gemfile)", &["rubygems.org"], &["ruby"]),
        (
            "composer.json",
            "PHP (composer.json)",
            &["repo.packagist.org"],
            &["php", "composer"],
        ),
    ];

    for (file, desc, hosts, pkgs) in rules {
        if Path::new(file).exists() {
            detections.push(ProjectDetection {
                description: desc.to_string(),
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
                packages: pkgs.iter().map(|p| p.to_string()).collect(),
            });
        }
    }

    // Dockerfile detection
    let dockerfile_names = ["Dockerfile", "dockerfile", "Containerfile"];
    for name in dockerfile_names {
        if Path::new(name).exists() {
            let mut pkgs = Vec::new();
            if let Ok(content) = std::fs::read_to_string(name) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    // Extract packages from RUN apt-get install / apk add
                    if let Some(rest) = trimmed
                        .strip_prefix("RUN ")
                        .or_else(|| trimmed.strip_prefix("RUN\t"))
                    {
                        pkgs.extend(parse_dockerfile_packages(rest));
                    }
                }
            }
            detections.push(ProjectDetection {
                description: format!("Dockerfile ({name})"),
                hosts: vec![],
                packages: pkgs,
            });
            break; // only detect one
        }
    }

    // Git remote detection (no packages, just hosts)
    if let Ok(config) = std::fs::read_to_string(".git/config") {
        if config.contains("github.com") {
            detections.push(ProjectDetection {
                description: "GitHub remote".into(),
                hosts: vec!["github.com".into(), "api.github.com".into()],
                packages: vec![],
            });
        } else if config.contains("gitlab.com") {
            detections.push(ProjectDetection {
                description: "GitLab remote".into(),
                hosts: vec!["gitlab.com".into()],
                packages: vec![],
            });
        }
    }

    detections
}

/// Extract package names from Dockerfile RUN lines.
/// Handles: apt-get install, apk add, dnf/yum install, pip install.
fn parse_dockerfile_packages(line: &str) -> Vec<String> {
    let mut packages = Vec::new();

    // Split on && to handle chained commands
    for cmd in line.split("&&") {
        let cmd = cmd.trim();
        let words: Vec<&str> = cmd.split_whitespace().collect();
        // Find the install/add verb and collect package args after it
        let start = words.iter().position(|&w| {
            w == "install" || w == "add"
        });
        if let Some(idx) = start {
            for &word in &words[idx + 1..] {
                // Skip flags, redirects, continuations
                if word.starts_with('-') || word.starts_with('\\')
                    || word == "&&" || word.contains('=')
                    || word.contains('/') || word.contains('>')
                {
                    continue;
                }
                packages.push(word.to_string());
            }
        }
    }
    packages
}

fn doctor(secret_specs: &[String], check_image: Option<&str>) {
    let mut ok = true;

    // KVM
    let kvm_path = Path::new("/dev/kvm");
    if kvm_path.exists() {
        match std::fs::File::open(kvm_path) {
            Ok(_) => println!("[ok]   kvm: /dev/kvm accessible"),
            Err(e) => {
                println!("[err]  kvm: exists but not accessible: {e}");
                println!("       add your user to the kvm group: sudo usermod -aG kvm $USER");
                ok = false;
            }
        }
    } else {
        println!("[err]  kvm: not found");
        println!("       enable KVM in your kernel or BIOS settings");
        ok = false;
    }

    // Shared library search paths
    let lib_paths = [
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
    ];

    let find_lib = |name: &str| -> Option<&str> {
        lib_paths
            .iter()
            .find(|dir| Path::new(&format!("{dir}/{name}")).exists())
            .copied()
    };

    match find_lib("libkrun.so") {
        Some(dir) => println!("[ok]   libkrun: {dir}/libkrun.so"),
        None => {
            println!("[err]  libkrun: not found");
            println!("       install libkrun from your distro packages");
            ok = false;
        }
    }

    match find_lib("libkrunfw.so") {
        Some(dir) => println!("[ok]   libkrunfw: {dir}/libkrunfw.so"),
        None => {
            println!("[err]  libkrunfw: not found");
            println!("       install libkrunfw from your distro packages");
            ok = false;
        }
    }

    // Images
    let images = image::list();
    if images.is_empty() {
        println!("[warn] images: none");
        println!(
            "       create one with: redan image create dev --packages 'curl ca-certificates'"
        );
    } else {
        println!("[ok]   images: {}", images.join(", "));
    }

    // Check specific image if requested
    if let Some(name) = check_image {
        match image::image_path(name) {
            Ok(p) if p.exists() => println!("[ok]   image {name}: found"),
            Ok(_) => {
                println!("[err]  image {name}: not found");
                println!("       run: redan image create {name} --packages '...'");
                ok = false;
            }
            Err(e) => {
                println!("[err]  image {name}: {e}");
                ok = false;
            }
        }
    }

    // Validate secrets if provided. Never print secret values.
    for spec in secret_specs {
        // Extract env name before parsing (safe prefix before '=')
        let env_label = spec
            .split_once('=')
            .map(|(name, _)| name)
            .unwrap_or("(invalid)");

        match parse_secret(spec) {
            Ok((env_name, binding)) => {
                let provider = if spec.contains("vault://") {
                    "vault"
                } else {
                    "literal"
                };
                println!(
                    "[ok]   {env_name}: {provider}  hosts: {}",
                    binding.allowed_hosts().join(", "),
                );
            }
            Err(e) => {
                println!("[err]  {env_label}: {e}");
                ok = false;
            }
        }
    }

    println!("[info] image dir: {}", image::image_dir().display());

    if ok {
        println!("\nready to go");
    } else {
        println!("\nsome checks failed");
        std::process::exit(1);
    }
}

fn dir_size(path: &std::path::Path) -> std::io::Result<u64> {
    let mut total = 0;
    for entry in walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    Ok(total)
}

fn humanize_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    }
}

/// Parse secret spec: `ENV_VAR=real_value:host1,host2`
///
/// The value can be a literal or a provider URI:
/// - `ENV_VAR=ghp_abc123:api.github.com` (literal)
/// - `ENV_VAR=vault://path#field:api.github.com` (Vault KV v2)
fn parse_secret(spec: &str) -> Result<(String, SecretBinding), String> {
    // Split on last ':' to separate hosts from value (value may contain ':')
    let colon_pos = spec.rfind(':').ok_or("expected ENV_VAR=value:hosts")?;
    let (name_value, hosts) = (&spec[..colon_pos], &spec[colon_pos + 1..]);

    let eq_pos = name_value.find('=').ok_or("expected ENV_VAR=value")?;
    let (env_name, value_ref) = (&name_value[..eq_pos], &name_value[eq_pos + 1..]);

    if env_name.is_empty() || value_ref.is_empty() || hosts.is_empty() {
        return Err("empty env name, value, or hosts".into());
    }

    // Cap env name length to prevent oversized placeholders that
    // would slow down inject/scrub scanning.
    if env_name.len() > 256 {
        return Err("env name too long (max 256 bytes)".into());
    }

    // Resolve the value through the provider system
    let real_value = redan::provider::resolve_secret_value(value_ref)
        .map_err(|e| format!("failed to resolve secret: {e}"))?;

    let allowed_hosts: Vec<String> = hosts.split(',').map(|h| h.trim().to_string()).collect();
    let binding =
        SecretBinding::new(env_name, real_value, allowed_hosts).map_err(|e| e.to_string())?;

    Ok((env_name.to_string(), binding))
}

/// Read secret specs from a file. One spec per line, `#` comments, blank lines skipped.
/// Opens the file once, checks permissions on the fd (no TOCTOU).
fn read_secret_file(path: &str) -> Result<Vec<String>, String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat {path}: {e}"))?;

    if !meta.is_file() {
        return Err(format!("{path}: not a regular file"));
    }
    if meta.len() > 1_048_576 {
        return Err(format!("{path}: too large (max 1MB)"));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: {path} is accessible by other users (mode {:o}). Consider chmod 600.",
                mode & 0o777
            );
        }
    }

    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("cannot read {path}: {e}"))?;

    Ok(content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}

/// Merge --secret and --secret-file into a single list.
fn collect_secret_specs(cli_secrets: &[String], secret_file: Option<&str>) -> Vec<String> {
    let mut specs: Vec<String> = cli_secrets.to_vec();
    if let Some(path) = secret_file {
        match read_secret_file(path) {
            Ok(file_specs) => specs.extend(file_specs),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
    specs
}

/// Parse mount spec: `/host/path:/guest/path` or `/host/path` (defaults to /workspace)
fn parse_mount(spec: &str) -> (String, String) {
    if let Some((host, guest)) = spec.split_once(':') {
        (host.to_string(), guest.to_string())
    } else {
        (spec.to_string(), "/workspace".to_string())
    }
}

fn exec(
    rootfs: &str,
    command: &str,
    interactive: bool,
    timeout_secs: u64,
    secret_specs: &[String],
    allow_host_specs: &[String],
    mount_specs: &[String],
    audit_log_path: Option<&str>,
    image_name: Option<&str>,
) {
    // Create session
    let session_id = session::new_id();
    let mut meta = session::SessionMeta::new(&session_id, image_name, Some(command));
    if let Err(e) = meta.save() {
        log::warn!("cannot save session metadata: {e}");
    }
    log::info!("session {session_id} started");

    // Use session audit log if no explicit --audit-log
    let session_audit = session::audit_log_path(&session_id);
    let audit_log_path = audit_log_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| session_audit.to_string_lossy().into_owned());
    let audit_log_path = Some(audit_log_path.as_str());

    let ca = MitmCa::generate();
    log::info!("MITM CA generated");

    // Install CA cert in guest rootfs
    if let Err(e) = vm::install_ca_cert(Path::new(rootfs), ca.ca_cert_pem()) {
        eprintln!("failed to install CA cert in rootfs: {e}");
        std::process::exit(1);
    }
    log::info!("CA cert installed in guest trust store");

    // Parse secrets: generate placeholders, collect bindings
    let mut secrets: Vec<SecretBinding> = Vec::new();
    let mut secret_env: Vec<(String, String)> = Vec::new();
    for spec in secret_specs {
        match parse_secret(spec) {
            Ok((env_name, binding)) => {
                log::info!(
                    "secret: {env_name} -> placeholder {} for [{}]",
                    binding.placeholder(),
                    binding.allowed_hosts().join(", ")
                );
                secret_env.push((env_name, binding.placeholder().to_string()));
                secrets.push(binding);
            }
            Err(e) => {
                eprintln!("invalid --secret spec '{spec}': {e}");
                std::process::exit(1);
            }
        }
    }

    // Validate --allow-host values are hostnames, not URLs or host:port
    for host in allow_host_specs {
        if host == "*" {
            continue; // wildcard = allow all
        }
        if host.contains("://") || host.contains('/') || host.contains(':') {
            eprintln!("error: --allow-host takes a hostname, not a URL or host:port: {host}");
            std::process::exit(1);
        }
    }

    // Default-deny: all outbound HTTPS blocked unless explicitly allowed.
    // --allow-host '*' or network.allow = ["*"] opts out to allow all.
    let allowed_hosts: Option<Vec<String>> = if allow_host_specs.iter().any(|h| h == "*") {
        None // explicit wildcard = allow all
    } else {
        let mut hosts: Vec<String> = allow_host_specs
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        // Include secret hosts automatically so injection still works
        for s in &secrets {
            for h in s.allowed_hosts() {
                let lower = h.to_ascii_lowercase();
                if !hosts.contains(&lower) {
                    hosts.push(lower);
                }
            }
        }
        if hosts.is_empty() {
            log::info!("network: default-deny (no hosts allowed)");
        } else {
            log::info!("allowed hosts: {}", hosts.join(", "));
        }
        Some(hosts)
    };

    // Parse mounts
    let mut virtiofs_mounts: Vec<(String, String)> = Vec::new();
    let mut mount_commands: Vec<String> = Vec::new();
    for (i, spec) in mount_specs.iter().enumerate() {
        let (host_path, guest_path) = parse_mount(spec);
        let tag = format!("fs{i}");
        log::info!("mount: {host_path} -> {guest_path} (tag={tag})");

        // Create mount point in the rootfs
        let mp = Path::new(rootfs).join(guest_path.trim_start_matches('/'));
        std::fs::create_dir_all(&mp).ok();

        virtiofs_mounts.push((tag.clone(), host_path));
        mount_commands.push(format!("mount -t virtiofs {tag} {guest_path}"));
    }

    // Build guest command: network setup + CA trust + mounts + user command
    let net_setup = vm::net_setup_commands(&proxy::GATEWAY_IP.to_string(), proxy::GUEST_IP);
    let ca_update = vm::ca_update_commands();
    let mount_setup = mount_commands.join("; ");
    let full_command = if mount_setup.is_empty() {
        format!("{net_setup}; {ca_update}; {command}")
    } else {
        format!("{net_setup}; {ca_update}; {mount_setup}; {command}")
    };

    let mut env: Vec<String> = vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        "TERM=xterm".into(),
        "SSL_CERT_FILE=/etc/ssl/certs/redan-ca.pem".into(),
        "NODE_EXTRA_CA_CERTS=/etc/ssl/certs/redan-ca.pem".into(),
    ];

    // Add secret placeholders as env vars in the guest
    for (name, placeholder) in &secret_env {
        env.push(format!("{name}={placeholder}"));
    }

    let config = vm::VmConfig {
        rootfs: rootfs.into(),
        vcpus: 1,
        ram_mib: 256,
        command: full_command,
        env,
        virtiofs_mounts,
        interactive,
    };

    // In interactive mode, set the host terminal to raw mode so
    // keypresses are forwarded directly to the guest PTY.
    let _raw_guard = if interactive {
        Some(RawTerminalGuard::enter())
    } else {
        None
    };

    let vm = vm::Vm::boot(config);

    // Run the MITM proxy on the host side.
    // When the proxy returns (timeout or VM socket closes), we're done.
    // The VM thread may still be alive (krun_start_enter blocks indefinitely)
    // but the process exit will clean it up.
    proxy::run(
        vm.net_sock
            .try_clone()
            .expect("failed to clone VM network socket"),
        std::sync::Arc::new(std::sync::Mutex::new(ca)),
        &secrets,
        Duration::from_secs(timeout_secs),
        allowed_hosts,
        audit_log_path,
    );

    meta.finish(true);
    log::info!("session {session_id} finished");
    // _raw_guard drops here, restoring terminal settings.
}

/// RAII guard that puts the terminal into raw mode on creation and
/// restores the original settings on drop.
struct RawTerminalGuard {
    original: libc::termios,
}

impl RawTerminalGuard {
    fn enter() -> Self {
        unsafe {
            let mut original: libc::termios = std::mem::zeroed();
            libc::tcgetattr(libc::STDIN_FILENO, &mut original);
            let mut raw = original;
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw);
            Self { original }
        }
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_secret_basic() {
        let (name, binding) = parse_secret("TOKEN=secret123:api.github.com").unwrap();
        assert_eq!(name, "TOKEN");
        assert_eq!(binding.real_value(), "secret123");
        assert_eq!(binding.allowed_hosts(), &["api.github.com"]);
        assert!(binding.placeholder().starts_with("redan_ph_token_"));
    }

    #[test]
    fn parse_secret_value_with_colons() {
        // Colon in value: `KEY=postgres://user:pass@host:5432:db.example.com`
        let (name, binding) =
            parse_secret("DB_URL=postgres://user:pass@host:5432:db.example.com").unwrap();
        assert_eq!(name, "DB_URL");
        assert_eq!(binding.real_value(), "postgres://user:pass@host:5432");
        assert_eq!(binding.allowed_hosts(), &["db.example.com"]);
    }

    #[test]
    fn parse_secret_multiple_hosts() {
        let (_, binding) = parse_secret("KEY=val:api.github.com, registry.npmjs.org").unwrap();
        assert_eq!(
            binding.allowed_hosts(),
            &["api.github.com", "registry.npmjs.org"]
        );
    }

    #[test]
    fn parse_secret_empty_name_fails() {
        assert!(parse_secret("=value:host.com").is_err());
    }

    #[test]
    fn parse_secret_empty_value_fails() {
        assert!(parse_secret("KEY=:host.com").is_err());
    }

    #[test]
    fn parse_secret_empty_hosts_fails() {
        assert!(parse_secret("KEY=value:").is_err());
    }

    #[test]
    fn parse_secret_no_colon_fails() {
        assert!(parse_secret("KEY=value").is_err());
    }

    #[test]
    fn parse_secret_crlf_in_value_rejected() {
        assert!(parse_secret("KEY=val\r\nue:host.com").is_err());
        assert!(parse_secret("KEY=val\nue:host.com").is_err());
        assert!(parse_secret("KEY=val\rue:host.com").is_err());
    }

    #[test]
    #[ignore = "requires running Vault"]
    fn parse_secret_vault_scheme() {
        // Requires: VAULT_ADDR + VAULT_TOKEN set, redan/test secret seeded
        let (name, binding) =
            parse_secret("TOKEN=vault://redan/test#github_token:api.github.com").unwrap();
        assert_eq!(name, "TOKEN");
        assert_eq!(binding.real_value(), "ghp_test123");
        assert_eq!(binding.allowed_hosts(), &["api.github.com"]);
    }

    #[test]
    fn parse_mount_with_guest_path() {
        let (host, guest) = parse_mount("/home/chris/project:/workspace");
        assert_eq!(host, "/home/chris/project");
        assert_eq!(guest, "/workspace");
    }

    #[test]
    fn parse_mount_default_guest_path() {
        let (host, guest) = parse_mount("/home/chris/project");
        assert_eq!(host, "/home/chris/project");
        assert_eq!(guest, "/workspace");
    }

    #[test]
    fn read_secret_file_parses_lines() {
        let dir = std::env::temp_dir().join("redan-test-secret-file");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secrets.conf");
        std::fs::write(
            &path,
            "# comment\nTOKEN=abc:api.github.com\n\n  KEY=xyz:host.com  \n# another comment\n",
        )
        .unwrap();
        // Set restrictive permissions to avoid the warning
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let specs = read_secret_file(path.to_str().unwrap()).unwrap();
        assert_eq!(specs, vec!["TOKEN=abc:api.github.com", "KEY=xyz:host.com"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dockerfile_packages_apt_get() {
        let pkgs = parse_dockerfile_packages("apt-get install -y curl wget git");
        assert_eq!(pkgs, vec!["curl", "wget", "git"]);
    }

    #[test]
    fn dockerfile_packages_apk_add() {
        let pkgs = parse_dockerfile_packages("apk add --no-cache python3 py3-pip make");
        assert_eq!(pkgs, vec!["python3", "py3-pip", "make"]);
    }

    #[test]
    fn dockerfile_packages_chained() {
        let pkgs = parse_dockerfile_packages(
            "apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*",
        );
        assert_eq!(pkgs, vec!["nodejs", "npm"]);
    }

    #[test]
    fn dockerfile_packages_no_install() {
        let pkgs = parse_dockerfile_packages("echo hello && npm install -g pnpm");
        // npm install is a different thing, but "install" triggers - pnpm gets picked up
        // This is best-effort, not a full parser
        assert!(pkgs.contains(&"pnpm".to_string()));
    }
}
