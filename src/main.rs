// Binary crate lints
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::redundant_pub_crate)] // cmd/ modules are pub(crate) by design

use clap::Parser;
use env_logger::Env;
use redan::config;
use redan::image;
use redan::session;

mod cmd;

const fn redan_banner() -> &'static str {
    r"
 ____  _____ ____    _    _   _
|  _ \| ____|  _ \  / \  | \ | |
| |_) |  _| | | | |/ _ \ |  \| |
|  _ <| |___| |_| / ___ \| |\  |
|_| \_\_____|____/_/   \_\_| \_|

Secure AI agent sandbox with network-layer secret injection"
}

fn init_logging(log_file: Option<&str>) {
    use std::os::unix::io::AsRawFd;

    let env = Env::default().default_filter_or("info");
    let mut builder = env_logger::Builder::from_env(env);
    if let Some(path) = log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| {
                eprintln!("cannot open log file {path}: {e}");
                std::process::exit(1);
            });
        unsafe {
            libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO);
        }
        builder.target(env_logger::Target::Pipe(Box::new(file)));
    }
    // try_init: no-op if logger already initialized (interactive re-init)
    builder.try_init().ok();
}

/// Redirect stderr to a log file (for interactive mode).
fn redirect_logs_to_file(path: &std::path::Path) {
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO);
        }
    }
}

#[derive(Parser)]
#[command(
    name = "redan",
    version,
    about = redan_banner(),
    long_about = redan_banner(),
)]
enum Cli {
    /// Check system readiness and validate configs
    Doctor {
        /// Validate a secret spec (same format as --secret for exec)
        #[arg(long = "secret", value_name = "SPEC")]
        secrets: Vec<String>,

        /// Read secret specs from file for validation
        #[arg(long, value_name = "PATH")]
        secret_file: Option<String>,

        /// Check a specific image exists and is valid
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

        /// Command to run in the guest (everything after --).
        /// If omitted in interactive mode, defaults to /bin/sh.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,

        /// Interactive mode: attach terminal to guest console.
        #[arg(long, short = 'i')]
        interactive: bool,

        /// Proxy timeout in seconds (0 = no timeout, wait for VM exit).
        /// Default: 3600
        #[arg(long)]
        timeout: Option<u64>,

        /// Inject a secret: `ENV_VAR=real_value:host1,host2`
        ///
        /// Multiple hosts: separate with commas (not colons).
        /// Values may contain colons (last colon separates value from hosts).
        /// Visible in ps output; prefer --secret-file for sensitive environments.
        /// The real value is replaced with a placeholder in the guest.
        /// The proxy injects the real value only for requests to allowed hosts.
        #[arg(long = "secret", short = 's', value_name = "SPEC")]
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
        #[arg(long = "mount", short = 'm', value_name = "HOST:GUEST")]
        mounts: Vec<String>,

        /// Write structured audit events to a JSON-lines file.
        /// Records: connections, injections, scrubs, rejections.
        #[arg(long, value_name = "PATH")]
        audit_log: Option<String>,

        /// Write proxy/VM logs to a file instead of stderr.
        /// Useful in interactive mode where stderr interleaves with the TUI.
        #[arg(long, value_name = "PATH")]
        log_file: Option<String>,

        /// Discover mode: allow all connections, print observed hosts at exit.
        /// Run once to find out what hosts the agent needs, then lock down.
        #[arg(long)]
        discover: bool,
    },

    /// Manage rootfs images
    Image {
        #[command(subcommand)]
        action: ImageAction,
    },

    /// Manage execution sessions
    Sessions {
        #[command(subcommand)]
        action: Option<SessionAction>,
    },

    /// View session logs
    Logs {
        /// Session ID (default: most recent)
        session: Option<String>,
        /// Follow (tail -f)
        #[arg(short, long)]
        follow: bool,
    },

    /// Generate redan.toml and image config for a project
    Init {
        /// Generate Claude Code devcontainer and config
        #[arg(long)]
        claude: bool,
    },
}

#[derive(clap::Subcommand)]
enum SessionAction {
    /// Show details for a session
    Show { id: String },
    /// Remove session(s). No ID = remove all exited sessions.
    Remove { id: Option<String> },
}

#[derive(clap::Subcommand)]
enum ImageAction {
    /// Create an Alpine-based image with specified packages
    Create {
        /// Image name
        name: String,
        /// APK packages to install
        #[arg(long = "packages", value_delimiter = ' ')]
        packages: Vec<String>,
        /// Extra commands to run in the build VM
        #[arg(long = "run", value_name = "CMD")]
        run_commands: Vec<String>,
    },
    /// List available images
    List,
    /// Remove an image
    Remove { name: String },
    /// Import from Docker image, Dockerfile, or devcontainer
    Import {
        /// Image name to create
        name: String,
        /// Docker image to import (e.g., ubuntu:24.04)
        #[arg(long)]
        from: Option<String>,
        /// Dockerfile to build and import
        #[arg(long)]
        dockerfile: Option<String>,
        /// Devcontainer directory or JSON path
        #[arg(long)]
        devcontainer: Option<String>,
    },
}

#[allow(clippy::expect_used)] // Crypto provider init is unrecoverable
fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cli = Cli::parse();

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
            let all_secrets = cmd::exec::collect_secret_specs(&secrets, secret_file.as_deref());
            cmd::doctor::run(&all_secrets, image.as_deref());
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
            discover,
        } => {
            let cfg = config::find_and_load();
            if let Some((path, _)) = &cfg {
                eprintln!("config: {}", path.display());
            }
            let cfg = cfg.map(|(_, c)| c).unwrap_or_default();

            let mut all_secrets = cmd::exec::collect_secret_specs(&secrets, secret_file.as_deref());
            all_secrets.extend(cfg.secret_specs());
            let secrets = all_secrets;

            let image_name = image_name.or_else(|| cfg.image.clone());
            let rootfs = rootfs.or_else(|| cfg.rootfs.clone());
            // Trailing args after -- joined into a shell command.
            // Falls back to config file, then /bin/sh for interactive.
            let command = if command.is_empty() {
                cfg.command.clone()
            } else {
                Some(shell_words::join(&command))
            };
            let timeout = timeout.or(cfg.timeout).unwrap_or(3600);
            let interactive = interactive || cfg.interactive.unwrap_or(false);
            let audit_log = audit_log.or_else(|| cfg.audit_log.clone());

            let mut allow_hosts = allow_hosts;
            allow_hosts.extend(cfg.network.allow.clone());

            // Import allowedDomains from Claude Code settings if present.
            // Lets users define network policy once in .claude/settings.json
            // and have redan enforce it with real VM isolation.
            let claude_domains = config::claude_allowed_domains();
            if !claude_domains.is_empty() {
                log::info!(
                    "imported {} domains from Claude Code settings",
                    claude_domains.len()
                );
                allow_hosts.extend(claude_domains);
            }

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
                    eprintln!("no image specified. Set image in redan.toml or pass --image <name>");
                    eprintln!("  redan init          generate a redan.toml");
                    eprintln!("  redan image list    show available images");
                    std::process::exit(1);
                }
            };
            let command = command.unwrap_or_else(|| {
                if interactive {
                    "/bin/sh".to_string()
                } else {
                    "echo 'no command specified; use: redan exec --image <name> -- <command>'".to_string()
                }
            });
            cmd::exec::run(&cmd::exec::ExecConfig {
                rootfs: &rootfs_path,
                command: &command,
                interactive,
                timeout_secs: timeout,
                secret_specs: &secrets,
                allow_host_specs: &allow_hosts,
                mount_specs: &mounts,
                audit_log_path: audit_log.as_deref(),
                image_name: image_name.as_deref(),
                guest_env: &cfg.env,
                discover,
            });
        }

        Cli::Image { action } => match action {
            ImageAction::Create {
                name,
                packages,
                run_commands,
            } => {
                if packages.is_empty() && run_commands.is_empty() {
                    eprintln!(
                        "warning: creating image with no packages or commands. Use --packages or --run."
                    );
                }
                match image::create(&name, &packages, &run_commands) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("image create failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
            ImageAction::List => {
                let images = image::list();
                if images.is_empty() {
                    eprintln!(
                        "no images. Create one with: redan image create <name> --packages 'nodejs npm'"
                    );
                } else {
                    for name in images {
                        let Ok(path) = image::image_path(&name) else {
                            continue;
                        };
                        let size = cmd::doctor::dir_size(&path);
                        println!("{name:20} {}", cmd::doctor::humanize_bytes(size));
                    }
                }
            }
            ImageAction::Remove { name } => match image::remove(&name) {
                Ok(()) => eprintln!("removed image '{name}'"),
                Err(e) => {
                    eprintln!("remove failed: {e}");
                    std::process::exit(1);
                }
            },
            ImageAction::Import {
                name,
                from,
                dockerfile,
                devcontainer,
            } => {
                let result = import_image(&name, from, dockerfile, devcontainer);
                if let Err(e) = result {
                    eprintln!("import failed: {e}");
                    std::process::exit(1);
                }
            }
        },
        Cli::Logs { session, follow } => logs(session.as_deref(), follow),
        Cli::Init { claude } => cmd::init::run(claude),
        Cli::Sessions { action } => match action {
            None => {
                let sessions = session::list_sessions();
                if sessions.is_empty() {
                    eprintln!("no sessions. Run: redan exec --image <name> -- <command>");
                } else {
                    for s in &sessions {
                        let status = session_status_label(s);
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
            Some(SessionAction::Show { id }) => {
                if !session::valid_session_id(&id) {
                    eprintln!("invalid session ID: {id}");
                    std::process::exit(1);
                }
                let dir = session::session_dir(&id);
                let meta_path = dir.join("meta.json");
                if let Ok(content) = std::fs::read_to_string(&meta_path) {
                    let meta: session::SessionMeta =
                        serde_json::from_str(&content).unwrap_or_else(|e| {
                            eprintln!("corrupt session metadata: {e}");
                            std::process::exit(1);
                        });
                    println!("session:  {}", meta.id);
                    println!("status:   {}", session_status_label(&meta));
                    println!("image:    {}", meta.image.as_deref().unwrap_or("-"));
                    println!("command:  {}", meta.command.as_deref().unwrap_or("-"));
                    println!("started:  {}", meta.started_at);
                    if let Some(pid) = meta.pid {
                        println!("pid:      {pid}");
                    }
                    println!("files:");
                    if let Ok(entries) = std::fs::read_dir(&dir) {
                        for entry in entries.flatten() {
                            let name = entry.file_name();
                            let size = entry.metadata().map_or(0, |m| m.len());
                            println!("  {} ({size} bytes)", name.to_string_lossy());
                        }
                    }
                } else {
                    eprintln!("session {id} not found");
                    std::process::exit(1);
                }
            }
            Some(SessionAction::Remove { id }) => {
                if let Some(id) = id {
                    if !session::valid_session_id(&id) {
                        eprintln!("invalid session ID: {id}");
                        std::process::exit(1);
                    }
                    let dir = session::session_dir(&id);
                    if dir.exists() {
                        std::fs::remove_dir_all(&dir).unwrap_or_else(|e| {
                            eprintln!("cannot remove session {id}: {e}");
                            std::process::exit(1);
                        });
                        eprintln!("removed session {id}");
                    } else {
                        eprintln!("session {id} not found");
                        std::process::exit(1);
                    }
                } else {
                    let sessions = session::list_sessions();
                    let mut removed = 0;
                    for s in &sessions {
                        let is_dead = matches!(
                            s.status,
                            session::SessionStatus::Finished | session::SessionStatus::Failed
                        ) || (matches!(s.status, session::SessionStatus::Running)
                            && !s.is_alive());
                        if is_dead {
                            let dir = session::session_dir(&s.id);
                            if std::fs::remove_dir_all(&dir).is_ok() {
                                removed += 1;
                            }
                        }
                    }
                    eprintln!("removed {removed} exited session(s)");
                }
            }
        },
    }
}

fn import_image(
    name: &str,
    from: Option<String>,
    dockerfile: Option<String>,
    devcontainer: Option<String>,
) -> std::io::Result<()> {
    if let Some(docker_image) = from {
        image::import_docker(name, &docker_image)?;
        return Ok(());
    }
    if let Some(path) = dockerfile {
        image::import_dockerfile(name, &path)?;
        return Ok(());
    }
    if let Some(path) = devcontainer {
        let config_path = cmd::init::resolve_devcontainer_path(&path);
        image::import_devcontainer(name, &config_path)?;
        return Ok(());
    }
    eprintln!("specify --from <image>, --dockerfile <path>, or --devcontainer <path>");
    std::process::exit(1);
}

fn session_status_label(s: &session::SessionMeta) -> &'static str {
    match &s.status {
        session::SessionStatus::Running if s.is_alive() => "running",
        session::SessionStatus::Running => "exited",
        session::SessionStatus::Finished => "finished",
        session::SessionStatus::Failed => "failed",
    }
}

fn logs(session_id: Option<&str>, follow: bool) {
    let id = session_id.map_or_else(
        || {
            let sessions = session::list_sessions();
            sessions.first().map_or_else(
                || {
                    eprintln!("no sessions found");
                    std::process::exit(1);
                },
                |s| s.id.clone(),
            )
        },
        String::from,
    );

    let log_path = session::session_dir(&id).join("redan.log");
    if !log_path.exists() {
        eprintln!("no logs for session {id} ({})", log_path.display());
        std::process::exit(1);
    }

    if follow {
        let status = std::process::Command::new("tail")
            .args(["-f", log_path.to_str().unwrap_or("")])
            .status();
        if let Err(e) = status {
            eprintln!("cannot run tail: {e}");
            std::process::exit(1);
        }
    } else {
        match std::fs::read_to_string(&log_path) {
            Ok(content) => print!("{content}"),
            Err(e) => {
                eprintln!("cannot read {}: {e}", log_path.display());
                std::process::exit(1);
            }
        }
    }
}
