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

        /// Run session in the background. Use `redan attach` to reconnect.
        #[arg(long, short = 'd')]
        detach: bool,

        /// Name this session for easy reference (e.g., `redan attach my-agent`).
        #[arg(long)]
        name: Option<String>,
    },

    /// Attach to a running session
    Attach {
        /// Session ID or name (default: most recent running session)
        session: Option<String>,
    },

    /// Stop a running session
    Stop {
        /// Session ID or name (default: most recent running session)
        session: Option<String>,
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

    /// Internal: daemon process for detached sessions. Not user-facing.
    #[command(hide = true)]
    Daemon {
        /// Session ID to run
        #[arg(long)]
        session: String,
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
    /// Rebuild an image from its original source
    Update { name: String },
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
            detach,
            name,
        } => {
            exec_command(ExecArgs {
                image_name,
                rootfs,
                command,
                interactive,
                timeout,
                secrets,
                secret_file,
                allow_hosts,
                mounts,
                audit_log,
                discover,
                detach,
                name,
            });
        }
        Cli::Attach { session } => attach_session(session.as_deref()),
        Cli::Stop { session } => stop_session(session.as_deref()),
        Cli::Daemon { session } => run_daemon(&session),

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
                        let age = redan::image_meta::ImageMeta::load(&path)
                            .and_then(|m| m.age_days())
                            .map_or(String::new(), |d| format!("  ({d}d ago)"));
                        println!("{name:20} {}{}", cmd::doctor::humanize_bytes(size), age);
                    }
                }
            }
            ImageAction::Update { name } => update_image(&name),
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
                    eprintln!("no sessions. Run: redan exec");
                } else {
                    for s in &sessions {
                        let status = session_status_label(s);
                        let name = s.name.as_deref().unwrap_or("");
                        let image = s.image.as_deref().unwrap_or("-");
                        if name.is_empty() {
                            println!("{}  {:10} {:20} {}", s.id, status, image, s.started_at,);
                        } else {
                            println!(
                                "{}  {:10} {:20} {} ({})",
                                s.id, status, image, s.started_at, name,
                            );
                        }
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

struct ExecArgs {
    image_name: Option<String>,
    rootfs: Option<String>,
    command: Vec<String>,
    interactive: bool,
    timeout: Option<u64>,
    secrets: Vec<String>,
    secret_file: Option<String>,
    allow_hosts: Vec<String>,
    mounts: Vec<String>,
    audit_log: Option<String>,
    discover: bool,
    detach: bool,
    name: Option<String>,
}

fn exec_command(args: ExecArgs) {
    let config_file = config::find_and_load();
    if let Some((ref path, _)) = config_file {
        eprintln!("config: {}", path.display());
    }

    let explicit = redan::auto_detect::has_explicit_flags(&redan::auto_detect::ExecFlags {
        image: &args.image_name,
        rootfs: &args.rootfs,
        command: &args.command,
        secrets: &args.secrets,
        secret_file: &args.secret_file,
        mounts: &args.mounts,
        discover: args.discover,
        detach: args.detach,
    });

    // Three paths:
    // 1. Config file exists → use it (existing behavior)
    // 2. Explicit CLI flags → use them (existing behavior)
    // 3. Neither → try auto-detect
    let cfg = if let Some((_, cfg)) = config_file {
        cfg
    } else if !explicit {
        // No config, no explicit flags: try auto-detect
        if let Some(auto) = redan::auto_detect::detect() {
            if auto.needs_image_build {
                eprintln!("Building claude-code image (this may take a minute)...");
                match image::import_dockerfile("claude-code", "dockerfiles/claude-code.dockerfile")
                {
                    Ok(_) => eprintln!("Image claude-code built successfully."),
                    Err(e) => {
                        eprintln!("error: failed to build claude-code image: {e}");
                        eprintln!(
                            "  Build manually: redan image import claude-code --dockerfile dockerfiles/claude-code.dockerfile"
                        );
                        std::process::exit(1);
                    }
                }
            }
            for msg in &auto.messages {
                eprintln!("  {msg}");
            }
            auto.config
        } else {
            eprintln!("no redan.toml found and auto-detect failed.");
            eprintln!();
            if std::env::var("ANTHROPIC_API_KEY").is_err() {
                eprintln!("  Set ANTHROPIC_API_KEY to auto-detect Claude Code:");
                eprintln!("    export ANTHROPIC_API_KEY=sk-ant-...");
                eprintln!();
            }
            eprintln!("  Or create a config:");
            eprintln!("    redan init          generate a redan.toml");
            eprintln!("    redan init --claude  generate config + devcontainer for Claude Code");
            eprintln!();
            eprintln!("  Or specify an image directly:");
            eprintln!("    redan exec --image <name> -- <command>");
            eprintln!("    redan image list    show available images");
            std::process::exit(1);
        }
    } else {
        config::Config::default()
    };

    let mut all_secrets =
        cmd::exec::collect_secret_specs(&args.secrets, args.secret_file.as_deref());
    all_secrets.extend(cfg.secret_specs());
    let secrets = all_secrets;

    let image_name = args.image_name.or_else(|| cfg.image.clone());
    let rootfs = args.rootfs.or_else(|| cfg.rootfs.clone());
    let command = if args.command.is_empty() {
        cfg.command.clone()
    } else {
        Some(shell_words::join(&args.command))
    };
    let timeout = args.timeout.or(cfg.timeout).unwrap_or(3600);
    let interactive = args.interactive || cfg.interactive.unwrap_or(false);
    let audit_log = args.audit_log.or_else(|| cfg.audit_log.clone());

    let mut allow_hosts = args.allow_hosts;
    allow_hosts.extend(cfg.network.allow.clone());

    // Import allowedDomains from Claude Code settings if present.
    let claude_domains = config::claude_allowed_domains();
    if !claude_domains.is_empty() {
        log::info!(
            "imported {} domains from Claude Code settings",
            claude_domains.len()
        );
        allow_hosts.extend(claude_domains);
    }

    let mut mounts = args.mounts;
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
            // Warn about stale images (don't block execution)
            if let Some(meta) = redan::image_meta::ImageMeta::load(&p)
                && let Some(days) = meta.age_days()
                && days > 30
            {
                eprintln!(
                    "warning: image '{name}' is {days} days old. Run: redan image update {name}"
                );
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
    if args.detach {
        exec_detached(
            &rootfs_path,
            &command,
            timeout,
            &secrets,
            &allow_hosts,
            &mounts,
            audit_log.as_deref(),
            image_name.as_deref(),
            &cfg.env,
            args.discover,
            args.name.as_deref(),
        );
    } else {
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
            discover: args.discover,
            session_name: args.name.as_deref(),
            session_id: None,
        });
    }
}

/// Serializable exec config for passing to the daemon process.
#[derive(serde::Serialize, serde::Deserialize)]
struct DaemonConfig {
    rootfs: String,
    command: String,
    timeout_secs: u64,
    secrets: Vec<String>,
    allow_hosts: Vec<String>,
    mounts: Vec<String>,
    audit_log: Option<String>,
    image_name: Option<String>,
    env: std::collections::BTreeMap<String, String>,
    discover: bool,
    session_name: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn exec_detached(
    rootfs: &str,
    command: &str,
    timeout: u64,
    secrets: &[String],
    allow_hosts: &[String],
    mounts: &[String],
    audit_log: Option<&str>,
    image_name: Option<&str>,
    env: &std::collections::BTreeMap<String, String>,
    discover: bool,
    session_name: Option<&str>,
) {
    // Create session directory and write daemon config
    let session_id = session::new_id();
    let session_dir = session::session_dir(&session_id);
    std::fs::create_dir_all(&session_dir).unwrap_or_else(|e| {
        eprintln!("cannot create session dir: {e}");
        std::process::exit(1);
    });

    let daemon_cfg = DaemonConfig {
        rootfs: rootfs.into(),
        command: command.into(),
        timeout_secs: timeout,
        secrets: secrets.to_vec(),
        allow_hosts: allow_hosts.to_vec(),
        mounts: mounts.to_vec(),
        audit_log: audit_log.map(Into::into),
        image_name: image_name.map(Into::into),
        env: env.clone(),
        discover,
        session_name: session_name.map(Into::into),
    };

    let config_path = session_dir.join("daemon_config.json");
    let config_json = serde_json::to_string(&daemon_cfg).unwrap_or_else(|e| {
        eprintln!("cannot serialize daemon config: {e}");
        std::process::exit(1);
    });
    std::fs::write(&config_path, &config_json).unwrap_or_else(|e| {
        eprintln!("cannot write daemon config: {e}");
        std::process::exit(1);
    });

    // Spawn daemon process
    let exe = std::env::current_exe().unwrap_or_else(|e| {
        eprintln!("cannot find redan executable: {e}");
        std::process::exit(1);
    });

    let log_path = session_dir.join("redan.log");
    let log_file = std::fs::File::create(&log_path).unwrap_or_else(|e| {
        eprintln!("cannot create log file: {e}");
        std::process::exit(1);
    });

    let mut child = std::process::Command::new(exe)
        .arg("daemon")
        .arg("--session")
        .arg(&session_id)
        .stdin(std::process::Stdio::null())
        .stdout(log_file.try_clone().unwrap_or_else(|e| {
            eprintln!("cannot clone log file handle: {e}");
            std::process::exit(1);
        }))
        .stderr(log_file)
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("cannot spawn daemon: {e}");
            std::process::exit(1);
        });

    let daemon_pid = child.id();

    // Detach from child: parent exits soon, daemon gets reparented to init.
    // Spawn a thread to wait() so we don't leave a zombie if parent lingers.
    std::thread::spawn(move || {
        let _ = child.wait();
    });

    // Write initial session metadata
    let mut meta = session::SessionMeta::new(&session_id, image_name, Some(command));
    meta.pid = Some(daemon_pid);
    meta.name = session_name.map(Into::into);
    if let Err(e) = meta.save() {
        eprintln!("warning: cannot save session metadata: {e}");
    }

    let name_display = session_name.map_or(String::new(), |n| format!(" ({n})"));
    eprintln!("session {session_id}{name_display} started (detached)");
    eprintln!("  redan logs {session_id} -f  tail logs");
    eprintln!("  redan stop {session_id}     stop session");
}

fn run_daemon(session_id: &str) {
    let session_dir = session::session_dir(session_id);
    let config_path = session_dir.join("daemon_config.json");

    let config_json = std::fs::read_to_string(&config_path).unwrap_or_else(|e| {
        eprintln!("cannot read daemon config: {e}");
        std::process::exit(1);
    });
    let cfg: DaemonConfig = serde_json::from_str(&config_json).unwrap_or_else(|e| {
        eprintln!("invalid daemon config: {e}");
        std::process::exit(1);
    });

    // Clean up the config file — it contains secret specs
    let _ = std::fs::remove_file(&config_path);

    // Run the VM+proxy (non-interactive: daemon has no terminal)
    cmd::exec::run(&cmd::exec::ExecConfig {
        rootfs: &cfg.rootfs,
        command: &cfg.command,
        interactive: false,
        timeout_secs: cfg.timeout_secs,
        secret_specs: &cfg.secrets,
        allow_host_specs: &cfg.allow_hosts,
        mount_specs: &cfg.mounts,
        audit_log_path: cfg.audit_log.as_deref(),
        image_name: cfg.image_name.as_deref(),
        guest_env: &cfg.env,
        discover: cfg.discover,
        session_name: cfg.session_name.as_deref(),
        session_id: Some(session_id),
    });
}

fn attach_session(id_or_name: Option<&str>) {
    let meta = session::find_session(id_or_name).unwrap_or_else(|| {
        if let Some(q) = id_or_name {
            eprintln!("session '{q}' not found");
        } else {
            eprintln!("no sessions found");
        }
        std::process::exit(1);
    });

    if !meta.is_alive() {
        eprintln!("session {} is not running", meta.id);
        std::process::exit(1);
    }

    let sock_path = meta.console_socket.unwrap_or_else(|| {
        eprintln!(
            "session {} has no console socket (started without --detach?)",
            meta.id
        );
        std::process::exit(1);
    });

    let sock_path = std::path::Path::new(&sock_path);
    if !sock_path.exists() {
        eprintln!("console socket not found: {}", sock_path.display());
        std::process::exit(1);
    }

    eprintln!("attaching to session {} ...", meta.id);

    let stream = std::os::unix::net::UnixStream::connect(sock_path).unwrap_or_else(|e| {
        eprintln!("cannot connect to console: {e}");
        std::process::exit(1);
    });

    // Raw terminal mode for interactive I/O
    let _raw_guard = redan::terminal::RawTerminalGuard::enter();

    // Relay between stdin/stdout and the console socket
    let reader = stream.try_clone().unwrap_or_else(|e| {
        eprintln!("cannot clone socket: {e}");
        std::process::exit(1);
    });

    // Socket → stdout
    let stdout_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut reader = reader;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    use std::io::Write;
                    let _ = std::io::stdout().write_all(&buf[..n]);
                    let _ = std::io::stdout().flush();
                }
            }
        }
    });

    // stdin → socket
    {
        use std::io::Read;
        let mut writer = stream;
        let mut buf = [0u8; 4096];
        loop {
            match std::io::stdin().read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    use std::io::Write;
                    if writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    }

    let _ = stdout_thread.join();
    eprintln!("\ndetached from session {}", meta.id);
}

fn stop_session(id_or_name: Option<&str>) {
    let meta = session::find_session(id_or_name).unwrap_or_else(|| {
        if let Some(q) = id_or_name {
            eprintln!("session '{q}' not found");
        } else {
            eprintln!("no sessions found");
        }
        std::process::exit(1);
    });

    if !meta.is_alive() {
        eprintln!("session {} is not running", meta.id);
        std::process::exit(1);
    }

    let pid = meta.pid.unwrap_or_else(|| {
        eprintln!("session {} has no pid recorded", meta.id);
        std::process::exit(1);
    });

    eprintln!("stopping session {} (pid {pid})...", meta.id);

    // Send SIGTERM for graceful shutdown
    let ret = unsafe { libc::kill(pid.cast_signed(), libc::SIGTERM) };
    if ret != 0 {
        eprintln!(
            "failed to send SIGTERM: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }

    // Wait briefly for exit, then SIGKILL
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if !meta.is_alive() {
            eprintln!("session {} stopped", meta.id);
            return;
        }
    }

    eprintln!("session {} did not exit, sending SIGKILL", meta.id);
    unsafe {
        libc::kill(pid.cast_signed(), libc::SIGKILL);
    }
    eprintln!("session {} killed", meta.id);
}

fn update_image(name: &str) {
    let path = match image::image_path(name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    if !path.exists() {
        eprintln!("image '{name}' not found");
        std::process::exit(1);
    }

    let meta = redan::image_meta::ImageMeta::load(&path).unwrap_or_else(|| {
        eprintln!("image '{name}' has no build metadata (cannot determine how it was built)");
        eprintln!("  remove and rebuild manually: redan image remove {name}");
        std::process::exit(1);
    });

    eprintln!("updating image '{name}'...");

    // Remove old image first
    if let Err(e) = image::remove(name) {
        eprintln!("cannot remove old image: {e}");
        std::process::exit(1);
    }

    let result = match &meta.source {
        redan::image_meta::ImageSource::Dockerfile { path } => image::import_dockerfile(name, path),
        redan::image_meta::ImageSource::Docker { image: img } => image::import_docker(name, img),
        redan::image_meta::ImageSource::Devcontainer { path } => {
            let config_path = cmd::init::resolve_devcontainer_path(path);
            image::import_devcontainer(name, &config_path)
        }
        redan::image_meta::ImageSource::Create {
            packages,
            run_commands,
        } => image::create(name, packages, run_commands),
        redan::image_meta::ImageSource::Unknown => {
            eprintln!("image '{name}' was built from an unknown source, cannot update");
            eprintln!("  remove and rebuild manually: redan image remove {name}");
            std::process::exit(1);
        }
    };

    match result {
        Ok(_) => eprintln!("image '{name}' updated"),
        Err(e) => {
            eprintln!("update failed: {e}");
            std::process::exit(1);
        }
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
