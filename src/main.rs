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

        /// Shell command to run in the guest.
        /// If omitted in interactive mode, defaults to /bin/sh.
        #[arg(long, short = 'c')]
        command: Option<String>,

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

        /// Forward a guest TCP port to host localhost.
        /// Format: PORT (same port both sides) or `GUEST_PORT:HOST_PORT`.
        /// The guest connects to the gateway IP on `GUEST_PORT`; redan
        /// relays to `127.0.0.1:HOST_PORT`.
        #[arg(long = "forward", value_name = "SPEC")]
        forwards: Vec<String>,

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

        /// Launch headless Chrome on the host with CDP access from the guest.
        /// Chrome's outbound traffic goes through an allowlist proxy (same
        /// hosts as `--allow-host`). The guest sees `REDAN_BROWSER=1`,
        /// `REDAN_BROWSER_HOST`, and `REDAN_BROWSER_CDP_PORT` env vars.
        #[arg(long)]
        browser: bool,

        /// Run session in the background. Use `redan attach` to reconnect.
        #[arg(long, short = 'd')]
        detach: bool,

        /// Name this session for easy reference (e.g., `redan attach my-agent`).
        #[arg(long)]
        name: Option<String>,
    },

    /// Launch a coding agent in a sandbox (claude, pi). Zero-config.
    ///
    /// `redan run` picks the agent's image, command, auth, and network
    /// policy for you. Omit the agent name to auto-detect. For full manual
    /// control over image and command, use `redan exec` instead.
    Run {
        /// Agent to launch (e.g. `claude`, `pi`). Omit to auto-detect.
        agent: Option<String>,

        /// Allow outbound HTTPS to a host (in addition to the agent's own).
        /// Use '*' to allow all outbound connections.
        #[arg(long = "allow-host", value_name = "HOST")]
        allow_hosts: Vec<String>,

        /// Launch headless Chrome on the host with CDP access from the guest.
        #[arg(long)]
        browser: bool,

        /// Mount a host directory into the guest via virtio-fs.
        #[arg(long = "mount", short = 'm', value_name = "HOST:GUEST")]
        mounts: Vec<String>,

        /// Forward a guest TCP port to host localhost (PORT or GUEST:HOST).
        #[arg(long = "forward", value_name = "SPEC")]
        forwards: Vec<String>,

        /// Inject a secret: `ENV_VAR=real_value:host1,host2`
        #[arg(long = "secret", short = 's', value_name = "SPEC")]
        secrets: Vec<String>,

        /// Read secret specs from a file (one per line).
        #[arg(long, value_name = "PATH")]
        secret_file: Option<String>,

        /// Write structured audit events to a JSON-lines file.
        #[arg(long, value_name = "PATH")]
        audit_log: Option<String>,

        /// Proxy timeout in seconds (0 = wait for VM exit).
        #[arg(long)]
        timeout: Option<u64>,

        /// Discover mode: allow all connections, print observed hosts at exit.
        #[arg(long)]
        discover: bool,

        /// Run session in the background. Use `redan attach` to reconnect.
        #[arg(long, short = 'd')]
        detach: bool,

        /// Name this session for easy reference.
        #[arg(long)]
        name: Option<String>,

        /// Extra arguments appended to the agent command (after `--`).
        #[arg(last = true)]
        extra: Vec<String>,
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

    /// View a session's audit event stream (logfmt; `--json` for raw events)
    Logs {
        /// Session ID or name (default: most recent)
        session: Option<String>,
        /// Follow the log live as new events arrive
        #[arg(short, long)]
        follow: bool,
        /// Print raw JSON events instead of logfmt (for piping to `jq`)
        #[arg(long)]
        json: bool,
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

    /// Review and trust a redan.toml so redan will act on it
    ///
    /// A working-directory redan.toml that reads host env vars or Vault, mounts
    /// host paths, sets a rootfs, forwards host ports, or writes host logs must
    /// be trusted first. Trust is a machine-local record keyed by the file's
    /// contents, so editing the file requires trusting it again.
    Trust {
        /// Path to the config (default: ./redan.toml)
        path: Option<String>,
    },

    /// Remove a redan.toml from the trust store
    Untrust {
        /// Path to the config (default: ./redan.toml)
        path: Option<String>,
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
        /// Replace existing image if it already exists
        #[arg(long, short = 'f')]
        force: bool,
    },
}

fn main() {
    redan::ensure_crypto_provider();

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
            forwards,
            mounts,
            audit_log,
            log_file: _,
            browser,
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
                forwards,
                discover,
                detach,
                name,
                run_as: None,
                browser,
            });
        }
        Cli::Run {
            agent,
            allow_hosts,
            browser,
            mounts,
            forwards,
            secrets,
            secret_file,
            audit_log,
            timeout,
            discover,
            detach,
            name,
            extra,
        } => {
            run_command(RunArgs {
                agent,
                allow_hosts,
                browser,
                mounts,
                forwards,
                secrets,
                secret_file,
                audit_log,
                timeout,
                discover,
                detach,
                name,
                extra,
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
                force,
            } => {
                let result = import_image(&name, from, dockerfile, devcontainer, force);
                if let Err(e) = result {
                    eprintln!("import failed: {e}");
                    std::process::exit(1);
                }
            }
        },
        Cli::Logs {
            session,
            follow,
            json,
        } => cmd::logs::run(session.as_deref(), follow, json),
        Cli::Init { claude } => cmd::init::run(claude),
        Cli::Trust { path } => cmd::trust::trust_cmd(path.as_deref()),
        Cli::Untrust { path } => cmd::trust::untrust_cmd(path.as_deref()),
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

#[allow(clippy::struct_excessive_bools)] // CLI flags map naturally to bools
struct ExecArgs {
    image_name: Option<String>,
    rootfs: Option<String>,
    command: Option<String>,
    interactive: bool,
    timeout: Option<u64>,
    secrets: Vec<String>,
    secret_file: Option<String>,
    allow_hosts: Vec<String>,
    mounts: Vec<String>,
    audit_log: Option<String>,
    forwards: Vec<String>,
    discover: bool,
    detach: bool,
    name: Option<String>,
    run_as: Option<String>,
    browser: bool,
}

fn exec_command(args: ExecArgs) {
    let config_file = cmd::trust::load_config();
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
    });

    // Three paths:
    // 1. Config file exists → use it (existing behavior)
    // 2. Explicit CLI flags → use them (existing behavior)
    // 3. Neither → try auto-detect
    let (cfg, run_as, stage_files) = if let Some((_, cfg)) = config_file {
        (cfg, None, Vec::new())
    } else if !explicit {
        // No config, no explicit flags: try auto-detect
        if let Some(auto) = redan::auto_detect::detect() {
            build_image_if_needed(&auto);
            for msg in &auto.messages {
                eprintln!("  {msg}");
            }
            let run_as = auto.run_as.map(Into::into);
            (auto.config, run_as, auto.stage_files)
        } else {
            eprintln!("no redan.toml found and auto-detect failed.");
            eprintln!();
            eprintln!("  Auto-detect needs one of:");
            eprintln!("    export ANTHROPIC_API_KEY=sk-ant-...    (API key)");
            eprintln!("    claude login                           (OAuth/Pro/Max/Team)");
            eprintln!();
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
        (config::Config::default(), None, Vec::new())
    };

    launch(&cfg, run_as, &stage_files, args);
}

/// Build an agent's image if auto-detect flagged it missing.
fn build_image_if_needed(auto: &redan::auto_detect::AutoDetected) {
    if !auto.needs_image_build {
        return;
    }
    let image_name = auto.config.image.as_deref().unwrap_or("unknown");
    eprintln!("Building {image_name} image (this may take a minute)...");
    match build_bundled_image(image_name) {
        Ok(_) => eprintln!("Image {image_name} built successfully."),
        Err(e) => {
            eprintln!("error: failed to build {image_name} image: {e}");
            std::process::exit(1);
        }
    }
}

/// Resolve final config from a base Config plus CLI overrides, then boot.
/// Shared by `redan exec` (base from config/flags/auto-detect) and
/// `redan run` (base from a named agent profile).
fn launch(
    cfg: &config::Config,
    detected_run_as: Option<String>,
    stage_files: &[(std::path::PathBuf, String, String)],
    args: ExecArgs,
) {
    let run_as = args.run_as.or(detected_run_as);

    let mut all_secrets =
        cmd::exec::collect_secret_specs(&args.secrets, args.secret_file.as_deref());
    all_secrets.extend(cfg.secret_specs());
    let secrets = all_secrets;

    let image_name = args.image_name.or_else(|| cfg.image.clone());
    let rootfs = args.rootfs.or_else(|| cfg.rootfs.clone());
    let command = args.command.or_else(|| cfg.command.clone());
    let timeout = args.timeout.or(cfg.timeout).unwrap_or(3600);
    let interactive = args.interactive || cfg.interactive.unwrap_or(false);
    let redirect_logs = interactive || redan::terminal::stdin_is_tty();
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

    let mut forwards = args.forwards;
    forwards.extend(cfg.network.forward.clone());

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
    // Stage credentials into the rootfs before boot (like CA cert install).
    // Runs on the host, no mount or runtime copy needed.
    let chown_dir: Option<String> = stage_files.first().map(|(_, d, _)| d.clone());
    for (host_path, guest_dir, filename) in stage_files {
        let target_dir = std::path::Path::new(&rootfs_path)
            .join(guest_dir.strip_prefix('/').unwrap_or(guest_dir));
        if let Err(e) = std::fs::create_dir_all(&target_dir) {
            eprintln!("error: cannot create {}: {e}", target_dir.display());
            std::process::exit(1);
        }
        let target_file = target_dir.join(filename);
        if let Err(e) = std::fs::copy(host_path, &target_file) {
            eprintln!(
                "error: cannot stage credentials {} → {}: {e}",
                host_path.display(),
                target_file.display()
            );
            std::process::exit(1);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // World-writable so the run_as user can update credentials.
            // Single-user VM; the VM itself is the security boundary.
            let _ = std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o777));
            let _ = std::fs::set_permissions(&target_file, std::fs::Permissions::from_mode(0o666));
        }
    }

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
            &forwards,
            &mounts,
            audit_log.as_deref(),
            image_name.as_deref(),
            &cfg.env,
            args.discover,
            args.name.as_deref(),
            run_as.as_deref(),
            chown_dir.as_deref(),
            args.browser,
        );
    } else {
        let guest_code = cmd::exec::run(&cmd::exec::ExecConfig {
            rootfs: &rootfs_path,
            command: &command,
            interactive,
            timeout_secs: timeout,
            secret_specs: &secrets,
            allow_host_specs: &allow_hosts,
            forward_specs: &forwards,
            mount_specs: &mounts,
            audit_log_path: audit_log.as_deref(),
            image_name: image_name.as_deref(),
            guest_env: &cfg.env,
            discover: args.discover,
            session_name: args.name.as_deref(),
            session_id: None,
            run_as: run_as.as_deref(),
            chown_dir: chown_dir.as_deref(),
            redirect_logs,
            browser: args.browser,
        });
        std::process::exit(guest_code);
    }
}

struct RunArgs {
    agent: Option<String>,
    allow_hosts: Vec<String>,
    browser: bool,
    mounts: Vec<String>,
    forwards: Vec<String>,
    secrets: Vec<String>,
    secret_file: Option<String>,
    audit_log: Option<String>,
    timeout: Option<u64>,
    discover: bool,
    detach: bool,
    name: Option<String>,
    extra: Vec<String>,
}

/// Resolve which agent `redan run` should launch. Exits with a helpful
/// message if the slug is unknown, the agent lacks credentials, or no
/// agent could be auto-detected.
fn resolve_run_target(agent: Option<&str>) -> redan::auto_detect::AutoDetected {
    use redan::auto_detect::{self, ResolveError};

    let Some(slug) = agent else {
        let Some(auto) = auto_detect::detect() else {
            eprintln!(
                "no agent detected. Known agents: {}",
                auto_detect::agent_slugs().join(", ")
            );
            eprintln!();
            eprintln!("  Authenticate one, then `redan run <agent>`:");
            eprintln!("    export ANTHROPIC_API_KEY=sk-ant-...   (API key)");
            eprintln!("    claude login                          (Claude Pro/Max/Team)");
            std::process::exit(1);
        };
        return auto;
    };

    match auto_detect::resolve_by_slug(slug) {
        Ok(auto) => auto,
        Err(ResolveError::Unknown) => {
            eprintln!(
                "unknown agent '{slug}'. Available: {}",
                auto_detect::agent_slugs().join(", ")
            );
            eprintln!("  Or run `redan run` with no agent to auto-detect.");
            std::process::exit(1);
        }
        Err(ResolveError::NoAuth(found)) => {
            eprintln!(
                "{} found, but no credentials in this environment.",
                found.name
            );
            print_agent_auth_hint(found);
            std::process::exit(1);
        }
    }
}

/// `redan run <agent>`: launch a named agent profile (or auto-detect when
/// no agent is given), then funnel into the shared `launch` path.
fn run_command(args: RunArgs) {
    // Trust-gate the project redan.toml up front, before any agent setup,
    // messages, or image build, so an untrusted config stops here cleanly
    // instead of after a wall of setup output. load_config exits the process
    // if the config needs trust it doesn't have.
    let project_config = cmd::trust::load_config();

    let auto = resolve_run_target(args.agent.as_deref());

    build_image_if_needed(&auto);
    for msg in &auto.messages {
        eprintln!("  {msg}");
    }

    let run_as = auto.run_as.map(Into::into);
    let stage_files = auto.stage_files;

    // The agent profile is a set of defaults; a project redan.toml layers on
    // top (overriding on conflict), then CLI flags override both in `launch`.
    // Precedence: agent defaults < redan.toml < CLI. With no redan.toml the
    // merge is a no-op.
    let config = match project_config {
        Some((path, project)) => {
            eprintln!("config: {}", path.display());
            config::overlay(auto.config, project)
        }
        None => auto.config,
    };

    // Append any post-`--` args to the agent command (e.g. an initial prompt).
    let command = if args.extra.is_empty() {
        None
    } else {
        let base = config.command.clone().unwrap_or_default();
        let extra = args
            .extra
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        Some(format!("{base} {extra}").trim().to_string())
    };

    launch(
        &config,
        run_as,
        &stage_files,
        ExecArgs {
            image_name: None, // the agent's Config carries the image
            rootfs: None,
            command,
            interactive: false, // the agent's Config carries interactive
            timeout: args.timeout,
            secrets: args.secrets,
            secret_file: args.secret_file,
            allow_hosts: args.allow_hosts,
            mounts: args.mounts,
            audit_log: args.audit_log,
            forwards: args.forwards,
            discover: args.discover,
            detach: args.detach,
            name: args.name,
            run_as: None, // the agent's run_as flows via detected_run_as
            browser: args.browser,
        },
    );
}

/// Print how to authenticate an agent whose creds weren't found.
fn print_agent_auth_hint(agent: &redan::auto_detect::AgentDef) {
    use redan::auto_detect::AuthMethod;
    for method in agent.auth {
        match method {
            AuthMethod::EnvSecret {
                env_var: "CLAUDE_CODE_OAUTH_TOKEN",
                ..
            } => {
                eprintln!(
                    "  run `claude setup-token`, then export CLAUDE_CODE_OAUTH_TOKEN (1-year)"
                );
            }
            AuthMethod::EnvSecret { env_var, .. } => eprintln!("  export {env_var}=..."),
            AuthMethod::StagedFiles { dir, probe, .. } => {
                eprintln!(
                    "  or sign in so ~/{dir}/{probe} exists (less reliable; it can go stale)"
                );
            }
        }
    }
}

/// Single-quote a shell argument so it survives `/bin/sh -c`.
fn shell_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Serializable exec config for passing to the daemon process.
#[derive(serde::Serialize, serde::Deserialize)]
struct DaemonConfig {
    rootfs: String,
    command: String,
    timeout_secs: u64,
    secrets: Vec<String>,
    allow_hosts: Vec<String>,
    forwards: Vec<String>,
    mounts: Vec<String>,
    audit_log: Option<String>,
    image_name: Option<String>,
    env: std::collections::BTreeMap<String, String>,
    discover: bool,
    session_name: Option<String>,
    run_as: Option<String>,
    chown_dir: Option<String>,
    browser: bool,
}

#[allow(clippy::too_many_arguments)]
fn exec_detached(
    rootfs: &str,
    command: &str,
    timeout: u64,
    secrets: &[String],
    allow_hosts: &[String],
    forwards: &[String],
    mounts: &[String],
    audit_log: Option<&str>,
    image_name: Option<&str>,
    env: &std::collections::BTreeMap<String, String>,
    discover: bool,
    session_name: Option<&str>,
    run_as: Option<&str>,
    chown_dir: Option<&str>,
    browser: bool,
) {
    // Create session directory and write daemon config.
    // Directory is 0o700 and config file is 0o600 because the config
    // contains secret specs that are briefly on disk until the daemon
    // reads and deletes them.
    let session_id = session::new_id();
    let session_dir = session::session_dir(&session_id);
    std::fs::create_dir_all(&session_dir).unwrap_or_else(|e| {
        eprintln!("cannot create session dir: {e}");
        std::process::exit(1);
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o700));
    }

    let daemon_cfg = DaemonConfig {
        rootfs: rootfs.into(),
        command: command.into(),
        timeout_secs: timeout,
        secrets: secrets.to_vec(),
        allow_hosts: allow_hosts.to_vec(),
        forwards: forwards.to_vec(),
        mounts: mounts.to_vec(),
        audit_log: audit_log.map(Into::into),
        image_name: image_name.map(Into::into),
        env: env.clone(),
        discover,
        session_name: session_name.map(Into::into),
        run_as: run_as.map(Into::into),
        chown_dir: chown_dir.map(Into::into),
        browser,
    };

    let config_path = session_dir.join("daemon_config.json");
    let config_json = serde_json::to_string(&daemon_cfg).unwrap_or_else(|e| {
        eprintln!("cannot serialize daemon config: {e}");
        std::process::exit(1);
    });
    {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        opts.open(&config_path)
            .and_then(|mut f| f.write_all(config_json.as_bytes()))
            .unwrap_or_else(|e| {
                eprintln!("cannot write daemon config: {e}");
                std::process::exit(1);
            });
    }

    // Spawn daemon process. If anything fails before the child starts,
    // clean up the session dir (it contains daemon_config.json with secret specs).
    let cleanup_and_exit = |msg: &str, err: &dyn std::fmt::Display| -> ! {
        eprintln!("{msg}: {err}");
        let _ = std::fs::remove_dir_all(&session_dir);
        std::process::exit(1);
    };

    let exe = std::env::current_exe().unwrap_or_else(|e| {
        cleanup_and_exit("cannot find redan executable", &e);
    });

    let log_path = session_dir.join("redan.log");
    let log_file = std::fs::File::create(&log_path).unwrap_or_else(|e| {
        cleanup_and_exit("cannot create log file", &e);
    });

    let mut child = std::process::Command::new(exe)
        .arg("daemon")
        .arg("--session")
        .arg(&session_id)
        .stdin(std::process::Stdio::null())
        .stdout(log_file.try_clone().unwrap_or_else(|e| {
            cleanup_and_exit("cannot clone log file handle", &e);
        }))
        .stderr(log_file)
        .spawn()
        .unwrap_or_else(|e| {
            cleanup_and_exit("cannot spawn daemon", &e);
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
    meta.audit_log = audit_log.map(Into::into);
    if let Err(e) = meta.save() {
        eprintln!("warning: cannot save session metadata: {e}");
    }

    let name_display = session_name.map_or(String::new(), |n| format!(" ({n})"));
    eprintln!("session {session_id}{name_display} started (detached)");
    eprintln!("  redan logs {session_id} -f  tail logs");
    eprintln!("  redan stop {session_id}     stop session");
}

fn run_daemon(session_id: &str) {
    if !session::valid_session_id(session_id) {
        eprintln!("invalid session ID: {session_id}");
        std::process::exit(1);
    }
    let session_dir = session::session_dir(session_id);
    let config_path = session_dir.join("daemon_config.json");

    // Open the file, then unlink it before reading. The fd keeps the
    // data accessible but the directory entry is gone, so a crash
    // between here and process exit can't leave secrets on disk.
    // Fail closed: if we can't unlink, don't proceed with secrets.
    let mut config_file = std::fs::File::open(&config_path).unwrap_or_else(|e| {
        eprintln!("cannot open daemon config: {e}");
        std::process::exit(1);
    });
    if let Err(e) = std::fs::remove_file(&config_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("cannot remove daemon config: {e}");
        std::process::exit(1);
    }

    let mut config_json = String::new();
    std::io::Read::read_to_string(&mut config_file, &mut config_json).unwrap_or_else(|e| {
        eprintln!("cannot read daemon config: {e}");
        std::process::exit(1);
    });
    let cfg: DaemonConfig = serde_json::from_str(&config_json).unwrap_or_else(|e| {
        eprintln!("invalid daemon config: {e}");
        std::process::exit(1);
    });

    // Run the VM+proxy (non-interactive: daemon has no terminal)
    let guest_code = cmd::exec::run(&cmd::exec::ExecConfig {
        rootfs: &cfg.rootfs,
        command: &cfg.command,
        interactive: false,
        timeout_secs: cfg.timeout_secs,
        secret_specs: &cfg.secrets,
        allow_host_specs: &cfg.allow_hosts,
        forward_specs: &cfg.forwards,
        mount_specs: &cfg.mounts,
        audit_log_path: cfg.audit_log.as_deref(),
        image_name: cfg.image_name.as_deref(),
        guest_env: &cfg.env,
        discover: cfg.discover,
        session_name: cfg.session_name.as_deref(),
        session_id: Some(session_id),
        run_as: cfg.run_as.as_deref(),
        chown_dir: cfg.chown_dir.as_deref(),
        redirect_logs: false,
        browser: cfg.browser,
    });
    std::process::exit(guest_code);
}

fn attach_session(id_or_name: Option<&str>) {
    let mut meta = session::find_session(id_or_name).unwrap_or_else(|| {
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

    // The daemon may not have written the console socket path to meta.json yet.
    // Retry briefly (up to 3s) before giving up.
    let sock_path_str = 'retry: {
        for _ in 0..10 {
            if let Some(ref s) = meta.console_socket {
                break 'retry s.clone();
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
            // Reload meta in case the daemon updated it
            let meta_path = session::session_dir(&meta.id).join("meta.json");
            if let Ok(json) = std::fs::read_to_string(&meta_path)
                && let Ok(fresh) = serde_json::from_str::<session::SessionMeta>(&json)
            {
                meta = fresh;
            }
        }
        eprintln!(
            "session {} has no console socket (started without --detach?)",
            meta.id
        );
        std::process::exit(1);
    };

    let sock_path = std::path::Path::new(&sock_path_str);
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
    let _raw_guard = redan::terminal::RawTerminalGuard::enter().unwrap_or_else(|e| {
        eprintln!("cannot enter raw terminal mode: {e}");
        std::process::exit(1);
    });

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

    if matches!(meta.source, redan::image_meta::ImageSource::Unknown) {
        eprintln!("image '{name}' was built from an unknown source, cannot update");
        eprintln!("  remove and rebuild manually: redan image remove {name}");
        std::process::exit(1);
    }

    // Move old image aside so we can restore it if the rebuild fails.
    // The build functions require the destination not to exist.
    let backup = {
        let mut b = path.clone();
        b.set_extension("bak");
        b
    };
    if let Err(e) = std::fs::rename(&path, &backup) {
        eprintln!("cannot back up old image: {e}");
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
        redan::image_meta::ImageSource::Unknown => unreachable!(),
    };

    match result {
        Ok(_) => {
            let _ = std::fs::remove_dir_all(&backup);
            eprintln!("image '{name}' updated");
        }
        Err(e) => {
            eprintln!("update failed: {e}");
            // Restore the old image so the user isn't left with nothing
            if let Err(restore_err) = std::fs::rename(&backup, &path) {
                eprintln!("cannot restore old image: {restore_err}");
                eprintln!("  backup is at: {}", backup.display());
            } else {
                eprintln!("old image restored");
            }
            std::process::exit(1);
        }
    }
}

fn import_image(
    name: &str,
    from: Option<String>,
    dockerfile: Option<String>,
    devcontainer: Option<String>,
    force: bool,
) -> std::io::Result<()> {
    if force
        && let Ok(path) = image::image_path(name)
        && path.exists()
    {
        eprintln!("removing existing image '{name}'...");
        image::remove(name)?;
    }
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

/// Build an agent image from a Dockerfile embedded in the binary.
fn build_bundled_image(name: &str) -> std::io::Result<std::path::PathBuf> {
    static CLAUDE_CODE_DOCKERFILE: &str = include_str!("../dockerfiles/claude-code.dockerfile");
    static PI_DOCKERFILE: &str = include_str!("../dockerfiles/pi.dockerfile");

    let dockerfile = match name {
        "claude-code" => CLAUDE_CODE_DOCKERFILE,
        "pi" => PI_DOCKERFILE,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no bundled Dockerfile for image '{name}'"),
            ));
        }
    };

    let tmp = std::env::temp_dir().join(format!("redan-{name}-build"));
    std::fs::create_dir_all(&tmp)?;
    let df_path = tmp.join("Dockerfile");
    std::fs::write(&df_path, dockerfile)?;
    let result = image::import_dockerfile(name, df_path.to_str().unwrap_or(""));
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

#[cfg(test)]
mod tests {
    use super::shell_quote;

    #[test]
    fn shell_quote_wraps_plain_arg() {
        assert_eq!(shell_quote("fix the bug"), "'fix the bug'");
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quote() {
        // don't -> 'don'\''t' (close, escaped quote, reopen)
        assert_eq!(shell_quote("don't"), "'don'\\''t'");
    }

    #[test]
    fn shell_quote_neutralizes_shell_metacharacters() {
        // Passthrough args must not break out of the agent command.
        assert_eq!(shell_quote("; rm -rf /"), "'; rm -rf /'");
        assert_eq!(shell_quote("$(whoami)"), "'$(whoami)'");
        assert_eq!(shell_quote("a && b"), "'a && b'");
    }
}
