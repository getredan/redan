use std::path::Path;

use redan::config;
use redan::templates;

pub(crate) struct ProjectDetection {
    pub description: String,
    pub hosts: Vec<String>,
    pub packages: Vec<String>,
    /// If set, this detection found a devcontainer config at this path
    pub devcontainer: Option<String>,
}

pub(crate) fn run(claude: bool) {
    if Path::new("redan.toml").exists() {
        eprintln!("redan.toml already exists. Remove it first to re-initialize.");
        std::process::exit(1);
    }

    let mut cfg = config::Config::default();

    // Detect project type and suggest defaults
    let detections = detect_project();
    let mut packages: Vec<String> = vec!["curl".into(), "ca-certificates".into(), "git".into()];

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

    if claude {
        cfg.command = Some("claude --dangerously-skip-permissions".into());
        cfg.interactive = Some(true);

        // Claude's config in a guest-only dir, not the mounted workspace,
        // so its credentials and history don't land in the project.
        cfg.env
            .insert("CLAUDE_CONFIG_DIR".into(), "/home/dev/.claude".into());

        // Claude Code API hosts
        let claude_hosts = [
            "api.anthropic.com",
            "statsig.anthropic.com",
            "sentry.io",
            "platform.claude.com",
            "raw.githubusercontent.com",
        ];
        for host in claude_hosts {
            if !cfg.network.allow.contains(&host.to_string()) {
                cfg.network.allow.push(host.into());
            }
        }

        write_claude_devcontainer(&detections, &packages);
    } else {
        cfg.command = Some("/bin/sh".into());
    }

    // Default mount: current directory
    cfg.mount.insert(
        "workspace".into(),
        config::MountConfig {
            source: ".".into(),
            target: Some("/workspace".into()),
            read_only: false,
        },
    );

    // Write redan.toml with inline comments
    let content = templates::redan_toml(&cfg, claude);

    std::fs::write("redan.toml", &content).unwrap_or_else(|e| {
        eprintln!("cannot write redan.toml: {e}");
        std::process::exit(1);
    });

    eprintln!("wrote redan.toml");
    let img = cfg.image.as_deref().unwrap_or("dev");

    eprintln!("\nnext steps:");
    if claude {
        eprintln!("  1. Build the image:");
        eprintln!("     redan image import {img} --devcontainer .devcontainer/redan");
    } else {
        let devcontainer_path = detections.iter().find_map(|d| d.devcontainer.as_deref());
        let dockerfile = ["Dockerfile", "dockerfile", "Containerfile"]
            .iter()
            .find(|f| Path::new(f).exists())
            .copied();

        if let Some(dc) = devcontainer_path {
            let dc_dir = Path::new(dc)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map_or_else(|| ".".into(), |p| p.to_string_lossy().into_owned());
            eprintln!("  1. Build the image from your devcontainer:");
            eprintln!("     redan image import {img} --devcontainer {dc_dir}");
        } else if let Some(df) = dockerfile {
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
    }
    eprintln!("  Run: redan exec");
}

fn write_claude_devcontainer(detections: &[ProjectDetection], packages: &[String]) {
    let dir = Path::new(".devcontainer/redan");
    if dir.exists() {
        eprintln!(".devcontainer/redan already exists, skipping generation");
        return;
    }
    std::fs::create_dir_all(dir).unwrap_or_else(|e| {
        eprintln!("cannot create {}: {e}", dir.display());
        std::process::exit(1);
    });

    let has = |name: &str| detections.iter().any(|d| d.description.contains(name));

    let base_image = if has("Python") {
        "python:3.13-trixie"
    } else if has("Node") || has("Yarn") || has("pnpm") {
        "node:22-bookworm"
    } else if has("Rust") {
        "rust:1-bookworm"
    } else if has("Go") {
        "golang:1.23-bookworm"
    } else if has("Ruby") {
        "ruby:3.3-bookworm"
    } else {
        "debian:trixie"
    };

    let mut apt_packages: Vec<&str> = vec![
        "build-essential",
        "ca-certificates",
        "curl",
        "git",
        "iproute2",
        "make",
    ];
    for pkg in packages {
        match pkg.as_str() {
            "nodejs" | "npm" | "python3" | "py3-pip" | "cargo" | "rust" | "go" | "ruby" | "php"
            | "composer" => {}
            other if !apt_packages.contains(&other) => apt_packages.push(other),
            _ => {}
        }
    }
    apt_packages.sort_unstable();
    apt_packages.dedup();

    let needs_node = !base_image.starts_with("node:");
    let has_python = has("Python");
    let dockerfile =
        templates::claude_dockerfile(base_image, &apt_packages, needs_node, has_python);

    std::fs::write(dir.join("Dockerfile"), &dockerfile).unwrap_or_else(|e| {
        eprintln!("cannot write Dockerfile: {e}");
        std::process::exit(1);
    });
    std::fs::write(
        dir.join("devcontainer.json"),
        templates::devcontainer_json(),
    )
    .unwrap_or_else(|e| {
        eprintln!("cannot write devcontainer.json: {e}");
        std::process::exit(1);
    });

    eprintln!("wrote .devcontainer/redan/Dockerfile");
    eprintln!("wrote .devcontainer/redan/devcontainer.json");
}

pub(crate) fn detect_project() -> Vec<ProjectDetection> {
    let mut detections = Vec::new();

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
        (
            "pubspec.yaml",
            "Flutter/Dart (pubspec.yaml)",
            &["pub.dev", "storage.googleapis.com"],
            &[],
        ),
        (
            "pom.xml",
            "Java (pom.xml)",
            &["repo1.maven.org"],
            &["openjdk21-jdk", "maven"],
        ),
        (
            "build.gradle",
            "Java/Kotlin (build.gradle)",
            &[
                "services.gradle.org",
                "plugins.gradle.org",
                "repo1.maven.org",
            ],
            &["openjdk21-jdk"],
        ),
        (
            "build.gradle.kts",
            "Kotlin (build.gradle.kts)",
            &[
                "services.gradle.org",
                "plugins.gradle.org",
                "repo1.maven.org",
            ],
            &["openjdk21-jdk"],
        ),
        ("Package.swift", "Swift (Package.swift)", &[], &[]),
        (
            "mix.exs",
            "Elixir (mix.exs)",
            &["hex.pm", "repo.hex.pm"],
            &["elixir"],
        ),
    ];

    for &(file, desc, hosts, pkgs) in rules {
        if Path::new(file).exists() {
            detections.push(ProjectDetection {
                description: desc.to_string(),
                hosts: hosts.iter().copied().map(String::from).collect(),
                packages: pkgs.iter().copied().map(String::from).collect(),
                devcontainer: None,
            });
        }
    }

    // Devcontainer detection (takes priority over Dockerfile)
    let devcontainer_paths = [".devcontainer/devcontainer.json", ".devcontainer.json"];
    let mut found_devcontainer = false;
    for path in devcontainer_paths {
        if Path::new(path).exists() {
            detections.push(ProjectDetection {
                description: format!("devcontainer ({path})"),
                hosts: vec![],
                packages: vec![],
                devcontainer: Some(path.to_string()),
            });
            found_devcontainer = true;
            break;
        }
    }

    // Dockerfile detection (skip if devcontainer found)
    if !found_devcontainer {
        for name in ["Dockerfile", "dockerfile", "Containerfile"] {
            if Path::new(name).exists() {
                let mut pkgs = Vec::new();
                if let Ok(content) = std::fs::read_to_string(name) {
                    for line in content.lines() {
                        let trimmed = line.trim();
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
                    devcontainer: None,
                });
                break;
            }
        }
    }

    // Git remote detection
    if let Ok(config) = std::fs::read_to_string(".git/config") {
        if config.contains("github.com") {
            detections.push(ProjectDetection {
                description: "GitHub remote".into(),
                hosts: vec!["github.com".into(), "api.github.com".into()],
                packages: vec![],
                devcontainer: None,
            });
        } else if config.contains("gitlab.com") {
            detections.push(ProjectDetection {
                description: "GitLab remote".into(),
                hosts: vec!["gitlab.com".into()],
                packages: vec![],
                devcontainer: None,
            });
        }
    }

    detections
}

pub(crate) fn parse_dockerfile_packages(line: &str) -> Vec<String> {
    let mut packages = Vec::new();

    for cmd in line.split("&&") {
        let cmd = cmd.trim();
        let words: Vec<&str> = cmd.split_whitespace().collect();
        let start = words.iter().position(|&w| w == "install" || w == "add");
        if let Some(idx) = start {
            for &word in &words[idx + 1..] {
                if word.starts_with('-')
                    || word.starts_with('\\')
                    || word == "&&"
                    || word.contains('=')
                    || word.contains('/')
                    || word.contains('>')
                {
                    continue;
                }
                packages.push(word.to_string());
            }
        }
    }
    packages
}

/// Resolve a --devcontainer argument to a devcontainer.json path.
pub(crate) fn resolve_devcontainer_path(path: &str) -> String {
    let p = Path::new(path);
    if p.is_file() {
        return path.to_string();
    }
    let candidates = [
        p.join("devcontainer.json"),
        p.join(".devcontainer/devcontainer.json"),
        p.join(".devcontainer.json"),
    ];
    for c in &candidates {
        if c.is_file() {
            return c.to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(pkgs.contains(&"pnpm".to_string()));
    }
}
