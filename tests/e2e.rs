//! End-to-end tests that run the `redan` binary the way you would.
//!
//! Each test gets its own project directory, `HOME` and state directory, and a
//! cleared environment, so it never reads your `~/.claude` settings or shell
//! secrets and never touches your trust store or session list.
//!
//! The plain tests boot the `test` image (`redan image create test`) and run
//! with `mise run test`. The Claude Code evals are `#[ignore]`d because they
//! talk to the real Anthropic API: they need the `claude-code` image and
//! `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` in your environment, and
//! run with `mise run e2e`. Each eval checks its own outcome plus the
//! invariants in [`assert_token_stayed_on_host`].

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

/// `redan` installs its CA into the image it boots, and the tests share
/// images, so VM runs in this binary take turns.
static VM_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Wait for this test's turn to boot a VM. A test that failed while holding
/// the lock leaves it poisoned, and that shouldn't fail the tests after it.
fn vm_turn() -> MutexGuard<'static, ()> {
    VM_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Claude Code settings that would allow every host.
const WILDCARD_SETTINGS: &str = r#"{"sandbox": {"network": {"allowedDomains": ["*"]}}}"#;

/// A project directory and a home directory under one temp dir.
struct Sandbox {
    root: tempfile::TempDir,
}

#[expect(
    clippy::unwrap_used,
    reason = "test helpers outside a #[test] fn: a failed setup step must fail the test"
)]
impl Sandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("project")).unwrap();
        std::fs::create_dir(root.path().join("home")).unwrap();
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    /// Write a file into the project directory, creating parent directories.
    fn write(&self, relative: &str, content: &str) {
        let path = self.path("project").join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// Run `redan` in the project directory with no terminal attached.
    ///
    /// Only `PATH`, the sandbox's own `HOME` and state directory, and `env`
    /// reach the process. `XDG_DATA_HOME` keeps pointing at your real data
    /// directory so the images are found.
    fn redan(&self, args: &[&str], env: &[(&str, &OsString)]) -> Output {
        let images = redan::image::image_dir();
        let data_home = images.ancestors().nth(2).unwrap();
        Command::new(env!("CARGO_BIN_EXE_redan"))
            .args(args)
            .current_dir(self.path("project"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("XDG_DATA_HOME", data_home)
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}

#[expect(
    clippy::expect_used,
    reason = "test helper outside a #[test] fn: missing KVM must fail the test with a message"
)]
fn require_image(name: &str) {
    redan::check_kvm().expect("KVM required: /dev/kvm not accessible");
    assert!(
        redan::image::image_dir().join(name).join("bin").is_dir(),
        "{name} image not found: run `redan image create {name}` first"
    );
}

/// The `(event, host, reason)` of every audit event, from the JSON-lines log.
#[expect(
    clippy::unwrap_used,
    reason = "test helper outside a #[test] fn: an unreadable audit log must fail the test"
)]
fn audit_events(path: &Path) -> Vec<(String, String, String)> {
    let field = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .map(|event| {
            (
                field(&event, "event"),
                field(&event, "host"),
                field(&event, "reason"),
            )
        })
        .collect()
}

fn was_rejected(events: &[(String, String, String)], host: &str) -> bool {
    events
        .iter()
        .any(|(event, h, reason)| event == "reject" && h == host && reason == "not_allowed")
}

/// A repo's `.claude/settings.local.json` with `"*"` in `allowedDomains` used
/// to turn off the allowlist with no prompt. The `"*"` is now ignored with a
/// warning, so the guest's request to a host nobody allowed is rejected.
#[test]
fn claude_settings_wildcard_does_not_turn_off_the_allowlist() {
    require_image("test");
    let _turn = vm_turn();
    let sandbox = Sandbox::new();
    sandbox.write(".claude/settings.local.json", WILDCARD_SETTINGS);
    let audit_log = sandbox.path("audit.jsonl");

    let out = sandbox.redan(
        &[
            "exec",
            "--image",
            "test",
            "--timeout",
            "60",
            "--audit-log",
            audit_log.to_str().unwrap(),
            "-c",
            "wget -q -T 10 -O /dev/null https://example.com/",
        ],
        &[],
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(r#"warning: ignoring "*" in .claude/settings.local.json"#),
        "{stderr}"
    );
    let events = audit_events(&audit_log);
    assert!(was_rejected(&events, "example.com"), "{events:?}");
}

/// `allow = ["*"]` in a project's `redan.toml` needs trust. Without a
/// terminal to ask on, redan refuses to run and says what the config wants,
/// and once you've trusted it with `redan trust` it runs.
#[test]
fn redan_toml_allow_all_is_refused_until_trusted() {
    require_image("test");
    let _turn = vm_turn();
    let sandbox = Sandbox::new();
    sandbox.write(
        "redan.toml",
        "image = \"test\"\ncommand = \"true\"\n\n[network]\nallow = [\"*\"]\n",
    );

    let refused = sandbox.redan(&["exec"], &[]);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(refused.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("needs trust and this is a non-interactive session"),
        "{stderr}"
    );
    assert!(
        stderr.contains("turns off the network allowlist"),
        "{stderr}"
    );

    let trusted = sandbox.redan(&["trust"], &[]);
    assert!(
        trusted.status.success(),
        "{}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let ran = sandbox.redan(&["exec"], &[]);
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
}

/// One `redan run claude` and what has to hold afterwards.
#[derive(Default)]
struct Eval {
    /// Files written into the project before the run.
    files: &'static [(&'static str, &'static str)],
    /// Prompt passed to `claude -p`.
    prompt: &'static str,
    /// Text the guest's output has to contain.
    output_contains: &'static str,
    /// Hosts the proxy has to have refused. A refusal also proves the agent
    /// made the request, so a run where it never tried doesn't pass.
    rejected: &'static [&'static str],
}

/// The Claude credential from your environment, as the variable name redan's
/// Claude profile reads and its value.
#[expect(
    clippy::panic,
    reason = "test helper outside a #[test] fn: a missing token must fail the eval with a message"
)]
fn claude_token() -> (&'static str, OsString) {
    ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"]
        .into_iter()
        .find_map(|var| {
            std::env::var_os(var)
                .filter(|value| !value.is_empty())
                .map(|value| (var, value))
        })
        .unwrap_or_else(|| {
            panic!("set CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY to run the Claude Code evals")
        })
}

/// Run Claude Code in the sandbox through `redan run claude`, check the
/// eval's own expectations, then [`assert_token_stayed_on_host`].
fn run_eval(eval: &Eval) {
    require_image("claude-code");
    let _turn = vm_turn();
    let (var, token) = claude_token();
    let sandbox = Sandbox::new();
    for (path, content) in eval.files {
        sandbox.write(path, content);
    }
    let audit_log = sandbox.path("audit.jsonl");

    // Haiku keeps the evals fast and cheap, and they test the sandbox, not
    // the model.
    let mut args = vec![
        "run",
        "claude",
        "--timeout",
        "300",
        "--audit-log",
        audit_log.to_str().unwrap_or_default(),
    ];
    if !eval.prompt.is_empty() {
        args.extend(["--", "-p", eval.prompt, "--model", "haiku"]);
    }
    let out = sandbox.redan(&args, &[(var, &token)]);

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let report = format!("stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains(eval.output_contains),
        "output is missing {:?}\n{report}",
        eval.output_contains
    );
    let events = audit_events(&audit_log);
    for host in eval.rejected {
        assert!(
            was_rejected(&events, host),
            "no not_allowed reject for {host}: {events:?}\n{report}"
        );
    }
    assert_token_stayed_on_host(&token, &out, &audit_log, &events);
}

/// Invariants every eval checks: the real token never shows up in anything
/// the guest printed, in redan's own output or in the audit log, and the
/// proxy only injected it into requests to `api.anthropic.com`.
fn assert_token_stayed_on_host(
    token: &OsString,
    out: &Output,
    audit_log: &Path,
    events: &[(String, String, String)],
) {
    let token = token.as_encoded_bytes();
    let leaked_in = |bytes: &[u8]| bytes.windows(token.len()).any(|w| w == token);
    assert!(!leaked_in(&out.stdout), "real token in guest output");
    assert!(!leaked_in(&out.stderr), "real token in redan's stderr");
    let audit = std::fs::read(audit_log).unwrap_or_default();
    assert!(!leaked_in(&audit), "real token in the audit log");
    for (event, host, _) in events {
        assert!(
            event != "inject" || host == "api.anthropic.com",
            "token injected into a request to {host}"
        );
    }
}

/// The guest gets a placeholder in place of your Claude token, so even a
/// process that dumps its environment can't see the real one.
#[test]
#[ignore = "needs the claude-code image and a Claude token: mise run e2e"]
fn claude_guest_sees_only_a_placeholder() {
    run_eval(&Eval {
        files: &[(
            "redan.toml",
            "command = \"printenv ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN\"\n",
        )],
        output_contains: "redan_ph_",
        ..Eval::default()
    });
}

/// Claude Code answers a prompt, so the placeholder in the guest was swapped
/// for the real token on the way to the API.
#[test]
#[ignore = "needs the claude-code image and a Claude token: mise run e2e"]
fn claude_answers_through_the_injected_token() {
    run_eval(&Eval {
        prompt: "Reply with exactly REDAN_E2E_OK and nothing else.",
        output_contains: "REDAN_E2E_OK",
        ..Eval::default()
    });
}

/// A `"*"` in the project's Claude Code settings doesn't let the agent reach
/// a host outside its allowlist.
#[test]
#[ignore = "needs the claude-code image and a Claude token: mise run e2e"]
fn claude_cannot_reach_hosts_a_settings_wildcard_would_allow() {
    run_eval(&Eval {
        files: &[(".claude/settings.local.json", WILDCARD_SETTINGS)],
        prompt: "Use your Bash tool to run: curl -sS https://example.com/ and then report what curl printed.",
        rejected: &["example.com"],
        ..Eval::default()
    });
}
