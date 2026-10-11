//! End-to-end tests that run the `redan` binary the way you would.
//!
//! Each test runs `redan` in a throwaway project with its own `HOME` and state
//! directory, so it never reads your `~/.claude` settings or touches your trust
//! store and session list. The environment is cleared too, so your shell's
//! secrets and `RUST_LOG` can't change the outcome. Only the image store is
//! shared with you, and like any redan session the tests boot your images in
//! place and install their own CA into them, so don't run other redan sessions
//! on the same image while they run.
//!
//! The plain tests boot the `test` image (`mise run test-setup` creates it) and
//! run with `mise run test`. The `redan run claude` tests need the
//! `claude-code` image (`redan run claude` builds it), so they're `#[ignore]`d
//! and run with `mise run e2e`. Two of them pass a made-up token and never
//! reach the API. The two evals use your `CLAUDE_CODE_OAUTH_TOKEN` or
//! `ANTHROPIC_API_KEY` and talk to the real API. They run `claude -p` without
//! a terminal, so the interactive session you get from a bare
//! `redan run claude` isn't covered. The trust prompt is, through `script`.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::Deserialize;

/// `redan` installs its CA into the image it boots, and the tests share
/// images, so the `redan` runs in this binary take turns.
static VM_LOCK: Mutex<()> = Mutex::new(());

/// Set in redan's environment for every run. Nothing from your shell should
/// reach the guest, so it must never show up in anything the guest prints.
const CANARY: (&str, &str) = ("REDAN_E2E_CANARY", "redan-e2e-canary-4b1d7e");

/// A project `redan.toml` that turns the allowlist off and prints what the
/// guest was told about its network.
const ALLOW_ALL_CONFIG: &str = r#"
image = "test"
command = "echo network=$REDAN_NETWORK"
timeout = 60

[network]
allow = ["*"]
"#;

/// One event from `redan logs --json`.
#[derive(Debug, Deserialize)]
struct AuditEvent {
    event: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    reason: String,
}

/// Wait for the `redan` run before this one to finish. A test that failed
/// during its run leaves the lock poisoned, and that shouldn't fail the tests
/// after it.
fn vm_turn() -> MutexGuard<'static, ()> {
    VM_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A project directory, a home directory and a state directory under one
/// temp dir.
struct Sandbox {
    root: tempfile::TempDir,
}

#[expect(
    clippy::unwrap_used,
    reason = "test helpers outside a #[test] fn: a failed setup step must fail the test"
)]
impl Sandbox {
    /// A fresh sandbox for a test that boots `image`.
    fn new(image: &str) -> Self {
        let kvm = redan::check_kvm();
        assert!(kvm.is_ok(), "KVM required: {kvm:?}");
        assert!(
            redan::image::list().iter().any(|name| name == image),
            "{image} image not found, see the top of tests/e2e.rs for how to create it"
        );
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

    /// `program` in the project directory, with only `PATH`, the sandbox's
    /// own `HOME` and state directory and the [`CANARY`] in its environment.
    /// `XDG_DATA_HOME` points at your real data directory so the images are
    /// found.
    fn command(&self, program: &str) -> Command {
        // image_dir() is <data home>/redan/images.
        let images = redan::image::image_dir();
        let data_home = images.ancestors().nth(2).unwrap();
        let mut command = Command::new(program);
        command
            .current_dir(self.path("project"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("XDG_DATA_HOME", data_home)
            .env(CANARY.0, CANARY.1);
        command
    }

    /// Run `redan` with no terminal attached, adding `env` to its
    /// environment.
    fn redan(&self, args: &[&str], env: &[(&str, OsString)]) -> Output {
        let mut command = self.command(env!("CARGO_BIN_EXE_redan"));
        command
            .args(args)
            .envs(env.iter().map(|(var, value)| (var, value)))
            .stdin(Stdio::null());
        let _turn = vm_turn();
        command.output().unwrap()
    }

    /// Run `redan` in a terminal, as you would from your shell, and type
    /// `input`. `script` provides the terminal, and everything redan prints
    /// comes back as stdout. The `args` go through a shell, so keep them to
    /// plain words.
    fn redan_in_terminal(&self, args: &[&str], input: &str) -> Output {
        let command_line = format!("'{}' {}", env!("CARGO_BIN_EXE_redan"), args.join(" "));
        let _turn = vm_turn();
        let mut child = self
            .command("script")
            .args(["-q", "-e", "-c", &command_line, "/dev/null"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// Run `git` in the project, without your git config.
    fn git(&self, args: &[&str]) {
        let out = self.command("git").args(args).output().unwrap();
        assert!(out.status.success(), "git {args:?}\n{}", report(&out));
    }

    /// The audit events of the session that `run` started, read with
    /// `redan logs --json` the way you would.
    fn audit_events(&self, run: &Output) -> Vec<AuditEvent> {
        let out = self.redan(&["logs", "--json"], &[]);
        assert!(
            out.status.success(),
            "redan logs failed\n{}\n\nthe run before it:\n{}",
            report(&out),
            self.explain(run)
        );
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// Assert that the proxy refused a connection to `host` because nobody
    /// allowed it. A rejection also proves the guest tried, so a run where it
    /// never did doesn't pass.
    fn assert_rejected(&self, host: &str, events: &[AuditEvent], run: &Output) {
        assert!(
            events
                .iter()
                .any(|e| e.event == "reject" && e.host == host && e.reason == "not_allowed"),
            "no not_allowed reject for {host}: {events:?}\n{}",
            self.explain(run)
        );
    }

    /// What `run` printed, and redan's session logs, which is where redan
    /// logs to when it runs in a terminal. Every failure message about a
    /// redan run uses it.
    fn explain(&self, run: &Output) -> String {
        let mut parts = vec![report(run)];
        parts.extend(
            self.files()
                .into_iter()
                .filter(|(path, _)| path.file_name() == Some(OsStr::new("redan.log")))
                .map(|(path, content)| {
                    format!("{}:\n{}", path.display(), String::from_utf8_lossy(&content))
                }),
        );
        parts.join("\n")
    }

    /// Every regular file redan or the guest left in the sandbox, with its
    /// content: session metadata, logs, the audit log and the project itself.
    /// Links aren't followed, so one the guest made can't send the leak
    /// checks into your own files.
    fn files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        walkdir::WalkDir::new(self.root.path())
            .into_iter()
            .map(Result::unwrap)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| {
                let content = std::fs::read(entry.path()).unwrap();
                (entry.into_path(), content)
            })
            .collect()
    }
}

fn report(out: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A repo's `.claude/settings.local.json` with `"*"` in `allowedDomains`
/// can't turn off the allowlist. redan skips the `"*"` with a warning, and
/// the guest's request to a host nobody allowed is rejected.
#[test]
fn claude_settings_wildcard_does_not_turn_off_the_allowlist() {
    let sandbox = Sandbox::new("test");
    sandbox.write(
        ".claude/settings.local.json",
        r#"{"sandbox": {"network": {"allowedDomains": ["*"]}}}"#,
    );

    let out = sandbox.redan(
        &[
            "exec",
            "--image",
            "test",
            "--timeout",
            "60",
            "-c",
            "wget -q -T 10 -O /dev/null https://example.com/ ; echo wget_exit=$?",
        ],
        &[],
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            r#"warning: ignoring "*" in ./.claude/settings.local.json: Claude Code settings can't turn off redan's allowlist"#
        ),
        "{}",
        sandbox.explain(&out)
    );
    let events = sandbox.audit_events(&out);
    sandbox.assert_rejected("example.com", &events, &out);
}

/// `allow = ["*"]` in a project's `redan.toml` needs trust. Without a
/// terminal to ask on (CI, a detached run), redan refuses to run and says what
/// the config wants, and once you've trusted it with `redan trust` it runs
/// with the allowlist off.
#[test]
fn redan_toml_allow_all_is_refused_until_trusted() {
    let sandbox = Sandbox::new("test");
    sandbox.write("redan.toml", ALLOW_ALL_CONFIG);

    let refused = sandbox.redan(&["exec"], &[]);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "{}",
        sandbox.explain(&refused)
    );
    assert!(
        stderr.contains("needs trust and this is a non-interactive session"),
        "{}",
        sandbox.explain(&refused)
    );
    assert!(
        stderr.contains("turns off the network allowlist"),
        "{}",
        sandbox.explain(&refused)
    );

    let trusted = sandbox.redan(&["trust"], &[]);
    assert!(trusted.status.success(), "{}", sandbox.explain(&trusted));

    let ran = sandbox.redan(&["exec"], &[]);
    assert!(ran.status.success(), "{}", sandbox.explain(&ran));
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("network=allow-all"),
        "{}",
        sandbox.explain(&ran)
    );
}

/// In a terminal, redan shows what a project's `redan.toml` wants and asks
/// before acting on it, the way you'd meet it after cloning a repo. No leaves
/// it untrusted, yes runs it and remembers the answer.
#[test]
fn redan_toml_allow_all_asks_in_a_terminal() {
    let sandbox = Sandbox::new("test");
    sandbox.write("redan.toml", ALLOW_ALL_CONFIG);

    let declined = sandbox.redan_in_terminal(&["exec"], "n\n");
    let output = String::from_utf8_lossy(&declined.stdout);
    assert_eq!(
        declined.status.code(),
        Some(1),
        "{}",
        sandbox.explain(&declined)
    );
    assert!(
        output.contains("let the guest reach any host  [turns off the network allowlist]"),
        "{}",
        sandbox.explain(&declined)
    );
    assert!(
        output.contains("Trust this config and continue? [y/N]"),
        "{}",
        sandbox.explain(&declined)
    );
    assert!(
        output.contains("left untrusted; not running."),
        "{}",
        sandbox.explain(&declined)
    );

    let accepted = sandbox.redan_in_terminal(&["exec"], "y\n");
    let output = String::from_utf8_lossy(&accepted.stdout);
    assert!(accepted.status.success(), "{}", sandbox.explain(&accepted));
    assert!(
        output.contains("network=allow-all"),
        "{}",
        sandbox.explain(&accepted)
    );

    let again = sandbox.redan(&["exec"], &[]);
    assert!(again.status.success(), "{}", sandbox.explain(&again));
}

/// `allow = ["*."]` isn't `"*"`, so it needs no trust, but as a pattern it
/// would match every name the guest sends with a trailing dot. redan refuses
/// to run with an allowlist entry that isn't a hostname or a `*.domain`
/// pattern, before it starts a session.
#[test]
fn redan_toml_allow_entry_that_is_not_a_hostname_is_refused() {
    let sandbox = Sandbox::new("test");
    sandbox.write(
        "redan.toml",
        r#"
image = "test"
command = "true"
timeout = 60

[network]
allow = ["*."]
"#,
    );

    let out = sandbox.redan(&["exec"], &[]);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", sandbox.explain(&out));
    assert!(
        stderr.contains(r#"take a hostname or a *.domain pattern, not a URL or host:port: "*.""#),
        "{}",
        sandbox.explain(&out)
    );
    let sessions = sandbox.redan(&["sessions"], &[]);
    assert!(
        String::from_utf8_lossy(&sessions.stderr).contains("no sessions"),
        "{}",
        sandbox.explain(&sessions)
    );
}

/// The Claude credentials set in your environment, the way your shell passes
/// them to `redan run claude`.
fn claude_credentials() -> Vec<(&'static str, OsString)> {
    let credentials: Vec<_> = ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"]
        .into_iter()
        .filter_map(|var| {
            std::env::var_os(var)
                .filter(|value| !value.to_string_lossy().trim().is_empty())
                .map(|value| (var, value))
        })
        .collect();
    assert!(
        !credentials.is_empty(),
        "set CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY to run the Claude Code evals"
    );
    credentials
}

/// A made-up Claude token for the tests that never reach the API. redan only
/// checks that one is set, and the leak checks look for it like a real one.
fn fake_claude_credentials() -> Vec<(&'static str, OsString)> {
    vec![(
        "CLAUDE_CODE_OAUTH_TOKEN",
        "sk-ant-oat01-redan-e2e-fake-token".into(),
    )]
}

/// Start Claude Code with `redan run claude`, passing `args` after `--`.
///
/// The `credentials` go in through the environment, as they would from your
/// shell. Afterwards it checks that no credential and no [`CANARY`] shows up
/// in redan's output or in any file in the sandbox, and that the proxy only
/// injected a credential into requests to `api.anthropic.com`.
fn run_claude(
    sandbox: &Sandbox,
    credentials: &[(&str, OsString)],
    args: &[&str],
) -> (Output, Vec<AuditEvent>) {
    let mut redan_args = vec!["run", "claude", "--timeout", "180"];
    if !args.is_empty() {
        redan_args.push("--");
        redan_args.extend(args);
    }
    let out = sandbox.redan(&redan_args, credentials);
    let events = sandbox.audit_events(&out);

    let files = sandbox.files();
    let assert_absent = |needle: &[u8], what: &str| {
        let leaked = |bytes: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(!leaked(&out.stdout), "{what} in the guest's output");
        assert!(!leaked(&out.stderr), "{what} in redan's stderr");
        for (file, content) in &files {
            assert!(!leaked(content), "{what} in {}", file.display());
        }
    };
    for (_, value) in credentials {
        assert_absent(value.as_encoded_bytes(), "your Claude credential");
    }
    assert_absent(CANARY.1.as_bytes(), "the canary from redan's environment");
    for event in &events {
        assert!(
            event.event != "inject" || event.host == "api.anthropic.com",
            "a credential was injected into a request to {}",
            event.host
        );
    }
    (out, events)
}

/// Ask Claude Code a one-shot question with your own credentials. Haiku and a
/// turn limit keep the evals fast and cheap, and they test the sandbox, not
/// the model.
fn ask_claude(sandbox: &Sandbox, prompt: &str) -> (Output, Vec<AuditEvent>) {
    run_claude(
        sandbox,
        &claude_credentials(),
        &["-p", prompt, "--model", "haiku", "--max-turns", "3"],
    )
}

/// The guest gets a placeholder in place of your Claude token, and none of
/// your shell's environment, so even a process that dumps its environment
/// can't see them.
#[test]
#[ignore = "needs the claude-code image: mise run e2e"]
fn claude_guest_env_has_placeholders_instead_of_your_credentials() {
    let sandbox = Sandbox::new("claude-code");
    // A project's redan.toml overrides the agent's command, as it would for you.
    sandbox.write("redan.toml", r#"command = "env""#);

    let (out, _) = run_claude(&sandbox, &fake_claude_credentials(), &[]);

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("CLAUDE_CODE_OAUTH_TOKEN=redan_ph_"),
        "{}",
        sandbox.explain(&out)
    );
}

/// `redan run` allows the hosts of your git remotes, and the guest can edit
/// `.git/config` through `/workspace`. A remote at `https://*/repo.git` must
/// not turn the allowlist off for the next session.
#[test]
#[ignore = "needs the claude-code image: mise run e2e"]
fn git_remote_wildcard_does_not_turn_off_the_allowlist() {
    let sandbox = Sandbox::new("claude-code");
    sandbox.write(
        "redan.toml",
        r#"command = "curl -sS -m 10 https://example.com/""#,
    );
    sandbox.git(&["init", "-q"]);
    sandbox.git(&[
        "remote",
        "add",
        "origin",
        "https://github.com/getredan/redan.git",
    ]);
    sandbox.git(&["remote", "add", "planted", "https://*/repo.git"]);

    let (out, events) = run_claude(&sandbox, &fake_claude_credentials(), &[]);

    // The real remote's host is allowed, so redan did read the remotes.
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Allowing git remote hosts: github.com\n"),
        "{}",
        sandbox.explain(&out)
    );
    sandbox.assert_rejected("example.com", &events, &out);
}

/// Claude Code answers a prompt, so the placeholder in the guest was swapped
/// for your real credential on the way to the API. The answer isn't in the
/// prompt, so an echo of the command line or an error that quotes the prompt
/// doesn't pass.
#[test]
#[ignore = "uses your Claude token and the real API: mise run e2e"]
fn claude_answers_through_the_injected_credential() {
    let sandbox = Sandbox::new("claude-code");

    let (out, events) = ask_claude(&sandbox, "What is 17 + 25? Reply with only the number.");

    assert!(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|line| line.trim() == "42"),
        "{}",
        sandbox.explain(&out)
    );
    assert!(
        events
            .iter()
            .any(|e| e.event == "inject" && e.host == "api.anthropic.com"),
        "{events:?}\n{}",
        sandbox.explain(&out)
    );
}

/// You clone a repo whose Claude Code settings allow every domain, and Claude
/// reaches for a host nobody allowed. The proxy still refuses it.
#[test]
#[ignore = "uses your Claude token and the real API: mise run e2e"]
fn claude_cannot_reach_other_hosts_when_project_settings_allow_all() {
    let sandbox = Sandbox::new("claude-code");
    sandbox.write(
        ".claude/settings.json",
        r#"{"sandbox": {"network": {"allowedDomains": ["*"]}}}"#,
    );

    let (out, events) = ask_claude(
        &sandbox,
        "Use your Bash tool to run: curl -sS https://example.com/ and then report what curl printed.",
    );

    sandbox.assert_rejected("example.com", &events, &out);
}
