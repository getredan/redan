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
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use redan::auto_detect::{AuthMethod, agent_by_slug};
use serde::Deserialize;

/// `redan` installs its CA into the image it boots, and the tests share
/// images, so VM runs in this binary take turns.
static VM_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Set in redan's environment for every run. Nothing from your shell should
/// reach the guest, so it must never show up in anything the guest prints.
const CANARY: (&str, &str) = ("REDAN_E2E_CANARY", "redan-e2e-canary-4b1d7e");

/// A project `redan.toml` that turns the allowlist off and prints what the
/// guest was told about its network.
const ALLOW_ALL_CONFIG: &str = "image = \"test\"\ncommand = \"echo network=$REDAN_NETWORK\"\ntimeout = 60\n\n[network]\nallow = [\"*\"]\n";

/// One event from `redan logs --json`.
#[derive(Debug, Deserialize)]
struct AuditEvent {
    event: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    reason: String,
}

impl AuditEvent {
    fn is_rejection_of(&self, host: &str) -> bool {
        self.event == "reject" && self.host == host && self.reason == "not_allowed"
    }
}

/// Wait for this test's turn to boot a VM. A test that failed while holding
/// the lock leaves it poisoned, and that shouldn't fail the tests after it.
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
    fn command(&self, program: impl AsRef<OsStr>) -> Command {
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
        self.command(env!("CARGO_BIN_EXE_redan"))
            .args(args)
            .envs(env.iter().map(|(var, value)| (var, value)))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// Run `redan` in a terminal, as you would from your shell, and type
    /// `input`. `script` provides the terminal, and everything redan prints
    /// comes back as stdout. The `args` go through a shell, so keep them to
    /// plain words.
    fn redan_in_terminal(&self, args: &[&str], input: &str) -> Output {
        let command_line = format!("'{}' {}", env!("CARGO_BIN_EXE_redan"), args.join(" "));
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
            events.iter().any(|e| e.is_rejection_of(host)),
            "no not_allowed reject for {host}: {events:?}\n{}",
            self.explain(run)
        );
    }

    /// `run`'s output and redan's session logs, which is where redan logs to
    /// when the agent runs interactively.
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
    let _turn = vm_turn();
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
        "{stderr}"
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
    let _turn = vm_turn();
    let sandbox = Sandbox::new("test");
    sandbox.write("redan.toml", ALLOW_ALL_CONFIG);

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
    assert!(trusted.status.success(), "{}", report(&trusted));

    let ran = sandbox.redan(&["exec"], &[]);
    assert!(ran.status.success(), "{}", report(&ran));
    assert!(
        String::from_utf8_lossy(&ran.stdout).contains("network=allow-all"),
        "{}",
        report(&ran)
    );
}

/// In a terminal, redan shows what a project's `redan.toml` wants and asks
/// before acting on it, the way you'd meet it after cloning a repo. No leaves
/// it untrusted, yes runs it and remembers the answer.
#[test]
fn redan_toml_allow_all_asks_in_a_terminal() {
    let _turn = vm_turn();
    let sandbox = Sandbox::new("test");
    sandbox.write("redan.toml", ALLOW_ALL_CONFIG);

    let declined = sandbox.redan_in_terminal(&["exec"], "n\n");
    let output = String::from_utf8_lossy(&declined.stdout);
    assert_eq!(declined.status.code(), Some(1), "{output}");
    assert!(
        output.contains("let the guest reach any host  [turns off the network allowlist]"),
        "{output}"
    );
    assert!(
        output.contains("Trust this config and continue? [y/N]"),
        "{output}"
    );
    assert!(output.contains("left untrusted; not running."), "{output}");

    let accepted = sandbox.redan_in_terminal(&["exec"], "y\n");
    let output = String::from_utf8_lossy(&accepted.stdout);
    assert!(accepted.status.success(), "{output}");
    assert!(output.contains("network=allow-all"), "{output}");

    let again = sandbox.redan(&["exec"], &[]);
    assert!(again.status.success(), "{}", report(&again));
}

/// `allow = ["*."]` isn't `"*"`, so it needs no trust, but as a pattern it
/// would match every name the guest sends with a trailing dot. redan refuses
/// to run with an allowlist entry that isn't a hostname or a `*.domain`
/// pattern.
#[test]
fn redan_toml_allow_entry_that_is_not_a_hostname_is_refused() {
    let _turn = vm_turn();
    let sandbox = Sandbox::new("test");
    sandbox.write(
        "redan.toml",
        "image = \"test\"\ncommand = \"true\"\ntimeout = 60\n\n[network]\nallow = [\"*.\"]\n",
    );

    let out = sandbox.redan(&["exec"], &[]);

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", report(&out));
    assert!(
        stderr.contains(r#"take a hostname or a *.domain pattern, not a URL or host:port: "*.""#),
        "{stderr}"
    );
}

/// The Claude credentials set in your environment, under the names redan's
/// Claude profile reads them from.
#[expect(
    clippy::expect_used,
    reason = "test helper outside a #[test] fn: a missing Claude profile must fail the eval with a message"
)]
fn claude_credentials() -> Vec<(&'static str, OsString)> {
    let claude = agent_by_slug("claude").expect("redan has a claude agent profile");
    let credentials: Vec<_> = claude
        .auth
        .iter()
        .filter_map(|method| match method {
            AuthMethod::EnvSecret { env_var, .. } => std::env::var_os(env_var)
                .filter(|value| !value.to_string_lossy().trim().is_empty())
                .map(|value| (*env_var, value)),
            AuthMethod::StagedFiles { .. } => None,
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
    let secrets = credentials
        .iter()
        .map(|(var, value)| (*var, value.as_encoded_bytes()))
        .chain([(CANARY.0, CANARY.1.as_bytes())]);
    for (name, secret) in secrets {
        let leaked = |bytes: &[u8]| bytes.windows(secret.len()).any(|w| w == secret);
        assert!(!leaked(&out.stdout), "{name} in the guest's output");
        assert!(!leaked(&out.stderr), "{name} in redan's stderr");
        for (file, content) in &files {
            assert!(!leaked(content), "{name} in {}", file.display());
        }
    }
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
    let _turn = vm_turn();
    let sandbox = Sandbox::new("claude-code");
    // A project's redan.toml overrides the agent's command, as it would for you.
    sandbox.write("redan.toml", "command = \"env\"\n");

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
    let _turn = vm_turn();
    let sandbox = Sandbox::new("claude-code");
    sandbox.write(
        "redan.toml",
        "command = \"curl -sS -m 10 https://example.com/\"\n",
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
/// for your real credential on the way to the API.
#[test]
#[ignore = "uses your Claude token and the real API: mise run e2e"]
fn claude_answers_through_the_injected_credential() {
    let _turn = vm_turn();
    let sandbox = Sandbox::new("claude-code");

    let (out, events) = ask_claude(
        &sandbox,
        "Reply with exactly REDAN_E2E_OK and nothing else.",
    );

    assert!(
        String::from_utf8_lossy(&out.stdout).contains("REDAN_E2E_OK"),
        "{}",
        sandbox.explain(&out)
    );
    assert!(
        events
            .iter()
            .any(|e| e.event == "inject" && e.host == "api.anthropic.com"),
        "{events:?}"
    );
}

/// You clone a repo whose Claude Code settings allow every domain, and Claude
/// reaches for a host nobody allowed. The proxy still refuses it.
#[test]
#[ignore = "uses your Claude token and the real API: mise run e2e"]
fn claude_cannot_reach_other_hosts_when_project_settings_allow_all() {
    let _turn = vm_turn();
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
