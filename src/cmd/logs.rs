//! `redan logs`: view a session's audit event stream.
//!
//! Renders the on-disk newline-delimited JSON as logfmt for humans (default),
//! or passes the raw JSON through with `--json` (for piping to `jq`). `-f`
//! follows the log live as new events are appended.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::Duration;

use redan::{logfmt, session};

/// Poll interval while following a log that has reached EOF.
const FOLLOW_POLL: Duration = Duration::from_millis(200);

pub fn run(session_id: Option<&str>, follow: bool, json: bool) {
    let Some(meta) = session::find_session(session_id) else {
        eprintln!("no matching session found");
        std::process::exit(1);
    };
    let path = session::audit_log_path(&meta.id);
    if !path.exists() {
        eprintln!("no audit log for session {} ({})", meta.id, path.display());
        std::process::exit(1);
    }

    let result = if follow {
        follow_log(&path, json)
    } else {
        dump_log(&path, json)
    };
    if let Err(e) = result {
        // A broken pipe (e.g. piping into `head`) is a normal exit, not a fault.
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            eprintln!("cannot read {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

/// Format one stored line for display. `--json` passes the raw event through;
/// otherwise it is rendered as a terminal-safe logfmt line.
fn present(line: &str, json: bool) -> String {
    if json {
        line.to_string()
    } else {
        logfmt::render(line)
    }
}

fn dump_log(path: &Path, json: bool) -> std::io::Result<()> {
    let reader = BufReader::new(std::fs::File::open(path)?);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in reader.lines() {
        writeln!(out, "{}", present(&line?, json))?;
    }
    Ok(())
}

fn follow_log(path: &Path, json: bool) -> std::io::Result<()> {
    let mut reader = BufReader::new(std::fs::File::open(path)?);
    let stdout = std::io::stdout();
    // `read_line` appends to `pending`. The audit writer flushes after the
    // trailing newline, so we render only once a complete line is in hand and
    // keep a partial line buffered across polls otherwise.
    let mut pending = String::new();
    loop {
        if reader.read_line(&mut pending)? == 0 {
            std::thread::sleep(FOLLOW_POLL);
            continue;
        }
        if pending.ends_with('\n') {
            let mut out = stdout.lock();
            writeln!(out, "{}", present(pending.trim_end_matches('\n'), json))?;
            out.flush()?;
            pending.clear();
        }
    }
}
