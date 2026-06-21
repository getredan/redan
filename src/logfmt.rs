//! logfmt rendering for the audit event stream.
//!
//! The audit log on disk is newline-delimited JSON, one event per line.
//! `redan logs` renders it as logfmt (`key=value`, Heroku style) for humans.
//!
//! Event values such as `host` are chosen by the guest agent and are therefore
//! untrusted. They are quoted and escaped here so a crafted value can't forge a
//! log line or drive the terminal: control characters (CR, LF, ANSI escapes,
//! DEL, ...) are rendered as a visible `\xNN`. See the OWASP Logging Cheat
//! Sheet (log injection / treat cross-trust-zone data as untrusted).

use std::fmt::Write as _;

/// Keys printed first; remaining keys follow in the line's own (JSON-sorted)
/// order. Keeps the important context (when, severity, what, host) up front.
const LEAD_KEYS: &[&str] = &["ts", "severity", "event", "host"];

/// Render one newline-delimited-JSON audit line as a logfmt line.
///
/// A line that isn't a JSON object (corrupt or tampered) is rendered as a
/// single safe `raw=...` field, so the viewer never prints unstructured
/// untrusted bytes.
#[must_use]
pub fn render(json_line: &str) -> String {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str(json_line) else {
        return format!("raw={}", encode(json_line));
    };
    let mut out = String::new();
    for key in LEAD_KEYS {
        if let Some(value) = map.get(*key) {
            push_pair(&mut out, key, value);
        }
    }
    for (key, value) in &map {
        if !LEAD_KEYS.contains(&key.as_str()) {
            push_pair(&mut out, key, value);
        }
    }
    out
}

fn push_pair(out: &mut String, key: &str, value: &serde_json::Value) {
    if !out.is_empty() {
        out.push(' ');
    }
    // Keys come from redan today, but the log file is untrusted input on read:
    // encode them too so a tampered line can't forge output via a crafted key.
    out.push_str(&encode(key));
    out.push('=');
    match value {
        serde_json::Value::String(s) => out.push_str(&encode(s)),
        other => out.push_str(&encode(&other.to_string())),
    }
}

/// Encode a value as a single logfmt token. Quotes when the value would
/// otherwise break token boundaries (empty, or contains a space, `=`, `"`, or a
/// control character), escaping `"`, `\`, and control characters so the result
/// is always a single terminal-safe token.
fn encode(s: &str) -> String {
    let needs_quote = s.is_empty()
        || s.chars()
            .any(|c| c == ' ' || c == '=' || c == '"' || c.is_control());
    if !needs_quote {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_event_as_logfmt_with_lead_order() {
        let line = r#"{"event":"connect","host":"api.anthropic.com","severity":"info","ts":"2026-06-20T12:30:01Z"}"#;
        assert_eq!(
            render(line),
            "ts=2026-06-20T12:30:01Z severity=info event=connect host=api.anthropic.com"
        );
    }

    #[test]
    fn quotes_values_containing_spaces() {
        let line = r#"{"event":"reject","reason":"not allowed","severity":"warning","ts":"t"}"#;
        let out = render(line);
        assert!(out.contains(r#"reason="not allowed""#), "{out}");
        assert!(out.contains("event=reject"), "{out}");
    }

    #[test]
    fn neutralizes_control_chars_and_ansi_in_untrusted_value() {
        // A hostname the agent could craft: embedded ANSI clear-screen + newline
        // (JSON-escaped here, so serde decodes them to real control bytes).
        let line = "{\"event\":\"connect\",\"host\":\"evil.com\\u001b[2J\\nFAKE\",\"severity\":\"info\",\"ts\":\"t\"}";
        let out = render(line);
        assert!(
            !out.chars().any(char::is_control),
            "output must contain no raw control chars: {out:?}"
        );
        assert_eq!(out.lines().count(), 1, "must stay one line: {out:?}");
        assert!(
            out.contains("\\x1b"),
            "escape must be visible, not executed: {out:?}"
        );
    }

    #[test]
    fn neutralizes_control_chars_in_tampered_keys() {
        // A tampered-but-valid JSON line could carry a control char in a key;
        // the rendered line must still be a single, control-free line.
        let line = "{\"ev\\nil\":\"x\",\"event\":\"connect\",\"severity\":\"info\",\"ts\":\"t\"}";
        let out = render(line);
        assert!(!out.chars().any(char::is_control), "{out:?}");
        assert_eq!(out.lines().count(), 1, "must stay one line: {out:?}");
    }

    #[test]
    fn corrupt_line_becomes_safe_raw_field() {
        let out = render("this is not json \u{1b}[2J");
        assert!(out.starts_with("raw="), "{out}");
        assert!(!out.chars().any(char::is_control), "{out:?}");
    }

    #[test]
    fn empty_value_is_quoted() {
        let line = r#"{"event":"connect","host":"","severity":"info","ts":"t"}"#;
        assert!(render(line).contains(r#"host="""#), "{}", render(line));
    }
}
