//! Session tracking. Each `redan exec` creates a session with a unique ID.
//!
//! Sessions are stored at `~/.local/state/redan/sessions/<id>/`.
//! Each session directory contains:
//! - `meta.json`: session metadata (image, command, start time, status)
//! - `audit.jsonl`: structured event log (if no --audit-log override)

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Short hex session ID (8 chars from random bytes).
pub fn new_id() -> String {
    use std::io::Read;
    let mut buf = [0u8; 4];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_err()
    {
        // Fallback: timestamp-based
        #[allow(clippy::cast_possible_truncation)] // Intentional: low 32 bits for entropy
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        buf = t.to_le_bytes();
    }
    hex::encode(&buf)
}

/// Inline hex encoding (avoid adding a dependency).
mod hex {
    use std::fmt::Write;

    pub fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}

/// Base directory for session state.
#[allow(clippy::unwrap_used)] // process::exit on missing $HOME is intentional
pub fn sessions_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map_or_else(
            || {
                let home = std::env::var_os("HOME").unwrap_or_else(|| {
                    eprintln!("$HOME not set -- cannot determine state directory");
                    std::process::exit(1);
                });
                PathBuf::from(home).join(".local/state")
            },
            PathBuf::from,
        )
        .join("redan/sessions")
}

/// Validate session ID format (hex characters only, max 32).
pub fn valid_session_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Directory for a specific session.
pub fn session_dir(id: &str) -> PathBuf {
    sessions_dir().join(id)
}

/// Default audit log path for a session.
pub fn audit_log_path(id: &str) -> PathBuf {
    session_dir(id).join("audit.jsonl")
}

/// Session metadata, written to `meta.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionMeta {
    pub id: String,
    pub image: Option<String>,
    pub command: Option<String>,
    pub started_at: String,
    pub status: SessionStatus,
    #[serde(default)]
    pub pid: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Running,
    Finished,
    Failed,
}

impl SessionMeta {
    pub fn new(id: &str, image: Option<&str>, command: Option<&str>) -> Self {
        let started_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Self {
            id: id.into(),
            image: image.map(Into::into),
            command: command.map(Into::into),
            started_at,
            status: SessionStatus::Running,
            pid: Some(std::process::id()),
        }
    }

    /// Write meta to the session directory. Creates the directory if needed.
    pub fn save(&self) -> Result<(), String> {
        let dir = session_dir(&self.id);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create session dir {}: {e}", dir.display()))?;
        let path = dir.join("meta.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("cannot serialize session meta: {e}"))?;
        std::fs::write(&path, json).map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    /// Check if the session's process is still running.
    pub fn is_alive(&self) -> bool {
        self.pid
            .is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists())
    }

    /// Update status and re-save.
    pub fn finish(&mut self, success: bool) {
        self.status = if success {
            SessionStatus::Finished
        } else {
            SessionStatus::Failed
        };
        let _ = self.save();
    }
}

/// List recent sessions, newest first.
pub fn list_sessions() -> Vec<SessionMeta> {
    let dir = sessions_dir();
    let mut sessions: Vec<SessionMeta> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let meta_path = entry.path().join("meta.json");
            if let Ok(content) = std::fs::read_to_string(&meta_path)
                && let Ok(meta) = serde_json::from_str(&content)
            {
                sessions.push(meta);
            }
        }
    }
    sessions.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    sessions
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_id_is_8_hex_chars() {
        let id = new_id();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn session_dir_structure() {
        let dir = session_dir("abcd1234");
        assert!(dir.to_string_lossy().contains("redan/sessions/abcd1234"));
    }

    #[test]
    fn session_meta_roundtrip() {
        let meta = SessionMeta::new("test123", Some("dev"), Some("bash"));
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: SessionMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "test123");
        assert_eq!(parsed.image.as_deref(), Some("dev"));
    }

    #[test]
    fn valid_session_id_accepts_hex() {
        assert!(valid_session_id("abcd1234"));
        assert!(valid_session_id("AABB0099"));
        assert!(valid_session_id("0"));
    }

    #[test]
    fn valid_session_id_rejects_traversal() {
        assert!(!valid_session_id("../../etc"));
        assert!(!valid_session_id(""));
        assert!(!valid_session_id("abcd/1234"));
        assert!(!valid_session_id("abc xyz"));
        assert!(!valid_session_id("a".repeat(33).as_str()));
    }
}
