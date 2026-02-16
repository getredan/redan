//! Session tracking. Each `redan exec` creates a session with a unique ID.
//!
//! Sessions are stored at `~/.local/state/redan/sessions/<id>/`.
//! Each session directory contains:
//! - `meta.json`: session metadata (image, command, start time, status)
//! - `audit.jsonl`: structured event log (if no --audit-log override)

use std::path::PathBuf;

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
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Base directory for session state.
pub fn sessions_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").expect("HOME not set");
            PathBuf::from(home).join(".local/state")
        })
        .join("redan/sessions")
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
            image: image.map(|s| s.into()),
            command: command.map(|s| s.into()),
            started_at,
            status: SessionStatus::Running,
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
            if let Ok(content) = std::fs::read_to_string(&meta_path) {
                if let Ok(meta) = serde_json::from_str(&content) {
                    sessions.push(meta);
                }
            }
        }
    }
    sessions.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    sessions
}

#[cfg(test)]
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
}
