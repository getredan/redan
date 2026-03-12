//! Image metadata: build date, source, and freshness tracking.
//!
//! Stored as `.redan-image.json` inside the image directory.

use std::path::Path;

use serde::{Deserialize, Serialize};

const META_FILE: &str = ".redan-image.json";

/// How the image was built, for rebuilding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ImageSource {
    /// Built from a Dockerfile.
    Dockerfile { path: String },
    /// Imported from a Docker image.
    Docker { image: String },
    /// Built from a devcontainer config.
    Devcontainer { path: String },
    /// Created via `redan image create`.
    Create {
        packages: Vec<String>,
        run_commands: Vec<String>,
    },
    /// Unknown source (pre-metadata images).
    Unknown,
}

/// Metadata stored alongside an image.
#[derive(Debug, Serialize, Deserialize)]
pub struct ImageMeta {
    /// When the image was built (RFC 3339).
    pub built_at: String,
    /// How it was built.
    pub source: ImageSource,
}

impl ImageMeta {
    pub fn new(source: ImageSource) -> Self {
        let built_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Self { built_at, source }
    }

    /// Write metadata to the image directory.
    pub fn save(&self, image_dir: &Path) -> Result<(), String> {
        let path = image_dir.join(META_FILE);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("cannot serialize image meta: {e}"))?;
        std::fs::write(&path, json).map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    /// Read metadata from an image directory. Returns None if not found.
    pub fn load(image_dir: &Path) -> Option<Self> {
        let path = image_dir.join(META_FILE);
        let content = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Age of the image in days. Returns None if timestamp can't be parsed.
    pub fn age_days(&self) -> Option<u64> {
        let built = time::OffsetDateTime::parse(
            &self.built_at,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()?;
        let now = time::OffsetDateTime::now_utc();
        let duration: time::Duration = now - built;
        #[allow(clippy::cast_sign_loss)] // Duration is always positive (now >= built)
        Some(duration.whole_days().max(0) as u64)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_dockerfile_source() {
        let meta = ImageMeta::new(ImageSource::Dockerfile {
            path: "Dockerfile".into(),
        });
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: ImageMeta = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed.source, ImageSource::Dockerfile { .. }));
        assert!(!parsed.built_at.is_empty());
    }

    #[test]
    fn roundtrip_create_source() {
        let meta = ImageMeta::new(ImageSource::Create {
            packages: vec!["curl".into(), "git".into()],
            run_commands: vec!["pip install flask".into()],
        });
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: ImageMeta = serde_json::from_str(&json).unwrap();
        if let ImageSource::Create { packages, .. } = &parsed.source {
            assert_eq!(packages, &["curl", "git"]);
        } else {
            panic!("wrong source type");
        }
    }

    #[test]
    fn age_days_is_zero_for_fresh_image() {
        let meta = ImageMeta::new(ImageSource::Unknown);
        let days = meta.age_days().unwrap();
        assert_eq!(days, 0);
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let meta = ImageMeta::new(ImageSource::Docker {
            image: "ubuntu:24.04".into(),
        });
        meta.save(dir.path()).unwrap();

        let loaded = ImageMeta::load(dir.path()).unwrap();
        assert!(matches!(loaded.source, ImageSource::Docker { .. }));
    }

    #[test]
    fn load_returns_none_for_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ImageMeta::load(dir.path()).is_none());
    }
}
