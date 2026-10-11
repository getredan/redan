//! Image metadata: build date, source, and freshness tracking.
//!
//! Stored as `.redan-image.json` inside the image directory.

use std::io::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::rootfs::Rootfs;

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
    #[must_use]
    pub fn new(source: ImageSource) -> Self {
        let built_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Self { built_at, source }
    }

    /// Write metadata to the image directory. The image directory is also
    /// the guest's rootfs, so the write goes through [`Rootfs`].
    ///
    /// # Errors
    ///
    /// Returns a message if the metadata cannot be serialized or
    /// `.redan-image.json` cannot be written in `image_dir`.
    pub fn save(&self, image_dir: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("cannot serialize image meta: {e}"))?;
        Rootfs::open(image_dir)
            .and_then(|root| {
                root.create(Path::new(META_FILE))?
                    .write_all(json.as_bytes())
            })
            .map_err(|e| format!("cannot write {}: {e}", image_dir.join(META_FILE).display()))
    }

    /// Read metadata from an image directory. Returns None if not found.
    #[must_use]
    pub fn load(image_dir: &Path) -> Option<Self> {
        let path = image_dir.join(META_FILE);
        let content = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Age of the image in days. Returns None if timestamp can't be parsed.
    #[must_use]
    pub fn age_days(&self) -> Option<u64> {
        let built = time::OffsetDateTime::parse(
            &self.built_at,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()?;
        let now = time::OffsetDateTime::now_utc();
        let duration: time::Duration = now - built;
        // A negative age (clock skew, future timestamp) counts as zero days
        Some(u64::try_from(duration.whole_days()).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Docker image can ship `/.redan-image.json` as a link, and the
    /// metadata is saved into the image right after the import.
    #[test]
    fn save_never_writes_outside_the_image() {
        let yours = tempfile::tempdir().unwrap();
        let victim = yours.path().join("victim");
        std::fs::write(&victim, "yours").unwrap();
        let image = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(&victim, image.path().join(META_FILE)).unwrap();

        let _ = ImageMeta::new(ImageSource::Unknown).save(image.path());

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "yours");
    }

    #[test]
    fn roundtrip_dockerfile_source() {
        let meta = ImageMeta::new(ImageSource::Dockerfile {
            path: "Dockerfile".into(),
        });
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: ImageMeta = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed.source, ImageSource::Dockerfile { .. }));
        assert_ne!(parsed.built_at, "");
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
