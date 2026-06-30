// Pedantic lints deferred until API stabilizes
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]

/// Install the rustls crypto provider (ring) if not already installed.
///
/// Safe to call multiple times; subsequent calls are no-ops.
/// Library code that depends on a crypto provider (`MitmCa`, TLS config)
/// calls this internally, so callers rarely need to invoke it directly.
pub fn ensure_crypto_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
}

pub mod auto_detect;
pub mod browser;
pub mod ca;
pub mod config;
pub mod dns;
pub mod error;
pub mod ffi;
pub mod image;
pub mod image_meta;
pub mod logfmt;
pub mod net;
pub mod provider;
pub mod proxy;
pub mod secret;
pub mod session;
pub mod templates;
pub mod terminal;
pub mod tls;
pub mod trust;
pub mod vm;
