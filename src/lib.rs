// Pedantic lints deferred until API stabilizes
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]

pub mod auto_detect;
pub mod browser;
pub mod ca;
pub mod config;
pub mod dns;
pub mod error;
pub mod ffi;
pub mod image;
pub mod image_meta;
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
