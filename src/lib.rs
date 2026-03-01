// Pedantic lints deferred until API stabilizes
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]

pub mod auto_detect;
pub mod ca;
pub mod config;
pub mod dns;
pub mod error;
pub mod ffi;
pub mod image;
pub mod net;
pub mod provider;
pub mod proxy;
pub mod secret;
pub mod session;
pub mod templates;
pub mod tls;
pub mod vm;
