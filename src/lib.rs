// Pedantic lints deferred until API stabilizes
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]
// Style lints - valid but low-value for now
#![allow(clippy::similar_names)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::too_long_first_doc_paragraph)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::if_not_else)]

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
