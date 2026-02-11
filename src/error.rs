use std::fmt;
use std::io;

/// Error type for redan operations.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Tls(rustls::Error),
    /// Configuration or parse errors (CLI input, secret specs, etc.)
    Config(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Tls(e) => write!(f, "tls: {e}"),
            Self::Config(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Tls(e) => Some(e),
            Self::Config(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Self::Tls(e)
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self::Config(s)
    }
}

impl<T> From<std::sync::mpsc::SendError<T>> for Error {
    fn from(e: std::sync::mpsc::SendError<T>) -> Self {
        Self::Io(io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))
    }
}
