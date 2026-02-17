use std::io;

/// Error type for redan operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] io::Error),

    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),

    #[error("{0}")]
    Config(String),
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
