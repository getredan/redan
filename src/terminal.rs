//! Terminal handling utilities.

/// RAII guard: raw terminal mode on creation, restore on drop.
pub struct RawTerminalGuard {
    original: libc::termios,
}

impl RawTerminalGuard {
    pub fn enter() -> Self {
        unsafe {
            let mut original: libc::termios = std::mem::zeroed();
            libc::tcgetattr(libc::STDIN_FILENO, std::ptr::from_mut(&mut original));
            let mut raw = original;
            libc::cfmakeraw(std::ptr::from_mut(&mut raw));
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, std::ptr::from_ref(&raw));
            Self { original }
        }
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(
                libc::STDIN_FILENO,
                libc::TCSANOW,
                std::ptr::from_ref(&self.original),
            );
        }
    }
}
