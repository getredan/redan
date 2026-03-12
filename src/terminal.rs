//! Terminal handling utilities.

use std::io;

/// RAII guard: raw terminal mode on creation, restore on drop.
pub struct RawTerminalGuard {
    original: libc::termios,
}

impl RawTerminalGuard {
    /// Switch stdin to raw mode. Returns an error if stdin is not a TTY
    /// or the termios syscalls fail.
    pub fn enter() -> io::Result<Self> {
        unsafe {
            // SAFETY: isatty, tcgetattr, tcsetattr are POSIX-specified and
            // safe to call with STDIN_FILENO. MaybeUninit avoids reading
            // uninitialized memory if tcgetattr fails.
            if libc::isatty(libc::STDIN_FILENO) != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "stdin is not a TTY",
                ));
            }
            let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
            if libc::tcgetattr(libc::STDIN_FILENO, original.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let original = original.assume_init();
            let mut raw = original;
            libc::cfmakeraw(std::ptr::from_mut(&mut raw));
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, std::ptr::from_ref(&raw)) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { original })
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
