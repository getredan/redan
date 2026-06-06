//! Terminal handling utilities.

use std::io;
use std::sync::Mutex;

pub fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// Read the host terminal's window size (columns, rows).
/// Returns None if stdin is not a TTY or the ioctl fails.
pub fn host_terminal_size() -> Option<(u16, u16)> {
    unsafe {
        if libc::isatty(libc::STDIN_FILENO) != 1 {
            return None;
        }
        let mut ws = std::mem::MaybeUninit::<libc::winsize>::uninit();
        if libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, ws.as_mut_ptr()) != 0 {
            return None;
        }
        let ws = ws.assume_init();
        if ws.ws_col > 0 && ws.ws_row > 0 {
            Some((ws.ws_col, ws.ws_row))
        } else {
            None
        }
    }
}

/// Saved terminal state for the atexit handler. `krun_start_enter` calls
/// `exit()`, bypassing Rust Drop impls, so we register a C atexit handler
/// that restores the terminal from this global.
static SAVED_TERMIOS: Mutex<Option<libc::termios>> = Mutex::new(None);

extern "C" fn restore_terminal() {
    if let Ok(guard) = SAVED_TERMIOS.lock()
        && let Some(ref original) = *guard
    {
        unsafe {
            libc::tcsetattr(
                libc::STDIN_FILENO,
                libc::TCSANOW,
                std::ptr::from_ref(original),
            );
        }
    }
}

/// RAII guard: raw terminal mode on creation, restore on drop.
/// Used by `redan attach` for direct socket-to-terminal relay.
/// NOT used by `redan exec`; libkrun handles raw mode for the VM console.
pub struct RawTerminalGuard {
    original: libc::termios,
}

impl RawTerminalGuard {
    /// Switch stdin to raw mode. Returns an error if stdin is not a TTY
    /// or the termios syscalls fail.
    pub fn enter() -> io::Result<Self> {
        unsafe {
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

/// Save the current terminal state and register an atexit handler,
/// without modifying the terminal mode.
///
/// libkrun's `setup_terminal_raw_mode` handles entering raw mode inside
/// `krun_start_enter`. This function provides a safety net: if libkrun's
/// exit observers fail to restore, the atexit handler will.
pub fn save_terminal_for_atexit() {
    unsafe {
        if libc::isatty(libc::STDIN_FILENO) != 1 {
            return;
        }
        let mut current = std::mem::MaybeUninit::<libc::termios>::uninit();
        if libc::tcgetattr(libc::STDIN_FILENO, current.as_mut_ptr()) != 0 {
            return;
        }
        let current = current.assume_init();
        if let Ok(mut saved) = SAVED_TERMIOS.lock()
            && saved.is_none()
        {
            *saved = Some(current);
            libc::atexit(restore_terminal);
        }
    }
}
