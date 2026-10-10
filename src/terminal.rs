//! Terminal handling utilities.

use std::io::{self, IsTerminal};
use std::mem::MaybeUninit;
use std::sync::Mutex;

#[must_use]
pub fn stdin_is_tty() -> bool {
    io::stdin().is_terminal()
}

/// Read the host terminal's window size (columns, rows).
/// Returns None if stdin is not a TTY or the ioctl fails.
#[must_use]
pub fn host_terminal_size() -> Option<(u16, u16)> {
    if !stdin_is_tty() {
        return None;
    }
    let mut ws = MaybeUninit::<libc::winsize>::uninit();
    // SAFETY: `ioctl(TIOCGWINSZ)` writes one `winsize` through its third
    // argument. `ws.as_mut_ptr()` points to writable, properly aligned memory
    // of exactly that type, and STDIN_FILENO is a valid descriptor number
    // (a closed one makes the call fail with EBADF instead).
    let ret = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, ws.as_mut_ptr()) };
    if ret != 0 {
        return None;
    }
    // SAFETY: the ioctl above returned 0, so the kernel filled in every field
    // of `ws`. `winsize` is four `c_ushort`s, for which any bit pattern is valid.
    let ws = unsafe { ws.assume_init() };
    if ws.ws_col > 0 && ws.ws_row > 0 {
        Some((ws.ws_col, ws.ws_row))
    } else {
        None
    }
}

/// Read the termios settings of stdin.
fn get_termios() -> io::Result<libc::termios> {
    let mut termios = MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `tcgetattr` writes one `termios` through its second argument.
    // `termios.as_mut_ptr()` points to writable, properly aligned memory of
    // that type, and STDIN_FILENO is a valid descriptor number (a closed one
    // makes the call fail with EBADF instead).
    let ret = unsafe { libc::tcgetattr(libc::STDIN_FILENO, termios.as_mut_ptr()) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `tcgetattr` returned 0, so it filled in the whole struct. All
    // fields of `termios` are integers or integer arrays, so any bit pattern
    // is valid.
    Ok(unsafe { termios.assume_init() })
}

/// Apply termios settings to stdin immediately.
fn set_termios(termios: &libc::termios) -> io::Result<()> {
    // SAFETY: `tcsetattr` reads one `termios` through its third argument.
    // The pointer comes from a reference, so it is non-null, aligned, and
    // points to an initialized value that outlives the call. STDIN_FILENO is
    // a valid descriptor number (a closed one makes the call fail with EBADF
    // instead).
    let ret = unsafe {
        libc::tcsetattr(
            libc::STDIN_FILENO,
            libc::TCSANOW,
            std::ptr::from_ref(termios),
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Terminal state saved before booting the VM. libkrun puts the shared
/// TTY into raw mode inside the VM child process; the parent restores
/// from this global after reaping the child.
static SAVED_TERMIOS: Mutex<Option<libc::termios>> = Mutex::new(None);

/// Restore the terminal to the state captured by [`save_terminal`].
///
/// No-op if nothing was saved. Idempotent: safe to call when the VM
/// child already restored the terminal itself (libkrun's exit observers
/// do this on clean guest shutdown, but not when the child is killed).
pub fn restore_saved_terminal() {
    if let Ok(guard) = SAVED_TERMIOS.lock()
        && let Some(ref original) = *guard
    {
        // Best effort: this runs on the way out, where there is nothing
        // useful to do about a failure.
        let _ = set_termios(original);
    }
}

/// RAII guard: raw terminal mode on creation, restore on drop.
/// Used by `redan attach` for direct socket-to-terminal relay.
/// NOT used by `redan exec`; libkrun handles raw mode for the VM console.
pub struct RawTerminalGuard {
    original: libc::termios,
}

impl RawTerminalGuard {
    /// Switch stdin to raw mode.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::InvalidInput` ("stdin is not a TTY") if stdin is
    /// not a terminal, or the OS error if reading or setting the termios
    /// attributes fails.
    pub fn enter() -> io::Result<Self> {
        if !stdin_is_tty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stdin is not a TTY",
            ));
        }
        let original = get_termios()?;

        let mut raw = original;
        // SAFETY: `cfmakeraw` modifies one `termios` in place. The pointer
        // comes from an exclusive reference to the initialized local `raw`,
        // so it is non-null, aligned, and not aliased during the call.
        unsafe { libc::cfmakeraw(std::ptr::from_mut(&mut raw)) };
        set_termios(&raw)?;
        Ok(Self { original })
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        // A destructor can't return an error, so a failed restore is
        // ignored. The terminal then stays in raw mode, which the user can
        // fix with `reset`.
        let _ = set_termios(&self.original);
    }
}

/// Save the current terminal state for [`restore_saved_terminal`],
/// without modifying the terminal mode. No-op if stdin is not a TTY
/// or a state was already saved.
pub fn save_terminal() {
    if !stdin_is_tty() {
        return;
    }
    let Ok(current) = get_termios() else {
        return;
    };
    if let Ok(mut saved) = SAVED_TERMIOS.lock()
        && saved.is_none()
    {
        *saved = Some(current);
    }
}
