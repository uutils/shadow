// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore ECHONL readpassphrase

//! Reading a line, and a password, from the user's terminal.
//!
//! Prompts go to the controlling terminal when there is one, so they reach the
//! user even if stdin and stdout are redirected. When there is none — `su -c`,
//! a systemd unit, cron — opening `/dev/tty` fails with `ENXIO`, and the
//! prompt falls back to stderr with the answer read from stdin, which is what
//! `getpass(3)` does.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::io::{AsFd, BorrowedFd};

use zeroize::Zeroizing;

/// Prompt on the terminal and read one line, with echo on.
///
/// # Errors
///
/// Returns the underlying I/O error if neither the terminal nor stdin can be
/// read.
pub fn prompt_line(prompt: &str) -> io::Result<String> {
    let line = read_line(prompt, true)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Prompt on the terminal and read one line with echo disabled.
///
/// Echo is restored when the guard drops, and `SIGINT`/`SIGQUIT` are blocked
/// for the duration of the read — otherwise Ctrl-C terminates without
/// unwinding and leaves the terminal unusable, since termios state persists
/// after the process is gone.
///
/// # Errors
///
/// Returns the underlying I/O error if neither the terminal nor stdin can be
/// read.
pub fn read_password(prompt: &str) -> io::Result<Zeroizing<String>> {
    let _signals = crate::process::block_critical_signals()
        .map(SignalRestore)
        .ok();
    let line = read_line(prompt, false)?;
    Ok(line)
}

/// Restores the signal mask saved before a password read.
struct SignalRestore(crate::process::SavedSigSet);

impl Drop for SignalRestore {
    fn drop(&mut self) {
        let _ = crate::process::restore_signals(&self.0);
    }
}

/// Read one line from stdin with no prompt, for non-interactive input.
///
/// # Errors
///
/// Returns the underlying I/O error.
pub fn read_stdin_line() -> io::Result<Zeroizing<String>> {
    read_trimmed(&mut io::stdin().lock())
}

fn read_line(prompt: &str, echo: bool) -> io::Result<Zeroizing<String>> {
    match File::options().read(true).write(true).open("/dev/tty") {
        Ok(tty) => {
            write_prompt(prompt, &tty)?;
            let _guard = if echo {
                None
            } else {
                Some(EchoGuard::disable(tty.as_fd())?)
            };
            let mut reader = BufReader::new(tty.try_clone()?);
            let line = read_trimmed(&mut reader)?;
            if !echo {
                // Move the cursor past the hidden input.
                let _ = (&tty).write_all(b"\n");
            }
            Ok(line)
        }
        // No controlling terminal.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENXIO | libc::ENODEV)) => {
            let stderr = io::stderr();
            write_prompt(prompt, &mut stderr.lock())?;
            let stdin = io::stdin();
            let _guard = if echo {
                None
            } else {
                EchoGuard::disable(stdin.as_fd()).ok()
            };
            let line = read_trimmed(&mut stdin.lock())?;
            if !echo {
                let _ = writeln!(stderr.lock());
            }
            Ok(line)
        }
        Err(e) => Err(e),
    }
}

fn write_prompt<W: Write>(prompt: &str, mut sink: W) -> io::Result<()> {
    if !prompt.is_empty() {
        sink.write_all(prompt.as_bytes())?;
        sink.flush()?;
    }
    Ok(())
}

fn read_trimmed<R: BufRead>(reader: &mut R) -> io::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    reader.read_line(&mut line)?;
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// RAII guard that disables terminal echo and restores it on drop.
///
/// It borrows the descriptor rather than storing a raw one, so restoring on
/// drop needs no `unsafe` and cannot outlive the terminal it belongs to.
pub struct EchoGuard<'a> {
    fd: BorrowedFd<'a>,
    original: rustix::termios::Termios,
}

impl<'a> EchoGuard<'a> {
    /// Disable echo on the given terminal.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor is not a terminal, which the caller
    /// may treat as "nothing to suppress".
    pub fn disable(fd: BorrowedFd<'a>) -> io::Result<Self> {
        let borrowed = fd;
        let original = rustix::termios::tcgetattr(borrowed).map_err(io::Error::other)?;

        let mut noecho = original.clone();
        noecho.local_modes &=
            !(rustix::termios::LocalModes::ECHO | rustix::termios::LocalModes::ECHONL);

        rustix::termios::tcsetattr(borrowed, rustix::termios::OptionalActions::Now, &noecho)
            .map_err(io::Error::other)?;

        Ok(Self {
            fd: borrowed,
            original,
        })
    }
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            self.fd,
            rustix::termios::OptionalActions::Now,
            &self.original,
        );
    }
}
