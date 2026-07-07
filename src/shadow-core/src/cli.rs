// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Common CLI plumbing shared by every shadow-rs tool.
//!
//! Identification strings appended to every tool's clap [`Command`] so that
//! `--help` and `--version` make the project origin explicit (issue #161),
//! plus the shared clap-error → exit-code handling that each `uumain` used
//! to copy-paste (issue #181).

use std::ffi::OsString;
use std::fmt;

use uucore::error::{UError, UResult};

/// Suffix used as the clap version string. clap renders `--version` as
/// `<bin> <version>`, so `passwd --version` prints `passwd (uutils shadow-rs) <ver>`.
pub const VERSION: &str = concat!("(uutils shadow-rs) ", env!("CARGO_PKG_VERSION"));

/// Footer appended to `--help` to identify the project.
pub const AFTER_HELP: &str = "Part of the uutils project: https://github.com/uutils/shadow-rs";

/// Error whose message has already been written to the terminal; it carries
/// only the exit code.
///
/// `Display` is intentionally empty so the uucore wrapper does not print a
/// second message on top of what clap (or the tool) already emitted.
#[derive(Debug)]
pub struct AlreadyPrinted(pub i32);

impl fmt::Display for AlreadyPrinted {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl std::error::Error for AlreadyPrinted {}

impl UError for AlreadyPrinted {
    fn code(&self) -> i32 {
        self.0
    }
}

/// Parse `args` against the tool's clap `Command`, mapping a parse failure to
/// the tool's syntax-error exit code via `code`.
///
/// Returns `Ok(None)` when clap already handled the invocation itself
/// (`--help`/`--version`, printed to stdout): the tool should exit 0. On a
/// real parse error the message is printed to stderr and the returned error
/// carries `code(&err)`.
pub fn parse_args(
    cmd: clap::Command,
    args: impl IntoIterator<Item = OsString>,
    code: impl FnOnce(&clap::Error) -> i32,
) -> UResult<Option<clap::ArgMatches>> {
    match cmd.try_get_matches_from(args) {
        Ok(matches) => Ok(Some(matches)),
        Err(e) => {
            e.print().ok();
            if e.use_stderr() {
                Err(AlreadyPrinted(code(&e)).into())
            } else {
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_cmd() -> clap::Command {
        clap::Command::new("demo").arg(
            clap::Arg::new("flag")
                .long("flag")
                .action(clap::ArgAction::SetTrue),
        )
    }

    #[test]
    fn already_printed_has_empty_display_and_carries_code() {
        let err = AlreadyPrinted(7);
        assert_eq!(err.to_string(), "");
        assert_eq!(err.code(), 7);
    }

    #[test]
    fn parse_args_returns_matches_on_success() {
        let args = ["demo", "--flag"].map(OsString::from);
        let matches = parse_args(demo_cmd(), args, |_| 2)
            .expect("should parse")
            .expect("should yield matches");
        assert!(matches.get_flag("flag"));
    }

    #[test]
    fn parse_args_maps_errors_through_code() {
        let args = ["demo", "--no-such-flag"].map(OsString::from);
        let err = parse_args(demo_cmd(), args, |_| 42).expect_err("should fail");
        assert_eq!(err.code(), 42);
    }

    #[test]
    fn parse_args_handles_version_as_none() {
        let cmd = demo_cmd().version("1.0").disable_help_flag(false);
        let args = ["demo", "--version"].map(OsString::from);
        let result = parse_args(cmd, args, |_| 2).expect("--version is not an error");
        assert!(result.is_none());
    }
}
