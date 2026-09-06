// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore setgid setuid gshadow newgrp

//! `sg` — run a command with a different primary group.
//!
//! Drop-in replacement for GNU shadow-utils `sg(1)`. `sg` is `newgrp(1)` for a
//! single command: it authorizes the caller into the group the same way, then
//! runs one command in it instead of replacing the caller's shell. On a
//! distribution shipping the GNU suite the two are literally the same binary,
//! and here they are the same [`shadow_core::group_switch`] call.

use std::ffi::CString;
use std::fmt;
use std::path::Path;

use clap::{Arg, Command};

use shadow_core::group_switch;
use shadow_core::sysroot::SysRoot;

use uucore::error::{UError, UResult};

mod options {
    /// `group [[-c] command]`, taken together: `-c` is optional, so the
    /// command has to be recognized positionally as well.
    pub const OPERANDS: &str = "operands";
}

/// What the command line asked for.
struct Operands<'a> {
    /// The target group, or `None` for the caller's primary group.
    group: Option<&'a str>,
    /// The command to run, or `None` to start a shell.
    command: Option<&'a str>,
}

/// Split `sg [group [[-c] command]]` into its parts.
///
/// `-c` is optional -- `sg staff 'id -gn'` and `sg staff -c 'id -gn'` are the
/// same request -- and anything after the command is ignored, both of which
/// match what the GNU tool accepts.
fn parse_operands(operands: &[String]) -> Operands<'_> {
    let command = match operands {
        [_, flag, command, ..] if flag == "-c" => Some(command.as_str()),
        // A trailing `-c` names no command. Falling through to the arm below
        // would take the flag itself as the command and hand `-c` to the
        // shell to run.
        [_, flag] if flag == "-c" => None,
        [_, command, ..] => Some(command.as_str()),
        _ => None,
    };
    Operands {
        group: operands.first().map(String::as_str),
        command,
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum SgError {
    /// Exit 1 — general error.
    Error(String),
}

impl fmt::Display for SgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for SgError {}

impl UError for SgError {
    fn code(&self) -> i32 {
        match self {
            Self::Error(_) => 1,
        }
    }
}

impl From<shadow_core::error::ShadowError> for SgError {
    fn from(e: shadow_core::error::ShadowError) -> Self {
        Self::Error(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    // Like newgrp, sg hands control to a shell running as the caller, so only
    // core dumps are suppressed; raising RLIMIT_FSIZE would leak into the
    // command the caller asked for.
    shadow_core::hardening::suppress_core_dumps();

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 1)? else {
        return Ok(());
    };

    let operands: Vec<String> = matches
        .get_many::<String>(options::OPERANDS)
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    let Operands { group, command } = parse_operands(&operands);

    let session = group_switch::enter(&SysRoot::default(), group).map_err(SgError::from)?;

    let shell_cstr = CString::new(session.shell.as_str())
        .map_err(|_| SgError::Error("invalid shell path".into()))?;
    let basename = Path::new(&session.shell)
        .file_name()
        .map_or_else(|| "sh".to_string(), |n| n.to_string_lossy().to_string());
    let argv0 =
        CString::new(basename.as_str()).map_err(|_| SgError::Error("invalid shell name".into()))?;

    // Exec rather than fork and wait: the shell then *is* this process, so the
    // command's exit status reaches the caller unaltered -- `sg staff -c 'exit
    // 7'` exits 7, and a command that cannot be run exits 127 -- without sg
    // having to reconstruct a wait status.
    let err = match command {
        None => shadow_core::process::execv(&shell_cstr, &[&argv0]),
        Some(command) => {
            let dash_c = c"-c";
            let command =
                CString::new(command).map_err(|_| SgError::Error("invalid command".into()))?;
            shadow_core::process::execv(&shell_cstr, &[&argv0, dash_c, &command])
        }
    };
    Err(SgError::Error(format!("cannot exec {}: {err}", session.shell)).into())
}

/// Build the clap `Command` for `sg`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("sg")
        .about("Run a command with a different primary group")
        .override_usage("sg <group> [[-c] <command>]")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::OPERANDS)
                .help("the target group, then the command to run in it")
                .value_name("group [[-c] command]")
                .num_args(0..)
                // `-c` is an operand here, matched positionally, not an option.
                .allow_hyphen_values(true)
                .index(1),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    #[test]
    fn test_help_does_not_error() {
        let result = uu_app().try_get_matches_from(["sg", "--help"]);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(!err.use_stderr());
    }

    fn operands(cli: &[&str]) -> Vec<String> {
        let mut full = vec!["sg".to_string()];
        full.extend(cli.iter().map(|s| (*s).to_string()));
        uu_app()
            .try_get_matches_from(full)
            .expect("should parse")
            .get_many::<String>(options::OPERANDS)
            .map(|v| v.cloned().collect())
            .unwrap_or_default()
    }

    /// No operands at all is a shell in the caller's own primary group, the
    /// same as bare `newgrp`.
    #[test]
    fn test_no_operands_is_a_shell_in_the_primary_group() {
        let ops = operands(&[]);
        let parsed = parse_operands(&ops);
        assert_eq!(parsed.group, None);
        assert_eq!(parsed.command, None);
    }

    #[test]
    fn test_group_alone_is_a_shell() {
        let ops = operands(&["staff"]);
        let parsed = parse_operands(&ops);
        assert_eq!(parsed.group, Some("staff"));
        assert_eq!(parsed.command, None);
    }

    /// `-c` is optional: both spellings name the same command.
    #[test]
    fn test_command_with_and_without_dash_c() {
        for cli in [vec!["staff", "-c", "id -gn"], vec!["staff", "id -gn"]] {
            let ops = operands(&cli);
            let parsed = parse_operands(&ops);
            assert_eq!(parsed.group, Some("staff"), "{cli:?}");
            assert_eq!(parsed.command, Some("id -gn"), "{cli:?}");
        }
    }

    /// The command is one operand, however many words it holds, and trailing
    /// operands after it are ignored -- as they are by the GNU tool.
    #[test]
    fn test_command_is_one_operand_and_extras_are_ignored() {
        for cli in [
            vec!["staff", "-c", "echo a b c", "ignored"],
            vec!["staff", "echo a b c", "ignored"],
        ] {
            let ops = operands(&cli);
            let parsed = parse_operands(&ops);
            assert_eq!(parsed.command, Some("echo a b c"), "{cli:?}");
        }
    }

    /// A trailing `-c` names no command, so it must not become one: handing
    /// the flag to the shell would run `-c` as if the caller had asked for it.
    #[test]
    fn test_trailing_dash_c_is_not_itself_the_command() {
        let ops = operands(&["staff", "-c"]);
        let parsed = parse_operands(&ops);
        assert_eq!(parsed.group, Some("staff"));
        assert_eq!(parsed.command, None);
    }
}
