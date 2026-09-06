// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore setgid setuid gshadow getgid getuid newgrp

//! `newgrp` — change effective group ID.
//!
//! Drop-in replacement for GNU shadow-utils / POSIX `newgrp(1)`.
//! Starts a new shell with the specified group as the effective GID.

use std::ffi::CString;
use std::fmt;
use std::path::Path;

use clap::{Arg, Command};

use shadow_core::group_switch::{self, Session};
use shadow_core::sysroot::SysRoot;

use uucore::error::{UError, UResult};

mod options {
    /// The `[-] [group]` operands, taken together so a leading `-` can be told
    /// from a group name.
    pub const OPERANDS: &str = "operands";
}

/// What the command line asked for.
struct Operands<'a> {
    /// `newgrp -`: reinitialize the environment as at login.
    login: bool,
    /// The target group, or `None` for the user's primary group.
    group: Option<&'a str>,
}

/// Split `newgrp [-] [group]` into its two parts.
///
/// newgrp(1) spells the login form as a bare `-`, not as an option letter, and
/// it may only come first. A second `-`, or anything after the group name, is
/// a usage error rather than a group called `-`.
fn parse_operands(operands: &[String]) -> Result<Operands<'_>, NewgrpError> {
    let usage = || NewgrpError::Error("usage: newgrp [-] [group]".into());
    match operands {
        [] => Ok(Operands {
            login: false,
            group: None,
        }),
        [first] if first == "-" => Ok(Operands {
            login: true,
            group: None,
        }),
        [first] => Ok(Operands {
            login: false,
            group: Some(first.as_str()),
        }),
        [first, second] if first == "-" && second != "-" => Ok(Operands {
            login: true,
            group: Some(second.as_str()),
        }),
        _ => Err(usage()),
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum NewgrpError {
    /// Exit 1 — general error.
    Error(String),
}

impl fmt::Display for NewgrpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for NewgrpError {}

impl UError for NewgrpError {
    fn code(&self) -> i32 {
        match self {
            Self::Error(_) => 1,
        }
    }
}

impl From<shadow_core::error::ShadowError> for NewgrpError {
    fn from(e: shadow_core::error::ShadowError) -> Self {
        Self::Error(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    // newgrp execs a shell, so only suppress core dumps -- do NOT raise
    // RLIMIT_FSIZE as that would leak into the user's interactive session.
    // The environment is deliberately not sanitized here either: without `-`,
    // newgrp(1) keeps the caller's environment, and it hands that environment
    // back to the caller's own uid, so there is nothing to protect it from.
    shadow_core::hardening::suppress_core_dumps();

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 1)? else {
        return Ok(());
    };

    let operands: Vec<String> = matches
        .get_many::<String>(options::OPERANDS)
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    let Operands {
        login,
        group: group_name,
    } = parse_operands(&operands)?;

    let session =
        group_switch::enter(&SysRoot::default(), group_name).map_err(NewgrpError::from)?;

    let shell_cstr = CString::new(session.shell.as_str())
        .map_err(|_| NewgrpError::Error("invalid shell path".into()))?;
    let basename = Path::new(&session.shell)
        .file_name()
        .map_or_else(|| "sh".to_string(), |n| n.to_string_lossy().to_string());

    if !login {
        // newgrp(1): without `-`, "the current environment, including current
        // working directory, remains unchanged". A login shell would re-read
        // the profile files in that unchanged environment on every `newgrp`,
        // so argv[0] carries no leading dash and the environment is inherited.
        let argv0 = CString::new(basename.as_str())
            .map_err(|_| NewgrpError::Error("invalid shell name".into()))?;
        let err = shadow_core::process::execv(&shell_cstr, &[&argv0]);
        return Err(NewgrpError::Error(format!("cannot exec {}: {err}", session.shell)).into());
    }

    // newgrp(1) with `-`: "the user's environment will be reinitialized as
    // though the user had logged in". That means a login shell, the home
    // directory as the working directory, and a login environment rather than
    // whatever the previous shell was carrying.
    let argv0 = CString::new(format!("-{basename}"))
        .map_err(|_| NewgrpError::Error("invalid shell name".into()))?;

    if !session.home.is_empty() {
        // A missing or unreadable home is not fatal; login(1) falls back to /.
        let _ = rustix::process::chdir(Path::new(&session.home));
    }

    let env = login_environment(&session);
    let env_cstrings: Vec<CString> = env
        .into_iter()
        .map(|kv| CString::new(kv).map_err(|_| NewgrpError::Error("invalid environment".into())))
        .collect::<Result<_, _>>()?;
    let env_refs: Vec<&std::ffi::CStr> = env_cstrings.iter().map(CString::as_c_str).collect();

    let err = shadow_core::process::execve(&shell_cstr, &[&argv0], &env_refs);
    Err(NewgrpError::Error(format!("cannot exec {}: {err}", session.shell)).into())
}

/// The environment a login shell is entitled to expect.
///
/// Everything else the caller was carrying is dropped, which is the whole
/// point of `newgrp -`. `TERM` and the locale variables are kept because a
/// login session inherits them from the terminal, not from the profile.
fn login_environment(session: &Session) -> Vec<String> {
    let Session {
        username,
        shell,
        home,
    } = session;
    let mut env = vec![
        format!("HOME={home}"),
        format!("SHELL={shell}"),
        format!("USER={username}"),
        format!("LOGNAME={username}"),
        "PATH=/usr/local/bin:/usr/bin:/bin".to_string(),
    ];
    for (k, v) in std::env::vars() {
        if k == "TERM" || k == "LANG" || k.starts_with("LC_") {
            env.push(format!("{k}={v}"));
        }
    }
    env
}

/// Build the clap `Command` for `newgrp`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("newgrp")
        .about("Switch the current shell's primary group")
        .override_usage("newgrp [group]")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::OPERANDS)
                .help("optional '-' to reinitialize the environment, then the target group")
                .value_name("[-] [group]")
                .num_args(0..=2)
                // A bare '-' is an operand here, not an unknown option.
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

    // -----------------------------------------------------------------------
    // Clap validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_help_does_not_error() {
        let result = uu_app().try_get_matches_from(["newgrp", "--help"]);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(!err.use_stderr());
    }

    // -----------------------------------------------------------------------
    // Operand parsing: newgrp [-] [group]
    // -----------------------------------------------------------------------

    fn operands(cli: &[&str]) -> Vec<String> {
        let mut full = vec!["newgrp".to_string()];
        full.extend(cli.iter().map(|s| (*s).to_string()));
        uu_app()
            .try_get_matches_from(full)
            .expect("should parse")
            .get_many::<String>(options::OPERANDS)
            .map(|v| v.cloned().collect())
            .unwrap_or_default()
    }

    #[test]
    fn test_no_operands_is_the_primary_group() {
        let ops = operands(&[]);
        let parsed = parse_operands(&ops).expect("should parse");
        assert!(!parsed.login);
        assert_eq!(parsed.group, None);
    }

    #[test]
    fn test_group_alone() {
        let ops = operands(&["docker"]);
        let parsed = parse_operands(&ops).expect("should parse");
        assert!(!parsed.login);
        assert_eq!(parsed.group, Some("docker"));
    }

    /// A bare `-` is newgrp(1)'s login form, not an unknown option and not a
    /// group named "-".
    #[test]
    fn test_dash_requests_a_login_environment() {
        let ops = operands(&["-"]);
        let parsed = parse_operands(&ops).expect("should parse");
        assert!(parsed.login);
        assert_eq!(parsed.group, None);

        let ops = operands(&["-", "docker"]);
        let parsed = parse_operands(&ops).expect("should parse");
        assert!(parsed.login);
        assert_eq!(parsed.group, Some("docker"));
    }

    /// `-` may only come first, and only once.
    #[test]
    fn test_misplaced_dash_is_a_usage_error() {
        for cli in [vec!["docker", "-"], vec!["-", "-"]] {
            let ops = operands(&cli);
            assert!(
                parse_operands(&ops).is_err(),
                "{cli:?} should be a usage error"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Login environment
    // -----------------------------------------------------------------------

    /// `newgrp -` reinitializes the environment, so the shell must be given
    /// the variables a login session defines and nothing the caller was
    /// carrying.
    #[test]
    fn test_login_environment_is_a_login_session() {
        let env = login_environment(&Session {
            username: "alice".to_string(),
            shell: "/bin/bash".to_string(),
            home: "/home/alice".to_string(),
        });
        for expected in [
            "HOME=/home/alice",
            "SHELL=/bin/bash",
            "USER=alice",
            "LOGNAME=alice",
        ] {
            assert!(env.iter().any(|e| e == expected), "missing {expected}");
        }
        assert!(
            env.iter().any(|e| e.starts_with("PATH=")),
            "a login shell needs a PATH"
        );
        assert!(
            !env.iter().any(|e| e.starts_with("LD_PRELOAD=")),
            "the caller's environment must not be carried over"
        );
    }
}
