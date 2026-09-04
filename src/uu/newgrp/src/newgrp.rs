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

use shadow_core::crypt;
use shadow_core::group;
use shadow_core::gshadow;
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

// ---------------------------------------------------------------------------
// Security hardening
// ---------------------------------------------------------------------------

// Hardening functions are now centralized in shadow_core::hardening.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get the current user's primary GID from the real UID.
fn get_current_gid() -> Result<u32, NewgrpError> {
    let uid = rustix::process::getuid().as_raw();
    match shadow_core::hardening::lookup_passwd_entry_by_uid(uid) {
        Ok(entry) => Ok(entry.gid),
        Err(e) => Err(NewgrpError::Error(format!(
            "cannot determine current user for uid {uid}: {e}"
        ))),
    }
}

/// Determine the shell to exec from the user's passwd entry.
///
/// Reads the shell field from `/etc/passwd` for the given UID rather
/// than trusting `$SHELL`, which is attacker-controlled in a
/// setuid-root context.
fn get_shell(uid: u32) -> String {
    match shadow_core::hardening::lookup_passwd_entry_by_uid(uid) {
        Ok(entry) => {
            if entry.shell.is_empty() {
                "/bin/sh".to_string()
            } else {
                entry.shell
            }
        }
        _ => "/bin/sh".to_string(),
    }
}

/// Check if the user is a member of the group (either as primary GID
/// in /etc/passwd or in the group's member list in /etc/group).
fn is_member(username: &str, user_gid: u32, target_gid: u32, group_members: &[String]) -> bool {
    if user_gid == target_gid {
        return true;
    }
    group_members.iter().any(|m| m == username)
}

/// Check if the group has a usable password in /etc/gshadow.
/// A password of `!`, `*`, `!!`, or empty means no password access.
fn group_has_password(gshadow_path: &Path, group_name: &str) -> Option<String> {
    let entries = gshadow::read_gshadow_file(gshadow_path).ok()?;
    let entry = entries.iter().find(|e| e.name == group_name)?;

    if entry.passwd.is_empty() || entry.passwd == "!" || entry.passwd == "*" || entry.passwd == "!!"
    {
        return None;
    }

    Some(entry.passwd.clone())
}

/// Read the group password, with echo off and interrupts blocked.
///
/// The shared helper is what keeps Ctrl-C at this prompt from leaving the
/// terminal with echo disabled, and it falls back to stderr/stdin where there
/// is no controlling terminal.
fn read_password(prompt: &str) -> Result<zeroize::Zeroizing<String>, NewgrpError> {
    shadow_core::tty::read_password(prompt)
        .map_err(|e| NewgrpError::Error(format!("cannot read the password: {e}")))
}

/// Verify a password against a crypt(3) hash.
///
/// Delegates to `shadow_core::crypt::verify_password` which wraps
/// the POSIX `crypt(3)` function.
fn verify_password(password: &str, hash: &str) -> Result<bool, NewgrpError> {
    crypt::verify_password(password, hash)
        .map_err(|e| NewgrpError::Error(format!("password verification failed: {e}")))
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

    let root = SysRoot::default();
    let username = shadow_core::hardening::current_username()
        .map_err(|e| NewgrpError::Error(e.to_string()))?;
    let user_gid = get_current_gid()?;

    let operands: Vec<String> = matches
        .get_many::<String>(options::OPERANDS)
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    let Operands {
        login,
        group: group_name,
    } = parse_operands(&operands)?;

    // Resolve the target GID.
    let target_gid = if let Some(gname) = group_name {
        let gname = &gname.to_string();
        // Look up the group in /etc/group.
        let group_path = root.group_path();
        let groups = group::read_group_file(&group_path).map_err(|e| {
            NewgrpError::Error(format!("cannot read {}: {e}", group_path.display()))
        })?;

        let Some(group_entry) = groups.iter().find(|g| g.name == *gname) else {
            return Err(NewgrpError::Error(format!("group '{gname}' does not exist")).into());
        };

        let gid = group_entry.gid;

        // Check membership: if the user is not a member, they need the
        // group password. Root always gets in.
        if !shadow_core::hardening::caller_is_root()
            && !is_member(&username, user_gid, gid, &group_entry.members)
        {
            // Check if the group has a password in /etc/gshadow.
            let gshadow_path = root.gshadow_path();
            match group_has_password(&gshadow_path, gname) {
                Some(hash) => {
                    let password = read_password("Password: ")?;
                    if !verify_password(&password, &hash)? {
                        return Err(NewgrpError::Error("incorrect password".into()).into());
                    }
                }
                None => {
                    return Err(NewgrpError::Error(format!(
                        "permission denied for group '{gname}'"
                    ))
                    .into());
                }
            }
        }

        gid
    } else {
        // No group specified — change to user's primary group.
        user_gid
    };

    // Set the new GID.
    shadow_core::process::setgid(target_gid)
        .map_err(|e| NewgrpError::Error(format!("cannot set group ID to {target_gid}: {e}")))?;

    // Reset supplementary groups. POSIX requires newgrp to reinitialize
    // the group list. Without this, the new shell inherits stale groups.
    let username_cstr = std::ffi::CString::new(username.as_str())
        .map_err(|_| NewgrpError::Error("invalid username".into()))?;
    shadow_core::process::initgroups(&username_cstr, target_gid)
        .map_err(|e| NewgrpError::Error(format!("cannot initialize groups: {e}")))?;

    // Drop back to the real UID (in case we are setuid-root).
    let real_uid = rustix::process::getuid().as_raw();
    if rustix::process::geteuid().as_raw() != real_uid {
        shadow_core::process::setuid(real_uid)
            .map_err(|e| NewgrpError::Error(format!("cannot drop privileges: {e}")))?;
    }

    // Exec the user's shell (from passwd entry, not $SHELL).
    let shell = get_shell(real_uid);
    let shell_cstr = CString::new(shell.as_str())
        .map_err(|_| NewgrpError::Error("invalid shell path".into()))?;

    let basename = Path::new(&shell)
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
        return Err(NewgrpError::Error(format!("cannot exec {shell}: {err}")).into());
    }

    // newgrp(1) with `-`: "the user's environment will be reinitialized as
    // though the user had logged in". That means a login shell, the home
    // directory as the working directory, and a login environment rather than
    // whatever the previous shell was carrying.
    let argv0 = CString::new(format!("-{basename}"))
        .map_err(|_| NewgrpError::Error("invalid shell name".into()))?;

    let home = shadow_core::hardening::lookup_passwd_entry_by_uid(real_uid)
        .map(|e| e.home)
        .unwrap_or_default();
    if !home.is_empty() {
        // A missing or unreadable home is not fatal; login(1) falls back to /.
        let _ = rustix::process::chdir(Path::new(&home));
    }

    let env = login_environment(&username, &home, &shell);
    let env_cstrings: Vec<CString> = env
        .into_iter()
        .map(|kv| CString::new(kv).map_err(|_| NewgrpError::Error("invalid environment".into())))
        .collect::<Result<_, _>>()?;
    let env_refs: Vec<&std::ffi::CStr> = env_cstrings.iter().map(CString::as_c_str).collect();

    let err = shadow_core::process::execve(&shell_cstr, &[&argv0], &env_refs);
    Err(NewgrpError::Error(format!("cannot exec {shell}: {err}")).into())
}

/// The environment a login shell is entitled to expect.
///
/// Everything else the caller was carrying is dropped, which is the whole
/// point of `newgrp -`. `TERM` and the locale variables are kept because a
/// login session inherits them from the terminal, not from the profile.
fn login_environment(user: &str, home: &str, shell: &str) -> Vec<String> {
    let mut env = vec![
        format!("HOME={home}"),
        format!("SHELL={shell}"),
        format!("USER={user}"),
        format!("LOGNAME={user}"),
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
    // Membership tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_member_by_primary_gid() {
        assert!(is_member("alice", 1000, 1000, &[]));
    }

    #[test]
    fn test_is_member_by_group_list() {
        let members = vec!["alice".to_string(), "bob".to_string()];
        assert!(is_member("alice", 1000, 27, &members));
    }

    #[test]
    fn test_is_not_member() {
        let members = vec!["bob".to_string()];
        assert!(!is_member("alice", 1000, 27, &members));
    }

    // -----------------------------------------------------------------------
    // Group password tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_group_has_password_locked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gshadow");
        std::fs::write(&path, "testgroup:!::\n").expect("write");
        assert!(group_has_password(&path, "testgroup").is_none());
    }

    #[test]
    fn test_group_has_password_star() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gshadow");
        std::fs::write(&path, "testgroup:*::\n").expect("write");
        assert!(group_has_password(&path, "testgroup").is_none());
    }

    #[test]
    fn test_group_has_password_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gshadow");
        std::fs::write(&path, "testgroup:::\n").expect("write");
        assert!(group_has_password(&path, "testgroup").is_none());
    }

    #[test]
    fn test_group_has_password_with_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gshadow");
        std::fs::write(&path, "testgroup:$6$saltsalt$hashhere::\n").expect("write");
        let pw = group_has_password(&path, "testgroup");
        assert!(pw.is_some());
        assert_eq!(pw.expect("should have password"), "$6$saltsalt$hashhere");
    }

    #[test]
    fn test_group_has_password_nonexistent_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gshadow");
        std::fs::write(&path, "other:!::\n").expect("write");
        assert!(group_has_password(&path, "testgroup").is_none());
    }

    #[test]
    fn test_group_has_password_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonexistent");
        assert!(group_has_password(&path, "testgroup").is_none());
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
        let env = login_environment("alice", "/home/alice", "/bin/bash");
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

    // -----------------------------------------------------------------------
    // get_shell tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_shell_default() {
        // This test is environment-dependent but should at least not panic.
        let uid = rustix::process::getuid().as_raw();
        let shell = get_shell(uid);
        assert!(!shell.is_empty());
    }
}
