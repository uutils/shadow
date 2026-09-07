// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore setgid chauthtok

//! `expiry` — check and enforce password expiration.
//!
//! Drop-in replacement for shadow-utils `expiry(1)`. It looks at the caller's
//! own shadow line and does what `login` would do with it: says nothing if
//! all is well, warns when the password is about to expire, forces a change
//! when it has, and turns the caller away when the account itself has
//! expired. Shell profiles run it so a session started by something other
//! than `login` -- a display manager, an ssh key -- still meets the policy.
//!
//! The GNU tool is setgid `shadow`: enough to read `/etc/shadow`, and the
//! password change goes through PAM as the caller. That is how the per-tool
//! install ships it. The single setuid binary keeps euid 0 for it instead,
//! having nothing narrower to offer.

use std::fmt;
use std::io::Write as _;
use std::path::Path;

use clap::{Arg, ArgAction, Command};

use shadow_core::shadow::{Aging, ShadowEntry};
use shadow_core::sysroot::SysRoot;

use uucore::error::{UError, UResult};

mod options {
    pub const CHECK: &str = "check";
    pub const FORCE: &str = "force";
    pub const PREFIX: &str = "prefix";
}

/// The PAM service the change goes through, as `passwd` does.
#[cfg(feature = "pam")]
const PAM_SERVICE: &str = "passwd";

/// Errors `expiry` can produce.
#[derive(Debug)]
enum ExpiryError {
    /// Exit 1 — the account may not continue, or the change failed.
    Refused(String),
    /// Exit 1 — the caller or their shadow line could not be read.
    Failure(String),
    /// Exit 2 — usage.
    Usage(String),
}

impl fmt::Display for ExpiryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(m) | Self::Failure(m) | Self::Usage(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ExpiryError {}

impl UError for ExpiryError {
    fn code(&self) -> i32 {
        match self {
            Self::Refused(_) | Self::Failure(_) => 1,
            Self::Usage(_) => 2,
        }
    }
}

/// The words `login` uses, which people and scripts know.
const ACCOUNT_EXPIRED: &str = "Your account has expired; please contact your system administrator.";
const MUST_CHANGE: &str =
    "You are required to change your password immediately (password expired).";

/// The warning for a password expiring in `days`.
fn warning(days: i64) -> String {
    match days {
        0 => "Your password will expire today.".to_string(),
        1 => "Your password will expire tomorrow.".to_string(),
        n => format!("Your password will expire in {n} days."),
    }
}

/// Entry point for the `expiry` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 2)? else {
        return Ok(());
    };
    let check = matches.get_flag(options::CHECK);
    let force = matches.get_flag(options::FORCE);
    if !check && !force {
        // expiry(1) does nothing without being asked; the GNU tool prints its
        // usage and exits 2.
        return Err(ExpiryError::Usage("one of -c or -f is required".into()).into());
    }
    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);

    let uid = rustix::process::getuid().as_raw();
    let account = shadow_core::hardening::lookup_passwd_entry_by_uid(uid)
        .map_err(|e| ExpiryError::Failure(format!("cannot identify the caller: {e}")))?;

    let shadow_path = root.shadow_path();
    let entries = shadow_core::shadow::read_shadow_file(&shadow_path)
        .map_err(|e| ExpiryError::Failure(format!("cannot read {}: {e}", shadow_path.display())))?;
    let Some(entry) = entries.iter().find(|e| e.name == account.name) else {
        // No shadow line: no policy to enforce.
        return Ok(());
    };
    let today = shadow_core::shadow::days_since_epoch()
        .map_err(|e| ExpiryError::Failure(format!("cannot determine the date: {e}")))?;

    match judge(entry, today) {
        Verdict::Fine => Ok(()),
        Verdict::Warn(text) => {
            let _ = writeln!(std::io::stdout(), "{text}");
            Ok(())
        }
        Verdict::AccountExpired => {
            let _ = writeln!(std::io::stdout(), "{ACCOUNT_EXPIRED}");
            Err(ExpiryError::Refused("account expired".into()).into())
        }
        Verdict::MustChange => {
            let _ = writeln!(std::io::stdout(), "{MUST_CHANGE}");
            // Under --prefix the line belongs to another tree, and a PAM
            // change would act on this system's account of the same name.
            if prefix.is_some() {
                return Err(ExpiryError::Refused("password change required".into()).into());
            }
            change_password(&account.name)
        }
    }
}

/// What to do about the line, as text rather than as `Aging`, so the
/// decision and its wording can be tested without a terminal.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Fine,
    Warn(String),
    MustChange,
    AccountExpired,
}

fn judge(entry: &ShadowEntry, today: i64) -> Verdict {
    // A locked account is not an expiring one: the lock is the policy.
    if entry.is_locked() {
        return Verdict::Fine;
    }
    match entry.aging(today) {
        Aging::Ok => Verdict::Fine,
        Aging::ExpiresIn(days) => Verdict::Warn(warning(days)),
        Aging::MustChange => Verdict::MustChange,
        Aging::AccountExpired => Verdict::AccountExpired,
    }
}

/// Change the caller's expired password through PAM, as `passwd` would.
///
/// The real uid is the caller's, so `pam_unix` asks for the current password
/// first; the euid -- root in the multicall layout, the caller's own with
/// setgid `shadow` -- decides whether the write goes through `pam_unix`
/// directly or through its setuid helper, and both work.
#[cfg(feature = "pam")]
fn change_password(user: &str) -> UResult<()> {
    use shadow_core::pam::{ConvMode, PamContext, flags};

    let mut pam = PamContext::new(PAM_SERVICE, user, ConvMode::Tty)
        .map_err(|e| ExpiryError::Failure(format!("PAM: {e}")))?;
    pam.chauthtok(flags::PAM_CHANGE_EXPIRED_AUTHTOK)
        .map_err(|e| ExpiryError::Refused(format!("password change failed: {e}")))?;
    shadow_core::audit::log_user_event(
        "CHNG_PASSWD",
        user,
        rustix::process::getuid().as_raw(),
        true,
    );
    Ok(())
}

#[cfg(not(feature = "pam"))]
fn change_password(_user: &str) -> UResult<()> {
    Err(ExpiryError::Refused(
        "PAM support is not compiled in \u{2014} the password must be changed with passwd(1)"
            .into(),
    )
    .into())
}

/// Build the clap `Command` for `expiry`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("expiry")
        .about("Check and enforce password expiration for the calling user")
        .override_usage("expiry [-c] [-f]")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::CHECK)
                .short('c')
                .long("check")
                .help("check the user's password expiration")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::FORCE)
                .short('f')
                .long("force")
                .help("force a password change if the user's password has expired")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::PREFIX)
                .short('P')
                .long("prefix")
                .help("read the account files under PREFIX_DIR; only reports, never changes")
                .value_name("PREFIX_DIR"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        last: Option<i64>,
        max: Option<i64>,
        warn: Option<i64>,
        expire: Option<i64>,
        passwd: &str,
    ) -> ShadowEntry {
        ShadowEntry {
            name: "a".to_string(),
            passwd: passwd.to_string(),
            last_change: last,
            min_age: Some(0),
            max_age: max,
            warn_days: warn,
            inactive_days: None,
            expire_date: expire,
            reserved: String::new(),
        }
    }

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    #[test]
    fn test_verdicts() {
        assert_eq!(
            judge(
                &entry(Some(20_000), Some(99_999), Some(7), None, "$6$x$y"),
                20_100
            ),
            Verdict::Fine
        );
        assert_eq!(
            judge(
                &entry(Some(0), Some(99_999), Some(7), None, "$6$x$y"),
                20_100
            ),
            Verdict::MustChange
        );
        assert_eq!(
            judge(
                &entry(Some(20_000), Some(30), Some(7), None, "$6$x$y"),
                20_040
            ),
            Verdict::MustChange
        );
        assert_eq!(
            judge(
                &entry(Some(20_000), Some(99_999), Some(7), Some(20_050), "$6$x$y"),
                20_100
            ),
            Verdict::AccountExpired
        );
        assert_eq!(
            judge(
                &entry(Some(20_000), Some(30), Some(7), None, "$6$x$y"),
                20_029
            ),
            Verdict::Warn("Your password will expire tomorrow.".to_string())
        );
    }

    /// A locked password is a policy of its own, not an expiring one.
    #[test]
    fn test_locked_is_fine() {
        assert_eq!(
            judge(&entry(Some(0), Some(1), Some(7), None, "!$6$x$y"), 30_000),
            Verdict::Fine
        );
    }

    #[test]
    fn test_warning_wording() {
        assert_eq!(warning(0), "Your password will expire today.");
        assert_eq!(warning(1), "Your password will expire tomorrow.");
        assert_eq!(warning(5), "Your password will expire in 5 days.");
    }

    #[test]
    fn test_exit_codes() {
        assert_eq!(ExpiryError::Refused("x".into()).code(), 1);
        assert_eq!(ExpiryError::Failure("x".into()).code(), 1);
        assert_eq!(ExpiryError::Usage("x".into()).code(), 2);
    }
}
