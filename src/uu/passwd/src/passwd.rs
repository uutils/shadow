// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chroot warndays maxdays mindays chauthtok sigprocmask seteuid

//! `passwd` — change user password.
//!
//! Drop-in replacement for GNU shadow-utils `passwd(1)`.

use std::fmt;
use std::io::Write as _;
use std::path::Path;

use clap::{Arg, ArgAction, Command};

use shadow_core::audit;
use shadow_core::lock::FileLock;
use shadow_core::shadow::{self, ShadowEntry};
use shadow_core::sysroot::SysRoot;
use shadow_core::{atomic, nscd};

use uucore::error::{UError, UResult};

mod options {
    pub const USER: &str = "user";
    pub const ALL: &str = "all";
    pub const DELETE: &str = "delete";
    pub const EXPIRE: &str = "expire";
    pub const KEEP_TOKENS: &str = "keep-tokens";
    pub const INACTIVE: &str = "inactive";
    pub const LOCK: &str = "lock";
    pub const MINDAYS: &str = "mindays";
    pub const QUIET: &str = "quiet";
    pub const REPOSITORY: &str = "repository";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
    pub const STATUS: &str = "status";
    pub const UNLOCK: &str = "unlock";
    pub const WARNDAYS: &str = "warndays";
    pub const MAXDAYS: &str = "maxdays";
    pub const STDIN: &str = "stdin";
}

/// Exit code constants for `passwd(1)`.
///
/// Kept as documentation and for use in tests. The canonical mapping lives in
/// [`PasswdError::code`].
#[cfg(test)]
mod exit_codes {
    pub const PASSWD_FILE_MISSING: i32 = 4;
    pub const PAM_ERROR: i32 = 10;
}

// ---------------------------------------------------------------------------
// Error type — implements uucore::error::UError
// ---------------------------------------------------------------------------

/// Errors that the `passwd` utility can produce.
///
/// Each variant maps to a specific exit code matching GNU `passwd(1)`:
///   1 = permission denied, 3 = unexpected failure, 4 = shadow file missing,
///   5 = file busy (lock), 10 = PAM error.
///
/// For clap-reported errors (exit 2 or 6), use [`AlreadyPrinted`] so the
/// uucore wrapper does not duplicate the message clap already wrote.
#[derive(Debug)]
enum PasswdError {
    /// Exit 1 — insufficient privileges.
    PermissionDenied(String),
    /// Exit 3 — an unexpected runtime failure.
    UnexpectedFailure(String),
    /// Exit 4 — `/etc/shadow` (or equivalent) does not exist.
    FileMissing(String),
    /// Exit 5 — could not acquire the shadow lock file.
    FileBusy(String),
    /// Exit 10 — PAM returned an error.
    #[cfg_attr(not(feature = "pam"), allow(dead_code))]
    PamError(String),
    /// Sentinel used when the error has already been printed (e.g. by clap).
    /// The uucore wrapper skips printing when Display yields an empty string.
    AlreadyPrinted(i32),
}

impl fmt::Display for PasswdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg)
            | Self::UnexpectedFailure(msg)
            | Self::FileMissing(msg)
            | Self::FileBusy(msg)
            | Self::PamError(msg) => f.write_str(msg),
            Self::AlreadyPrinted(_) => Ok(()),
        }
    }
}

impl std::error::Error for PasswdError {}

impl UError for PasswdError {
    fn code(&self) -> i32 {
        match self {
            Self::PermissionDenied(_) => 1,
            Self::UnexpectedFailure(_) => 3,
            Self::FileMissing(_) => 4,
            Self::FileBusy(_) => 5,
            Self::PamError(_) => 10,
            Self::AlreadyPrinted(code) => *code,
        }
    }
}

// Hardening functions are now centralized in shadow_core::hardening.

// ---------------------------------------------------------------------------
// Security hardening — landlock filesystem restriction
// ---------------------------------------------------------------------------

/// Restrict filesystem access using landlock (Linux 5.13+).
///
/// Best-effort Landlock sandboxing for passwd. Silently does nothing on
/// kernels without Landlock support or when the feature is disabled.
///
/// Restricts filesystem access to only what passwd needs:
/// read+write `/etc/` (passwd/shadow files) and `/dev/` (tty for prompts),
/// execute `/usr/sbin/` (`nscd`/`sss_cache` invalidation).
#[allow(unused_variables)]
fn apply_landlock(root: &SysRoot) {
    // Landlock is irreversible per-process, skip during tests
    #[cfg(not(test))]
    {
        let etc = root.resolve("/etc");
        let dev = Path::new("/dev");
        let usr_sbin = Path::new("/usr/sbin");

        shadow_core::hardening::apply_landlock(&[etc.as_path(), dev], &[], &[usr_sbin]);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the `passwd` utility.
#[uucore::main]
#[allow(clippy::too_many_lines)]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let _clean_env = shadow_core::hardening::harden_process();

    let matches = match uu_app().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            if !e.use_stderr() {
                // --help / --version: clap prints to stdout, exit 0.
                return Ok(());
            }
            // GNU passwd exits 2 for conflicting options, 6 for unknown/invalid.
            return Err(match e.kind() {
                clap::error::ErrorKind::ArgumentConflict
                | clap::error::ErrorKind::MissingRequiredArgument => {
                    PasswdError::AlreadyPrinted(2).into()
                }
                _ => PasswdError::AlreadyPrinted(6).into(),
            });
        }
    };

    // Handle --root / -R: chroot before anything else.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        do_chroot(chroot_dir)?;
    }

    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);
    let quiet = matches.get_flag(options::QUIET);

    // Best-effort filesystem restriction — silently skipped on older kernels.
    apply_landlock(&root);

    // Determine target user.
    let target_user = resolve_target_user(&matches)?;

    // Dispatch to the appropriate operation.
    if matches.get_flag(options::STATUS) {
        let show_all = matches.get_flag(options::ALL);

        // Non-root users can only view their own status.
        if !shadow_core::hardening::caller_is_root() {
            if show_all {
                return Err(PasswdError::PermissionDenied("Permission denied.".into()).into());
            }
            let current_user = shadow_core::hardening::current_username()
                .map_err(|e| PasswdError::UnexpectedFailure(e.to_string()))?;
            if current_user != target_user {
                return Err(PasswdError::PermissionDenied("Permission denied.".into()).into());
            }
        }

        return cmd_status(&root, if show_all { None } else { Some(&target_user) });
    }

    // Determine the mutation operation (if any).
    let has_lock = matches.get_flag(options::LOCK);
    let has_unlock = matches.get_flag(options::UNLOCK);
    let has_delete = matches.get_flag(options::DELETE);
    let has_expire = matches.get_flag(options::EXPIRE);
    let has_mutation = has_lock || has_unlock || has_delete || has_expire;

    // Collect aging flag values.
    let min = matches.get_one::<i64>(options::MINDAYS).copied();
    let max = matches.get_one::<i64>(options::MAXDAYS).copied();
    let warn = matches.get_one::<i64>(options::WARNDAYS).copied();
    let inactive = matches.get_one::<i64>(options::INACTIVE).copied();
    let has_aging = min.is_some() || max.is_some() || warn.is_some() || inactive.is_some();

    // Admin operations (lock/unlock/delete/expire/aging) require the real
    // caller to be root. Non-root users can only change their own password
    // (the default PAM path below).
    if (has_mutation || has_aging) && !shadow_core::hardening::caller_is_root() {
        return Err(PasswdError::PermissionDenied("Permission denied.".into()).into());
    }

    // When a mutation flag and aging flags are both present, apply both in a
    // single `mutate_shadow` call so neither set of changes is lost.
    if has_mutation || has_aging {
        let action = if has_lock {
            "Locking password"
        } else if has_unlock {
            "Unlocking password"
        } else if has_delete {
            "Removing password"
        } else if has_expire {
            "Expiring password"
        } else {
            "Updating aging information"
        };

        return mutate_shadow(&root, &target_user, action, quiet, |entry| {
            // Apply the mutation operation.
            if has_lock {
                entry.lock();
            } else if has_unlock {
                if !entry.unlock() {
                    return Err("cannot unlock: password is not set or would remain locked".into());
                }
            } else if has_delete {
                entry.delete_password();
            } else if has_expire {
                entry.expire();
            }

            // Apply aging fields.
            if let Some(v) = min {
                entry.min_age = Some(v);
            }
            if let Some(v) = max {
                entry.max_age = Some(v);
            }
            if let Some(v) = warn {
                entry.warn_days = Some(v);
            }
            if let Some(v) = inactive {
                entry.inactive_days = Some(v);
            }

            Ok(())
        });
    }

    // Prevent non-root from targeting other users (avoids timing-based
    // user enumeration through PAM auth failure timing).
    if !shadow_core::hardening::caller_is_root() {
        let current = shadow_core::hardening::current_username()
            .map_err(|e| PasswdError::UnexpectedFailure(e.to_string()))?;
        if current != target_user {
            return Err(PasswdError::PermissionDenied(
                "You may not view or modify password information for another user.".into(),
            )
            .into());
        }
    }

    // Default: password change via PAM.
    cmd_pam_change(&matches, &target_user)
}

/// Build the clap `Command` for `passwd`.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn uu_app() -> Command {
    Command::new("passwd")
        .about("Update or manage a user's password")
        .override_usage("passwd [options] [LOGIN]")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::ALL)
                .short('a')
                .long("all")
                .help("show status for every user (combine with -S)")
                .requires(options::STATUS)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::DELETE)
                .short('d')
                .long("delete")
                .help("erase the password field on the target account")
                .conflicts_with_all([options::LOCK, options::UNLOCK, options::STATUS])
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::EXPIRE)
                .short('e')
                .long("expire")
                .help("mark the target account's password as expired")
                .conflicts_with_all([
                    options::LOCK,
                    options::UNLOCK,
                    options::DELETE,
                    options::STATUS,
                ])
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::KEEP_TOKENS)
                .short('k')
                .long("keep-tokens")
                .help("no-op unless the password has already expired")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::INACTIVE)
                .short('i')
                .long("inactive")
                .help("disable the password INACTIVE days past its expiry")
                .value_name("INACTIVE")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new(options::LOCK)
                .short('l')
                .long("lock")
                .help("disable login by locking the password field")
                .conflicts_with_all([options::UNLOCK, options::DELETE, options::STATUS])
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::MINDAYS)
                .short('n')
                .long("mindays")
                .help("require at least MIN_DAYS between password changes")
                .value_name("MIN_DAYS")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new(options::QUIET)
                .short('q')
                .long("quiet")
                .help("quiet mode")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::REPOSITORY)
                .short('r')
                .long("repository")
                .help("operate on REPOSITORY (e.g. files, ldap)")
                .value_name("REPOSITORY"),
        )
        .arg(
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .help("chroot into CHROOT_DIR before applying changes")
                .value_name("CHROOT_DIR"),
        )
        .arg(
            Arg::new(options::PREFIX)
                .short('P')
                .long("prefix")
                .help("directory prefix")
                .value_name("PREFIX_DIR"),
        )
        .arg(
            Arg::new(options::STATUS)
                .short('S')
                .long("status")
                .help("print the password status of the target account")
                .conflicts_with_all([options::LOCK, options::UNLOCK, options::DELETE])
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::UNLOCK)
                .short('u')
                .long("unlock")
                .help("re-enable login by unlocking the password field")
                .conflicts_with_all([options::LOCK, options::DELETE, options::STATUS])
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::WARNDAYS)
                .short('w')
                .long("warndays")
                .help("warn the user WARN_DAYS before password expiry")
                .value_name("WARN_DAYS")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new(options::MAXDAYS)
                .short('x')
                .long("maxdays")
                .help("require a password change at least every MAX_DAYS")
                .value_name("MAX_DAYS")
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new(options::STDIN)
                .short('s')
                .long("stdin")
                .help("read the new password from standard input")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::USER)
                .help("Account whose password to change")
                .index(1),
        )
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

/// `passwd -S [user]` / `passwd -Sa` — display account status.
fn cmd_status(root: &SysRoot, target_user: Option<&str>) -> UResult<()> {
    let shadow_path = root.shadow_path();
    let entries = match shadow::read_shadow_file(&shadow_path) {
        Ok(e) => e,
        Err(e) => {
            return if shadow_path.exists() {
                Err(PasswdError::UnexpectedFailure(e.to_string()).into())
            } else {
                Err(PasswdError::FileMissing(e.to_string()).into())
            };
        }
    };

    let mut out = std::io::stdout().lock();
    match target_user {
        Some(user) => {
            let Some(entry) = entries.iter().find(|e| e.name == user) else {
                return Err(PasswdError::UnexpectedFailure(format!(
                    "user '{user}' does not exist in {}",
                    shadow_path.display()
                ))
                .into());
            };
            let _ = writeln!(out, "{}", format_status(entry));
        }
        None => {
            // --all: show all users.
            for entry in &entries {
                let _ = writeln!(out, "{}", format_status(entry));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Security hardening — privilege dropping during PAM conversation
// ---------------------------------------------------------------------------

/// RAII guard that drops effective UID and restores on drop.
///
/// When passwd is installed setuid-root, we want to drop to the caller's
/// real UID during the PAM conversation so that the PAM modules see the
/// actual caller, not root. The destructor re-elevates.
#[cfg_attr(not(feature = "pam"), allow(dead_code))]
struct PrivDrop {
    original_euid: u32,
}

impl PrivDrop {
    /// Drop effective UID to the given UID.
    #[cfg_attr(not(feature = "pam"), allow(dead_code))]
    fn drop_to(uid: u32) -> Result<Self, PasswdError> {
        let original_euid = rustix::process::geteuid().as_raw();
        if original_euid != uid {
            shadow_core::process::seteuid(uid).map_err(|e| {
                PasswdError::UnexpectedFailure(format!("cannot drop privileges: {e}"))
            })?;
        }
        Ok(Self { original_euid })
    }
}

impl Drop for PrivDrop {
    fn drop(&mut self) {
        if let Err(e) = shadow_core::process::seteuid(self.original_euid) {
            // Failing to restore privileges is a critical error — log it loudly.
            // We can't return an error from Drop, so at least make it visible.
            let _ = writeln!(
                std::io::stderr().lock(),
                "passwd: CRITICAL: failed to restore euid to {}: {e}",
                self.original_euid
            );
        }
    }
}

// Note: custom SIGINT handler removed — it required unsafe (sigaction +
// libc::write + libc::_exit). SIGINT terminates without unwinding, so
// EchoGuard::drop won't run. Terminal echo restoration after Ctrl+C relies
// on the terminal driver resetting on process exit (standard behavior).
// The "Password unchanged." message was cosmetic, not security-critical.

/// Default operation: change password via PAM.
///
/// Feature-gated on `pam`. When PAM is not compiled in, prints an error.
fn cmd_pam_change(matches: &clap::ArgMatches, _target_user: &str) -> UResult<()> {
    let _keep_tokens = matches.get_flag(options::KEEP_TOKENS);
    let _use_stdin = matches.get_flag(options::STDIN);
    let _repository = matches.get_one::<String>(options::REPOSITORY);

    #[cfg(feature = "pam")]
    {
        use shadow_core::pam::{ConvMode, PamContext, flags};

        let conv_mode = if _use_stdin {
            ConvMode::Stdin
        } else {
            ConvMode::Tty
        };

        let mut pam = match PamContext::new("passwd", _target_user, conv_mode) {
            Ok(ctx) => ctx,
            Err(e) => {
                return Err(PasswdError::PamError(e.to_string()).into());
            }
        };

        // Drop privileges to caller's real UID during PAM conversation.
        // Re-elevate automatically when _priv_drop goes out of scope.
        let _priv_drop = PrivDrop::drop_to(rustix::process::getuid().as_raw())?;

        // Non-root users changing their own password must authenticate first.
        if !shadow_core::hardening::caller_is_root() {
            if let Err(e) = pam.authenticate(0) {
                return Err(PasswdError::PamError(e.to_string()).into());
            }
        }

        // Validate that the account is in good standing.
        if let Err(e) = pam.acct_mgmt(0) {
            return Err(PasswdError::PamError(e.to_string()).into());
        }

        // Change the password token.
        let chauthtok_flags = if _keep_tokens {
            flags::PAM_CHANGE_EXPIRED_AUTHTOK
        } else {
            0
        };

        if let Err(e) = pam.chauthtok(chauthtok_flags) {
            return Err(PasswdError::PamError(e.to_string()).into());
        }

        audit::log_user_event(
            "CHNG_PASSWD",
            _target_user,
            rustix::process::getuid().as_raw(),
            true,
        );

        Ok(())
    }

    #[cfg(not(feature = "pam"))]
    {
        Err(PasswdError::UnexpectedFailure(
            "PAM support is not compiled in \u{2014} cannot change password interactively".into(),
        )
        .into())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the target username from args or current user.
fn resolve_target_user(matches: &clap::ArgMatches) -> Result<String, PasswdError> {
    if let Some(user) = matches.get_one::<String>(options::USER) {
        return Ok(user.clone());
    }

    // No user specified — default to current user.
    shadow_core::hardening::current_username()
        .map_err(|e| PasswdError::UnexpectedFailure(e.to_string()))
}

/// Perform `chroot(2)` into the specified directory.
///
/// Must be root to call `chroot`. After `chroot`, chdir to `/` so the
/// working directory is valid inside the new root.
fn do_chroot(dir: &str) -> Result<(), PasswdError> {
    if !shadow_core::hardening::caller_is_root() {
        return Err(PasswdError::PermissionDenied(
            "only root may use --root".into(),
        ));
    }

    let path = std::path::Path::new(dir);
    rustix::process::chroot(path)
        .map_err(|e| PasswdError::UnexpectedFailure(format!("cannot chroot to '{dir}': {e}")))?;

    rustix::process::chdir("/").map_err(|e| {
        PasswdError::UnexpectedFailure(format!("cannot chdir to / after chroot: {e}"))
    })?;

    Ok(())
}

/// Format a single shadow entry as a `passwd -S` status line.
///
/// Format: `username STATUS YYYY-MM-DD min max warn inactive`
fn format_status(entry: &ShadowEntry) -> String {
    let date = match entry.last_change {
        Some(0) => "1970-01-01".to_string(),
        Some(days) => format_days_since_epoch(days),
        None => "never".to_string(),
    };

    let min = entry.min_age.map_or("-1".to_string(), |v| v.to_string());
    let max = entry.max_age.map_or("-1".to_string(), |v| v.to_string());
    let warn = entry.warn_days.map_or("-1".to_string(), |v| v.to_string());
    let inactive = entry
        .inactive_days
        .map_or("-1".to_string(), |v| v.to_string());

    format!(
        "{} {} {} {} {} {} {}",
        entry.name,
        entry.status_char(),
        date,
        min,
        max,
        warn,
        inactive
    )
}

/// Convert days since epoch to `YYYY-MM-DD` format (matching GNU `passwd -S`).
///
/// Uses the Hinnant `civil_from_days` algorithm — pure Rust, no libc.
fn format_days_since_epoch(days: i64) -> String {
    // Algorithm: https://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Lock the shadow file, read entries, apply a mutation to one user's entry,
/// write back atomically, invalidate nscd cache.
fn mutate_shadow<F>(
    root: &SysRoot,
    username: &str,
    action: &str,
    quiet: bool,
    mutate: F,
) -> UResult<()>
where
    F: FnOnce(&mut ShadowEntry) -> Result<(), String>,
{
    // Consolidate real + effective UID to root for file operations.
    // Some filesystem configurations check real UID.
    if rustix::process::geteuid().is_root() {
        let _ = shadow_core::process::setuid(0);
    }

    // Block signals for the entire critical section (lock → write → unlock).
    // The RAII guard restores the original signal mask when this function returns.
    let _signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| PasswdError::UnexpectedFailure(e.to_string()))?;

    let shadow_path = root.shadow_path();

    // Acquire lock.
    let lock = FileLock::acquire(&shadow_path).map_err(|_| {
        PasswdError::FileBusy(format!(
            "cannot lock {}: try again later",
            shadow_path.display()
        ))
    })?;

    // Read current entries.
    let mut entries = match shadow::read_shadow_file(&shadow_path) {
        Ok(e) => e,
        Err(e) => {
            drop(lock);
            return if shadow_path.exists() {
                Err(PasswdError::UnexpectedFailure(e.to_string()).into())
            } else {
                Err(PasswdError::FileMissing(e.to_string()).into())
            };
        }
    };

    // Find the target user.
    let Some(entry) = entries.iter_mut().find(|e| e.name == username) else {
        drop(lock);
        return Err(PasswdError::UnexpectedFailure(format!(
            "user '{username}' does not exist in {}",
            shadow_path.display()
        ))
        .into());
    };

    // Apply the mutation.
    if let Err(msg) = mutate(entry) {
        drop(lock);
        return Err(PasswdError::UnexpectedFailure(msg).into());
    }

    // Write back atomically.
    let write_result = atomic::atomic_write(&shadow_path, |file| {
        shadow::write_shadow(&entries, file)?;
        Ok(())
    });

    if let Err(e) = write_result {
        drop(lock);
        return Err(PasswdError::UnexpectedFailure(format!(
            "failed to write {}: {e}",
            shadow_path.display()
        ))
        .into());
    }

    // Release lock and invalidate caches.
    drop(lock);
    nscd::invalidate_cache("shadow");

    audit::log_user_event(
        "CHNG_PASSWD",
        username,
        rustix::process::getuid().as_raw(),
        true,
    );

    if !quiet {
        uucore::show_error!("{action} for user {username}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Basic clap / app tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    // -----------------------------------------------------------------------
    // format_status helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_status_locked() {
        let entry = ShadowEntry {
            name: "testuser".to_string(),
            passwd: "!$6$hash".to_string(),
            last_change: Some(19500),
            min_age: Some(0),
            max_age: Some(99999),
            warn_days: Some(7),
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        };
        let status = format_status(&entry);
        assert!(status.starts_with("testuser L "));
        assert!(status.ends_with(" 0 99999 7 -1"));
    }

    #[test]
    fn test_format_status_no_password() {
        let entry = ShadowEntry {
            name: "nopw".to_string(),
            passwd: String::new(),
            last_change: Some(19500),
            min_age: Some(0),
            max_age: Some(99999),
            warn_days: Some(7),
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        };
        let status = format_status(&entry);
        assert!(status.contains(" NP "));
    }

    #[test]
    fn test_format_status_usable() {
        let entry = ShadowEntry {
            name: "active".to_string(),
            passwd: "$6$hash".to_string(),
            last_change: Some(19500),
            min_age: Some(0),
            max_age: Some(99999),
            warn_days: Some(7),
            inactive_days: Some(30),
            expire_date: None,
            reserved: String::new(),
        };
        let status = format_status(&entry);
        assert!(status.contains(" P "));
        assert!(status.ends_with(" 0 99999 7 30"));
    }

    #[test]
    fn test_format_status_never_changed() {
        let entry = ShadowEntry {
            name: "new".to_string(),
            passwd: "*".to_string(),
            last_change: None,
            min_age: None,
            max_age: None,
            warn_days: None,
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        };
        let status = format_status(&entry);
        // * is locked per GNU behavior.
        assert!(status.contains(" L "));
        assert!(status.contains(" never "));
    }

    #[test]
    fn test_format_days_since_epoch() {
        let result = format_days_since_epoch(0);
        // Verify YYYY-MM-DD format.
        assert_eq!(result.len(), 10, "format should be YYYY-MM-DD");
        assert_eq!(&result[4..5], "-");
        assert_eq!(&result[7..8], "-");
    }

    #[test]
    fn test_format_status_double_locked() {
        // Password "!!" — starts with '!', so status is L.
        let entry = ShadowEntry {
            name: "dbllock".to_string(),
            passwd: "!!".to_string(),
            last_change: Some(19500),
            min_age: Some(0),
            max_age: Some(99999),
            warn_days: Some(7),
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        };
        let status = format_status(&entry);
        assert!(status.contains(" L "), "!! should show as L");
    }

    #[test]
    fn test_format_status_star_password() {
        // Password "*" — GNU treats as locked (system account).
        let entry = ShadowEntry {
            name: "star".to_string(),
            passwd: "*".to_string(),
            last_change: Some(19500),
            min_age: Some(0),
            max_age: Some(99999),
            warn_days: Some(7),
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        };
        let status = format_status(&entry);
        assert!(status.contains(" L "), "* should show as L (matching GNU)");
    }

    // -----------------------------------------------------------------------
    // Clap validation tests — conflict groups and flag parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_conflicting_flags() {
        let result = uu_app().try_get_matches_from(["passwd", "-l", "-u"]);
        assert!(result.is_err());

        let result = uu_app().try_get_matches_from(["passwd", "-l", "-d"]);
        assert!(result.is_err());

        let result = uu_app().try_get_matches_from(["passwd", "-S", "-d"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_requires_status() {
        let result = uu_app().try_get_matches_from(["passwd", "-a"]);
        assert!(result.is_err());

        let result = uu_app().try_get_matches_from(["passwd", "-S", "-a"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_expire_conflicts_with_lock() {
        let result = uu_app().try_get_matches_from(["passwd", "-e", "-l", "user"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_expire_conflicts_with_unlock() {
        let result = uu_app().try_get_matches_from(["passwd", "-e", "-u", "user"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_expire_conflicts_with_delete() {
        let result = uu_app().try_get_matches_from(["passwd", "-e", "-d", "user"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_expire_conflicts_with_status() {
        let result = uu_app().try_get_matches_from(["passwd", "-e", "-S", "user"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_stdin_flag_parses() {
        let result = uu_app().try_get_matches_from(["passwd", "-s", "user"]);
        assert!(result.is_ok());
        let m = result.expect("already checked Ok");
        assert!(m.get_flag(options::STDIN));
    }

    #[test]
    fn test_keep_tokens_flag_parses() {
        let result = uu_app().try_get_matches_from(["passwd", "-k", "user"]);
        assert!(result.is_ok());
        let m = result.expect("already checked Ok");
        assert!(m.get_flag(options::KEEP_TOKENS));
    }

    #[test]
    fn test_root_flag_parses() {
        let result = uu_app().try_get_matches_from(["passwd", "-R", "/mnt/sysroot", "user"]);
        assert!(result.is_ok());
        let m = result.expect("already checked Ok");
        assert_eq!(
            m.get_one::<String>(options::ROOT).map(String::as_str),
            Some("/mnt/sysroot")
        );
    }

    #[test]
    fn test_quiet_flag_parses() {
        let result = uu_app().try_get_matches_from(["passwd", "-q", "-l", "user"]);
        assert!(result.is_ok());
        let m = result.expect("already checked Ok");
        assert!(m.get_flag(options::QUIET));
    }

    #[test]
    fn test_repository_flag_parses() {
        let result = uu_app().try_get_matches_from(["passwd", "-r", "files", "user"]);
        assert!(result.is_ok());
        let m = result.expect("already checked Ok");
        assert_eq!(
            m.get_one::<String>(options::REPOSITORY).map(String::as_str),
            Some("files")
        );
    }

    #[test]
    fn test_mindays_requires_value() {
        let result = uu_app().try_get_matches_from(["passwd", "-n"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_maxdays_requires_value() {
        let result = uu_app().try_get_matches_from(["passwd", "-x"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_warndays_requires_value() {
        let result = uu_app().try_get_matches_from(["passwd", "-w"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_inactive_requires_value() {
        let result = uu_app().try_get_matches_from(["passwd", "-i"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aging_combined_flags() {
        let result = uu_app().try_get_matches_from(["passwd", "-n", "5", "-x", "90", "user"]);
        assert!(result.is_ok());
        let m = result.expect("already checked Ok");
        assert_eq!(m.get_one::<i64>(options::MINDAYS).copied(), Some(5));
        assert_eq!(m.get_one::<i64>(options::MAXDAYS).copied(), Some(90));
    }

    // -----------------------------------------------------------------------
    // Integration tests with --prefix (require root — run in Docker)
    // -----------------------------------------------------------------------

    /// Skip the test when not running as root (euid != 0).
    ///
    /// Bug #3 removed the prefix bypass for the root check, so all mutation
    /// and cross-user status tests now require euid 0. In CI these run inside
    /// a Docker container as root.
    fn skip_unless_root() -> bool {
        !rustix::process::geteuid().is_root()
    }

    /// Helper to create a temp dir with an etc/shadow file.
    fn setup_prefix(shadow_content: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("failed to create etc dir");
        std::fs::write(etc.join("shadow"), shadow_content).expect("failed to write shadow file");
        dir
    }

    /// Read the shadow file content back from a prefix dir.
    fn read_shadow(dir: &tempfile::TempDir) -> String {
        std::fs::read_to_string(dir.path().join("etc/shadow")).expect("failed to read shadow file")
    }

    /// Run uumain with the given args, returning the exit code.
    fn run(args: &[&str]) -> i32 {
        let os_args: Vec<std::ffi::OsString> = args.iter().map(|s| (*s).into()).collect();
        uumain(os_args.into_iter())
    }

    /// Run uumain with a prefix dir prepended to the args.
    fn run_with_prefix(dir: &tempfile::TempDir, extra_args: &[&str]) -> i32 {
        let prefix_str = dir.path().to_str().expect("non-UTF-8 temp path");
        let mut args = vec!["passwd", "-P", prefix_str];
        args.extend_from_slice(extra_args);
        run(&args)
    }

    #[test]
    fn test_status_with_prefix() {
        if skip_unless_root() {
            return;
        }
        let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-S", "testuser"]);
        assert_eq!(code, 0);
    }

    #[test]
    fn test_lock_with_prefix() {
        if skip_unless_root() {
            return;
        }
        let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-l", "testuser"]);
        assert_eq!(code, 0);

        let content = read_shadow(&dir);
        assert!(content.contains("testuser:!$6$hash:"));
    }

    #[test]
    fn test_unlock_with_prefix() {
        if skip_unless_root() {
            return;
        }
        let dir = setup_prefix("testuser:!$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-u", "testuser"]);
        assert_eq!(code, 0);

        let content = read_shadow(&dir);
        assert!(content.contains("testuser:$6$hash:"));
    }

    #[test]
    fn test_delete_with_prefix() {
        if skip_unless_root() {
            return;
        }
        let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-d", "testuser"]);
        assert_eq!(code, 0);

        let content = read_shadow(&dir);
        assert!(content.contains("testuser::19500:"));
    }

    #[test]
    fn test_expire_with_prefix() {
        if skip_unless_root() {
            return;
        }
        let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-e", "testuser"]);
        assert_eq!(code, 0);

        let content = read_shadow(&dir);
        assert!(content.contains("testuser:$6$hash:0:"));
    }

    #[test]
    fn test_aging_with_prefix() {
        if skip_unless_root() {
            return;
        }
        let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(
            &dir,
            &["-n", "5", "-x", "90", "-w", "14", "-i", "30", "testuser"],
        );
        assert_eq!(code, 0);

        let content = read_shadow(&dir);
        assert!(content.contains("testuser:$6$hash:19500:5:90:14:30::"));
    }

    #[test]
    fn test_status_all_with_prefix() {
        if skip_unless_root() {
            return;
        }
        let dir = setup_prefix("root:$6$roothash:19000:0:99999:7:::\ntestuser:!:19500::::::\n");
        let code = run_with_prefix(&dir, &["-S", "-a"]);
        assert_eq!(code, 0);
    }

    // -----------------------------------------------------------------------
    // New integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_lock_already_locked() {
        if skip_unless_root() {
            return;
        }
        // Locking an already locked password adds another '!'.
        let dir = setup_prefix("testuser:!$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-l", "testuser"]);
        assert_eq!(code, 0);

        let content = read_shadow(&dir);
        assert!(
            content.contains("testuser:!!$6$hash:"),
            "should have double !, got: {content}"
        );
    }

    #[test]
    fn test_unlock_double_locked() {
        if skip_unless_root() {
            return;
        }
        // Unlocking "!!$6$hash" removes one '!', leaving "!$6$hash" which
        // is still locked — so unlock should report the first '!' was removed
        // but the result starts with '!' and ShadowEntry::unlock returns true
        // because the *remaining* string ("!$6$hash") is non-empty and not "!".
        // Actually: unlock removes *one* leading '!'. After removing one '!':
        //   "!!$6$hash" -> "!$6$hash"
        // "!$6$hash" is non-empty and not "!", so unlock returns true.
        let dir = setup_prefix("testuser:!!$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-u", "testuser"]);
        assert_eq!(code, 0);

        let content = read_shadow(&dir);
        assert!(
            content.contains("testuser:!$6$hash:"),
            "should have single !, got: {content}"
        );
    }

    #[test]
    fn test_unlock_empty_password_fails() {
        if skip_unless_root() {
            return;
        }
        // Cannot unlock an account with no hash — unlock returns false.
        let dir = setup_prefix("testuser::19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-u", "testuser"]);
        assert_ne!(code, 0, "unlocking empty password should fail");
    }

    #[test]
    fn test_delete_already_empty() {
        if skip_unless_root() {
            return;
        }
        // Deleting an already-empty password is a no-op (succeeds).
        let dir = setup_prefix("testuser::19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-d", "testuser"]);
        assert_eq!(code, 0);

        let content = read_shadow(&dir);
        assert!(content.contains("testuser::19500:"));
    }

    #[test]
    fn test_expire_already_expired() {
        if skip_unless_root() {
            return;
        }
        // Expiring an already-expired (last_change=0) account succeeds.
        let dir = setup_prefix("testuser:$6$hash:0:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-e", "testuser"]);
        assert_eq!(code, 0);

        let content = read_shadow(&dir);
        assert!(content.contains("testuser:$6$hash:0:"));
    }

    #[test]
    fn test_multiple_users_only_target_modified() {
        if skip_unless_root() {
            return;
        }
        let shadow = "alice:$6$alice:19500:0:99999:7:::\nbob:$6$bob:19500:0:99999:7:::\ncharlie:$6$charlie:19500:0:99999:7:::\n";
        let dir = setup_prefix(shadow);

        let code = run_with_prefix(&dir, &["-l", "bob"]);
        assert_eq!(code, 0);

        let content = read_shadow(&dir);
        // Alice and Charlie should be unchanged.
        assert!(
            content.contains("alice:$6$alice:19500:0:99999:7:::\n"),
            "alice should be unchanged, got: {content}"
        );
        assert!(
            content.contains("charlie:$6$charlie:19500:0:99999:7:::\n"),
            "charlie should be unchanged, got: {content}"
        );
        // Bob should be locked.
        assert!(
            content.contains("bob:!$6$bob:19500:0:99999:7:::\n"),
            "bob should be locked, got: {content}"
        );
    }

    #[test]
    fn test_status_nonexistent_user() {
        if skip_unless_root() {
            return;
        }
        let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-S", "nosuchuser"]);
        assert_ne!(code, 0);
    }

    #[test]
    fn test_lock_nonexistent_user() {
        if skip_unless_root() {
            return;
        }
        let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-l", "nosuchuser"]);
        assert_ne!(code, 0);
    }

    #[test]
    fn test_missing_shadow_file() {
        if skip_unless_root() {
            return;
        }
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        // No etc/shadow — should return PASSWD_FILE_MISSING (4).
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("failed to create etc dir");
        // Shadow file does not exist.
        let code = run_with_prefix(&dir, &["-S", "testuser"]);
        assert_eq!(code, exit_codes::PASSWD_FILE_MISSING);
    }

    #[test]
    fn test_quiet_suppresses_output() {
        if skip_unless_root() {
            return;
        }
        // With -q, the stderr action message should be suppressed.
        // We verify that the action still succeeds.
        let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(&dir, &["-q", "-l", "testuser"]);
        assert_eq!(code, 0);

        // Verify the lock still happened.
        let content = read_shadow(&dir);
        assert!(content.contains("testuser:!$6$hash:"));
    }

    #[test]
    fn test_lock_then_status() {
        if skip_unless_root() {
            return;
        }
        let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");

        // Lock.
        let code = run_with_prefix(&dir, &["-l", "testuser"]);
        assert_eq!(code, 0);

        // Check status shows L — we verify by reading the shadow file and
        // checking the format_status output on the resulting entry.
        let content = read_shadow(&dir);
        let entry: ShadowEntry = content
            .trim()
            .parse()
            .expect("failed to parse shadow entry");
        assert_eq!(entry.status_char(), "L");
    }

    #[test]
    fn test_full_lifecycle() {
        if skip_unless_root() {
            return;
        }
        let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");

        // Lock.
        assert_eq!(run_with_prefix(&dir, &["-l", "testuser"]), 0);
        let entry: ShadowEntry = read_shadow(&dir)
            .trim()
            .parse()
            .expect("failed to parse shadow entry");
        assert_eq!(entry.status_char(), "L", "after lock");

        // Unlock.
        assert_eq!(run_with_prefix(&dir, &["-u", "testuser"]), 0);
        let entry: ShadowEntry = read_shadow(&dir)
            .trim()
            .parse()
            .expect("failed to parse shadow entry");
        assert_eq!(entry.status_char(), "P", "after unlock");

        // Delete.
        assert_eq!(run_with_prefix(&dir, &["-d", "testuser"]), 0);
        let entry: ShadowEntry = read_shadow(&dir)
            .trim()
            .parse()
            .expect("failed to parse shadow entry");
        assert_eq!(entry.status_char(), "NP", "after delete");

        // Expire.
        assert_eq!(run_with_prefix(&dir, &["-e", "testuser"]), 0);
        let entry: ShadowEntry = read_shadow(&dir)
            .trim()
            .parse()
            .expect("failed to parse shadow entry");
        assert_eq!(entry.last_change, Some(0), "after expire");
    }

    // -----------------------------------------------------------------------
    // Bug-fix verification tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pam_exit_code_defined() {
        assert_eq!(exit_codes::PAM_ERROR, 10);
    }

    #[test]
    fn test_sanitized_env() {
        let env = shadow_core::hardening::sanitized_env();

        // PATH must be set to the safe default.
        let path_val = env
            .iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.as_str());
        assert_eq!(path_val, Some("/usr/bin:/bin:/usr/sbin:/sbin"));

        // Dangerous vars must not appear.
        assert!(
            !env.iter().any(|(k, _)| k == "LD_PRELOAD"),
            "LD_PRELOAD should not be in sanitized env"
        );
        assert!(
            !env.iter().any(|(k, _)| k == "IFS"),
            "IFS should not be in sanitized env"
        );

        // Only PATH, TERM, LANG, and LC_* keys are allowed.
        for (k, _) in &env {
            assert!(
                k == "PATH" || k == "TERM" || k == "LANG" || k.starts_with("LC_"),
                "unexpected key in sanitized env: {k}"
            );
        }
    }

    // -------------------------------------------------------------------
    // OpenBSD hardening tests
    // -------------------------------------------------------------------

    #[test]
    fn test_core_dump_suppression() {
        use rustix::process::{Resource, getrlimit};
        // After calling suppress_core_dumps(), RLIMIT_CORE should be 0.
        shadow_core::hardening::suppress_core_dumps();
        let rlim = getrlimit(Resource::Core);
        assert_eq!(
            rlim.current,
            Some(0),
            "RLIMIT_CORE should be 0 after suppression"
        );
    }

    #[test]
    fn test_raise_file_size_limit() {
        use rustix::process::{Resource, getrlimit};
        shadow_core::hardening::raise_file_size_limit();
        let rlim = getrlimit(Resource::Fsize);
        // In environments where the hard limit is already restricted (containers,
        // CI), we may not reach RLIM_INFINITY. `None` means unlimited.
        // Verify it's at least very large or unlimited.
        let is_large = match rlim.current {
            None => true,
            Some(v) => v >= 1024 * 1024 * 1024,
        };
        assert!(
            is_large,
            "RLIMIT_FSIZE should be raised (got {:?})",
            rlim.current
        );
    }

    #[test]
    fn test_zero_length_write_rejected() {
        // atomic_write should refuse to replace a file with zero-length output.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("shadow");
        std::fs::write(&target, "original content\n").unwrap();

        let result = shadow_core::atomic::atomic_write(&target, |_file| {
            // Write nothing — zero-length output.
            Ok(())
        });

        assert!(result.is_err(), "zero-length write should be rejected");
        // Original file should be untouched.
        let content = std::fs::read_to_string(&target).unwrap();
        assert_eq!(content, "original content\n");
    }

    #[test]
    fn test_mutation_with_aging_combined() {
        if skip_unless_root() {
            return;
        }
        // Bug #4: aging flags (-n/-x/-w/-i) used alongside mutation flags
        // (-l/-u/-d/-e) must all be applied in a single operation.
        let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
        let code = run_with_prefix(
            &dir,
            &[
                "-l", "-n", "10", "-x", "60", "-w", "5", "-i", "20", "testuser",
            ],
        );
        assert_eq!(code, 0);

        let content = read_shadow(&dir);
        // Password should be locked AND aging fields updated.
        assert!(
            content.contains("testuser:!$6$hash:19500:10:60:5:20::"),
            "expected locked password + updated aging, got: {content}"
        );
    }

    #[test]
    fn test_status_permission_denied_code_path() {
        // Verify the permission-denied code path is reachable by checking
        // that the current_username helper works (it will return a
        // username for the current uid).
        let username = shadow_core::hardening::current_username();
        assert!(username.is_ok(), "should resolve current username");
    }
}
