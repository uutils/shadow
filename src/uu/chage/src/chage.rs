// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chage lstchg warndays maxdays mindays expiredate lastday chroot sigprocmask

//! `chage` — change user password aging information.
//!
//! Drop-in replacement for GNU shadow-utils `chage(1)`.

use std::fmt;
use std::io::Write;
use std::path::Path;

use clap::{Arg, ArgAction, Command};

use shadow_core::date;
use shadow_core::lock::FileLock;
use shadow_core::shadow::{self, ShadowEntry};
use shadow_core::sysroot::SysRoot;
use shadow_core::{atomic, nscd};

use uucore::error::{UError, UResult};

mod options {
    pub const LOGIN: &str = "login";
    pub const LASTDAY: &str = "lastday";
    pub const EXPIREDATE: &str = "expiredate";
    pub const INACTIVE: &str = "inactive";
    pub const LIST: &str = "list";
    pub const MINDAYS: &str = "mindays";
    pub const MAXDAYS: &str = "maxdays";
    pub const ROOT: &str = "root";
    pub const WARNDAYS: &str = "warndays";
    pub const PREFIX: &str = "prefix";
}

/// Exit code constants for `chage(1)`.
///
/// Kept as documentation and for use in tests. The canonical mapping lives in
/// [`ChageError::code`].
#[cfg(test)]
mod exit_codes {
    pub const SUCCESS: i32 = 0;
    pub const PERMISSION_DENIED: i32 = 1;
    pub const INVALID_SYNTAX: i32 = 2;
    pub const SHADOW_NOT_FOUND: i32 = 15;
    pub const USER_NOT_FOUND: i32 = 1;
}

// ---------------------------------------------------------------------------
// Error type — implements uucore::error::UError
// ---------------------------------------------------------------------------

/// Errors that the `chage` utility can produce.
///
/// Each variant maps to a specific exit code matching GNU `chage(1)`:
///   1 = permission denied, 2 = invalid syntax, 3 = unexpected failure,
///   5 = file busy (lock), 15 = can't find shadow entry.
#[derive(Debug)]
enum ChageError {
    /// Exit 1 — insufficient privileges.
    PermissionDenied(String),
    /// Exit 3 — an unexpected runtime failure.
    UnexpectedFailure(String),
    /// Exit 5 — could not acquire the shadow lock file.
    FileBusy(String),
    /// Exit 15 — the shadow file itself could not be read.
    ShadowNotFound(String),
    /// Exit 1 — the account does not exist.
    ///
    /// chage(1) reserves 15 for "can't find the shadow password file"; a
    /// missing *account* is an ordinary failure, and GNU exits 1 for it.
    UserNotFound(String),
    /// Exit 2 — a numeric option was given a value outside its range.
    InvalidArgument(String),
}

impl fmt::Display for ChageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg)
            | Self::UnexpectedFailure(msg)
            | Self::FileBusy(msg)
            | Self::ShadowNotFound(msg)
            | Self::UserNotFound(msg)
            | Self::InvalidArgument(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ChageError {}

impl UError for ChageError {
    fn code(&self) -> i32 {
        match self {
            // A missing account is an ordinary failure, and shares the general
            // failure code with a refused one; chage(1) reserves 15 for the
            // shadow *file*.
            Self::PermissionDenied(_) | Self::UserNotFound(_) => 1,
            Self::UnexpectedFailure(_) => 3,
            Self::FileBusy(_) => 5,
            Self::ShadowNotFound(_) => 15,
            Self::InvalidArgument(_) => 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Date parsing
// ---------------------------------------------------------------------------

/// Parse a date argument: `YYYY-MM-DD`, days since the epoch, or `-1`.
///
/// `-1` reaches the caller as `-1` rather than `None`, because chage(1) uses
/// it to clear the field and the caller has to tell "clear it" from "leave it
/// alone" -- an absent option.
fn parse_date_arg(input: &str) -> Result<i64, String> {
    if input == "-1" {
        return Ok(-1);
    }
    match date::parse_expire_date(input) {
        Ok(Some(days)) => Ok(days),
        // An empty argument is not a date; only `-1` clears a field.
        Ok(None) => Err(format!("invalid date '{input}'")),
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the `chage` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 2)? else {
        return Ok(());
    };

    // Handle --root / -R: chroot before anything else.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        do_chroot(chroot_dir)?;
    }

    // --prefix points a setuid binary at files of the caller's choosing, so
    // like --root it is root-only.
    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    if prefix.is_some() && !shadow_core::hardening::caller_is_root() {
        return Err(ChageError::PermissionDenied("only root may use --prefix".into()).into());
    }
    let root = SysRoot::new(prefix);

    // The LOGIN argument is required by clap.
    let login = matches
        .get_one::<String>(options::LOGIN)
        .ok_or(shadow_core::cli::AlreadyPrinted(2))?;

    let is_list = matches.get_flag(options::LIST);

    // Collect modification flags.
    let lastday = matches.get_one::<String>(options::LASTDAY);
    let expiredate = matches.get_one::<String>(options::EXPIREDATE);
    let inactive = matches.get_one::<i64>(options::INACTIVE);
    let mindays = matches.get_one::<i64>(options::MINDAYS);
    let maxdays = matches.get_one::<i64>(options::MAXDAYS);
    let warndays = matches.get_one::<i64>(options::WARNDAYS);

    let has_modifications = lastday.is_some()
        || expiredate.is_some()
        || inactive.is_some()
        || mindays.is_some()
        || maxdays.is_some()
        || warndays.is_some();

    if is_list {
        // -l mode: non-root can view own aging info.
        if !shadow_core::hardening::caller_is_root() {
            let current_user = shadow_core::hardening::current_username()
                .map_err(|e| ChageError::UnexpectedFailure(e.to_string()))?;
            if current_user != *login {
                return Err(ChageError::PermissionDenied(
                    shadow_core::os_error::permission_denied(),
                )
                .into());
            }
        }
        return cmd_list(&root, login);
    }

    // All modification flags require root.
    if !shadow_core::hardening::caller_is_root() {
        return Err(
            ChageError::PermissionDenied(shadow_core::os_error::permission_denied()).into(),
        );
    }

    if !has_modifications {
        // GNU chage enters interactive mode when no flags are given.
        return Err(ChageError::UnexpectedFailure(
            "no aging fields specified (interactive mode not yet supported)".into(),
        )
        .into());
    }

    // The aging fields count days: only -1, meaning "unset", may be negative.
    // A value such as -5 was accepted and written, and every later reader then
    // saw a nonsensical policy.
    for (value, flag) in [
        (inactive, "--inactive"),
        (mindays, "--mindays"),
        (maxdays, "--maxdays"),
        (warndays, "--warndays"),
    ] {
        if let Some(&days) = value
            && days < -1
        {
            return Err(ChageError::InvalidArgument(format!(
                "invalid value '{days}' for {flag}: expected -1 or a day count"
            ))
            .into());
        }
    }

    // Parse date-valued arguments before acquiring locks.
    let lastday_val = match lastday {
        Some(s) => Some(parse_date_arg(s).map_err(ChageError::InvalidArgument)?),
        None => None,
    };
    let expiredate_val = match expiredate {
        Some(s) => Some(parse_date_arg(s).map_err(ChageError::InvalidArgument)?),
        None => None,
    };

    mutate_shadow(&root, login, |entry| {
        if let Some(v) = lastday_val {
            entry.last_change = if v == -1 { None } else { Some(v) };
        }
        if let Some(v) = expiredate_val {
            entry.expire_date = if v == -1 { None } else { Some(v) };
        }
        if let Some(&v) = inactive {
            entry.inactive_days = if v == -1 { None } else { Some(v) };
        }
        if let Some(&v) = mindays {
            entry.min_age = if v == -1 { None } else { Some(v) };
        }
        if let Some(&v) = maxdays {
            entry.max_age = if v == -1 { None } else { Some(v) };
        }
        if let Some(&v) = warndays {
            entry.warn_days = if v == -1 { None } else { Some(v) };
        }
        Ok(())
    })
}

/// Build the clap `Command` for `chage`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("chage")
        .about("Manage password aging fields for a user")
        .override_usage("chage [options] LOGIN")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::LASTDAY)
                .short('d')
                .long("lastday")
                .help("record LAST_DAY as the date of the last password change")
                .value_name("LAST_DAY")
                .allow_hyphen_values(true),
        )
        .arg(
            Arg::new(options::EXPIREDATE)
                .short('E')
                .long("expiredate")
                .help("expire the account on EXPIRE_DATE")
                .value_name("EXPIRE_DATE")
                .allow_hyphen_values(true),
        )
        .arg(
            Arg::new(options::INACTIVE)
                .short('I')
                .long("inactive")
                .help("disable the password INACTIVE days past its expiry")
                .value_name("INACTIVE")
                .allow_hyphen_values(true)
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new(options::LIST)
                .short('l')
                .long("list")
                .help("print the user's aging fields and exit")
                .conflicts_with_all([
                    options::LASTDAY,
                    options::EXPIREDATE,
                    options::INACTIVE,
                    options::MINDAYS,
                    options::MAXDAYS,
                    options::WARNDAYS,
                ])
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::MINDAYS)
                .short('m')
                .long("mindays")
                .help("require at least MIN_DAYS between password changes")
                .value_name("MIN_DAYS")
                .allow_hyphen_values(true)
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new(options::MAXDAYS)
                .short('M')
                .long("maxdays")
                .help("require a password change at least every MAX_DAYS")
                .value_name("MAX_DAYS")
                .allow_hyphen_values(true)
                .value_parser(clap::value_parser!(i64)),
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
            Arg::new(options::WARNDAYS)
                .short('W')
                .long("warndays")
                .help("warn the user WARN_DAYS before expiry")
                .value_name("WARN_DAYS")
                .allow_hyphen_values(true)
                .value_parser(clap::value_parser!(i64)),
        )
        .arg(
            Arg::new(options::LOGIN)
                .help("user login name")
                .required(true)
                .index(1),
        )
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

/// `chage -l LOGIN` — display aging information.
fn cmd_list(root: &SysRoot, login: &str) -> UResult<()> {
    let shadow_path = root.shadow_path();
    let entries = shadow::read_shadow_file(&shadow_path).map_err(|e| {
        ChageError::ShadowNotFound(format!("Cannot open {}: {e}", shadow_path.display()))
    })?;

    let entry = entries
        .iter()
        .find(|e| e.name == login)
        .ok_or_else(|| ChageError::UserNotFound(format!("user '{login}' does not exist")))?;

    print_aging_info(entry);
    Ok(())
}

/// A `max_age` at or above this many days disables expiry.
///
/// chage(1) prints `never` for the two password lines at this value and a real
/// date one day below it, verified against GNU shadow 4.17: `-M 9999` shows a
/// date, `-M 10000` shows `never`.
const MAX_AGE_NEVER: i64 = 10_000;

/// Print the aging information to stdout in the GNU `chage -l` format.
fn print_aging_info(entry: &ShadowEntry) {
    let mut out = std::io::stdout().lock();
    write_aging_info(entry, &mut out);
}

/// Render the aging information, so the exact output can be asserted on.
fn write_aging_info<W: Write>(entry: &ShadowEntry, out: &mut W) {
    // A last-change day of 0 is the "expired, must change at next login" marker
    // that `passwd -e` writes. It is not a date, and it makes the two derived
    // dates meaningless too, so all three lines say so.
    let must_change = entry.last_change == Some(0);

    let never = || "never".to_string();
    let last_change = if must_change {
        MUST_CHANGE.to_string()
    } else {
        entry
            .last_change
            .and_then(date::format_human)
            .unwrap_or_else(never)
    };
    let password_expires = if must_change {
        MUST_CHANGE.to_string()
    } else {
        expiry_display(entry.last_change, entry.max_age)
    };
    let password_inactive = if must_change {
        MUST_CHANGE.to_string()
    } else {
        inactive_display(entry.last_change, entry.max_age, entry.inactive_days)
    };
    let account_expires = entry
        .expire_date
        .filter(|d| *d >= 0)
        .and_then(date::format_human)
        .unwrap_or_else(never);

    let field = |v: Option<i64>| v.map_or_else(|| "-1".to_string(), |v| v.to_string());
    let min_days = field(entry.min_age);
    let max_days = field(entry.max_age);
    let warn_days = field(entry.warn_days);

    let _ = writeln!(out, "Last password change\t\t\t\t\t: {last_change}");
    let _ = writeln!(out, "Password expires\t\t\t\t\t: {password_expires}");
    let _ = writeln!(out, "Password inactive\t\t\t\t\t: {password_inactive}");
    let _ = writeln!(out, "Account expires\t\t\t\t\t\t: {account_expires}");
    let _ = writeln!(
        out,
        "Minimum number of days between password change\t\t: {min_days}"
    );
    let _ = writeln!(
        out,
        "Maximum number of days between password change\t\t: {max_days}"
    );
    let _ = writeln!(
        out,
        "Number of days of warning before password expires\t: {warn_days}"
    );
}

/// What `chage -l` prints in place of a date for an expired password.
const MUST_CHANGE: &str = "password must be changed";

/// The date the password expires, or `never`.
fn expiry_display(last_change: Option<i64>, max_age: Option<i64>) -> String {
    match (last_change, max_age) {
        (Some(lc), Some(max)) if (0..MAX_AGE_NEVER).contains(&max) => {
            date::format_human_sum(&[lc, max])
        }
        _ => None,
    }
    .unwrap_or_else(|| "never".to_string())
}

/// The date the account goes inactive, or `never`.
fn inactive_display(
    last_change: Option<i64>,
    max_age: Option<i64>,
    inactive_days: Option<i64>,
) -> String {
    match (last_change, max_age, inactive_days) {
        (Some(lc), Some(max), Some(inactive))
            if (0..MAX_AGE_NEVER).contains(&max) && inactive >= 0 =>
        {
            date::format_human_sum(&[lc, max, inactive])
        }
        _ => None,
    }
    .unwrap_or_else(|| "never".to_string())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Perform `chroot(2)` into the specified directory.
///
/// Must be root to call `chroot`. After `chroot`, chdir to `/` so the
/// working directory is valid inside the new root.
fn do_chroot(dir: &str) -> Result<(), ChageError> {
    if !shadow_core::hardening::caller_is_root() {
        return Err(ChageError::PermissionDenied(
            "only root may use --root".into(),
        ));
    }

    let path = Path::new(dir);
    rustix::process::chroot(path)
        .map_err(|e| ChageError::UnexpectedFailure(format!("cannot chroot to '{dir}': {e}")))?;

    rustix::process::chdir("/").map_err(|e| {
        ChageError::UnexpectedFailure(format!("cannot chdir to / after chroot: {e}"))
    })?;

    Ok(())
}

/// Lock the shadow file, read entries, apply a mutation to one user's entry,
/// write back atomically, invalidate nscd cache.
fn mutate_shadow<F>(root: &SysRoot, username: &str, mutate: F) -> UResult<()>
where
    F: FnOnce(&mut ShadowEntry) -> Result<(), String>,
{
    // Consolidate real + effective UID to root for file operations.
    // Some filesystem configurations check real UID.
    if rustix::process::geteuid().is_root() {
        let _ = shadow_core::process::setuid(0);
    }

    // Block signals for the entire critical section (lock -> write -> unlock).
    let _signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| ChageError::UnexpectedFailure(e.to_string()))?;

    let shadow_path = root.shadow_path();

    // Acquire lock.
    let lock = FileLock::acquire(&shadow_path).map_err(|_| {
        ChageError::FileBusy(format!(
            "cannot lock {}: try again later",
            shadow_path.display()
        ))
    })?;

    // Read current entries.
    let (mut entries, layout) = match shadow::read_shadow_with_layout(&shadow_path) {
        Ok(e) => e,
        Err(e) => {
            drop(lock);
            return Err(ChageError::ShadowNotFound(format!(
                "Cannot open {}: {e}",
                shadow_path.display()
            ))
            .into());
        }
    };

    // Find the target user.
    let Some(entry) = entries.iter_mut().find(|e| e.name == username) else {
        drop(lock);
        return Err(ChageError::UserNotFound(format!(
            "user '{username}' does not exist in {}",
            shadow_path.display()
        ))
        .into());
    };

    // Apply the mutation.
    if let Err(msg) = mutate(entry) {
        drop(lock);
        return Err(ChageError::UnexpectedFailure(msg).into());
    }

    // Write back atomically.
    let write_result = atomic::atomic_write(&shadow_path, |file| {
        shadow::write_shadow_with_layout(&entries, &layout, file)?;
        Ok(())
    });

    if let Err(e) = write_result {
        drop(lock);
        return Err(ChageError::UnexpectedFailure(format!(
            "failed to write {}: {e}",
            shadow_path.display()
        ))
        .into());
    }

    // Release lock and invalidate caches.
    drop(lock);
    nscd::invalidate_cache("shadow");

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    #[test]
    fn test_list_flag_accepted() {
        let m = uu_app()
            .try_get_matches_from(["chage", "-l", "testuser"])
            .expect("should parse -l flag");
        assert!(m.get_flag(options::LIST));
        assert_eq!(
            m.get_one::<String>(options::LOGIN).map(String::as_str),
            Some("testuser")
        );
    }

    #[test]
    fn test_list_conflicts_with_modification_flags() {
        // -l cannot be combined with -m
        let result = uu_app().try_get_matches_from(["chage", "-l", "-m", "5", "testuser"]);
        assert!(result.is_err());

        // -l cannot be combined with -M
        let result = uu_app().try_get_matches_from(["chage", "-l", "-M", "90", "testuser"]);
        assert!(result.is_err());

        // -l cannot be combined with -d
        let result = uu_app().try_get_matches_from(["chage", "-l", "-d", "0", "testuser"]);
        assert!(result.is_err());

        // -l cannot be combined with -E
        let result = uu_app().try_get_matches_from(["chage", "-l", "-E", "2027-01-01", "testuser"]);
        assert!(result.is_err());

        // -l cannot be combined with -I
        let result = uu_app().try_get_matches_from(["chage", "-l", "-I", "30", "testuser"]);
        assert!(result.is_err());

        // -l cannot be combined with -W
        let result = uu_app().try_get_matches_from(["chage", "-l", "-W", "7", "testuser"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_login_required() {
        let result = uu_app().try_get_matches_from(["chage", "-l"]);
        assert!(result.is_err(), "LOGIN argument should be required");
    }

    #[test]
    fn test_all_flags_parse() {
        let m = uu_app()
            .try_get_matches_from([
                "chage",
                "-d",
                "2026-01-15",
                "-E",
                "2027-12-31",
                "-I",
                "30",
                "-m",
                "7",
                "-M",
                "90",
                "-W",
                "14",
                "testuser",
            ])
            .expect("should parse all flags");

        assert_eq!(
            m.get_one::<String>(options::LASTDAY).map(String::as_str),
            Some("2026-01-15")
        );
        assert_eq!(
            m.get_one::<String>(options::EXPIREDATE).map(String::as_str),
            Some("2027-12-31")
        );
        assert_eq!(m.get_one::<i64>(options::INACTIVE).copied(), Some(30));
        assert_eq!(m.get_one::<i64>(options::MINDAYS).copied(), Some(7));
        assert_eq!(m.get_one::<i64>(options::MAXDAYS).copied(), Some(90));
        assert_eq!(m.get_one::<i64>(options::WARNDAYS).copied(), Some(14));
        assert_eq!(
            m.get_one::<String>(options::LOGIN).map(String::as_str),
            Some("testuser")
        );
    }

    #[test]
    fn test_root_flag_parse() {
        let m = uu_app()
            .try_get_matches_from(["chage", "-R", "/mnt/chroot", "-l", "testuser"])
            .expect("should parse -R flag");

        assert_eq!(
            m.get_one::<String>(options::ROOT).map(String::as_str),
            Some("/mnt/chroot")
        );
    }

    #[test]
    fn test_negative_one_inactive() {
        let m = uu_app()
            .try_get_matches_from(["chage", "-I", "-1", "testuser"])
            .expect("should parse -I -1");

        assert_eq!(m.get_one::<i64>(options::INACTIVE).copied(), Some(-1));
    }

    // -----------------------------------------------------------------------
    // Date parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_date_arg_integer() {
        assert_eq!(
            parse_date_arg("19500").expect("should parse integer"),
            19500
        );
    }

    #[test]
    fn test_parse_date_arg_negative() {
        assert_eq!(parse_date_arg("-1").expect("should parse -1"), -1);
    }

    #[test]
    fn test_parse_date_arg_zero() {
        assert_eq!(parse_date_arg("0").expect("should parse 0"), 0);
    }

    #[test]
    fn test_parse_date_arg_yyyy_mm_dd() {
        let days = parse_date_arg("2000-01-01").expect("should parse YYYY-MM-DD");
        // 2000-01-01 is about 10957 days since 1970-01-01.
        assert!(days > 10900 && days < 11000, "expected ~10957, got {days}");
    }

    #[test]
    fn test_parse_date_arg_invalid_format() {
        assert!(parse_date_arg("not-a-date").is_err());
    }

    #[test]
    fn test_parse_date_arg_invalid_month() {
        assert!(parse_date_arg("2026-13-01").is_err());
    }

    #[test]
    fn test_parse_date_arg_invalid_day() {
        assert!(parse_date_arg("2026-01-32").is_err());
    }

    #[test]
    fn test_parse_date_arg_month_zero() {
        assert!(parse_date_arg("2026-00-15").is_err());
    }

    #[test]
    fn test_parse_date_arg_day_zero() {
        assert!(parse_date_arg("2026-06-00").is_err());
    }

    // -----------------------------------------------------------------------
    // `chage -l` output
    //
    // The expected text is GNU shadow 4.17's, captured from the Debian image:
    // the label columns, the "password must be changed" wording and the
    // `never` threshold all have to match for scripts that parse this.
    // -----------------------------------------------------------------------

    fn aging_lines(entry: &ShadowEntry) -> Vec<String> {
        let mut out = Vec::new();
        write_aging_info(entry, &mut out);
        String::from_utf8(out)
            .expect("utf-8")
            .lines()
            .map(|l| {
                let (label, value) = l.rsplit_once(": ").unwrap_or((l, ""));
                format!("{}|{value}", label.trim_end_matches(['\t', ' ']))
            })
            .collect()
    }

    fn entry_with(last_change: Option<i64>, max_age: Option<i64>) -> ShadowEntry {
        ShadowEntry {
            name: "u".into(),
            passwd: "$6$hash".into(),
            last_change,
            min_age: Some(0),
            max_age,
            warn_days: Some(7),
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        }
    }

    #[test]
    fn test_aging_output_has_the_gnu_labels_and_order() {
        let lines = aging_lines(&entry_with(Some(20454), Some(99999)));
        let labels: Vec<&str> = lines
            .iter()
            .map(|l| l.split('|').next().unwrap_or(""))
            .collect();
        assert_eq!(
            labels,
            [
                "Last password change",
                "Password expires",
                "Password inactive",
                "Account expires",
                "Minimum number of days between password change",
                "Maximum number of days between password change",
                "Number of days of warning before password expires",
            ]
        );
    }

    /// A last-change day of 0 is `passwd -e`'s "must change at next login"
    /// marker, not a date, and it makes both derived dates meaningless too.
    #[test]
    fn test_last_change_zero_reports_must_be_changed_on_three_lines() {
        let mut entry = entry_with(Some(0), Some(90));
        entry.inactive_days = Some(30);
        entry.expire_date = Some(0);
        let lines = aging_lines(&entry);
        assert_eq!(lines[0], "Last password change|password must be changed");
        assert_eq!(lines[1], "Password expires|password must be changed");
        assert_eq!(lines[2], "Password inactive|password must be changed");
        // The account expiry is a separate field and keeps its own date.
        assert_eq!(lines[3], "Account expires|Jan 01, 1970");
    }

    /// GNU shows a date at `-M 9999` and `never` at `-M 10000`.
    #[test]
    fn test_max_age_never_threshold_is_10000() {
        let base = shadow_core::date::days_from_civil(2026, 1, 1);
        let lines = aging_lines(&entry_with(Some(base), Some(9999)));
        assert_eq!(lines[1], "Password expires|May 18, 2053");
        let lines = aging_lines(&entry_with(Some(base), Some(10000)));
        assert_eq!(lines[1], "Password expires|never");
        let lines = aging_lines(&entry_with(Some(base), Some(99999)));
        assert_eq!(lines[1], "Password expires|never");
    }

    #[test]
    fn test_inactive_date_is_the_sum_of_three_fields() {
        let base = shadow_core::date::days_from_civil(2026, 1, 1);
        let mut entry = entry_with(Some(base), Some(90));
        entry.inactive_days = Some(30);
        let lines = aging_lines(&entry);
        assert_eq!(lines[1], "Password expires|Apr 01, 2026");
        assert_eq!(lines[2], "Password inactive|May 01, 2026");
    }

    #[test]
    fn test_unset_fields_report_never_and_minus_one() {
        let lines = aging_lines(&ShadowEntry {
            name: "u".into(),
            passwd: "*".into(),
            last_change: None,
            min_age: None,
            max_age: None,
            warn_days: None,
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        });
        assert_eq!(lines[0], "Last password change|never");
        assert_eq!(lines[1], "Password expires|never");
        assert_eq!(lines[2], "Password inactive|never");
        assert_eq!(lines[3], "Account expires|never");
        assert_eq!(
            lines[4],
            "Minimum number of days between password change|-1"
        );
        assert_eq!(
            lines[5],
            "Maximum number of days between password change|-1"
        );
        assert_eq!(
            lines[6],
            "Number of days of warning before password expires|-1"
        );
    }

    /// Anyone who can write /etc/shadow can put a value in it that overflows
    /// the `lastchg + max + inactive` sums. That must show as `never`, not
    /// wrap into a plausible-looking date or panic in a debug build.
    #[test]
    fn test_absurd_field_values_report_never() {
        let mut entry = entry_with(Some(i64::MAX), Some(90));
        entry.inactive_days = Some(i64::MAX);
        let lines = aging_lines(&entry);
        assert_eq!(lines[0], "Last password change|never");
        assert_eq!(lines[1], "Password expires|never");
        assert_eq!(lines[2], "Password inactive|never");
    }

    // -----------------------------------------------------------------------
    // Error code tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_error_codes() {
        use uucore::error::UError;

        assert_eq!(
            ChageError::PermissionDenied("test".into()).code(),
            exit_codes::PERMISSION_DENIED
        );
        assert_eq!(ChageError::UnexpectedFailure("test".into()).code(), 3);
        assert_eq!(ChageError::FileBusy("test".into()).code(), 5);
        assert_eq!(
            ChageError::ShadowNotFound("test".into()).code(),
            exit_codes::SHADOW_NOT_FOUND
        );
        // A missing account is not a missing shadow file: chage(1) reserves 15
        // for the file, and GNU exits 1 for an unknown login.
        assert_eq!(
            ChageError::UserNotFound("test".into()).code(),
            exit_codes::USER_NOT_FOUND
        );
        assert_eq!(
            shadow_core::cli::AlreadyPrinted(exit_codes::INVALID_SYNTAX).code(),
            exit_codes::INVALID_SYNTAX
        );
    }

    #[test]
    fn test_error_display() {
        let err = ChageError::PermissionDenied("denied".into());
        assert_eq!(format!("{err}"), "denied");

        let err = ChageError::ShadowNotFound("no entry".into());
        assert_eq!(format!("{err}"), "no entry");

        let err = shadow_core::cli::AlreadyPrinted(2);
        assert_eq!(format!("{err}"), "");
    }

    #[test]
    fn test_error_is_std_error() {
        let err = ChageError::UnexpectedFailure("fail".into());
        let _: &dyn std::error::Error = &err;
    }

    // -----------------------------------------------------------------------
    // Exit code constants consistency
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_feb_29_non_leap_year() {
        assert!(
            parse_date_arg("2025-02-29").is_err(),
            "2025 is not a leap year, Feb 29 should be rejected"
        );
    }

    #[test]
    fn test_reject_feb_31() {
        assert!(
            parse_date_arg("2025-02-31").is_err(),
            "February never has 31 days"
        );
    }

    #[test]
    fn test_accept_feb_29_leap_year() {
        assert!(
            parse_date_arg("2024-02-29").is_ok(),
            "2024 is a leap year, Feb 29 should be accepted"
        );
    }

    #[test]
    fn test_reject_apr_31() {
        assert!(
            parse_date_arg("2025-04-31").is_err(),
            "April has 30 days, day 31 should be rejected"
        );
    }

    #[test]
    fn test_accept_jan_31() {
        assert!(
            parse_date_arg("2025-01-31").is_ok(),
            "January has 31 days, should be accepted"
        );
    }

    #[test]
    fn test_exit_code_constants() {
        assert_eq!(exit_codes::SUCCESS, 0);
        assert_eq!(exit_codes::PERMISSION_DENIED, 1);
        assert_eq!(exit_codes::INVALID_SYNTAX, 2);
        assert_eq!(exit_codes::SHADOW_NOT_FOUND, 15);
    }
}
