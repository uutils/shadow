// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chage lstchg warndays maxdays mindays expiredate lastday chroot sigprocmask

//! `chage` — change user password aging information.
//!
//! Drop-in replacement for GNU shadow-utils `chage(1)`.

use std::fmt;
use std::io::Write as _;
use std::path::Path;

use clap::{Arg, ArgAction, Command};

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
    /// Exit 15 — shadow entry not found for user.
    ShadowNotFound(String),
    /// Sentinel used when the error has already been printed (e.g. by clap).
    AlreadyPrinted(i32),
}

impl fmt::Display for ChageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg)
            | Self::UnexpectedFailure(msg)
            | Self::FileBusy(msg)
            | Self::ShadowNotFound(msg) => f.write_str(msg),
            Self::AlreadyPrinted(_) => Ok(()),
        }
    }
}

impl std::error::Error for ChageError {}

impl UError for ChageError {
    fn code(&self) -> i32 {
        match self {
            Self::PermissionDenied(_) => 1,
            Self::UnexpectedFailure(_) => 3,
            Self::FileBusy(_) => 5,
            Self::ShadowNotFound(_) => 15,
            Self::AlreadyPrinted(code) => *code,
        }
    }
}

// ---------------------------------------------------------------------------
// Date parsing
// ---------------------------------------------------------------------------

/// Parse a date argument that can be either days since epoch or YYYY-MM-DD.
///
/// Returns days since epoch. The value `-1` means "remove the field".
fn parse_date_arg(input: &str) -> Result<i64, String> {
    // Try plain integer (days since epoch) first.
    if let Ok(days) = input.parse::<i64>() {
        return Ok(days);
    }

    // Try YYYY-MM-DD format.
    parse_yyyy_mm_dd(input)
}

/// Parse `YYYY-MM-DD` into days since epoch using pure calendar math.
///
/// Uses the Howard Hinnant algorithm to avoid timezone-dependent `mktime`.
fn parse_yyyy_mm_dd(input: &str) -> Result<i64, String> {
    let parts: Vec<&str> = input.split('-').collect();
    if parts.len() != 3 {
        return Err(format!(
            "invalid date '{input}' (expected YYYY-MM-DD or days since epoch)"
        ));
    }

    let year: i64 = parts[0]
        .parse()
        .map_err(|_| format!("invalid year in '{input}'"))?;
    let month: i64 = parts[1]
        .parse()
        .map_err(|_| format!("invalid month in '{input}'"))?;
    let day: i64 = parts[2]
        .parse()
        .map_err(|_| format!("invalid day in '{input}'"))?;

    if !(1..=12).contains(&month) {
        return Err(format!("invalid month {month} in '{input}'"));
    }

    let max_day = days_in_month(year, month);
    if day < 1 || day > max_day {
        return Err(format!(
            "invalid day {day} for {year}-{month:02} in '{input}'"
        ));
    }

    Ok(days_since_epoch(year, month, day))
}

/// Calculate days since Unix epoch (1970-01-01) for a given date.
///
/// Uses the algorithm from <https://howardhinnant.github.io/date_algorithms.html>.
/// Pure arithmetic, no timezone dependency.
fn days_since_epoch(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };

    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Whether `year` is a leap year in the Gregorian calendar.
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Number of days in a given month (1-indexed) for `year`.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        // Month range is already validated before calling this function.
        _ => 0,
    }
}

/// Convert days since epoch back to (year, month, day).
///
/// Inverse of `days_since_epoch`, also from the Hinnant algorithms.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
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
    (y, m, d)
}

/// Convert days since epoch to a human-readable date string (e.g., "Mar 23, 2026").
///
/// Uses pure calendar math instead of `localtime_r` to avoid timezone issues.
fn format_date_human(days: i64) -> String {
    let (year, month, day) = civil_from_days(days);

    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let month_name = usize::try_from(month - 1)
        .ok()
        .and_then(|idx| month_names.get(idx))
        .copied()
        .unwrap_or("???");

    format!("{month_name} {day:02}, {year:04}")
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the `chage` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let _clean_env = shadow_core::hardening::harden_process();

    let matches = match uu_app().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            if !e.use_stderr() {
                return Ok(());
            }
            return Err(ChageError::AlreadyPrinted(2).into());
        }
    };

    // Handle --root / -R: chroot before anything else.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        do_chroot(chroot_dir)?;
    }

    let root = SysRoot::default();

    // The LOGIN argument is required by clap.
    let login = matches
        .get_one::<String>(options::LOGIN)
        .ok_or(ChageError::AlreadyPrinted(2))?;

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
                return Err(ChageError::PermissionDenied("Permission denied.".into()).into());
            }
        }
        return cmd_list(&root, login);
    }

    // All modification flags require root.
    if !shadow_core::hardening::caller_is_root() {
        return Err(ChageError::PermissionDenied("Permission denied.".into()).into());
    }

    if !has_modifications {
        // GNU chage enters interactive mode when no flags are given.
        return Err(ChageError::UnexpectedFailure(
            "no aging fields specified (interactive mode not yet supported)".into(),
        )
        .into());
    }

    // Parse date-valued arguments before acquiring locks.
    let lastday_val = match lastday {
        Some(s) => Some(parse_date_arg(s).map_err(ChageError::UnexpectedFailure)?),
        None => None,
    };
    let expiredate_val = match expiredate {
        Some(s) => Some(parse_date_arg(s).map_err(ChageError::UnexpectedFailure)?),
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
        .ok_or_else(|| ChageError::ShadowNotFound(format!("user '{login}' does not exist")))?;

    print_aging_info(entry);
    Ok(())
}

/// Print the aging information in the GNU `chage -l` format.
fn print_aging_info(entry: &ShadowEntry) {
    let last_change = match entry.last_change {
        Some(0) => "password must be changed".to_string(),
        Some(days) => format_date_human(days),
        None => "never".to_string(),
    };

    let password_expires = compute_expiry_display(entry.last_change, entry.max_age);
    let password_inactive =
        compute_inactive_display(entry.last_change, entry.max_age, entry.inactive_days);
    let account_expires = match entry.expire_date {
        Some(days) if days >= 0 => format_date_human(days),
        _ => "never".to_string(),
    };

    let min_days = entry
        .min_age
        .map_or_else(|| "-1".to_string(), |v| v.to_string());
    let max_days = entry
        .max_age
        .map_or_else(|| "-1".to_string(), |v| v.to_string());
    let warn_days = entry
        .warn_days
        .map_or_else(|| "-1".to_string(), |v| v.to_string());

    let mut out = std::io::stdout().lock();
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

/// Compute the password expiry display string.
fn compute_expiry_display(last_change: Option<i64>, max_age: Option<i64>) -> String {
    match (last_change, max_age) {
        (Some(lc), Some(max)) if (0..99999).contains(&max) => format_date_human(lc + max),
        _ => "never".to_string(),
    }
}

/// Compute the password inactive display string.
fn compute_inactive_display(
    last_change: Option<i64>,
    max_age: Option<i64>,
    inactive_days: Option<i64>,
) -> String {
    match (last_change, max_age, inactive_days) {
        (Some(lc), Some(max), Some(inactive)) if (0..99999).contains(&max) && inactive >= 0 => {
            format_date_human(lc + max + inactive)
        }
        _ => "never".to_string(),
    }
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
    let mut entries = match shadow::read_shadow_file(&shadow_path) {
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
        return Err(ChageError::ShadowNotFound(format!(
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
        shadow::write_shadow(&entries, file)?;
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

    #[test]
    fn test_parse_yyyy_mm_dd_epoch() {
        let days = parse_yyyy_mm_dd("1970-01-01").expect("should parse epoch date");
        assert_eq!(days, 0);
    }

    #[test]
    fn test_parse_yyyy_mm_dd_known_date() {
        // 2000-01-01 should be exactly 10957 days since epoch.
        let days = parse_yyyy_mm_dd("2000-01-01").expect("should parse 2000-01-01");
        assert!(
            (10956..=10958).contains(&days),
            "expected ~10957, got {days}"
        );
    }

    // -----------------------------------------------------------------------
    // Display formatting tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_date_human_epoch() {
        let result = format_date_human(0);
        assert!(
            result.contains("1970"),
            "epoch should show 1970, got: {result}"
        );
        assert!(
            result.contains("Jan"),
            "epoch should show Jan, got: {result}"
        );
    }

    #[test]
    fn test_format_date_human_known_date() {
        // Day 10957 = 2000-01-01
        let result = format_date_human(10957);
        assert!(
            result.contains("2000"),
            "day 10957 should show 2000, got: {result}"
        );
    }

    #[test]
    fn test_compute_expiry_display_never_no_fields() {
        assert_eq!(compute_expiry_display(None, None), "never");
    }

    #[test]
    fn test_compute_expiry_display_never_no_max() {
        assert_eq!(compute_expiry_display(Some(19500), None), "never");
    }

    #[test]
    fn test_compute_expiry_display_never_large_max() {
        assert_eq!(compute_expiry_display(Some(19500), Some(99999)), "never");
    }

    #[test]
    fn test_compute_expiry_display_date() {
        let result = compute_expiry_display(Some(0), Some(90));
        // 0 + 90 = day 90 since epoch.
        assert!(
            result.contains("1970"),
            "should show 1970 date, got: {result}"
        );
    }

    #[test]
    fn test_compute_inactive_display_never() {
        assert_eq!(compute_inactive_display(None, None, None), "never");
        assert_eq!(
            compute_inactive_display(Some(19500), Some(90), None),
            "never"
        );
        assert_eq!(
            compute_inactive_display(Some(19500), None, Some(30)),
            "never"
        );
    }

    #[test]
    fn test_compute_inactive_display_date() {
        let result = compute_inactive_display(Some(0), Some(90), Some(30));
        // 0 + 90 + 30 = day 120 since epoch.
        assert!(
            result.contains("1970"),
            "should show 1970 date, got: {result}"
        );
    }

    // -----------------------------------------------------------------------
    // print_aging_info smoke test
    // -----------------------------------------------------------------------

    #[test]
    fn test_print_aging_info_no_panic() {
        let entry = ShadowEntry {
            name: "testuser".into(),
            passwd: "$6$hash".into(),
            last_change: Some(19500),
            min_age: Some(0),
            max_age: Some(99999),
            warn_days: Some(7),
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        };
        // Verify it doesn't panic.
        print_aging_info(&entry);
    }

    #[test]
    fn test_print_aging_info_expired_password() {
        let entry = ShadowEntry {
            name: "expired".into(),
            passwd: "$6$hash".into(),
            last_change: Some(0),
            min_age: Some(0),
            max_age: Some(90),
            warn_days: Some(7),
            inactive_days: Some(30),
            expire_date: Some(20000),
            reserved: String::new(),
        };
        print_aging_info(&entry);
    }

    #[test]
    fn test_print_aging_info_all_none() {
        let entry = ShadowEntry {
            name: "minimal".into(),
            passwd: "*".into(),
            last_change: None,
            min_age: None,
            max_age: None,
            warn_days: None,
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        };
        print_aging_info(&entry);
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
        assert_eq!(
            ChageError::AlreadyPrinted(exit_codes::INVALID_SYNTAX).code(),
            exit_codes::INVALID_SYNTAX
        );
    }

    #[test]
    fn test_error_display() {
        let err = ChageError::PermissionDenied("denied".into());
        assert_eq!(format!("{err}"), "denied");

        let err = ChageError::ShadowNotFound("no entry".into());
        assert_eq!(format!("{err}"), "no entry");

        let err = ChageError::AlreadyPrinted(2);
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
            parse_yyyy_mm_dd("2025-02-29").is_err(),
            "2025 is not a leap year, Feb 29 should be rejected"
        );
    }

    #[test]
    fn test_reject_feb_31() {
        assert!(
            parse_yyyy_mm_dd("2025-02-31").is_err(),
            "February never has 31 days"
        );
    }

    #[test]
    fn test_accept_feb_29_leap_year() {
        assert!(
            parse_yyyy_mm_dd("2024-02-29").is_ok(),
            "2024 is a leap year, Feb 29 should be accepted"
        );
    }

    #[test]
    fn test_reject_apr_31() {
        assert!(
            parse_yyyy_mm_dd("2025-04-31").is_err(),
            "April has 30 days, day 31 should be rejected"
        );
    }

    #[test]
    fn test_accept_jan_31() {
        assert!(
            parse_yyyy_mm_dd("2025-01-31").is_ok(),
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
