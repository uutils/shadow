// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore pwck nologin gecos lstchg nscd

//! `pwck` -- verify integrity of password files.
//!
//! Drop-in replacement for GNU shadow-utils `pwck(8)`.

use std::collections::HashSet;
use std::fmt;
use std::io::{BufRead, Write as _};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, Command};

use shadow_core::group::{self, GroupEntry};
use shadow_core::lock::FileLock;
use shadow_core::passwd::{self, PasswdEntry};
use shadow_core::shadow::{self, ShadowEntry};
use shadow_core::sysroot::SysRoot;
use shadow_core::{atomic, nscd};

use uucore::error::{UError, UResult};

mod options {
    pub const READ_ONLY: &str = "read-only";
    pub const SORT: &str = "sort";
    pub const QUIET: &str = "quiet";
    pub const ROOT: &str = "root";
    pub const PASSWD_FILE: &str = "passwd_file";
    pub const SHADOW_FILE: &str = "shadow_file";
}

/// Exit code constants for `pwck(8)`.
///
/// Kept as documentation and for use in tests. The canonical mapping lives in
/// [`PwckError::code`].
mod exit_codes {
    /// One or more bad password entries.
    pub const BAD_ENTRY: i32 = 2;
    /// Cannot open files.
    pub const CANT_OPEN: i32 = 3;
    /// Cannot lock files.
    pub const CANT_LOCK: i32 = 4;
    /// Cannot update files.
    pub const CANT_UPDATE: i32 = 5;
    /// Cannot sort files.
    pub const CANT_SORT: i32 = 6;
}

// ---------------------------------------------------------------------------
// Error type -- implements uucore::error::UError
// ---------------------------------------------------------------------------

/// Errors that the `pwck` utility can produce.
///
/// Each variant maps to a specific exit code matching GNU `pwck(8)`.
#[derive(Debug)]
enum PwckError {
    /// Exit 2 -- one or more bad entries found.
    BadEntry(String),
    /// Exit 3 -- cannot open password or shadow file.
    CantOpen(String),
    /// Exit 4 -- cannot lock files.
    CantLock(String),
    /// Exit 5 -- cannot update files.
    CantUpdate(String),
    /// Exit 6 -- cannot sort files (sort logic errors only).
    #[cfg_attr(not(test), allow(dead_code))]
    CantSort(String),
}

impl fmt::Display for PwckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadEntry(msg)
            | Self::CantOpen(msg)
            | Self::CantLock(msg)
            | Self::CantUpdate(msg)
            | Self::CantSort(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for PwckError {}

impl UError for PwckError {
    fn code(&self) -> i32 {
        match self {
            Self::BadEntry(_) => exit_codes::BAD_ENTRY,
            Self::CantOpen(_) => exit_codes::CANT_OPEN,
            Self::CantLock(_) => exit_codes::CANT_LOCK,
            Self::CantUpdate(_) => exit_codes::CANT_UPDATE,
            Self::CantSort(_) => exit_codes::CANT_SORT,
        }
    }
}

// ---------------------------------------------------------------------------
// Parsed options
// ---------------------------------------------------------------------------

struct PwckOptions {
    quiet: bool,
    sort: bool,
    read_only: bool,
    root: SysRoot,
    passwd_path: PathBuf,
    shadow_path: PathBuf,
}

impl PwckOptions {
    fn from_matches(matches: &clap::ArgMatches) -> Self {
        let root = SysRoot::new(matches.get_one::<String>(options::ROOT).map(Path::new));

        let passwd_path = matches
            .get_one::<String>(options::PASSWD_FILE)
            .map_or_else(|| root.passwd_path(), PathBuf::from);
        let shadow_path = matches
            .get_one::<String>(options::SHADOW_FILE)
            .map_or_else(|| root.shadow_path(), PathBuf::from);

        Self {
            quiet: matches.get_flag(options::QUIET),
            sort: matches.get_flag(options::SORT),
            read_only: matches.get_flag(options::READ_ONLY),
            root,
            passwd_path,
            shadow_path,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let _ = shadow_core::hardening::harden_process();

    let matches = uu_app().try_get_matches_from(args)?;
    let opts = PwckOptions::from_matches(&matches);
    run_checks(&opts)
}

/// Core logic, separated from argument parsing to keep `uumain` short.
fn run_checks(opts: &PwckOptions) -> UResult<()> {
    let passwd_lines = read_raw_lines(&opts.passwd_path).map_err(|e| {
        PwckError::CantOpen(format!("cannot open {}: {e}", opts.passwd_path.display()))
    })?;

    // Parse passwd entries, tracking per-line errors.
    let mut passwd_entries = Vec::new();
    let mut errors: u32 = 0;

    for (line_no, raw_line) in passwd_lines.iter().enumerate() {
        let line_num = line_no + 1;
        match raw_line.parse::<PasswdEntry>() {
            Ok(entry) => passwd_entries.push(entry),
            Err(e) => {
                uucore::show_error!("invalid password file entry at line {line_num}: {e}");
                errors += 1;
            }
        }
    }

    let shadow_entries = load_shadow_file(&opts.shadow_path)?;

    // Check shadow file permissions (should be 0600 or 0640).
    if !opts.quiet {
        check_shadow_permissions(&opts.shadow_path);
    }

    let group_entries = load_group_file(&opts.root.group_path(), opts.quiet);

    let shells_path = opts.root.resolve("/etc/shells");
    let valid_shells = read_valid_shells(&shells_path);

    let result = check_passwd_entries(
        &passwd_entries,
        &shadow_entries,
        &group_entries,
        &valid_shells,
        opts.quiet,
        &opts.root,
    );
    errors += result.errors;

    let shadow_result = check_shadow_entries(&shadow_entries, &passwd_entries, opts.quiet);
    errors += shadow_result.errors;

    if opts.sort {
        sort_and_write(
            &opts.passwd_path,
            &opts.shadow_path,
            &passwd_entries,
            &shadow_entries,
            opts.read_only,
        )?;
    } else {
        uucore::show_error!("no changes");
    }

    if errors > 0 {
        // GNU exits 2 silently (no additional message beyond the per-entry output).
        Err(PwckError::BadEntry(String::new()).into())
    } else {
        Ok(())
    }
}

/// Load shadow file, returning empty vec if file does not exist.
fn load_shadow_file(path: &Path) -> UResult<Vec<ShadowEntry>> {
    if path.exists() {
        shadow::read_shadow_file(path)
            .map_err(|e| PwckError::CantOpen(format!("cannot open {}: {e}", path.display())).into())
    } else {
        Ok(Vec::new())
    }
}

/// Load group file for GID validation. Returns empty vec on failure.
fn load_group_file(path: &Path, quiet: bool) -> Vec<GroupEntry> {
    if !path.exists() {
        return Vec::new();
    }
    match group::read_group_file(path) {
        Ok(entries) => entries,
        Err(e) => {
            if !quiet {
                uucore::show_warning!("cannot open {}: {e}", path.display());
            }
            Vec::new()
        }
    }
}

/// Sort passwd entries by UID and write back atomically (for `--sort`).
///
/// When `read_only` is true (i.e. `-r -s`), compute the sorted order but
/// skip all file writes, matching GNU `pwck -r -s` behaviour.
///
/// NOTE: Sorting operates on parsed entries and discards any comments or
/// blank lines from the original file. A lossless (comment-preserving)
/// sort would require a significantly different parser that tracks raw
/// lines alongside parsed entries. This matches GNU `pwck -s` behavior.
fn sort_and_write(
    passwd_path: &Path,
    shadow_path: &Path,
    passwd_entries: &[PasswdEntry],
    shadow_entries: &[ShadowEntry],
    read_only: bool,
) -> UResult<()> {
    let mut sorted_passwd = passwd_entries.to_vec();
    sorted_passwd.sort_by_key(|e| e.uid);

    if sorted_passwd == passwd_entries {
        return Ok(());
    }

    if read_only {
        return Ok(());
    }

    let passwd_lock = FileLock::acquire(passwd_path)
        .map_err(|e| PwckError::CantLock(format!("cannot lock {}: {e}", passwd_path.display())))?;

    atomic::atomic_write(passwd_path, |f| passwd::write_passwd(&sorted_passwd, f)).map_err(
        |e| PwckError::CantUpdate(format!("cannot update {}: {e}", passwd_path.display())),
    )?;

    if shadow_path.exists() && !shadow_entries.is_empty() {
        let shadow_lock = FileLock::acquire(shadow_path).map_err(|e| {
            PwckError::CantLock(format!("cannot lock {}: {e}", shadow_path.display()))
        })?;

        let sorted_shadow = sort_shadow_by_passwd(&sorted_passwd, shadow_entries);

        atomic::atomic_write(shadow_path, |f| shadow::write_shadow(&sorted_shadow, f)).map_err(
            |e| PwckError::CantUpdate(format!("cannot update {}: {e}", shadow_path.display())),
        )?;

        drop(shadow_lock);
    }

    drop(passwd_lock);
    nscd::invalidate_cache("passwd");

    Ok(())
}

#[must_use]
pub fn uu_app() -> Command {
    Command::new(uucore::util_name())
        .version(shadow_core::cli::VERSION)
        .about("Audit /etc/passwd and /etc/shadow for inconsistencies")
        .override_usage("pwck [options] [passwd [shadow]]")
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::READ_ONLY)
                .short('r')
                .long("read-only")
                .help("Audit only; never write the files")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::SORT)
                .short('s')
                .long("sort")
                .help("Reorder entries by ascending UID")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::QUIET)
                .short('q')
                .long("quiet")
                .help("Suppress warnings; print errors only")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .value_name("CHROOT_DIR")
                .help("Chroot into CHROOT_DIR before applying changes")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(options::PASSWD_FILE)
                .index(1)
                .value_name("passwd")
                .help("Path to use instead of /etc/passwd"),
        )
        .arg(
            Arg::new(options::SHADOW_FILE)
                .index(2)
                .value_name("shadow")
                .help("Path to use instead of /etc/shadow"),
        )
}

// ---------------------------------------------------------------------------
// Check results
// ---------------------------------------------------------------------------

struct CheckResult {
    errors: u32,
    #[cfg_attr(not(test), allow(dead_code))]
    warnings: u32,
}

// ---------------------------------------------------------------------------
// Core verification logic
// ---------------------------------------------------------------------------

/// Run all passwd-related integrity checks.
#[allow(clippy::too_many_arguments)]
fn check_passwd_entries(
    passwd_entries: &[PasswdEntry],
    shadow_entries: &[ShadowEntry],
    group_entries: &[GroupEntry],
    valid_shells: &HashSet<PathBuf>,
    quiet: bool,
    root: &SysRoot,
) -> CheckResult {
    let mut errors: u32 = 0;
    let mut warnings: u32 = 0;

    let mut seen_names: HashSet<&str> = HashSet::new();
    let group_gids: HashSet<u32> = group_entries.iter().map(|g| g.gid).collect();
    let shadow_names: HashSet<&str> = shadow_entries.iter().map(|s| s.name.as_str()).collect();
    let mut stderr = std::io::stderr().lock();

    for entry in passwd_entries {
        // Check 2: Unique and valid usernames.
        if entry.name.is_empty() {
            uucore::show_error!("invalid password entry: blank username");
            errors += 1;
        } else if !seen_names.insert(entry.name.as_str()) {
            uucore::show_error!("duplicate password entry for '{}'", entry.name);
            errors += 1;
        } else if !quiet && shadow_core::validate::validate_username(&entry.name).is_err() {
            uucore::show_warning!("user '{}': invalid username", entry.name);
            warnings += 1;
        }

        // Check 4: Primary group exists in /etc/group.
        if !group_entries.is_empty() && !group_gids.contains(&entry.gid) {
            uucore::show_error!("user '{}': no group {}", entry.name, entry.gid);
            errors += 1;
        }

        // Check 4b: UID/GID range validation (advisory warning only).
        if !quiet {
            const MAX_SYSTEM_ID: u32 = 60_000;
            if entry.uid > MAX_SYSTEM_ID {
                uucore::show_warning!(
                    "user '{}': UID {} is outside the normal range (> {})",
                    entry.name,
                    entry.uid,
                    MAX_SYSTEM_ID
                );
                warnings += 1;
            }
            if entry.gid > MAX_SYSTEM_ID {
                uucore::show_warning!(
                    "user '{}': GID {} is outside the normal range (> {})",
                    entry.name,
                    entry.gid,
                    MAX_SYSTEM_ID
                );
                warnings += 1;
            }
        }

        // Check 5: Home directory exists.
        // GNU skips "/nonexistent" (conventional placeholder for system accounts).
        // Output format matches GNU exactly (no "pwck:" prefix).
        if !quiet && !entry.home.is_empty() && entry.home != "/nonexistent" {
            let home_path = if entry.home.starts_with('/') {
                root.resolve(&entry.home)
            } else {
                PathBuf::from(&entry.home)
            };
            if !home_path.exists() {
                let _ = writeln!(
                    stderr,
                    "user '{}': directory '{}' does not exist",
                    entry.name, entry.home
                );
                errors += 1;
            }
        }

        // Check 6: Login shell is valid.
        if !quiet && !entry.shell.is_empty() {
            let shell_path = if entry.shell.starts_with('/') {
                root.resolve(&entry.shell)
            } else {
                PathBuf::from(&entry.shell)
            };
            let is_nologin = entry.shell == "/usr/sbin/nologin"
                || entry.shell == "/sbin/nologin"
                || entry.shell == "/bin/false"
                || entry.shell == "/usr/bin/false";

            if !is_nologin
                && !valid_shells.contains(Path::new(&entry.shell))
                && !shell_path.exists()
            {
                let _ = writeln!(
                    stderr,
                    "user '{}': program '{}' does not exist",
                    entry.name, entry.shell
                );
                errors += 1;
            }
        }

        // Check 9: Password should be 'x' (hash in shadow file).
        if entry.passwd != "x" && entry.passwd != "*" {
            if entry.passwd.is_empty() {
                uucore::show_error!("user '{}': no password entry in shadow file", entry.name);
                errors += 1;
            } else if !quiet {
                uucore::show_warning!("user '{}': password not in shadow file", entry.name);
                warnings += 1;
            }
        }

        // Check 7: Every passwd entry has a matching shadow entry.
        if !shadow_names.is_empty() && !shadow_names.contains(entry.name.as_str()) {
            uucore::show_error!("no matching shadow entry for user '{}'", entry.name);
            errors += 1;
        }
    }

    CheckResult { errors, warnings }
}

/// Run shadow-specific consistency checks.
fn check_shadow_entries(
    shadow_entries: &[ShadowEntry],
    passwd_entries: &[PasswdEntry],
    quiet: bool,
) -> CheckResult {
    let mut errors: u32 = 0;
    let mut warnings: u32 = 0;

    let passwd_names: HashSet<&str> = passwd_entries.iter().map(|p| p.name.as_str()).collect();
    let mut seen_shadow_names: HashSet<&str> = HashSet::new();

    // Days since epoch for "today".
    let today_days = today_as_days();

    for entry in shadow_entries {
        // Check 10: Shadow entries are unique.
        if !seen_shadow_names.insert(entry.name.as_str()) {
            uucore::show_error!("duplicate shadow entry for '{}'", entry.name);
            errors += 1;
        }

        // Check 8: Every shadow entry has a matching passwd entry.
        if !passwd_names.contains(entry.name.as_str()) {
            uucore::show_error!("no matching passwd entry for shadow user '{}'", entry.name);
            errors += 1;
        }

        // Check 11: Shadow last_change is not in the future (warning).
        if !quiet
            && let Some(last_change) = entry.last_change
            && last_change > today_days
        {
            uucore::show_warning!("user '{}': last password change in the future", entry.name);
            warnings += 1;
        }
    }

    CheckResult { errors, warnings }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Warn if `/etc/shadow` has overly permissive file permissions.
///
/// The shadow file should be mode 0600 (root-only) or 0640 (root + shadow group).
/// Any other mode is a security concern.
#[cfg(unix)]
fn check_shadow_permissions(path: &Path) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let mode = meta.permissions().mode() & 0o7777;
    if mode != 0o600 && mode != 0o640 {
        uucore::show_warning!(
            "{}: bad permissions (0{:o}), should be 0600 or 0640",
            path.display(),
            mode
        );
    }
}

#[cfg(not(unix))]
fn check_shadow_permissions(_path: &Path) {
    // File permission checks are only meaningful on Unix.
}

/// Current date as days since the Unix epoch.
fn today_as_days() -> i64 {
    let now = std::time::SystemTime::now();
    let since_epoch = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Seconds-per-day is well within u64 range, so the division result fits i64.
    #[allow(clippy::cast_possible_wrap)]
    let days = (since_epoch.as_secs() / 86400) as i64;
    days
}

/// Read raw (non-blank, non-comment) lines from a file.
///
/// We read raw lines so we can report line numbers for parse errors
/// rather than silently skipping malformed entries.
fn read_raw_lines(path: &Path) -> Result<Vec<String>, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut lines = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        lines.push(line);
    }

    Ok(lines)
}

/// Read valid login shells from `/etc/shells`.
///
/// Returns a set of absolute paths. If the file cannot be read,
/// returns an empty set (all shells will be validated by existence only).
fn read_valid_shells(path: &Path) -> HashSet<PathBuf> {
    let mut shells = HashSet::new();

    let Ok(file) = std::fs::File::open(path) else {
        return shells;
    };

    let reader = std::io::BufReader::new(file);
    for line in reader.lines() {
        let Ok(line) = line else {
            continue;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        shells.insert(PathBuf::from(trimmed));
    }

    shells
}

/// Sort shadow entries to match the order of sorted passwd entries.
///
/// Shadow entries without a matching passwd entry are appended at the end.
/// Uses a position map instead of a `HashMap` to preserve duplicate shadow
/// entries (a `HashMap` would silently drop all but one entry per username).
fn sort_shadow_by_passwd(
    sorted_passwd: &[PasswdEntry],
    shadow_entries: &[ShadowEntry],
) -> Vec<ShadowEntry> {
    // Build a position lookup: username -> index in sorted passwd list.
    let position: std::collections::HashMap<&str, usize> = sorted_passwd
        .iter()
        .enumerate()
        .map(|(i, pe)| (pe.name.as_str(), i))
        .collect();

    let mut indexed: Vec<(usize, &ShadowEntry)> = Vec::with_capacity(shadow_entries.len());
    let mut orphans: Vec<&ShadowEntry> = Vec::new();

    for se in shadow_entries {
        if let Some(&pos) = position.get(se.name.as_str()) {
            indexed.push((pos, se));
        } else {
            orphans.push(se);
        }
    }

    // Stable sort keeps duplicates in their original relative order.
    indexed.sort_by_key(|(pos, _)| *pos);

    let mut result: Vec<ShadowEntry> = Vec::with_capacity(shadow_entries.len());
    for (_, se) in indexed {
        result.push(se.clone());
    }
    for se in orphans {
        result.push(se.clone());
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helper: build test entries
    // -----------------------------------------------------------------------

    fn make_passwd(name: &str, uid: u32, gid: u32, home: &str, shell: &str) -> PasswdEntry {
        PasswdEntry {
            name: name.into(),
            passwd: "x".into(),
            uid,
            gid,
            gecos: String::new(),
            home: home.into(),
            shell: shell.into(),
        }
    }

    fn make_shadow(name: &str) -> ShadowEntry {
        ShadowEntry {
            name: name.into(),
            passwd: "$6$hash".into(),
            last_change: Some(19000),
            min_age: Some(0),
            max_age: Some(99999),
            warn_days: Some(7),
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        }
    }

    fn make_group(name: &str, gid: u32) -> GroupEntry {
        GroupEntry {
            name: name.into(),
            passwd: "x".into(),
            gid,
            members: vec![],
        }
    }

    // -----------------------------------------------------------------------
    // clap validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_clap_valid_args() {
        let app = uu_app();
        assert!(app.try_get_matches_from(["pwck"]).is_ok());
    }

    #[test]
    fn test_clap_read_only_flag() {
        let app = uu_app();
        let m = app.try_get_matches_from(["pwck", "-r"]).expect("parse -r");
        assert!(m.get_flag(options::READ_ONLY));
    }

    #[test]
    fn test_clap_sort_flag() {
        let app = uu_app();
        let m = app
            .try_get_matches_from(["pwck", "--sort"])
            .expect("parse --sort");
        assert!(m.get_flag(options::SORT));
    }

    #[test]
    fn test_clap_quiet_flag() {
        let app = uu_app();
        let m = app.try_get_matches_from(["pwck", "-q"]).expect("parse -q");
        assert!(m.get_flag(options::QUIET));
    }

    #[test]
    fn test_clap_root_option() {
        let app = uu_app();
        let m = app
            .try_get_matches_from(["pwck", "-R", "/mnt/chroot"])
            .expect("parse -R");
        assert_eq!(
            m.get_one::<String>(options::ROOT).map(String::as_str),
            Some("/mnt/chroot")
        );
    }

    #[test]
    fn test_clap_positional_files() {
        let app = uu_app();
        let m = app
            .try_get_matches_from(["pwck", "/tmp/passwd", "/tmp/shadow"])
            .expect("parse positional");
        assert_eq!(
            m.get_one::<String>(options::PASSWD_FILE)
                .map(String::as_str),
            Some("/tmp/passwd")
        );
        assert_eq!(
            m.get_one::<String>(options::SHADOW_FILE)
                .map(String::as_str),
            Some("/tmp/shadow")
        );
    }

    #[test]
    fn test_clap_unknown_flag_rejected() {
        let app = uu_app();
        assert!(app.try_get_matches_from(["pwck", "--bogus"]).is_err());
    }

    // -----------------------------------------------------------------------
    // check_passwd_entries
    // -----------------------------------------------------------------------

    #[test]
    fn test_clean_entries_no_errors() {
        let passwd = vec![make_passwd("root", 0, 0, "/root", "/bin/bash")];
        let shadow = vec![make_shadow("root")];
        let groups = vec![make_group("root", 0)];
        let shells: HashSet<PathBuf> = [PathBuf::from("/bin/bash")].into();
        let root = SysRoot::default();

        let result = check_passwd_entries(&passwd, &shadow, &groups, &shells, false, &root);
        assert_eq!(result.errors, 0);
    }

    #[test]
    fn test_duplicate_username_is_error() {
        let passwd = vec![
            make_passwd("alice", 1000, 1000, "/home/alice", "/bin/bash"),
            make_passwd("alice", 1001, 1000, "/home/alice2", "/bin/bash"),
        ];
        let shadow = vec![make_shadow("alice")];
        let groups = vec![make_group("users", 1000)];
        let shells: HashSet<PathBuf> = [PathBuf::from("/bin/bash")].into();
        let root = SysRoot::default();

        let result = check_passwd_entries(&passwd, &shadow, &groups, &shells, false, &root);
        assert!(result.errors >= 1, "duplicate username should be an error");
    }

    #[test]
    fn test_empty_username_is_error() {
        let passwd = vec![make_passwd("", 1000, 1000, "/home/x", "/bin/bash")];
        let shadow: Vec<ShadowEntry> = vec![];
        let groups = vec![make_group("users", 1000)];
        let shells: HashSet<PathBuf> = [PathBuf::from("/bin/bash")].into();
        let root = SysRoot::default();

        let result = check_passwd_entries(&passwd, &shadow, &groups, &shells, false, &root);
        assert!(result.errors >= 1, "empty username should be an error");
    }

    #[test]
    fn test_missing_group_is_error() {
        let passwd = vec![make_passwd("alice", 1000, 9999, "/home/alice", "/bin/bash")];
        let shadow = vec![make_shadow("alice")];
        // GID 9999 does not exist in groups.
        let groups = vec![make_group("users", 1000)];
        let shells: HashSet<PathBuf> = [PathBuf::from("/bin/bash")].into();
        let root = SysRoot::default();

        let result = check_passwd_entries(&passwd, &shadow, &groups, &shells, false, &root);
        assert!(
            result.errors >= 1,
            "missing primary group should be an error"
        );
    }

    #[test]
    fn test_missing_shadow_entry_is_error() {
        let passwd = vec![make_passwd("alice", 1000, 1000, "/home/alice", "/bin/bash")];
        // Shadow file has entries but not for alice.
        let shadow = vec![make_shadow("bob")];
        let groups = vec![make_group("users", 1000)];
        let shells: HashSet<PathBuf> = [PathBuf::from("/bin/bash")].into();
        let root = SysRoot::default();

        let result = check_passwd_entries(&passwd, &shadow, &groups, &shells, false, &root);
        assert!(
            result.errors >= 1,
            "missing shadow entry should be an error"
        );
    }

    #[test]
    fn test_password_not_x_is_warning() {
        let mut entry = make_passwd("alice", 1000, 1000, "/home/alice", "/bin/bash");
        entry.passwd = "$6$hash".into();

        let passwd = vec![entry];
        let shadow = vec![make_shadow("alice")];
        let groups = vec![make_group("users", 1000)];
        let shells: HashSet<PathBuf> = [PathBuf::from("/bin/bash")].into();
        let root = SysRoot::default();

        let result = check_passwd_entries(&passwd, &shadow, &groups, &shells, false, &root);
        assert!(
            result.warnings >= 1,
            "password not in shadow file should be a warning"
        );
    }

    #[test]
    fn test_missing_home_dir_is_error() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let root = SysRoot::new(Some(dir.path()));

        let passwd = vec![make_passwd(
            "alice",
            1000,
            1000,
            "/home/nonexistent",
            "/bin/bash",
        )];
        let shadow = vec![make_shadow("alice")];
        let groups = vec![make_group("users", 1000)];
        let shells: HashSet<PathBuf> = [PathBuf::from("/bin/bash")].into();

        let result = check_passwd_entries(&passwd, &shadow, &groups, &shells, false, &root);
        assert!(
            result.errors >= 1,
            "missing home directory should be an error (matching GNU)"
        );
    }

    #[test]
    fn test_quiet_suppresses_warnings() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let root = SysRoot::new(Some(dir.path()));

        let passwd = vec![make_passwd(
            "alice",
            1000,
            1000,
            "/home/nonexistent",
            "/bin/bash",
        )];
        let shadow = vec![make_shadow("alice")];
        let groups = vec![make_group("users", 1000)];
        let shells: HashSet<PathBuf> = [PathBuf::from("/bin/bash")].into();

        let result = check_passwd_entries(&passwd, &shadow, &groups, &shells, true, &root);
        assert_eq!(result.warnings, 0, "quiet mode should suppress warnings");
    }

    // -----------------------------------------------------------------------
    // check_shadow_entries
    // -----------------------------------------------------------------------

    #[test]
    fn test_orphan_shadow_entry_is_error() {
        let passwd = vec![make_passwd("alice", 1000, 1000, "/home/alice", "/bin/bash")];
        let shadow = vec![make_shadow("alice"), make_shadow("ghost")];

        let result = check_shadow_entries(&shadow, &passwd, false);
        assert!(result.errors >= 1, "orphan shadow entry should be an error");
    }

    #[test]
    fn test_duplicate_shadow_entry_is_error() {
        let passwd = vec![make_passwd("alice", 1000, 1000, "/home/alice", "/bin/bash")];
        let shadow = vec![make_shadow("alice"), make_shadow("alice")];

        let result = check_shadow_entries(&shadow, &passwd, false);
        assert!(
            result.errors >= 1,
            "duplicate shadow entry should be an error"
        );
    }

    #[test]
    fn test_future_last_change_is_warning() {
        let passwd = vec![make_passwd("alice", 1000, 1000, "/home/alice", "/bin/bash")];
        let mut se = make_shadow("alice");
        // Set last_change far in the future.
        se.last_change = Some(999_999);

        let result = check_shadow_entries(&[se], &passwd, false);
        assert!(
            result.warnings >= 1,
            "future last_change should be a warning"
        );
    }

    #[test]
    fn test_future_last_change_quiet_suppressed() {
        let passwd = vec![make_passwd("alice", 1000, 1000, "/home/alice", "/bin/bash")];
        let mut se = make_shadow("alice");
        se.last_change = Some(999_999);

        let result = check_shadow_entries(&[se], &passwd, true);
        assert_eq!(
            result.warnings, 0,
            "quiet mode should suppress future last_change warning"
        );
    }

    // -----------------------------------------------------------------------
    // read_valid_shells
    // -----------------------------------------------------------------------

    #[test]
    fn test_read_valid_shells() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let shells_path = dir.path().join("shells");
        std::fs::write(
            &shells_path,
            "# /etc/shells\n/bin/bash\n/bin/zsh\n\n# comment\n/bin/sh\n",
        )
        .expect("failed to write shells");

        let shells = read_valid_shells(&shells_path);
        assert!(shells.contains(Path::new("/bin/bash")));
        assert!(shells.contains(Path::new("/bin/zsh")));
        assert!(shells.contains(Path::new("/bin/sh")));
        assert!(!shells.contains(Path::new("/bin/fish")));
    }

    #[test]
    fn test_read_valid_shells_missing_file() {
        let shells = read_valid_shells(Path::new("/nonexistent/shells"));
        assert!(shells.is_empty());
    }

    // -----------------------------------------------------------------------
    // sort_shadow_by_passwd
    // -----------------------------------------------------------------------

    #[test]
    fn test_sort_shadow_by_passwd_order() {
        let sorted_passwd = vec![
            make_passwd("root", 0, 0, "/root", "/bin/bash"),
            make_passwd("alice", 1000, 1000, "/home/alice", "/bin/bash"),
            make_passwd("bob", 1001, 1000, "/home/bob", "/bin/bash"),
        ];
        let shadow = vec![
            make_shadow("bob"),
            make_shadow("alice"),
            make_shadow("root"),
        ];

        let result = sort_shadow_by_passwd(&sorted_passwd, &shadow);
        assert_eq!(result[0].name, "root");
        assert_eq!(result[1].name, "alice");
        assert_eq!(result[2].name, "bob");
    }

    #[test]
    fn test_sort_shadow_orphans_appended() {
        let sorted_passwd = vec![make_passwd("root", 0, 0, "/root", "/bin/bash")];
        let shadow = vec![make_shadow("root"), make_shadow("orphan")];

        let result = sort_shadow_by_passwd(&sorted_passwd, &shadow);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "root");
        assert_eq!(result[1].name, "orphan");
    }

    #[test]
    fn test_sort_shadow_preserves_duplicates() {
        let sorted_passwd = vec![
            make_passwd("root", 0, 0, "/root", "/bin/bash"),
            make_passwd("alice", 1000, 1000, "/home/alice", "/bin/bash"),
        ];
        // Duplicate shadow entries for alice must both be preserved.
        let shadow = vec![
            make_shadow("alice"),
            make_shadow("root"),
            make_shadow("alice"),
        ];

        let result = sort_shadow_by_passwd(&sorted_passwd, &shadow);
        assert_eq!(result.len(), 3, "duplicates must not be dropped");
        assert_eq!(result[0].name, "root");
        assert_eq!(result[1].name, "alice");
        assert_eq!(result[2].name, "alice");
    }

    // -----------------------------------------------------------------------
    // read_raw_lines
    // -----------------------------------------------------------------------

    #[test]
    fn test_read_raw_lines_skips_comments_and_blanks() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let path = dir.path().join("test");
        std::fs::write(
            &path,
            "# comment\nroot:x:0:0:root:/root:/bin/bash\n\n\nalice:x:1000:1000::/home/alice:/bin/bash\n",
        )
        .expect("failed to write test file");

        let lines = read_raw_lines(&path).expect("failed to read");
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("root:"));
        assert!(lines[1].starts_with("alice:"));
    }

    #[test]
    fn test_read_raw_lines_nonexistent_file() {
        let result = read_raw_lines(Path::new("/nonexistent/passwd"));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Exit code mapping
    // -----------------------------------------------------------------------

    #[test]
    fn test_exit_codes() {
        assert_eq!(
            PwckError::BadEntry("test".into()).code(),
            exit_codes::BAD_ENTRY
        );
        assert_eq!(
            PwckError::CantOpen("test".into()).code(),
            exit_codes::CANT_OPEN
        );
        assert_eq!(
            PwckError::CantLock("test".into()).code(),
            exit_codes::CANT_LOCK
        );
        assert_eq!(
            PwckError::CantUpdate("test".into()).code(),
            exit_codes::CANT_UPDATE
        );
        assert_eq!(
            PwckError::CantSort("test".into()).code(),
            exit_codes::CANT_SORT
        );
    }

    // -----------------------------------------------------------------------
    // Integration: uumain with temp files
    // -----------------------------------------------------------------------

    /// Run `uumain` with the given args, returning the exit code.
    fn run(args: &[&str]) -> i32 {
        let os_args: Vec<std::ffi::OsString> = args.iter().map(|s| (*s).into()).collect();
        uumain(os_args.into_iter())
    }

    #[test]
    fn test_uumain_clean_files() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let passwd_path = dir.path().join("passwd");
        let shadow_path = dir.path().join("shadow");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("mkdir etc");

        std::fs::write(&passwd_path, "root:x:0:0:root:/root:/bin/bash\n").expect("write passwd");
        std::fs::write(&shadow_path, "root:$6$hash:19000:0:99999:7:::\n").expect("write shadow");

        // Write /etc/group inside root for group lookup.
        std::fs::write(etc.join("group"), "root:x:0:\n").expect("write etc/group");
        // Write /etc/shells.
        std::fs::write(etc.join("shells"), "/bin/bash\n").expect("write shells");
        // Create the home dir.
        std::fs::create_dir_all(dir.path().join("root")).expect("mkdir root home");

        let code = run(&[
            "pwck",
            "-r",
            "-R",
            dir.path().to_str().expect("non-utf8 path"),
            passwd_path.to_str().expect("non-utf8 path"),
            shadow_path.to_str().expect("non-utf8 path"),
        ]);

        assert_eq!(code, 0, "clean files should succeed");
    }

    #[test]
    fn test_uumain_bad_passwd_line() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let passwd_path = dir.path().join("passwd");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("mkdir etc");

        // Malformed line: only 4 fields.
        std::fs::write(&passwd_path, "root:x:0:0\n").expect("write passwd");
        std::fs::write(etc.join("group"), "root:x:0:\n").expect("write group");

        let code = run(&[
            "pwck",
            "-r",
            "-R",
            dir.path().to_str().expect("non-utf8 path"),
            passwd_path.to_str().expect("non-utf8 path"),
        ]);

        assert_eq!(
            code,
            exit_codes::BAD_ENTRY,
            "bad passwd line should return exit code 2"
        );
    }

    #[test]
    fn test_uumain_nonexistent_passwd() {
        let code = run(&["pwck", "-r", "/nonexistent/passwd"]);
        assert_eq!(
            code,
            exit_codes::CANT_OPEN,
            "nonexistent passwd should return exit code 3"
        );
    }

    // -----------------------------------------------------------------------
    // today_as_days
    // -----------------------------------------------------------------------

    #[test]
    fn test_today_as_days_reasonable() {
        let days = today_as_days();
        // 2024-01-01 is ~19723 days since epoch; 2030-01-01 is ~21915.
        assert!(days > 19000, "today should be well past epoch");
        assert!(days < 100_000, "sanity upper bound");
    }
}
