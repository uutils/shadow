// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore grpck gshadow nscd sysroot

//! `grpck` -- verify integrity of group files.
//!
//! Drop-in replacement for GNU shadow-utils `grpck(8)`.
//!
//! Checks `/etc/group` and `/etc/gshadow` for consistency:
//! - Correct field count (parsed via structured types)
//! - Unique group names
//! - Valid GIDs
//! - Matching group/gshadow entries

use std::collections::HashSet;
use std::fmt;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, Command};
use uucore::error::{UError, UResult};

use shadow_core::atomic;
use shadow_core::group::{self, GroupEntry};
use shadow_core::gshadow::{self, GshadowEntry};
use shadow_core::lock::FileLock;
use shadow_core::nscd;
use shadow_core::sysroot::SysRoot;

mod options {
    pub const READ_ONLY: &str = "read-only";
    pub const SORT: &str = "sort";
    pub const QUIET: &str = "quiet";
    pub const ROOT: &str = "root";
    pub const GROUP_FILE: &str = "group_file";
    pub const GSHADOW_FILE: &str = "gshadow_file";
}

mod exit_codes {
    /// One or more bad group entries.
    pub const BAD_ENTRY: i32 = 2;
    /// Cannot open files.
    pub const CANT_OPEN: i32 = 3;
    /// Cannot lock files.
    pub const CANT_LOCK: i32 = 4;
    /// Cannot update files.
    pub const CANT_UPDATE: i32 = 5;
}

#[derive(Debug)]
enum GrpckError {
    BadEntry(String),
    CantOpen(String),
    CantLock(String),
    CantUpdate(String),
}

impl fmt::Display for GrpckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadEntry(msg)
            | Self::CantOpen(msg)
            | Self::CantLock(msg)
            | Self::CantUpdate(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for GrpckError {}

impl UError for GrpckError {
    fn code(&self) -> i32 {
        match self {
            Self::BadEntry(_) => exit_codes::BAD_ENTRY,
            Self::CantOpen(_) => exit_codes::CANT_OPEN,
            Self::CantLock(_) => exit_codes::CANT_LOCK,
            Self::CantUpdate(_) => exit_codes::CANT_UPDATE,
        }
    }
}

// ---------------------------------------------------------------------------
// Parsed options
// ---------------------------------------------------------------------------

struct GrpckOptions {
    quiet: bool,
    sort: bool,
    read_only: bool,
    group_path: PathBuf,
    gshadow_path: PathBuf,
    root: SysRoot,
}

impl GrpckOptions {
    fn from_matches(matches: &clap::ArgMatches) -> Self {
        // grpck has no --prefix, matching GNU; --root is a real chroot, done
        // before this runs, so paths resolve against the new root.
        let root = SysRoot::default();

        let group_path = matches
            .get_one::<String>(options::GROUP_FILE)
            .map_or_else(|| root.group_path(), PathBuf::from);
        let gshadow_path = matches
            .get_one::<String>(options::GSHADOW_FILE)
            .map_or_else(|| root.gshadow_path(), PathBuf::from);

        Self {
            quiet: matches.get_flag(options::QUIET),
            sort: matches.get_flag(options::SORT),
            read_only: matches.get_flag(options::READ_ONLY),
            group_path,
            gshadow_path,
            root,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    let matches = uu_app().try_get_matches_from(args)?;
    // --root DIR is a real chroot: the account files come from the new root,
    // and so does every absolute path read out of them. Done before anything
    // else, so nothing has resolved a path against the old root yet.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        shadow_core::hardening::chroot_into(std::path::Path::new(chroot_dir))
            .map_err(|e| GrpckError::CantOpen(e.to_string()))?;
    }

    let opts = GrpckOptions::from_matches(&matches);
    run_checks(&opts)
}

/// Core logic, separated from argument parsing.
fn run_checks(opts: &GrpckOptions) -> UResult<()> {
    let group_lines = read_raw_lines(&opts.group_path).map_err(|e| {
        GrpckError::CantOpen(format!("cannot open {}: {e}", opts.group_path.display()))
    })?;

    // Parse group entries, tracking per-line errors.
    let mut group_entries = Vec::new();
    let mut errors: u32 = 0;

    for (line_no, raw_line) in group_lines.iter().enumerate() {
        let line_num = line_no + 1;
        match raw_line.parse::<GroupEntry>() {
            Ok(entry) => group_entries.push(entry),
            Err(e) => {
                // grpck(8) -q: "Report errors only." Errors are always shown.
                uucore::show_error!("invalid group file entry at line {line_num}: {e}");
                errors += 1;
            }
        }
    }

    // Check for duplicate group names.
    errors += check_duplicate_names(&group_entries, opts.quiet);

    // Check for valid GIDs (the parser already validates u32, but check for
    // groups with GID 0 that are not "root").
    errors += check_gid_consistency(&group_entries, opts.quiet);

    // Load and check gshadow whenever the file is there. Keying the check on
    // "did any entry parse" meant a malformed or empty gshadow next to a
    // populated group file reported nothing at all.
    if opts.gshadow_path.exists() {
        match gshadow::read_gshadow_file(&opts.gshadow_path) {
            Ok(gshadow_entries) => {
                errors +=
                    check_group_gshadow_consistency(&group_entries, &gshadow_entries, opts.quiet);
            }
            Err(e) => {
                uucore::show_error!("cannot read {}: {e}", opts.gshadow_path.display());
                errors += 1;
            }
        }
    }

    // Members and administrators must name real users.
    errors += check_members_exist(&group_entries, &opts.root);

    // Never rewrite the files when errors were found: sorting works on the
    // entries that parsed, so writing would drop every line just reported.
    if errors > 0 {
        return Err(GrpckError::BadEntry(String::new()).into());
    }

    // Sort by GID if requested. `-r` and `-s` cannot be combined (rejected by
    // clap), so the read-only guard is defensive.
    if opts.sort && !opts.read_only {
        sort_and_write(&opts.group_path, &opts.gshadow_path)?;
    }

    Ok(())
}

/// Read raw non-comment, non-blank lines from a file.
fn read_raw_lines(path: &Path) -> Result<Vec<String>, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut lines = Vec::new();

    for line in reader.lines() {
        let line = line?;
        // Comments, blank lines and NIS compat lines are not entries to check;
        // they are preserved verbatim when -s rewrites the file.
        if shadow_core::records::is_raw_line(&line) {
            continue;
        }
        lines.push(line);
    }

    Ok(lines)
}

/// Check for duplicate group names.
fn check_duplicate_names(entries: &[GroupEntry], quiet: bool) -> u32 {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut errors: u32 = 0;

    for entry in entries {
        if !seen.insert(&entry.name) {
            if !quiet {
                uucore::show_error!("duplicate group entry: '{}'", entry.name);
            }
            errors += 1;
        }
    }

    errors
}

/// Check GID consistency (warn on multiple groups with GID 0).
fn check_gid_consistency(entries: &[GroupEntry], quiet: bool) -> u32 {
    let mut errors: u32 = 0;

    // Check for empty group names (the parser generally rejects these,
    // but be defensive).
    for entry in entries {
        if entry.name.is_empty() {
            if !quiet {
                uucore::show_error!("group entry has empty name (GID {})", entry.gid);
            }
            errors += 1;
        }
    }

    errors
}

/// Check that every group has a matching gshadow entry and vice versa.
fn check_group_gshadow_consistency(
    group_entries: &[GroupEntry],
    gshadow_entries: &[GshadowEntry],
    quiet: bool,
) -> u32 {
    let mut errors: u32 = 0;

    let group_names: HashSet<&str> = group_entries.iter().map(|g| g.name.as_str()).collect();
    let gshadow_names: HashSet<&str> = gshadow_entries.iter().map(|g| g.name.as_str()).collect();

    // Groups without gshadow entries.
    for name in &group_names {
        if !gshadow_names.contains(name) {
            if !quiet {
                uucore::show_error!("no matching gshadow entry for group '{name}'");
            }
            errors += 1;
        }
    }

    // Gshadow entries without matching groups.
    for name in &gshadow_names {
        if !group_names.contains(name) {
            if !quiet {
                uucore::show_error!("no matching group entry for gshadow '{name}'");
            }
            errors += 1;
        }
    }

    errors
}

/// Sort group entries by GID and write back atomically.
///
/// NOTE: Sorting operates on parsed entries and discards any comments or
/// blank lines from the original file. A lossless (comment-preserving)
/// sort would require a significantly different parser that tracks raw
/// lines alongside parsed entries. This matches GNU `grpck -s` behavior.
fn sort_and_write(group_path: &Path, gshadow_path: &Path) -> UResult<()> {
    let group_lock = FileLock::acquire(group_path)
        .map_err(|e| GrpckError::CantLock(format!("cannot lock {}: {e}", group_path.display())))?;

    // Re-read under the lock: the entries checked above were read before it.
    // The layout keeps comments, blank lines and NIS compat lines, each
    // anchored to the entry it preceded, so a comment follows its group.
    let (mut sorted_groups, group_layout) =
        group::read_group_with_layout(group_path).map_err(|e| {
            GrpckError::CantUpdate(format!("cannot read {}: {e}", group_path.display()))
        })?;
    let original = sorted_groups.clone();
    sorted_groups.sort_by_key(|g| g.gid);

    if sorted_groups == original {
        drop(group_lock);
        return Ok(());
    }

    atomic::atomic_write(group_path, |f| {
        group::write_group_with_layout(&sorted_groups, &group_layout, f)
    })
    .map_err(|e| GrpckError::CantUpdate(format!("cannot update {}: {e}", group_path.display())))?;

    // Sort gshadow to match the new group order.
    if gshadow_path.exists() {
        let gs_lock = FileLock::acquire(gshadow_path).map_err(|e| {
            GrpckError::CantLock(format!("cannot lock {}: {e}", gshadow_path.display()))
        })?;

        let (gshadow_entries, gshadow_layout) = gshadow::read_gshadow_with_layout(gshadow_path)
            .map_err(|e| {
                GrpckError::CantUpdate(format!("cannot read {}: {e}", gshadow_path.display()))
            })?;

        if !gshadow_entries.is_empty() {
            let sorted_gshadow = sort_gshadow_by_group(&sorted_groups, &gshadow_entries);
            atomic::atomic_write(gshadow_path, |f| {
                gshadow::write_gshadow_with_layout(&sorted_gshadow, &gshadow_layout, f)
            })
            .map_err(|e| {
                GrpckError::CantUpdate(format!("cannot update {}: {e}", gshadow_path.display()))
            })?;
        }

        drop(gs_lock);
    }

    drop(group_lock);
    nscd::invalidate_cache("group");

    Ok(())
}

/// Reorder gshadow entries to match the group entry order.
fn sort_gshadow_by_group(
    sorted_groups: &[GroupEntry],
    gshadow_entries: &[GshadowEntry],
) -> Vec<GshadowEntry> {
    let mut result = Vec::with_capacity(gshadow_entries.len());
    let mut gs_by_name: std::collections::HashMap<&str, Vec<&GshadowEntry>> =
        std::collections::HashMap::new();
    for gs in gshadow_entries {
        gs_by_name.entry(gs.name.as_str()).or_default().push(gs);
    }

    // Add entries in group-sorted order, preserving duplicates.
    for g in sorted_groups {
        if let Some(entries) = gs_by_name.get(g.name.as_str()) {
            for gs in entries {
                result.push((*gs).clone());
            }
        }
    }

    // Then, add any gshadow entries without matching groups (orphans).
    let group_names: HashSet<&str> = sorted_groups.iter().map(|g| g.name.as_str()).collect();
    for gs in gshadow_entries {
        if !group_names.contains(gs.name.as_str()) {
            result.push(gs.clone());
        }
    }

    result
}

/// grpck(8) verifies "a valid list of members and administrators": a name in
/// either list that no account carries is a dangling reference.
fn check_members_exist(entries: &[GroupEntry], root: &shadow_core::sysroot::SysRoot) -> u32 {
    let passwd_path = root.passwd_path();
    if !passwd_path.exists() {
        return 0;
    }
    let Ok(users) = shadow_core::passwd::read_passwd_file(&passwd_path) else {
        return 0;
    };
    let known: std::collections::HashSet<&str> = users.iter().map(|u| u.name.as_str()).collect();

    let mut errors = 0;
    for group in entries {
        for member in &group.members {
            if !known.contains(member.as_str()) {
                uucore::show_error!("group '{}': member '{member}' does not exist", group.name);
                errors += 1;
            }
        }
    }
    errors
}
#[must_use]
pub fn uu_app() -> Command {
    Command::new("grpck")
        .about("Audit /etc/group and /etc/gshadow for inconsistencies")
        .override_usage("grpck [options] [group [gshadow]]")
        .version(shadow_core::cli::VERSION)
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
                .help("Reorder entries by ascending GID")
                // grpck(8): "The -r and -s options cannot be combined."
                .conflicts_with(options::READ_ONLY)
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
                .value_name("ROOT_DIR")
                .help("Locate the system files under ROOT_DIR instead of /")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new(options::GROUP_FILE)
                .index(1)
                .value_name("group")
                .help("Path to use instead of /etc/group"),
        )
        .arg(
            Arg::new(options::GSHADOW_FILE)
                .index(2)
                .value_name("gshadow")
                .help("Path to use instead of /etc/gshadow"),
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
    fn test_read_only_flag() {
        let m = uu_app()
            .try_get_matches_from(["grpck", "-r"])
            .expect("valid args");
        assert!(m.get_flag(options::READ_ONLY));
    }

    #[test]
    fn test_sort_flag() {
        let m = uu_app()
            .try_get_matches_from(["grpck", "-s"])
            .expect("valid args");
        assert!(m.get_flag(options::SORT));
    }

    #[test]
    fn test_quiet_flag() {
        let m = uu_app()
            .try_get_matches_from(["grpck", "-q"])
            .expect("valid args");
        assert!(m.get_flag(options::QUIET));
    }

    #[test]
    fn test_duplicate_names_detected() {
        let entries = vec![
            GroupEntry {
                name: "dup".into(),
                passwd: "x".into(),
                gid: 100,
                members: vec![],
            },
            GroupEntry {
                name: "dup".into(),
                passwd: "x".into(),
                gid: 101,
                members: vec![],
            },
        ];
        assert_eq!(check_duplicate_names(&entries, true), 1);
    }

    #[test]
    fn test_no_duplicate_names() {
        let entries = vec![
            GroupEntry {
                name: "grp1".into(),
                passwd: "x".into(),
                gid: 100,
                members: vec![],
            },
            GroupEntry {
                name: "grp2".into(),
                passwd: "x".into(),
                gid: 101,
                members: vec![],
            },
        ];
        assert_eq!(check_duplicate_names(&entries, true), 0);
    }

    #[test]
    fn test_group_gshadow_consistency_ok() {
        let groups = vec![GroupEntry {
            name: "grp1".into(),
            passwd: "x".into(),
            gid: 100,
            members: vec![],
        }];
        let gshadow = vec![GshadowEntry {
            name: "grp1".into(),
            passwd: "!".into(),
            admins: vec![],
            members: vec![],
        }];
        assert_eq!(check_group_gshadow_consistency(&groups, &gshadow, true), 0);
    }

    #[test]
    fn test_group_without_gshadow() {
        let groups = vec![GroupEntry {
            name: "grp1".into(),
            passwd: "x".into(),
            gid: 100,
            members: vec![],
        }];
        let gshadow: Vec<GshadowEntry> = vec![];
        assert_eq!(check_group_gshadow_consistency(&groups, &gshadow, true), 1);
    }

    #[test]
    fn test_gshadow_without_group() {
        let groups: Vec<GroupEntry> = vec![];
        let gshadow = vec![GshadowEntry {
            name: "orphan".into(),
            passwd: "!".into(),
            admins: vec![],
            members: vec![],
        }];
        assert_eq!(check_group_gshadow_consistency(&groups, &gshadow, true), 1);
    }

    #[test]
    fn test_valid_group_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let group_path = dir.path().join("group");
        std::fs::write(&group_path, "root:x:0:\nusers:x:100:\n").expect("write group");

        let opts = GrpckOptions {
            quiet: false,
            sort: false,
            read_only: true,
            group_path,
            gshadow_path: dir.path().join("gshadow_nonexistent"),
            root: SysRoot::new(Some(dir.path())),
        };

        let result = run_checks(&opts);
        assert!(result.is_ok());
    }

    #[test]
    fn test_malformed_group_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let group_path = dir.path().join("group");
        // Missing members field.
        std::fs::write(&group_path, "root:x:0:\nbadentry:x\n").expect("write group");

        let opts = GrpckOptions {
            quiet: true,
            sort: false,
            read_only: true,
            group_path,
            gshadow_path: dir.path().join("gshadow_nonexistent"),
            root: SysRoot::new(Some(dir.path())),
        };

        let result = run_checks(&opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_sort_group_by_gid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let group_path = dir.path().join("group");
        std::fs::write(&group_path, "users:x:100:\nroot:x:0:\nadm:x:4:\n").expect("write group");
        let gshadow_path = dir.path().join("gshadow_nonexistent");

        let opts = GrpckOptions {
            quiet: false,
            sort: true,
            read_only: false,
            group_path: group_path.clone(),
            gshadow_path,
            root: SysRoot::new(Some(dir.path())),
        };

        let result = run_checks(&opts);
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&group_path).expect("read group");
        let lines: Vec<&str> = content.lines().collect();
        assert!(lines.len() >= 3);
        assert!(lines[0].starts_with("root:"));
        assert!(lines[1].starts_with("adm:"));
        assert!(lines[2].starts_with("users:"));
    }
}
