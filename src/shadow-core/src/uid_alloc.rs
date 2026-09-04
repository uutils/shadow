// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! UID and GID allocation from ranges defined in `/etc/login.defs`.
//!
//! Finds the next available UID or GID by scanning existing entries and
//! returning the lowest unused value in the configured range. Range
//! boundaries come from `login.defs` keys (`UID_MIN`, `UID_MAX`,
//! `SYS_UID_MIN`, `SYS_UID_MAX`, and the GID equivalents).
//!
//! Default ranges follow the Debian/upstream convention:
//! - Regular users: 1000 -- 60000
//! - System accounts: 101 -- 999

use std::collections::HashSet;

use crate::error::ShadowError;
use crate::group::GroupEntry;
use crate::login_defs::LoginDefs;
use crate::passwd::PasswdEntry;

/// Find the next available UID in the given range.
///
/// Scans `existing` entries and returns the lowest UID in `[min, max]`
/// that is not already in use.
///
/// # Errors
///
/// Returns `ShadowError::Other` if every UID in the range is taken.
pub fn next_uid(existing: &[PasswdEntry], min: u32, max: u32) -> Result<u32, ShadowError> {
    let used: HashSet<u32> = existing.iter().map(|e| e.uid).collect();
    next_free(&used, min, max)
        .ok_or_else(|| ShadowError::Other(format!("no available UID in range {min}-{max}").into()))
}

/// Find the next available GID in the given range.
///
/// Scans `existing` entries and returns the lowest GID in `[min, max]`
/// that is not already in use.
///
/// # Errors
///
/// Returns `ShadowError::Other` if every GID in the range is taken.
pub fn next_gid(existing: &[GroupEntry], min: u32, max: u32) -> Result<u32, ShadowError> {
    let used: HashSet<u32> = existing.iter().map(|e| e.gid).collect();
    next_free(&used, min, max)
        .ok_or_else(|| ShadowError::Other(format!("no available GID in range {min}-{max}").into()))
}

/// The ID to hand out next: one past the highest already in use within the
/// range, and only once the range is exhausted that way, the lowest free ID.
///
/// Handing out the lowest free ID would reuse the ID of a deleted account, so
/// the new user would inherit any files the old one left behind. Verified
/// against shadow-utils: creating a, then b, deleting a, then creating c gives
/// c the ID after b's, not a's.
fn next_free(used: &HashSet<u32>, min: u32, max: u32) -> Option<u32> {
    let highest = used
        .iter()
        .copied()
        .filter(|id| (min..=max).contains(id))
        .max();
    if let Some(highest) = highest
        && let Some(next) = highest.checked_add(1)
        && next <= max
    {
        return Some(next);
    }
    (min..=max).find(|id| !used.contains(id))
}

/// Read a `login.defs` key as `u32`, ignoring negative or overflowing values.
fn get_u32(defs: &LoginDefs, key: &str) -> Option<u32> {
    defs.get_i64(key).and_then(|v| u32::try_from(v).ok())
}

/// Get the UID allocation range from `login.defs`.
///
/// Returns `(min, max)`. When `system` is `true`, uses `SYS_UID_MIN` /
/// `SYS_UID_MAX` (defaults 101 / 999). Otherwise uses `UID_MIN` /
/// `UID_MAX` (defaults 1000 / 60000).
#[must_use]
pub fn uid_range(defs: &LoginDefs, system: bool) -> (u32, u32) {
    if system {
        let min = get_u32(defs, "SYS_UID_MIN").unwrap_or(101);
        let max = get_u32(defs, "SYS_UID_MAX").unwrap_or(999);
        (min, max)
    } else {
        let min = get_u32(defs, "UID_MIN").unwrap_or(1000);
        let max = get_u32(defs, "UID_MAX").unwrap_or(60000);
        (min, max)
    }
}

/// Get the GID allocation range from `login.defs`.
///
/// Returns `(min, max)`. When `system` is `true`, uses `SYS_GID_MIN` /
/// `SYS_GID_MAX` (defaults 101 / 999). Otherwise uses `GID_MIN` /
/// `GID_MAX` (defaults 1000 / 60000).
#[must_use]
pub fn gid_range(defs: &LoginDefs, system: bool) -> (u32, u32) {
    if system {
        let min = get_u32(defs, "SYS_GID_MIN").unwrap_or(101);
        let max = get_u32(defs, "SYS_GID_MAX").unwrap_or(999);
        (min, max)
    } else {
        let min = get_u32(defs, "GID_MIN").unwrap_or(1000);
        let max = get_u32(defs, "GID_MAX").unwrap_or(60000);
        (min, max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn make_passwd_entries(uids: &[u32]) -> Vec<PasswdEntry> {
        uids.iter()
            .map(|&uid| PasswdEntry {
                name: format!("user{uid}"),
                passwd: "x".into(),
                uid,
                gid: uid,
                gecos: String::new(),
                home: format!("/home/user{uid}"),
                shell: "/bin/bash".into(),
            })
            .collect()
    }

    fn make_group_entries(gids: &[u32]) -> Vec<GroupEntry> {
        gids.iter()
            .map(|&gid| GroupEntry {
                name: format!("group{gid}"),
                passwd: "x".into(),
                gid,
                members: vec![],
            })
            .collect()
    }

    // --- next_uid ---

    #[test]
    fn test_next_uid_empty() {
        let entries: Vec<PasswdEntry> = vec![];
        assert_eq!(next_uid(&entries, 1000, 1005).unwrap(), 1000);
    }

    // Not the gap at 1002: reusing a deleted account's UID would hand the new
    // user its leftover files. shadow-utils allocates past the highest in use.
    #[test]
    fn test_next_uid_goes_past_the_highest_in_use() {
        let entries = make_passwd_entries(&[1000, 1001, 1003]);
        assert_eq!(next_uid(&entries, 1000, 1005).unwrap(), 1004);
    }

    // Only once the top of the range is taken does it fall back to a gap.
    #[test]
    fn test_next_uid_falls_back_to_a_gap_when_the_range_top_is_used() {
        let entries = make_passwd_entries(&[1000, 1001, 1003, 1004, 1005]);
        assert_eq!(next_uid(&entries, 1000, 1005).unwrap(), 1002);
    }

    // IDs outside the range must not push the allocation past the maximum.
    #[test]
    fn test_next_uid_ignores_ids_outside_the_range() {
        let entries = make_passwd_entries(&[0, 65534, 1000]);
        assert_eq!(next_uid(&entries, 1000, 1005).unwrap(), 1001);
    }

    #[test]
    fn test_next_uid_skips_used_start() {
        let entries = make_passwd_entries(&[1000]);
        assert_eq!(next_uid(&entries, 1000, 1005).unwrap(), 1001);
    }

    #[test]
    fn test_next_uid_exhausted() {
        let entries = make_passwd_entries(&[100, 101, 102]);
        let result = next_uid(&entries, 100, 102);
        assert!(result.is_err());
    }

    #[test]
    fn test_next_uid_single_value_range() {
        let entries: Vec<PasswdEntry> = vec![];
        assert_eq!(next_uid(&entries, 500, 500).unwrap(), 500);
    }

    #[test]
    fn test_next_uid_single_value_range_taken() {
        let entries = make_passwd_entries(&[500]);
        assert!(next_uid(&entries, 500, 500).is_err());
    }

    // --- next_gid ---

    #[test]
    fn test_next_gid_empty() {
        let entries: Vec<GroupEntry> = vec![];
        assert_eq!(next_gid(&entries, 1000, 1005).unwrap(), 1000);
    }

    #[test]
    fn test_next_gid_goes_past_the_highest_in_use() {
        let entries = make_group_entries(&[1000, 1002]);
        assert_eq!(next_gid(&entries, 1000, 1005).unwrap(), 1003);
    }

    #[test]
    fn test_next_gid_falls_back_to_a_gap_when_the_range_top_is_used() {
        let entries = make_group_entries(&[1000, 1002, 1003, 1004, 1005]);
        assert_eq!(next_gid(&entries, 1000, 1005).unwrap(), 1001);
    }

    #[test]
    fn test_next_gid_exhausted() {
        let entries = make_group_entries(&[10, 11, 12]);
        assert!(next_gid(&entries, 10, 12).is_err());
    }

    // --- uid_range ---

    #[test]
    fn test_uid_range_defaults_regular() {
        let defs = LoginDefs::load(Path::new("/nonexistent/login.defs")).unwrap();
        assert_eq!(uid_range(&defs, false), (1000, 60000));
    }

    #[test]
    fn test_uid_range_defaults_system() {
        let defs = LoginDefs::load(Path::new("/nonexistent/login.defs")).unwrap();
        assert_eq!(uid_range(&defs, true), (101, 999));
    }

    #[test]
    fn test_uid_range_from_login_defs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("login.defs");
        std::fs::write(&path, "UID_MIN 500\nUID_MAX 50000\n").unwrap();
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(uid_range(&defs, false), (500, 50000));
    }

    #[test]
    fn test_uid_range_system_from_login_defs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("login.defs");
        std::fs::write(&path, "SYS_UID_MIN 200\nSYS_UID_MAX 499\n").unwrap();
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(uid_range(&defs, true), (200, 499));
    }

    // --- gid_range ---

    #[test]
    fn test_gid_range_defaults_regular() {
        let defs = LoginDefs::load(Path::new("/nonexistent/login.defs")).unwrap();
        assert_eq!(gid_range(&defs, false), (1000, 60000));
    }

    #[test]
    fn test_gid_range_defaults_system() {
        let defs = LoginDefs::load(Path::new("/nonexistent/login.defs")).unwrap();
        assert_eq!(gid_range(&defs, true), (101, 999));
    }

    #[test]
    fn test_gid_range_from_login_defs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("login.defs");
        std::fs::write(&path, "GID_MIN 500\nGID_MAX 50000\n").unwrap();
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(gid_range(&defs, false), (500, 50000));
    }

    #[test]
    fn test_gid_range_system_from_login_defs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("login.defs");
        std::fs::write(&path, "SYS_GID_MIN 200\nSYS_GID_MAX 499\n").unwrap();
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(gid_range(&defs, true), (200, 499));
    }
}
