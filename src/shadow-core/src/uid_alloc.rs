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

/// Which sources an allocation must avoid colliding with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The account files given, and the local name service as well.
    ///
    /// `/etc/passwd` is not the only source of accounts. An ID that is free in
    /// the file may belong to an LDAP, SSSD or systemd-homed account, and
    /// handing it out gives two accounts one ID -- which the kernel cannot
    /// tell apart, so the new local user ends up owning the directory user's
    /// files.
    IncludingNameService,
    /// The account files given, and nothing else.
    ///
    /// What a `--prefix` or `--root` run needs: those files belong to another
    /// system, and the name service running here describes this one. Asking it
    /// would skip IDs that are free on the target and claim none that are
    /// taken there.
    FilesOnly,
}

impl Scope {
    /// The scope implied by whether the tool was pointed at another root.
    #[must_use]
    pub fn for_prefix(prefixed: bool) -> Self {
        if prefixed {
            Self::FilesOnly
        } else {
            Self::IncludingNameService
        }
    }
}

/// Find the next available UID in the given range.
///
/// # Errors
///
/// Returns `ShadowError::Other` if every UID in the range is taken.
pub fn next_uid(
    existing: &[PasswdEntry],
    min: u32,
    max: u32,
    scope: Scope,
) -> Result<u32, ShadowError> {
    let used: HashSet<u32> = existing.iter().map(|e| e.uid).collect();
    let taken = |uid: u32| {
        scope == Scope::IncludingNameService && matches!(crate::process::getpwuid(uid), Ok(Some(_)))
    };
    next_free_checked(&used, min, max, &taken)
        .ok_or_else(|| ShadowError::Other(format!("no available UID in range {min}-{max}").into()))
}

/// Find the next available GID in the given range.
///
/// # Errors
///
/// Returns `ShadowError::Other` if every GID in the range is taken.
pub fn next_gid(
    existing: &[GroupEntry],
    min: u32,
    max: u32,
    scope: Scope,
) -> Result<u32, ShadowError> {
    let used: HashSet<u32> = existing.iter().map(|e| e.gid).collect();
    let taken = |gid: u32| {
        scope == Scope::IncludingNameService && matches!(crate::process::gid_exists(gid), Ok(true))
    };
    next_free_checked(&used, min, max, &taken)
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

/// [`next_free`], skipping any ID the system knows about beyond the local file.
///
/// `/etc/passwd` is not the only source of accounts. An ID that is free in the
/// file may belong to a directory account, and handing it out gives two
/// accounts one ID -- which the kernel cannot tell apart, so the new local user
/// owns the directory user's files. `taken` asks NSS, which sees every
/// configured backend.
///
/// Each rejected candidate is recorded, so the search advances and terminates
/// even when the whole range is claimed elsewhere.
fn next_free_checked(
    used: &HashSet<u32>,
    min: u32,
    max: u32,
    taken: &dyn Fn(u32) -> bool,
) -> Option<u32> {
    let mut used = used.clone();
    loop {
        let candidate = next_free(&used, min, max)?;
        if !taken(candidate) {
            return Some(candidate);
        }
        used.insert(candidate);
    }
}

/// Read a `login.defs` key as `u32`, ignoring negative or overflowing values.
fn get_u32(defs: &LoginDefs, key: &str) -> Option<u32> {
    defs.get_i64(key).and_then(|v| u32::try_from(v).ok())
}

/// The allocation range for one ID kind, from `login.defs`.
///
/// `kind` is `UID` or `GID`; the system ranges use the same keys with a `SYS_`
/// prefix. The two kinds share their defaults, which is why one function
/// serves both: regular accounts 1000-60000, system accounts 101-999.
fn id_range(defs: &LoginDefs, kind: &str, system: bool) -> (u32, u32) {
    let (prefix, (default_min, default_max)) = if system {
        ("SYS_", (101, 999))
    } else {
        ("", (1000, 60000))
    };
    let min = get_u32(defs, &format!("{prefix}{kind}_MIN")).unwrap_or(default_min);
    let max = get_u32(defs, &format!("{prefix}{kind}_MAX")).unwrap_or(default_max);
    (min, max)
}

/// Get the UID allocation range from `login.defs`.
///
/// Returns `(min, max)`. When `system` is `true`, uses `SYS_UID_MIN` /
/// `SYS_UID_MAX` (defaults 101 / 999). Otherwise uses `UID_MIN` /
/// `UID_MAX` (defaults 1000 / 60000).
#[must_use]
pub fn uid_range(defs: &LoginDefs, system: bool) -> (u32, u32) {
    id_range(defs, "UID", system)
}

/// Get the GID allocation range from `login.defs`.
///
/// Returns `(min, max)`. When `system` is `true`, uses `SYS_GID_MIN` /
/// `SYS_GID_MAX` (defaults 101 / 999). Otherwise uses `GID_MIN` /
/// `GID_MAX` (defaults 1000 / 60000).
#[must_use]
pub fn gid_range(defs: &LoginDefs, system: bool) -> (u32, u32) {
    id_range(defs, "GID", system)
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

    // --- allocation policy ---
    //
    // The policy is exercised through `next_free`, which takes the set of used
    // IDs directly. `next_uid` and `next_gid` also consult NSS, so a test that
    // called them would depend on which accounts happen to exist on the
    // machine running it -- and on a typical container, 1000 and 1001 do.

    fn used_uids(uids: &[u32]) -> HashSet<u32> {
        make_passwd_entries(uids).iter().map(|e| e.uid).collect()
    }

    fn used_gids(gids: &[u32]) -> HashSet<u32> {
        make_group_entries(gids).iter().map(|e| e.gid).collect()
    }

    #[test]
    fn test_next_free_empty_range_starts_at_the_minimum() {
        assert_eq!(next_free(&HashSet::new(), 1000, 1005), Some(1000));
    }

    // Not the gap at 1002: reusing a deleted account's UID would hand the new
    // user its leftover files. shadow-utils allocates past the highest in use.
    #[test]
    fn test_next_free_goes_past_the_highest_in_use() {
        assert_eq!(
            next_free(&used_uids(&[1000, 1001, 1003]), 1000, 1005),
            Some(1004)
        );
    }

    // Only once the top of the range is taken does it fall back to a gap.
    #[test]
    fn test_next_free_falls_back_to_a_gap_when_the_range_top_is_used() {
        assert_eq!(
            next_free(&used_uids(&[1000, 1001, 1003, 1004, 1005]), 1000, 1005),
            Some(1002)
        );
    }

    // IDs outside the range must not push the allocation past the maximum.
    #[test]
    fn test_next_free_ignores_ids_outside_the_range() {
        assert_eq!(
            next_free(&used_uids(&[0, 65534, 1000]), 1000, 1005),
            Some(1001)
        );
    }

    #[test]
    fn test_next_free_exhausted_range() {
        assert_eq!(next_free(&used_uids(&[100, 101, 102]), 100, 102), None);
        assert_eq!(next_free(&used_uids(&[500]), 500, 500), None);
    }

    #[test]
    fn test_next_free_single_value_range() {
        assert_eq!(next_free(&HashSet::new(), 500, 500), Some(500));
    }

    #[test]
    fn test_next_free_applies_to_gids_the_same_way() {
        assert_eq!(next_free(&used_gids(&[1000, 1002]), 1000, 1005), Some(1003));
        assert_eq!(
            next_free(&used_gids(&[1000, 1002, 1003, 1004, 1005]), 1000, 1005),
            Some(1001)
        );
        assert_eq!(next_free(&used_gids(&[10, 11, 12]), 10, 12), None);
    }

    // --- allocation against the live system ---

    /// Whatever the machine looks like, an allocated ID must be inside the
    /// range, absent from the entries given, and unknown to NSS.
    #[test]
    fn test_next_uid_returns_an_id_nobody_holds() {
        let entries = make_passwd_entries(&[1000]);
        let (min, max) = (60_100, 60_200);
        let uid = next_uid(&entries, min, max, Scope::IncludingNameService)
            .expect("a free UID in an unused range");
        assert!((min..=max).contains(&uid));
        assert!(
            matches!(crate::process::getpwuid(uid), Ok(None)),
            "allocated UID {uid} is already known to NSS"
        );
    }

    #[test]
    fn test_next_gid_returns_an_id_nobody_holds() {
        let entries = make_group_entries(&[1000]);
        let (min, max) = (60_100, 60_200);
        let gid = next_gid(&entries, min, max, Scope::IncludingNameService)
            .expect("a free GID in an unused range");
        assert!((min..=max).contains(&gid));
        assert!(
            matches!(crate::process::gid_exists(gid), Ok(false)),
            "allocated GID {gid} is already known to NSS"
        );
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

    // --- NSS-aware allocation ---

    /// A UID absent from /etc/passwd may still belong to a directory account.
    /// Handing it out would give two accounts one ID, and the kernel cannot
    /// tell them apart: the new local user would own the other one's files.
    #[test]
    fn test_allocation_skips_ids_nss_already_knows() {
        let used: HashSet<u32> = [1000].into_iter().collect();
        // 1001 and 1002 exist in a directory but not in the local file.
        let directory = |id: u32| id == 1001 || id == 1002;
        assert_eq!(next_free_checked(&used, 1000, 1005, &directory), Some(1003));
    }

    #[test]
    fn test_allocation_fails_when_the_directory_claims_the_range() {
        let used: HashSet<u32> = HashSet::new();
        assert_eq!(next_free_checked(&used, 1000, 1002, &|_| true), None);
    }

    #[test]
    fn test_allocation_without_a_directory_matches_the_plain_policy() {
        let used: HashSet<u32> = [1000, 1001, 1003].into_iter().collect();
        assert_eq!(
            next_free_checked(&used, 1000, 1005, &|_| false),
            next_free(&used, 1000, 1005)
        );
    }

    /// A prefixed run must not consult the name service: those files describe
    /// another system, and this one's accounts say nothing about it.
    #[test]
    fn test_files_only_scope_ignores_the_name_service() {
        // uid 0 exists in NSS on any system, so IncludingNameService would
        // have to skip it while FilesOnly hands it out.
        let entries = make_passwd_entries(&[]);
        assert_eq!(next_uid(&entries, 0, 0, Scope::FilesOnly).expect("uid"), 0);
        assert!(next_uid(&entries, 0, 0, Scope::IncludingNameService).is_err());
    }

    #[test]
    fn test_scope_for_prefix() {
        assert_eq!(Scope::for_prefix(true), Scope::FilesOnly);
        assert_eq!(Scope::for_prefix(false), Scope::IncludingNameService);
    }
}
