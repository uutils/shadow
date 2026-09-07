// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore gshadow initgroups setgid newgrp

//! Entering a group — the half `newgrp(1)` and `sg(1)` share.
//!
//! Both tools do the same three things before they diverge: work out which
//! group the caller asked for, decide whether the caller is entitled to it,
//! and move the process into it. Only what follows differs — `newgrp` replaces
//! the caller's shell, `sg` runs a single command — so everything up to that
//! point lives here.
//!
//! Distributions that ship the GNU suite make `sg` a symlink to `newgrp`, so
//! the two cannot disagree there. Keeping the shared half in one module is
//! what buys us the same guarantee.

use std::ffi::CString;

use crate::error::ShadowError;
use crate::sysroot::SysRoot;

/// The caller, resolved once, so the tool can exec their shell afterwards.
#[derive(Debug, Clone)]
pub struct Session {
    /// The caller's login name.
    pub username: String,
    /// The login shell from the caller's passwd entry — never `$SHELL`, which
    /// is attacker-controlled in a setuid-root process.
    pub shell: String,
    /// The home directory from the passwd entry. May be empty.
    pub home: String,
}

/// The shell to fall back to when the passwd entry names none.
const DEFAULT_SHELL: &str = "/bin/sh";

/// Whether `username` may enter the group without knowing its password.
///
/// Membership is either holding the group as one's primary GID or appearing in
/// its member list. Being listed as a group *administrator* in `/etc/gshadow`
/// is deliberately not enough: an administrator may change the membership, and
/// can therefore add themselves, but until they do they are not a member.
fn is_member(username: &str, user_gid: u32, target_gid: u32, members: &[String]) -> bool {
    user_gid == target_gid || members.iter().any(|m| m == username)
}

/// The group's password hash, or `None` when it has no usable one.
///
/// `!`, `*`, `!!` and the empty string all mean "no password will ever match".
fn group_password(root: &SysRoot, group_name: &str) -> Option<String> {
    let entries = crate::gshadow::read_gshadow_file(&root.gshadow_path()).ok()?;
    let entry = entries.iter().find(|e| e.name == group_name)?;
    if matches!(entry.passwd.as_str(), "" | "!" | "*" | "!!") {
        return None;
    }
    Some(entry.passwd.clone())
}

/// Prompt for the group password and check it.
///
/// The prompt is unconditional. A group with no password could be refused
/// outright without ever asking, but then the presence of a prompt would tell
/// any caller which groups have passwords set and which do not, and that is a
/// map of the ones worth attacking. Asking either way costs one wasted prompt
/// and answers nothing.
fn authenticate(root: &SysRoot, group_name: &str) -> Result<(), ShadowError> {
    let hash = group_password(root, group_name);

    let password = crate::tty::read_password("Password: ")
        .map_err(|e| ShadowError::Auth(format!("cannot read the password: {e}").into()))?;

    let Some(hash) = hash else {
        return Err(ShadowError::Auth(
            format!("permission denied for group '{group_name}'").into(),
        ));
    };

    if crate::crypt::verify_password(&password, &hash)? {
        Ok(())
    } else {
        Err(ShadowError::Auth("incorrect password".into()))
    }
}

/// Resolve `group`, authorize the caller, and move the process into it.
///
/// `group` is `None` when the caller named no group, which both tools take to
/// mean their own primary group. That leaves the group ID where it was, but it
/// still reinitializes the supplementary set, which is what POSIX asks for.
///
/// On return the process holds the target group, the caller's full
/// supplementary set, and the caller's own real UID — so a setuid-root caller
/// has already given the privilege back before the shell is reached.
pub fn enter(root: &SysRoot, group: Option<&str>) -> Result<Session, ShadowError> {
    let real_uid = rustix::process::getuid().as_raw();
    let entry = crate::hardening::lookup_passwd_entry_by_uid(real_uid)?;

    let target_gid = match group {
        None => entry.gid,
        Some(name) => {
            let group_path = root.group_path();
            let groups = crate::group::read_group_file(&group_path).map_err(|e| {
                ShadowError::Other(format!("cannot read {}: {e}", group_path.display()).into())
            })?;
            let Some(target) = groups.iter().find(|g| g.name == name) else {
                // GNU's wording, which scripts match on.
                return Err(ShadowError::Validation("no such group".into()));
            };

            if !crate::hardening::caller_is_root()
                && !is_member(&entry.name, entry.gid, target.gid, &target.members)
            {
                authenticate(root, name)?;
            }
            target.gid
        }
    };

    crate::process::setgid(target_gid).map_err(|e| {
        ShadowError::Other(format!("cannot set group ID to {target_gid}: {e}").into())
    })?;

    // POSIX has newgrp reinitialize the group list; without this the new shell
    // would carry the supplementary groups of the old one.
    let username_c = CString::new(entry.name.as_str())
        .map_err(|_| ShadowError::Validation("invalid username".into()))?;
    crate::process::initgroups(&username_c, target_gid)
        .map_err(|e| ShadowError::Other(format!("cannot initialize groups: {e}").into()))?;

    // The group the caller started in has to survive the switch. `initgroups`
    // rebuilds the list from the member lists in `/etc/group`, and a primary
    // group is never named there, so on its own it drops the caller's original
    // group -- `sg staff` would cost them access to their own files. Adding it
    // back is what the GNU tools do, and it has to happen while the privilege
    // to call setgroups(2) is still in hand.
    if entry.gid != target_gid {
        let mut groups = crate::process::getgroups()
            .map_err(|e| ShadowError::Other(format!("cannot read the group list: {e}").into()))?;
        if !groups.contains(&entry.gid) {
            groups.push(entry.gid);
            crate::process::setgroups(&groups).map_err(|e| {
                ShadowError::Other(format!("cannot set the group list: {e}").into())
            })?;
        }
    }

    // Give the setuid privilege back before anything the caller chose runs.
    if rustix::process::geteuid().as_raw() != real_uid {
        crate::process::setuid(real_uid)
            .map_err(|e| ShadowError::Other(format!("cannot drop privileges: {e}").into()))?;
    }

    Ok(Session {
        username: entry.name,
        shell: if entry.shell.is_empty() {
            DEFAULT_SHELL.to_string()
        } else {
            entry.shell
        },
        home: entry.home,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A locked, disabled, or absent group password is never a usable hash,
    /// however it is spelled.
    #[test]
    fn test_group_password_recognizes_no_password() {
        let dir = tempfile::tempdir().expect("tempdir");
        for locked in ["!", "*", "!!", ""] {
            std::fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
            std::fs::write(
                dir.path().join("etc/gshadow"),
                format!("staff:{locked}::\n"),
            )
            .expect("write");
            let root = SysRoot::new(Some(dir.path()));
            assert!(
                group_password(&root, "staff").is_none(),
                "{locked:?} should not be a usable password"
            );
        }
    }

    #[test]
    fn test_group_password_returns_the_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        std::fs::write(
            dir.path().join("etc/gshadow"),
            "staff:$6$saltsalt$hashhere::\n",
        )
        .expect("write");
        let root = SysRoot::new(Some(dir.path()));
        assert_eq!(
            group_password(&root, "staff").as_deref(),
            Some("$6$saltsalt$hashhere")
        );
    }

    #[test]
    fn test_group_password_missing_group_and_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("etc")).expect("mkdir");
        std::fs::write(dir.path().join("etc/gshadow"), "other:!::\n").expect("write");
        let root = SysRoot::new(Some(dir.path()));
        assert!(group_password(&root, "staff").is_none());

        let empty = tempfile::tempdir().expect("tempdir");
        let root = SysRoot::new(Some(empty.path()));
        assert!(group_password(&root, "staff").is_none());
    }
}
