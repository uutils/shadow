// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore userdel

//! `userdel` — delete a user account and related files.
//!
//! Drop-in replacement for GNU shadow-utils `userdel(8)`.

use std::fmt;
use std::path::Path;

use clap::{Arg, ArgAction, Command};
use uucore::error::{UError, UResult};

use shadow_core::audit;
use shadow_core::group::{self};
use shadow_core::gshadow::{self};
use shadow_core::lock::FileLock;
use shadow_core::passwd::{self, PasswdEntry};
use shadow_core::shadow::ShadowEntry;
use shadow_core::sysroot::SysRoot;
use shadow_core::{atomic, nscd};

mod options {
    pub const FORCE: &str = "force";
    pub const REMOVE: &str = "remove";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
    pub const LOGIN: &str = "LOGIN";
}

mod exit_codes {
    pub const CANT_UPDATE_PASSWD: i32 = 1;
    pub const INVALID_SYNTAX: i32 = 2;
    pub const CANT_UPDATE_GROUP: i32 = 10;
    pub const CANT_REMOVE_HOME: i32 = 12;
}

mod extra_exit_codes {
    pub const USER_NOT_FOUND: i32 = 6;
}

#[derive(Debug)]
enum UserdelError {
    CantUpdatePasswd(String),
    CantUpdateGroup(String),
    CantRemoveHome(String),
    UserNotFound(String),
}

impl fmt::Display for UserdelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CantUpdatePasswd(msg)
            | Self::CantUpdateGroup(msg)
            | Self::CantRemoveHome(msg)
            | Self::UserNotFound(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for UserdelError {}

impl UError for UserdelError {
    fn code(&self) -> i32 {
        match self {
            Self::CantUpdatePasswd(_) => exit_codes::CANT_UPDATE_PASSWD,
            Self::CantUpdateGroup(_) => exit_codes::CANT_UPDATE_GROUP,
            Self::CantRemoveHome(_) => exit_codes::CANT_REMOVE_HOME,
            Self::UserNotFound(_) => extra_exit_codes::USER_NOT_FOUND,
        }
    }
}

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    let Some(matches) =
        shadow_core::cli::parse_args(uu_app(), args, |_| exit_codes::INVALID_SYNTAX)?
    else {
        return Ok(());
    };

    let Some(login) = matches.get_one::<String>(options::LOGIN) else {
        return Err(shadow_core::cli::AlreadyPrinted(exit_codes::INVALID_SYNTAX).into());
    };
    let remove_home = matches.get_flag(options::REMOVE);
    let force = matches.get_flag(options::FORCE);
    // --root DIR is a real chroot: the account files come from the new root,
    // and so does every absolute path read out of them. Done before anything
    // else, so nothing has resolved a path against the old root yet.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        shadow_core::hardening::chroot_into(std::path::Path::new(chroot_dir))
            .map_err(|e| UserdelError::CantUpdatePasswd(e.to_string()))?;
    }

    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);

    // Must be root.
    if !rustix::process::getuid().is_root() {
        return Err(
            UserdelError::CantUpdatePasswd(shadow_core::os_error::permission_denied()).into(),
        );
    }

    // Read the account BEFORE removing it: home, uid and primary gid are
    // needed for home removal, the private-group cleanup and the audit event.
    let passwd_path = root.passwd_path();
    let pre_entries = passwd::read_passwd_file(&passwd_path)
        .map_err(|e| UserdelError::CantUpdatePasswd(format!("cannot read passwd: {e}")))?;

    let target = pre_entries.iter().find(|e| e.name == *login).cloned();

    // userdel(8): exit 6 when the user does not exist. With -f the removal of
    // whatever remains (group membership, subordinate IDs) still proceeds.
    if target.is_none() && !force {
        return Err(UserdelError::UserNotFound(format!("user '{login}' does not exist")).into());
    }

    let saved_uid = target.as_ref().map_or(0, |e| e.uid);
    let primary_gid = target.as_ref().map(|e| e.gid);
    let saved_home = target.as_ref().map(|e| e.home.clone());
    // A home shared with another still-present account must not be deleted
    // unless forced (userdel(8): -r removes it "even if another user uses the
    // same home directory" only with -f).
    let home_shared_by_other = target.as_ref().is_some_and(|t| {
        !t.home.is_empty()
            && pre_entries
                .iter()
                .any(|e| e.name != *login && e.home == t.home)
    });

    // USERGROUPS_ENAB defaults to "yes" when unset or the file is absent.
    let usergroups_enab = shadow_core::login_defs::LoginDefs::load(&root.login_defs_path())
        .ok()
        .and_then(|d| d.get("USERGROUPS_ENAB").map(|v| v == "yes"))
        .unwrap_or(true);

    // Block signals for the file-modification critical section only.
    // Dropped before home removal so long-running deletions remain interruptible.
    let signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| UserdelError::CantUpdatePasswd(format!("cannot block signals: {e}")))?;

    // 1. Remove from /etc/passwd (only if present; with -f it may be absent).
    if target.is_some() {
        remove_entry_from_file::<PasswdEntry>(&passwd_path, login, "passwd")
            .map_err(UserdelError::CantUpdatePasswd)?;
    }

    // 2. Remove from /etc/shadow (a missing entry is not an error).
    let shadow_path = root.shadow_path();
    if shadow_path.exists() {
        let _ = remove_entry_from_file::<ShadowEntry>(&shadow_path, login, "shadow");
    }

    // 3. Remove from /etc/group membership lists.
    let group_path = root.group_path();
    if group_path.exists() {
        remove_from_group_members(&group_path, login).map_err(UserdelError::CantUpdateGroup)?;
    }

    // 4. Remove from /etc/gshadow membership lists.
    let gshadow_path = root.gshadow_path();
    if gshadow_path.exists() {
        let _ = remove_from_gshadow_members(&gshadow_path, login);
    }

    // 5. Remove the user's private group (USERGROUPS_ENAB), the counterpart of
    //    what useradd creates.
    if usergroups_enab {
        remove_user_private_group(&root, login, primary_gid, &pre_entries, force)
            .map_err(UserdelError::CantUpdateGroup)?;
    }

    // 6. Remove any subordinate UID/GID ranges owned by the user, so a later
    //    user of the same name does not inherit them.
    remove_subid_rows(&root.subuid_path(), login);
    remove_subid_rows(&root.subgid_path(), login);

    // Restore signals before potentially long-running home removal.
    drop(signals);

    // 7. Optionally remove the home directory and mail spool.
    if remove_home {
        if let Some(ref home_dir) = saved_home
            && !home_dir.is_empty()
        {
            let home = root.resolve(home_dir);
            safe_remove_home(&home, saved_uid, force, home_shared_by_other)?;
        }

        let mail = root.resolve(&format!("/var/mail/{login}"));
        if mail.exists() {
            let _ = std::fs::remove_file(&mail);
        }
    }

    nscd::invalidate_cache("passwd");
    nscd::invalidate_cache("group");

    audit::log_user_event("DEL_USER", login, saved_uid, true);

    Ok(())
}

#[must_use]
pub fn uu_app() -> Command {
    Command::new("userdel")
        .about("Remove a user account (and optionally its files)")
        .override_usage("userdel [options] LOGIN")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::FORCE)
                .short('f')
                .long("force")
                .help(
                    "Remove even if the user does not exist, and with -r remove the home \
                     directory even if it is not owned by the user or is shared",
                )
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::REMOVE)
                .short('r')
                .long("remove")
                .help("Also delete the home directory and mail spool")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .value_name("ROOT_DIR")
                .help("Locate the system files under ROOT_DIR instead of /"),
        )
        .arg(
            Arg::new(options::PREFIX)
                .short('P')
                .long("prefix")
                .value_name("PREFIX_DIR")
                .help("Directory prefix"),
        )
        .arg(
            Arg::new(options::LOGIN)
                .required(true)
                .index(1)
                .help("Account to remove"),
        )
}

// ---------------------------------------------------------------------------
// Safe home directory removal
// ---------------------------------------------------------------------------

/// Directories that must never be removed, even if listed as a user's home.
const PROTECTED_DIRS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt", "/opt",
    "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
];

/// Safely remove a home directory with multiple safeguards:
/// - Refuse a home shared with another account, or not owned by the user,
///   unless `force` (userdel(8) ties both to `-f`).
/// - Refuse to remove protected system directories.
/// - Refuse to follow symlinks at the top level.
/// - Refuse to remove a mount point (different device than parent).
fn safe_remove_home(
    home: &Path,
    owner_uid: u32,
    force: bool,
    shared_by_other: bool,
) -> Result<(), UserdelError> {
    if !home.exists() {
        return Ok(());
    }

    if shared_by_other && !force {
        return Err(UserdelError::CantRemoveHome(format!(
            "not removing '{}': it is used by another user (use -f to force)",
            home.display()
        )));
    }

    // Resolve symlinks and relative components so tricks like
    // `/home/../etc` cannot bypass the protected-directory check.
    let canonical = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_owned());
    let canonical_str = canonical.to_string_lossy();
    for &protected in PROTECTED_DIRS {
        if canonical_str == protected {
            return Err(UserdelError::CantRemoveHome(format!(
                "refusing to remove protected directory '{}'",
                home.display()
            )));
        }
    }

    // Refuse to follow symlinks at the top level.
    let meta = std::fs::symlink_metadata(home).map_err(|e| {
        UserdelError::CantRemoveHome(format!("cannot stat '{}': {e}", home.display()))
    })?;

    if meta.file_type().is_symlink() {
        return Err(UserdelError::CantRemoveHome(format!(
            "refusing to follow symlink at '{}'",
            home.display()
        )));
    }

    // Refuse a directory the user does not own, unless forced: it may be a
    // shared or system path the account merely pointed at.
    {
        use std::os::unix::fs::MetadataExt;
        if !force && meta.uid() != owner_uid {
            return Err(UserdelError::CantRemoveHome(format!(
                "not removing '{}': owned by uid {} not {owner_uid} (use -f to force)",
                home.display(),
                meta.uid()
            )));
        }
    }

    // Refuse to remove a mount point (device ID differs from parent).
    if let Some(parent) = home.parent()
        && parent.exists()
    {
        use std::os::unix::fs::MetadataExt;
        let parent_meta = std::fs::metadata(parent).map_err(|e| {
            UserdelError::CantRemoveHome(format!("cannot stat parent of '{}': {e}", home.display()))
        })?;
        if meta.dev() != parent_meta.dev() {
            return Err(UserdelError::CantRemoveHome(format!(
                "refusing to remove mount point at '{}'",
                home.display()
            )));
        }
    }

    std::fs::remove_dir_all(&canonical).map_err(|e| {
        UserdelError::CantRemoveHome(format!("cannot remove '{}': {e}", canonical.display()))
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

trait HasName {
    fn name(&self) -> &str;
}

impl HasName for PasswdEntry {
    fn name(&self) -> &str {
        &self.name
    }
}

impl HasName for ShadowEntry {
    fn name(&self) -> &str {
        &self.name
    }
}

/// Remove an entry by name from a file (passwd or shadow format).
fn remove_entry_from_file<T>(path: &Path, login: &str, file_label: &str) -> Result<(), String>
where
    T: std::str::FromStr + std::fmt::Display + HasName,
    T::Err: std::fmt::Display,
{
    let lock = FileLock::acquire(path).map_err(|e| format!("cannot lock {file_label}: {e}"))?;

    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let mut found = false;
    let mut kept_lines = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            kept_lines.push(line.to_string());
            continue;
        }

        if let Ok(entry) = line.parse::<T>()
            && entry.name() == login
        {
            found = true;
            continue; // skip this entry
        }
        kept_lines.push(line.to_string());
    }

    if !found {
        drop(lock);
        return Err(format!("user '{login}' does not exist in {file_label}"));
    }

    atomic::atomic_write(path, |f| {
        for line in &kept_lines {
            writeln!(f, "{line}")?;
        }
        Ok(())
    })
    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;

    drop(lock);
    Ok(())
}

/// Remove a username from all group membership lists in /etc/group.
fn remove_from_group_members(path: &Path, login: &str) -> Result<(), String> {
    let lock = FileLock::acquire(path).map_err(|e| format!("cannot lock group file: {e}"))?;

    let (mut entries, layout) = group::read_group_with_layout(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let mut changed = false;
    for entry in &mut entries {
        let before = entry.members.len();
        entry.members.retain(|m| m != login);
        if entry.members.len() != before {
            changed = true;
        }
    }

    if changed {
        atomic::atomic_write(path, |f| {
            group::write_group_with_layout(&entries, &layout, f)
        })
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }

    drop(lock);
    Ok(())
}

/// Remove a username from all gshadow membership and admin lists.
fn remove_from_gshadow_members(path: &Path, login: &str) -> Result<(), String> {
    let lock = FileLock::acquire(path).map_err(|e| format!("cannot lock gshadow file: {e}"))?;

    let (mut entries, layout) = gshadow::read_gshadow_with_layout(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let mut changed = false;
    for entry in &mut entries {
        let before_m = entry.members.len();
        let before_a = entry.admins.len();
        entry.members.retain(|m| m != login);
        entry.admins.retain(|a| a != login);
        if entry.members.len() != before_m || entry.admins.len() != before_a {
            changed = true;
        }
    }

    if changed {
        atomic::atomic_write(path, |f| {
            gshadow::write_gshadow_with_layout(&entries, &layout, f)
        })
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }

    drop(lock);
    Ok(())
}

/// Remove the user's private group — the group named after the login that
/// `useradd` creates under `USERGROUPS_ENAB`.
///
/// It is removed only when it has no members left; and, unless `force`, only
/// when it is not another user's primary group (userdel(8): `-f` removes it
/// "even if it is the primary group of another user"). Membership stripping
/// has already run, so `members` holds only supplementary members.
fn remove_user_private_group(
    root: &SysRoot,
    login: &str,
    saved_gid: Option<u32>,
    pre_entries: &[PasswdEntry],
    force: bool,
) -> Result<(), String> {
    let group_path = root.group_path();
    if !group_path.exists() {
        return Ok(());
    }

    let group_lock =
        FileLock::acquire(&group_path).map_err(|e| format!("cannot lock group file: {e}"))?;
    let (mut entries, group_layout) = group::read_group_with_layout(&group_path)
        .map_err(|e| format!("cannot read group: {e}"))?;

    let Some(idx) = entries.iter().position(|g| g.name == login) else {
        return Ok(());
    };
    // Keep it if other users still belong to it.
    if !entries[idx].members.is_empty() {
        return Ok(());
    }
    let gid = entries[idx].gid;
    // Keep it if it is a private group whose GID is not the user's primary
    // one (then it is not really this user's), or another user's primary
    // group, unless forced.
    if saved_gid != Some(gid) && !force {
        return Ok(());
    }
    if !force && pre_entries.iter().any(|e| e.name != login && e.gid == gid) {
        return Ok(());
    }

    entries.remove(idx);
    write_group_or_empty(&group_path, &entries, &group_layout)
        .map_err(|e| format!("cannot write group: {e}"))?;
    drop(group_lock);

    // Mirror the removal in gshadow.
    let gshadow_path = root.gshadow_path();
    if gshadow_path.exists() {
        let gs_lock =
            FileLock::acquire(&gshadow_path).map_err(|e| format!("cannot lock gshadow: {e}"))?;
        if let Ok((mut gs, gshadow_layout)) = gshadow::read_gshadow_with_layout(&gshadow_path) {
            let before = gs.len();
            gs.retain(|g| g.name != login);
            if gs.len() != before {
                write_gshadow_or_empty(&gshadow_path, &gs, &gshadow_layout)
                    .map_err(|e| format!("cannot write gshadow: {e}"))?;
            }
        }
        drop(gs_lock);
    }

    Ok(())
}

/// Remove every subordinate-ID row owned by `login` from a subuid/subgid file.
///
/// Best-effort: a missing file is nothing to do, and if the user held the only
/// rows the now-empty file is unlinked (an absent file means "no ranges",
/// which the atomic writer's zero-length guard would otherwise forbid).
fn remove_subid_rows(path: &Path, login: &str) {
    use shadow_core::subid;

    if !path.exists() {
        return;
    }
    let Ok(lock) = FileLock::acquire(path) else {
        return;
    };
    if let Ok((mut entries, layout)) = subid::read_subid_with_layout(path) {
        let before = entries.len();
        entries.retain(|e| e.name != login);
        if entries.len() != before {
            if entries.is_empty() && layout.is_empty() {
                let _ = std::fs::remove_file(path);
            } else {
                let _ = atomic::atomic_write(path, |f| {
                    subid::write_subid_with_layout(&entries, &layout, f)
                });
            }
        }
    }
    drop(lock);
}

/// Write group entries, unlinking the file instead if the result is empty
/// (the atomic writer refuses a zero-length file, but an empty group file is
/// valid — and only reached in a fully torn-down `--prefix` tree).
fn write_group_or_empty(
    path: &Path,
    entries: &[group::GroupEntry],
    layout: &group::Layout,
) -> Result<(), shadow_core::error::ShadowError> {
    if entries.is_empty() && layout.is_empty() {
        let _ = std::fs::remove_file(path);
        Ok(())
    } else {
        atomic::atomic_write(path, |f| group::write_group_with_layout(entries, layout, f))
    }
}

fn write_gshadow_or_empty(
    path: &Path,
    entries: &[gshadow::GshadowEntry],
    layout: &gshadow::Layout,
) -> Result<(), shadow_core::error::ShadowError> {
    if entries.is_empty() && layout.is_empty() {
        let _ = std::fs::remove_file(path);
        Ok(())
    } else {
        atomic::atomic_write(path, |f| {
            gshadow::write_gshadow_with_layout(entries, layout, f)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    #[test]
    fn test_login_required() {
        let result = uu_app().try_get_matches_from(["userdel"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_flag() {
        let m = uu_app()
            .try_get_matches_from(["userdel", "-r", "testuser"])
            .unwrap();
        assert!(m.get_flag(options::REMOVE));
    }

    #[test]
    fn test_force_flag() {
        let m = uu_app()
            .try_get_matches_from(["userdel", "-f", "testuser"])
            .unwrap();
        assert!(m.get_flag(options::FORCE));
    }

    // Duplicated from tests/common/mod.rs — unit tests inside the crate
    // cannot import from the workspace-level tests directory.
    fn skip_unless_root() -> bool {
        !rustix::process::geteuid().is_root()
    }

    #[test]
    fn test_delete_user_from_passwd() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\ntestuser:x:1000:1000::/home/testuser:/bin/bash\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("shadow"),
            "root:$6$hash:19000:0:99999:7:::\ntestuser:$6$hash:19000:0:99999:7:::\n",
        )
        .unwrap();

        let args: Vec<std::ffi::OsString> = vec![
            "userdel".into(),
            "-P".into(),
            dir.path().as_os_str().to_owned(),
            "testuser".into(),
        ];
        let code = uumain(args.into_iter());
        assert_eq!(code, 0);

        let passwd = std::fs::read_to_string(etc.join("passwd")).unwrap();
        assert!(!passwd.contains("testuser"));
        assert!(passwd.contains("root"));
    }

    #[test]
    fn test_delete_nonexistent_user() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(etc.join("passwd"), "root:x:0:0:root:/root:/bin/bash\n").unwrap();
        std::fs::write(etc.join("shadow"), "root:$6$hash:19000:0:99999:7:::\n").unwrap();

        let args: Vec<std::ffi::OsString> = vec![
            "userdel".into(),
            "-P".into(),
            dir.path().as_os_str().to_owned(),
            "nouser".into(),
        ];
        let code = uumain(args.into_iter());
        assert_ne!(code, 0);
    }

    #[test]
    fn test_remove_from_group_members_list() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("group");
        std::fs::write(
            &path,
            "sudo:x:27:alice,testuser,bob\nusers:x:100:testuser\n",
        )
        .unwrap();

        remove_from_group_members(&path, "testuser").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("sudo:x:27:alice,bob"));
        assert!(content.contains("users:x:100:"));
        assert!(!content.contains("testuser"));
    }
}
