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

#[derive(Debug)]
enum UserdelError {
    CantUpdatePasswd(String),
    CantUpdateGroup(String),
    CantRemoveHome(String),
    AlreadyPrinted(i32),
}

impl fmt::Display for UserdelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CantUpdatePasswd(msg)
            | Self::CantUpdateGroup(msg)
            | Self::CantRemoveHome(msg) => f.write_str(msg),
            Self::AlreadyPrinted(_) => Ok(()),
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
            Self::AlreadyPrinted(code) => *code,
        }
    }
}

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let _ = shadow_core::hardening::harden_process();

    let matches = match uu_app().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            if !e.use_stderr() {
                return Ok(());
            }
            return Err(UserdelError::AlreadyPrinted(exit_codes::INVALID_SYNTAX).into());
        }
    };

    let Some(login) = matches.get_one::<String>(options::LOGIN) else {
        return Err(UserdelError::AlreadyPrinted(exit_codes::INVALID_SYNTAX).into());
    };
    let remove_home = matches.get_flag(options::REMOVE);
    let prefix = matches
        .get_one::<String>(options::PREFIX)
        .or_else(|| matches.get_one::<String>(options::ROOT))
        .map(Path::new);
    let root = SysRoot::new(prefix);

    // Must be root.
    if !rustix::process::getuid().is_root() {
        return Err(UserdelError::CantUpdatePasswd("Permission denied.".into()).into());
    }

    // Read the user's home directory and UID from /etc/passwd BEFORE removing
    // the entry (needed for home removal and audit logging).
    let passwd_path = root.passwd_path();
    let pre_entries = passwd::read_passwd_file(&passwd_path)
        .map_err(|e| UserdelError::CantUpdatePasswd(format!("cannot read passwd: {e}")))?;
    let saved_uid = pre_entries
        .iter()
        .find(|e| e.name == *login)
        .map_or(0, |e| e.uid);
    let saved_home = if remove_home {
        pre_entries
            .iter()
            .find(|e| e.name == *login)
            .map(|e| e.home.clone())
    } else {
        None
    };

    // Block signals for the file-modification critical section only.
    // Dropped before home removal so long-running deletions remain interruptible.
    let signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| UserdelError::CantUpdatePasswd(format!("cannot block signals: {e}")))?;

    // 1. Remove from /etc/passwd
    remove_entry_from_file::<PasswdEntry>(&passwd_path, login, "passwd")
        .map_err(UserdelError::CantUpdatePasswd)?;

    // 2. Remove from /etc/shadow
    let shadow_path = root.shadow_path();
    if shadow_path.exists() {
        let _ = remove_entry_from_file::<ShadowEntry>(&shadow_path, login, "shadow");
    }

    // 3. Remove from /etc/group membership lists
    let group_path = root.group_path();
    if group_path.exists() {
        remove_from_group_members(&group_path, login).map_err(UserdelError::CantUpdateGroup)?;
    }

    // 4. Remove from /etc/gshadow membership lists
    let gshadow_path = root.resolve("/etc/gshadow");
    if gshadow_path.exists() {
        let _ = remove_from_gshadow_members(&gshadow_path, login);
    }

    // Restore signals before potentially long-running home removal.
    drop(signals);

    // 5. Optionally remove home directory (using the path saved from passwd).
    if remove_home {
        if let Some(ref home_dir) = saved_home
            && !home_dir.is_empty()
        {
            let home = root.resolve(home_dir);
            safe_remove_home(&home)?;
        }

        // Remove mail spool.
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
                .help("Proceed even if the user is logged in")
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
                .value_name("CHROOT_DIR")
                .help("Chroot into CHROOT_DIR before applying changes"),
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
/// - Refuse to remove protected system directories.
/// - Refuse to follow symlinks at the top level.
/// - Refuse to remove a mount point (different device than parent).
fn safe_remove_home(home: &Path) -> Result<(), UserdelError> {
    if !home.exists() {
        return Ok(());
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
        use std::io::Write;
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

    let mut entries =
        group::read_group_file(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let mut changed = false;
    for entry in &mut entries {
        let before = entry.members.len();
        entry.members.retain(|m| m != login);
        if entry.members.len() != before {
            changed = true;
        }
    }

    if changed {
        atomic::atomic_write(path, |f| group::write_group(&entries, f))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }

    drop(lock);
    Ok(())
}

/// Remove a username from all gshadow membership and admin lists.
fn remove_from_gshadow_members(path: &Path, login: &str) -> Result<(), String> {
    let lock = FileLock::acquire(path).map_err(|e| format!("cannot lock gshadow file: {e}"))?;

    let mut entries = gshadow::read_gshadow_file(path)
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
        atomic::atomic_write(path, |f| gshadow::write_gshadow(&entries, f))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }

    drop(lock);
    Ok(())
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
