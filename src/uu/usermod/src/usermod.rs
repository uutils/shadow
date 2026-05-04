// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore usermod

//! `usermod` — modify a user account.
//!
//! Drop-in replacement for GNU shadow-utils `usermod(8)`.

use std::fmt;
use std::path::Path;

use clap::{Arg, ArgAction, Command};
use uucore::error::{UError, UResult};

use shadow_core::audit;
use shadow_core::group::{self};
use shadow_core::lock::FileLock;
use shadow_core::passwd::{self};
use shadow_core::shadow::{self};
use shadow_core::sysroot::SysRoot;
use shadow_core::{atomic, nscd, validate};

mod options {
    pub const COMMENT: &str = "comment";
    pub const HOME: &str = "home";
    pub const EXPIREDATE: &str = "expiredate";
    pub const INACTIVE: &str = "inactive";
    pub const GID: &str = "gid";
    pub const GROUPS: &str = "groups";
    pub const APPEND: &str = "append";
    pub const LOCK: &str = "lock";
    pub const UNLOCK: &str = "unlock";
    pub const LOGIN: &str = "login";
    pub const SHELL: &str = "shell";
    pub const UID: &str = "uid";
    pub const PASSWORD: &str = "password";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
    pub const USER: &str = "USER";
}

#[derive(Debug)]
enum UsermodError {
    CantUpdate(String),
    UserNotFound(String),
    UidInUse(String),
    AlreadyPrinted(i32),
}

impl fmt::Display for UsermodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CantUpdate(msg) | Self::UserNotFound(msg) | Self::UidInUse(msg) => {
                f.write_str(msg)
            }
            Self::AlreadyPrinted(_) => Ok(()),
        }
    }
}

impl std::error::Error for UsermodError {}

impl UError for UsermodError {
    fn code(&self) -> i32 {
        match self {
            Self::CantUpdate(_) => 1,
            Self::UserNotFound(_) => 6,
            Self::UidInUse(_) => 4,
            Self::AlreadyPrinted(c) => *c,
        }
    }
}

#[uucore::main]
#[allow(clippy::too_many_lines)]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let _ = shadow_core::hardening::harden_process();

    let matches = match uu_app().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            if !e.use_stderr() {
                return Ok(());
            }
            return Err(UsermodError::AlreadyPrinted(2).into());
        }
    };

    let Some(login) = matches.get_one::<String>(options::USER) else {
        return Err(UsermodError::AlreadyPrinted(2).into());
    };
    let prefix = matches
        .get_one::<String>(options::PREFIX)
        .or_else(|| matches.get_one::<String>(options::ROOT))
        .map(Path::new);
    let root = SysRoot::new(prefix);

    if !rustix::process::getuid().is_root() {
        return Err(UsermodError::CantUpdate("Permission denied.".into()).into());
    }

    // Block signals for the passwd lock→write critical section only.
    // Dropped before recursive_chown so long-running operations remain interruptible.
    let signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| UsermodError::CantUpdate(format!("cannot block signals: {e}")))?;

    // Modify /etc/passwd.
    let passwd_path = root.passwd_path();
    let lock = FileLock::acquire(&passwd_path)
        .map_err(|e| UsermodError::CantUpdate(format!("cannot lock: {e}")))?;

    let mut entries = passwd::read_passwd_file(&passwd_path)
        .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;

    let Some(idx) = entries.iter().position(|e| e.name == *login) else {
        drop(lock);
        return Err(UsermodError::UserNotFound(format!("user '{login}' does not exist")).into());
    };

    // Save the old UID and home dir before mutation so we can chown if needed.
    let old_uid = entries[idx].uid;
    let home_for_chown = entries[idx].home.clone();
    let home_is_changing = matches.get_one::<String>(options::HOME).is_some();

    // Check UID collision before mutating.
    if let Some(&uid) = matches.get_one::<u32>(options::UID) {
        if entries.iter().any(|e| e.uid == uid && e.name != *login) {
            drop(lock);
            return Err(UsermodError::UidInUse(format!("UID {uid} already in use")).into());
        }
        entries[idx].uid = uid;
    }

    if let Some(c) = matches.get_one::<String>(options::COMMENT) {
        entries[idx].gecos.clone_from(c);
    }
    if let Some(h) = matches.get_one::<String>(options::HOME) {
        entries[idx].home.clone_from(h);
    }
    if let Some(s) = matches.get_one::<String>(options::SHELL) {
        entries[idx].shell.clone_from(s);
    }
    if let Some(&gid) = matches.get_one::<u32>(options::GID) {
        entries[idx].gid = gid;
    }
    let new_login = matches.get_one::<String>(options::LOGIN);
    if let Some(new_name) = new_login {
        validate::validate_username(new_name)
            .map_err(|e| UsermodError::CantUpdate(format!("invalid login name: {e}")))?;
        entries[idx].name.clone_from(new_name);
    }

    let new_uid = entries[idx].uid;

    atomic::atomic_write(&passwd_path, |f| passwd::write_passwd(&entries, f))
        .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;
    drop(lock);

    // Restore signals before potentially long-running recursive chown.
    drop(signals);

    // If the UID changed and the home directory was not explicitly moved,
    // recursively chown the existing home directory to the new UID.
    // Only files owned by old_uid are touched (files owned by other users
    // are left alone, matching GNU shadow-utils behavior).
    if new_uid != old_uid && !home_is_changing && !home_for_chown.is_empty() {
        let home_path = root.resolve(&home_for_chown);
        if home_path.exists() {
            recursive_chown(&home_path, old_uid, new_uid);
        }
    }

    // Shadow modifications.
    let shadow_path = root.shadow_path();
    let do_lock = matches.get_flag(options::LOCK);
    let do_unlock = matches.get_flag(options::UNLOCK);
    let expire = matches.get_one::<String>(options::EXPIREDATE);
    let inactive = matches.get_one::<i64>(options::INACTIVE);
    let new_password = matches.get_one::<String>(options::PASSWORD);

    if let Some(pw) = new_password
        && pw.contains([':', '\n', '\r'])
    {
        return Err(UsermodError::CantUpdate(
            "invalid password hash: must not contain ':', '\\n', or '\\r'".into(),
        )
        .into());
    }

    let login_changing = new_login.is_some();
    if shadow_path.exists()
        && (do_lock
            || do_unlock
            || expire.is_some()
            || inactive.is_some()
            || new_password.is_some()
            || login_changing)
    {
        let slock = FileLock::acquire(&shadow_path)
            .map_err(|e| UsermodError::CantUpdate(format!("cannot lock shadow: {e}")))?;

        let mut se = shadow::read_shadow_file(&shadow_path)
            .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;

        let Some(s) = se.iter_mut().find(|e| e.name == *login) else {
            drop(slock);
            return Err(UsermodError::CantUpdate(format!(
                "user '{login}' not found in shadow file"
            ))
            .into());
        };

        if do_lock {
            s.lock();
        }
        if do_unlock {
            s.unlock();
        }
        if let Some(exp) = expire {
            s.expire_date = if exp == "-1" || exp.is_empty() {
                None
            } else {
                Some(exp.parse::<i64>().map_err(|_| {
                    UsermodError::CantUpdate(format!(
                        "invalid expire date '{exp}' (expected days since epoch)"
                    ))
                })?)
            };
        }
        if let Some(&i) = inactive {
            s.inactive_days = if i < 0 { None } else { Some(i) };
        }
        if let Some(pw) = new_password {
            s.passwd.clone_from(pw);
            s.last_change = Some(shadow::days_since_epoch().map_err(|e| {
                UsermodError::CantUpdate(format!("cannot determine current date: {e}"))
            })?);
        }
        if let Some(new_name) = new_login {
            s.name.clone_from(new_name);
        }

        atomic::atomic_write(&shadow_path, |f| shadow::write_shadow(&se, f))
            .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;
        drop(slock);
    }

    // Rename user in group membership lists when --login changes the name.
    if let Some(new_name) = new_login {
        let group_path = root.group_path();
        if group_path.exists() {
            let glock = FileLock::acquire(&group_path)
                .map_err(|e| UsermodError::CantUpdate(format!("cannot lock group: {e}")))?;

            let mut ge = group::read_group_file(&group_path)
                .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;

            let mut changed = false;
            for g in &mut ge {
                if let Some(m) = g.members.iter_mut().find(|m| **m == *login) {
                    m.clone_from(new_name);
                    changed = true;
                }
            }

            if changed {
                atomic::atomic_write(&group_path, |f| group::write_group(&ge, f))
                    .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;
            }
            drop(glock);
        }
    }

    // Group modifications.
    if let Some(groups_str) = matches.get_one::<String>(options::GROUPS) {
        let group_path = root.group_path();
        if group_path.exists() {
            let append = matches.get_flag(options::APPEND);
            let new_groups: Vec<&str> = groups_str.split(',').map(str::trim).collect();

            let glock = FileLock::acquire(&group_path)
                .map_err(|e| UsermodError::CantUpdate(format!("cannot lock group: {e}")))?;

            let mut ge = group::read_group_file(&group_path)
                .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;

            // Validate all requested groups exist before mutating anything.
            for gname in &new_groups {
                if !ge.iter().any(|g| g.name == *gname) {
                    drop(glock);
                    return Err(UsermodError::CantUpdate(format!(
                        "group '{gname}' does not exist"
                    ))
                    .into());
                }
            }

            if !append {
                for g in &mut ge {
                    g.members.retain(|m| m != login);
                }
            }
            for gname in &new_groups {
                if let Some(g) = ge.iter_mut().find(|g| g.name == *gname)
                    && !g.members.iter().any(|m| m == login)
                {
                    g.members.push(login.clone());
                }
            }

            atomic::atomic_write(&group_path, |f| group::write_group(&ge, f))
                .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;
            drop(glock);
        }
    }

    nscd::invalidate_cache("passwd");
    nscd::invalidate_cache("group");

    audit::log_user_event("MOD_USER", login, new_uid, true);

    Ok(())
}

/// Recursively chown all files and directories under `path` that are owned by
/// `old_uid` to `new_uid`. Files owned by other users are left untouched.
///
/// Uses `fchownat` with `AT_SYMLINK_NOFOLLOW` so symlinks themselves are
/// re-owned without following them.
fn recursive_chown(path: &Path, old_uid: u32, new_uid: u32) {
    use std::os::unix::fs::MetadataExt;

    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if let Ok(meta) = std::fs::symlink_metadata(&entry_path) {
                if meta.uid() == old_uid {
                    let _ = rustix::fs::chownat(
                        rustix::fs::CWD,
                        &entry_path,
                        Some(rustix::process::Uid::from_raw(new_uid)),
                        None,
                        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                    );
                }
                if meta.is_dir() {
                    recursive_chown(&entry_path, old_uid, new_uid);
                }
            }
        }
    }
    // Also chown the directory itself.
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.uid() == old_uid
    {
        let _ = rustix::fs::chownat(
            rustix::fs::CWD,
            path,
            Some(rustix::process::Uid::from_raw(new_uid)),
            None,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        );
    }
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn uu_app() -> Command {
    Command::new("usermod")
        .about("Edit a user account's fields")
        .override_usage("usermod [options] LOGIN")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::COMMENT)
                .short('c')
                .long("comment")
                .value_name("COMMENT")
                .help("Replace the GECOS comment"),
        )
        .arg(
            Arg::new(options::HOME)
                .short('d')
                .long("home")
                .value_name("HOME_DIR")
                .help("Replace the home directory path"),
        )
        .arg(
            Arg::new(options::EXPIREDATE)
                .short('e')
                .long("expiredate")
                .value_name("EXPIRE_DATE")
                .help("Set the account expiration date"),
        )
        .arg(
            Arg::new(options::INACTIVE)
                .short('f')
                .long("inactive")
                .value_name("INACTIVE")
                .value_parser(clap::value_parser!(i64))
                .help("Days the password may stay expired before disabling the account"),
        )
        .arg(
            Arg::new(options::GID)
                .short('g')
                .long("gid")
                .value_name("GROUP")
                .value_parser(clap::value_parser!(u32))
                .help("Replace the primary group (numeric GID)"),
        )
        .arg(
            Arg::new(options::GROUPS)
                .short('G')
                .long("groups")
                .value_name("GROUPS")
                .help("Replace supplementary groups (comma-separated)"),
        )
        .arg(
            Arg::new(options::APPEND)
                .short('a')
                .long("append")
                .help("Add to (instead of replace) supplementary groups")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::LOCK)
                .short('L')
                .long("lock")
                .help("Disable login by locking the password")
                .conflicts_with(options::UNLOCK)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::UNLOCK)
                .short('U')
                .long("unlock")
                .help("Re-enable login by unlocking the password")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::LOGIN)
                .short('l')
                .long("login")
                .value_name("NEW_LOGIN")
                .help("Rename the account"),
        )
        .arg(
            Arg::new(options::PASSWORD)
                .short('p')
                .long("password")
                .value_name("PASSWORD")
                .help("Replace the password field with a crypt(3) hash"),
        )
        .arg(
            Arg::new(options::SHELL)
                .short('s')
                .long("shell")
                .value_name("SHELL")
                .help("Replace the login shell"),
        )
        .arg(
            Arg::new(options::UID)
                .short('u')
                .long("uid")
                .value_name("UID")
                .value_parser(clap::value_parser!(u32))
                .help("Replace the numeric UID"),
        )
        .arg(
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .value_name("CHROOT_DIR")
                .help("Chroot directory"),
        )
        .arg(
            Arg::new(options::PREFIX)
                .short('P')
                .long("prefix")
                .value_name("PREFIX_DIR")
                .help("Directory prefix"),
        )
        .arg(
            Arg::new(options::USER)
                .required(true)
                .index(1)
                .help("Login name"),
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
    fn test_user_required() {
        assert!(uu_app().try_get_matches_from(["usermod"]).is_err());
    }

    #[test]
    fn test_lock_unlock_conflict() {
        assert!(
            uu_app()
                .try_get_matches_from(["usermod", "-L", "-U", "u"])
                .is_err()
        );
    }

    #[test]
    fn test_append_groups() {
        let m = uu_app()
            .try_get_matches_from(["usermod", "-a", "-G", "sudo,docker", "u"])
            .unwrap();
        assert!(m.get_flag(options::APPEND));
        assert_eq!(
            m.get_one::<String>(options::GROUPS).map(String::as_str),
            Some("sudo,docker")
        );
    }

    fn skip_unless_root() -> bool {
        !rustix::process::geteuid().is_root()
    }

    #[test]
    fn test_modify_shell_with_prefix() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            etc.join("passwd"),
            "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        )
        .unwrap();

        let code = uumain(
            vec![
                "usermod".into(),
                "-s".into(),
                "/bin/zsh".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "testuser".into(),
            ]
            .into_iter(),
        );
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(etc.join("passwd")).unwrap();
        assert!(content.contains("/bin/zsh"));
    }
}
