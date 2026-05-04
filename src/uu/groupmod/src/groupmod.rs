// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore groupmod gshadow nscd sysroot

//! `groupmod` -- modify a group definition.
//!
//! Drop-in replacement for GNU shadow-utils `groupmod(8)`.

use std::fmt;
use std::path::Path;

use clap::{Arg, ArgAction, Command};
use uucore::error::{UError, UResult};

use shadow_core::atomic;
use shadow_core::audit;
use shadow_core::group::{self};
use shadow_core::gshadow::{self};
use shadow_core::lock::FileLock;
use shadow_core::nscd;
use shadow_core::sysroot::SysRoot;

mod options {
    pub const GROUP: &str = "GROUP";
    pub const GID: &str = "gid";
    pub const NEW_NAME: &str = "new-name";
    pub const NON_UNIQUE: &str = "non-unique";
    pub const PASSWORD: &str = "password";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
}

mod exit_codes {
    pub const BAD_SYNTAX: i32 = 2;
    pub const BAD_ARGUMENT: i32 = 3;
    pub const GID_IN_USE: i32 = 4;
    pub const GROUP_NOT_FOUND: i32 = 6;
    pub const NAME_IN_USE: i32 = 9;
    pub const CANT_UPDATE: i32 = 10;
}

#[derive(Debug)]
enum GroupmodError {
    BadSyntax(String),
    BadArgument(String),
    GidInUse(String),
    GroupNotFound(String),
    NameInUse(String),
    CantUpdate(String),
    AlreadyPrinted(i32),
}

impl fmt::Display for GroupmodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSyntax(msg)
            | Self::BadArgument(msg)
            | Self::GidInUse(msg)
            | Self::GroupNotFound(msg)
            | Self::NameInUse(msg)
            | Self::CantUpdate(msg) => f.write_str(msg),
            Self::AlreadyPrinted(_) => Ok(()),
        }
    }
}

impl std::error::Error for GroupmodError {}

impl UError for GroupmodError {
    fn code(&self) -> i32 {
        match self {
            Self::BadSyntax(_) => exit_codes::BAD_SYNTAX,
            Self::BadArgument(_) => exit_codes::BAD_ARGUMENT,
            Self::GidInUse(_) => exit_codes::GID_IN_USE,
            Self::GroupNotFound(_) => exit_codes::GROUP_NOT_FOUND,
            Self::NameInUse(_) => exit_codes::NAME_IN_USE,
            Self::CantUpdate(_) => exit_codes::CANT_UPDATE,
            Self::AlreadyPrinted(c) => *c,
        }
    }
}

// ---------------------------------------------------------------------------
// Security hardening
// ---------------------------------------------------------------------------

// Hardening functions are now centralized in shadow_core::hardening.

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[uucore::main]
#[allow(clippy::too_many_lines)]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let _clean_env = shadow_core::hardening::harden_process();

    let matches = match uu_app().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            if !e.use_stderr() {
                return Ok(());
            }
            return Err(GroupmodError::AlreadyPrinted(exit_codes::BAD_SYNTAX).into());
        }
    };

    if !shadow_core::hardening::caller_is_root() {
        uucore::show_error!("Permission denied.");
        return Err(GroupmodError::AlreadyPrinted(1).into());
    }

    let group_name = matches
        .get_one::<String>(options::GROUP)
        .ok_or_else(|| GroupmodError::BadSyntax("group name required".into()))?;
    let new_gid = matches.get_one::<String>(options::GID);
    let new_name = matches.get_one::<String>(options::NEW_NAME);
    let non_unique = matches.get_flag(options::NON_UNIQUE);
    let new_password = matches.get_one::<String>(options::PASSWORD);
    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root_dir = matches.get_one::<String>(options::ROOT).map(Path::new);
    let root = SysRoot::new(prefix.or(root_dir));

    // Validate new name if provided.
    if let Some(name) = new_name {
        shadow_core::validate::validate_username(name)
            .map_err(|e| GroupmodError::BadArgument(format!("{e}")))?;
    }

    // Parse new GID if provided.
    let parsed_gid: Option<u32> = new_gid
        .map(|s| {
            s.parse::<u32>()
                .map_err(|_| GroupmodError::BadArgument(format!("invalid GID '{s}'")))
        })
        .transpose()?;

    // Block signals for the duration of the critical section so a SIGINT
    // between lock acquisition and atomic_write cannot leave stale lock files.
    let _signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| GroupmodError::CantUpdate(format!("cannot block signals: {e}")))?;

    // Lock and read /etc/group.
    let group_path = root.group_path();
    let group_lock = FileLock::acquire(&group_path).map_err(|e| {
        GroupmodError::CantUpdate(format!("cannot lock {}: {e}", group_path.display()))
    })?;

    let mut entries = group::read_group_file(&group_path).map_err(|e| {
        GroupmodError::CantUpdate(format!("cannot read {}: {e}", group_path.display()))
    })?;

    // Find the target group.
    let idx = entries
        .iter()
        .position(|g| g.name == *group_name)
        .ok_or_else(|| {
            GroupmodError::GroupNotFound(format!("group '{group_name}' does not exist"))
        })?;

    // Check GID collision.
    if let Some(gid) = parsed_gid {
        if !non_unique
            && entries
                .iter()
                .any(|g| g.gid == gid && g.name != *group_name)
        {
            drop(group_lock);
            return Err(GroupmodError::GidInUse(format!("GID '{gid}' already exists")).into());
        }
        entries[idx].gid = gid;
    }

    // Check name collision.
    if let Some(name) = new_name {
        if entries
            .iter()
            .any(|g| g.name == *name && g.name != *group_name)
        {
            drop(group_lock);
            return Err(GroupmodError::NameInUse(format!("group '{name}' already exists")).into());
        }
        entries[idx].name.clone_from(name);
    }

    let modified_gid = entries[idx].gid;

    // Write /etc/group.
    atomic::atomic_write(&group_path, |f| group::write_group(&entries, f)).map_err(|e| {
        GroupmodError::CantUpdate(format!("cannot write {}: {e}", group_path.display()))
    })?;

    drop(group_lock);

    // Update /etc/gshadow.
    let gshadow_path = root.gshadow_path();
    if gshadow_path.exists() && (new_name.is_some() || new_password.is_some()) {
        let gs_lock = FileLock::acquire(&gshadow_path).map_err(|e| {
            GroupmodError::CantUpdate(format!("cannot lock {}: {e}", gshadow_path.display()))
        })?;

        let mut gs_entries = gshadow::read_gshadow_file(&gshadow_path).map_err(|e| {
            GroupmodError::CantUpdate(format!("cannot read {}: {e}", gshadow_path.display()))
        })?;

        if let Some(gs) = gs_entries.iter_mut().find(|g| g.name == *group_name) {
            if let Some(name) = new_name {
                gs.name.clone_from(name);
            }
            if let Some(pw) = new_password {
                gs.passwd.clone_from(pw);
            }
        }

        atomic::atomic_write(&gshadow_path, |f| gshadow::write_gshadow(&gs_entries, f)).map_err(
            |e| GroupmodError::CantUpdate(format!("cannot write {}: {e}", gshadow_path.display())),
        )?;

        drop(gs_lock);
    }

    nscd::invalidate_cache("group");

    audit::log_user_event("MOD_GROUP", group_name, modified_gid, true);

    Ok(())
}

#[must_use]
pub fn uu_app() -> Command {
    Command::new("groupmod")
        .about("Edit a group's fields")
        .override_usage("groupmod [options] GROUP")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::GID)
                .short('g')
                .long("gid")
                .value_name("GID")
                .help("Set the group's GID"),
        )
        .arg(
            Arg::new(options::NEW_NAME)
                .short('n')
                .long("new-name")
                .value_name("NEW_GROUP")
                .help("Rename the group to NEW_GROUP"),
        )
        .arg(
            Arg::new(options::NON_UNIQUE)
                .short('o')
                .long("non-unique")
                .help("Permit a duplicate GID (must accompany -g)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::PASSWORD)
                .short('p')
                .long("password")
                .value_name("PASSWORD")
                .help("Replace the group password (PASSWORD must be a crypt(3) hash)"),
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
            Arg::new(options::GROUP)
                .required(true)
                .index(1)
                .help("Group to edit"),
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
    fn test_group_required() {
        assert!(uu_app().try_get_matches_from(["groupmod"]).is_err());
    }

    #[test]
    fn test_rename_flag() {
        let m = uu_app()
            .try_get_matches_from(["groupmod", "-n", "newname", "oldname"])
            .expect("valid args");
        assert_eq!(
            m.get_one::<String>(options::NEW_NAME).map(String::as_str),
            Some("newname")
        );
    }

    #[test]
    fn test_gid_flag() {
        let m = uu_app()
            .try_get_matches_from(["groupmod", "-g", "5000", "mygrp"])
            .expect("valid args");
        assert_eq!(
            m.get_one::<String>(options::GID).map(String::as_str),
            Some("5000")
        );
    }

    #[test]
    fn test_non_unique_flag() {
        let m = uu_app()
            .try_get_matches_from(["groupmod", "-o", "-g", "0", "mygrp"])
            .expect("valid args");
        assert!(m.get_flag(options::NON_UNIQUE));
    }

    fn skip_unless_root() -> bool {
        !rustix::process::geteuid().is_root()
    }

    #[test]
    fn test_change_gid() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("create etc");
        std::fs::write(etc.join("group"), "testgrp:x:1000:\n").expect("write group");

        let code = uumain(
            vec![
                "groupmod".into(),
                "-g".into(),
                "2000".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "testgrp".into(),
            ]
            .into_iter(),
        );
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(etc.join("group")).expect("read group");
        assert!(content.contains("testgrp:x:2000:"));
    }

    #[test]
    fn test_rename_group() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("create etc");
        std::fs::write(etc.join("group"), "oldgrp:x:1000:\n").expect("write group");

        let code = uumain(
            vec![
                "groupmod".into(),
                "-n".into(),
                "newgrp".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "oldgrp".into(),
            ]
            .into_iter(),
        );
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(etc.join("group")).expect("read group");
        assert!(content.contains("newgrp:x:1000:"));
        assert!(!content.contains("oldgrp"));
    }

    #[test]
    fn test_nonexistent_group_fails() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("create etc");
        std::fs::write(etc.join("group"), "root:x:0:\n").expect("write group");

        let code = uumain(
            vec![
                "groupmod".into(),
                "-g".into(),
                "5000".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "nogroup".into(),
            ]
            .into_iter(),
        );
        assert_ne!(code, 0);
    }

    #[test]
    fn test_gid_collision_fails() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("create etc");
        std::fs::write(etc.join("group"), "grp1:x:1000:\ngrp2:x:2000:\n").expect("write group");

        let code = uumain(
            vec![
                "groupmod".into(),
                "-g".into(),
                "2000".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "grp1".into(),
            ]
            .into_iter(),
        );
        assert_ne!(code, 0);
    }
}
