// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore groupdel gshadow nscd sysroot

//! `groupdel` -- delete a group.
//!
//! Drop-in replacement for GNU shadow-utils `groupdel(8)`.

use std::fmt;
use std::path::Path;

use clap::{Arg, Command};
use uucore::error::{UError, UResult};

use shadow_core::audit;
use shadow_core::group::GroupEntry;
use shadow_core::gshadow::GshadowEntry;
use shadow_core::nscd;
use shadow_core::passwd;
use shadow_core::sysroot::SysRoot;
use shadow_core::transaction::LockedFile;

mod options {
    pub const GROUP: &str = "GROUP";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
    pub const FORCE: &str = "force";
}

mod exit_codes {
    pub const BAD_SYNTAX: i32 = 2;
    pub const GROUP_NOT_FOUND: i32 = 6;
    pub const PRIMARY_GROUP: i32 = 8;
    pub const CANT_UPDATE: i32 = 10;
}

#[derive(Debug)]
enum GroupdelError {
    BadSyntax(String),
    GroupNotFound(String),
    PrimaryGroup(String),
    CantUpdate(String),
}

impl fmt::Display for GroupdelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSyntax(msg)
            | Self::GroupNotFound(msg)
            | Self::PrimaryGroup(msg)
            | Self::CantUpdate(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for GroupdelError {}

impl UError for GroupdelError {
    fn code(&self) -> i32 {
        match self {
            Self::BadSyntax(_) => exit_codes::BAD_SYNTAX,
            Self::GroupNotFound(_) => exit_codes::GROUP_NOT_FOUND,
            Self::PrimaryGroup(_) => exit_codes::PRIMARY_GROUP,
            Self::CantUpdate(_) => exit_codes::CANT_UPDATE,
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
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| exit_codes::BAD_SYNTAX)?
    else {
        return Ok(());
    };

    // --root DIR is a real chroot: the account files come from the new root,
    // and so does every absolute path read out of them. Done before anything
    // else, so nothing has resolved a path against the old root yet.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        shadow_core::hardening::chroot_into(std::path::Path::new(chroot_dir))
            .map_err(|e| GroupdelError::BadSyntax(e.to_string()))?;
    }

    if !shadow_core::hardening::caller_is_root() {
        uucore::show_error!("{}", shadow_core::os_error::permission_denied());
        return Err(shadow_core::cli::AlreadyPrinted(1).into());
    }

    let group_name = matches
        .get_one::<String>(options::GROUP)
        .ok_or_else(|| GroupdelError::BadSyntax("group name required".into()))?;

    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);

    // The transaction locks, then reads, and blocks signals for its lifetime,
    // so a SIGINT between the lock and the write cannot leave a stale lock.
    let group_path = root.group_path();
    let mut groups = LockedFile::<GroupEntry>::open(&group_path).map_err(|e| {
        GroupdelError::CantUpdate(format!("cannot open {}: {e}", group_path.display()))
    })?;

    let force = matches.get_flag(options::FORCE);

    let Some(target) = groups.find(group_name) else {
        // groupdel(8) -f: "succeed even if the group does not exist".
        if force {
            return Ok(());
        }
        return Err(
            GroupdelError::GroupNotFound(format!("group '{group_name}' does not exist")).into(),
        );
    };

    let target_gid = target.gid;

    // Check that no user has this group as their primary group; -f removes it
    // regardless, which groupdel(8) documents.
    let passwd_path = root.passwd_path();
    if !force && passwd_path.exists() {
        let passwd_entries = passwd::read_passwd_file(&passwd_path).map_err(|e| {
            GroupdelError::CantUpdate(format!("cannot read {}: {e}", passwd_path.display()))
        })?;

        if let Some(user) = passwd_entries.iter().find(|u| u.gid == target_gid) {
            // `groups` drops here, releasing the lock with the file untouched.
            return Err(GroupdelError::PrimaryGroup(format!(
                "cannot remove the primary group of user '{}'",
                user.name
            ))
            .into());
        }
    }

    // Remove the group entry. Removing the last one empties the file, and an
    // absent group file means the same thing as an empty one, so the
    // transaction unlinks rather than writing a zero-length file the atomic
    // writer would refuse.
    groups.entries_mut().retain(|g| g.name != *group_name);
    groups.commit_or_remove().map_err(|e| {
        GroupdelError::CantUpdate(format!("cannot write {}: {e}", group_path.display()))
    })?;

    // Remove from /etc/gshadow.
    let gshadow_path = root.gshadow_path();
    if gshadow_path.exists() {
        let mut gshadow = LockedFile::<GshadowEntry>::open(&gshadow_path).map_err(|e| {
            GroupdelError::CantUpdate(format!("cannot open {}: {e}", gshadow_path.display()))
        })?;
        gshadow.entries_mut().retain(|g| g.name != *group_name);
        gshadow.commit_or_remove().map_err(|e| {
            GroupdelError::CantUpdate(format!("cannot write {}: {e}", gshadow_path.display()))
        })?;
    }

    nscd::invalidate_cache("group");

    audit::log_user_event("DEL_GROUP", group_name, target_gid, true);

    Ok(())
}

#[must_use]
pub fn uu_app() -> Command {
    Command::new("groupdel")
        .about("Remove a group entry")
        .override_usage("groupdel [options] GROUP")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::FORCE)
                .short('f')
                .long("force")
                .help("Delete even if it is a user's primary group, and succeed if it is missing")
                .action(clap::ArgAction::SetTrue),
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
            Arg::new(options::GROUP)
                .required(true)
                .index(1)
                .help("Group to remove"),
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
        assert!(uu_app().try_get_matches_from(["groupdel"]).is_err());
    }

    #[test]
    fn test_prefix_flag() {
        let m = uu_app()
            .try_get_matches_from(["groupdel", "-P", "/mnt", "testgrp"])
            .expect("valid args");
        assert_eq!(
            m.get_one::<String>(options::PREFIX).map(String::as_str),
            Some("/mnt")
        );
    }

    fn skip_unless_root() -> bool {
        !rustix::process::geteuid().is_root()
    }

    #[test]
    fn test_delete_group() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("create etc");
        std::fs::write(
            etc.join("group"),
            "root:x:0:\ntestgrp:x:1000:\nother:x:1001:\n",
        )
        .expect("write group");
        std::fs::write(etc.join("passwd"), "root:x:0:0:root:/root:/bin/bash\n")
            .expect("write passwd");

        let code = uumain(
            vec![
                "groupdel".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "testgrp".into(),
            ]
            .into_iter(),
        );
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(etc.join("group")).expect("read group");
        assert!(!content.contains("testgrp"));
        assert!(content.contains("root:x:0:"));
        assert!(content.contains("other:x:1001:"));
    }

    #[test]
    fn test_delete_nonexistent_group() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("create etc");
        std::fs::write(etc.join("group"), "root:x:0:\n").expect("write group");

        let code = uumain(
            vec![
                "groupdel".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "nogrp".into(),
            ]
            .into_iter(),
        );
        assert_ne!(code, 0);
    }

    #[test]
    fn test_cannot_delete_primary_group() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("create etc");
        std::fs::write(etc.join("group"), "testgrp:x:1000:\n").expect("write group");
        std::fs::write(
            etc.join("passwd"),
            "testuser:x:1000:1000::/home/testuser:/bin/bash\n",
        )
        .expect("write passwd");

        let code = uumain(
            vec![
                "groupdel".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "testgrp".into(),
            ]
            .into_iter(),
        );
        assert_ne!(code, 0);
    }
}
