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

use shadow_core::audit;
use shadow_core::group::GroupEntry;
use shadow_core::gshadow::GshadowEntry;
use shadow_core::nscd;
use shadow_core::passwd::PasswdEntry;
use shadow_core::sysroot::SysRoot;
use shadow_core::transaction::{self, Commit, LockedFile};

mod options {
    pub const GROUP: &str = "GROUP";
    pub const GID: &str = "gid";
    pub const NEW_NAME: &str = "new-name";
    pub const NON_UNIQUE: &str = "non-unique";
    pub const PASSWORD: &str = "password";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
    pub const USERS: &str = "users";
    pub const APPEND: &str = "append";
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
            .map_err(|e| GroupmodError::BadSyntax(e.to_string()))?;
    }

    if !shadow_core::hardening::caller_is_root() {
        uucore::show_error!("{}", shadow_core::os_error::permission_denied());
        return Err(shadow_core::cli::AlreadyPrinted(1).into());
    }

    let group_name = matches
        .get_one::<String>(options::GROUP)
        .ok_or_else(|| GroupmodError::BadSyntax("group name required".into()))?;
    let new_gid = matches.get_one::<String>(options::GID);
    let new_name = matches.get_one::<String>(options::NEW_NAME);
    let non_unique = matches.get_flag(options::NON_UNIQUE);
    let new_password = matches.get_one::<String>(options::PASSWORD);
    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);

    // Validate new name if provided.
    if let Some(name) = new_name {
        shadow_core::validate::validate_username(name)
            .map_err(|e| GroupmodError::BadArgument(format!("{e}")))?;
    }
    if let Some(password) = new_password {
        shadow_core::validate::validate_field("password", password)
            .map_err(|e| GroupmodError::BadArgument(e.to_string()))?;
    }

    // Parse new GID if provided. u32::MAX is (gid_t)-1, the "no change"
    // sentinel of chown/setresgid, and must never be stored.
    let parsed_gid: Option<u32> = new_gid
        .map(|s| {
            let gid = s
                .parse::<u32>()
                .map_err(|_| GroupmodError::BadArgument(format!("invalid GID '{s}'")))?;
            if gid == u32::MAX {
                return Err(GroupmodError::BadArgument(format!("invalid GID '{s}'")));
            }
            Ok(gid)
        })
        .transpose()?;

    // Lock order across the tools is passwd < group < gshadow < shadow, so the
    // files are opened in that order and never in another. This keeps the
    // ordering acyclic with useradd and usermod. Each transaction blocks
    // signals for its lifetime and releases its lock on every path out.
    let group_path = root.group_path();
    let passwd_path = root.passwd_path();
    let gshadow_path = root.gshadow_path();

    let cant_update = |path: &std::path::Path| {
        let display = path.display().to_string();
        move |e: shadow_core::error::ShadowError| {
            GroupmodError::CantUpdate(format!("cannot open {display}: {e}"))
        }
    };

    // Only the -g path touches passwd, and only if it exists: a --prefix tree
    // may not carry one.
    let mut passwd = if parsed_gid.is_some() && passwd_path.exists() {
        Some(LockedFile::<PasswdEntry>::open(&passwd_path).map_err(cant_update(&passwd_path))?)
    } else {
        None
    };

    let mut groups =
        LockedFile::<GroupEntry>::open(&group_path).map_err(cant_update(&group_path))?;

    // gshadow is only touched by a rename or a password change.
    let touches_gshadow = new_name.is_some() || new_password.is_some();
    let mut gshadow = if gshadow_path.exists() && touches_gshadow {
        Some(LockedFile::<GshadowEntry>::open(&gshadow_path).map_err(cant_update(&gshadow_path))?)
    } else {
        None
    };

    // Find the target group.
    let entries = groups.entries_mut();
    let idx = entries
        .iter()
        .position(|g| g.name == *group_name)
        .ok_or_else(|| {
            GroupmodError::GroupNotFound(format!("group '{group_name}' does not exist"))
        })?;

    let old_gid = entries[idx].gid;

    // Check GID collision.
    if let Some(gid) = parsed_gid {
        if !non_unique
            && entries
                .iter()
                .any(|g| g.gid == gid && g.name != *group_name)
        {
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
            return Err(GroupmodError::NameInUse(format!("group '{name}' already exists")).into());
        }
        entries[idx].name.clone_from(name);
    }

    // groupmod(8) -U sets the member list; with -a the users are added to it.
    if let Some(users) = matches.get_one::<String>(options::USERS) {
        let requested: Vec<String> = users
            .split(',')
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        for name in &requested {
            shadow_core::validate::validate_username(name)
                .map_err(|e| GroupmodError::BadArgument(format!("invalid member name: {e}")))?;
        }
        if !matches.get_flag(options::APPEND) {
            entries[idx].members.clear();
        }
        for name in requested {
            if !entries[idx].members.contains(&name) {
                entries[idx].members.push(name);
            }
        }
    }

    // Without a gshadow file the password belongs in the group file, which is
    // where a system with no gshadow keeps it; otherwise -p was a silent no-op.
    if gshadow.is_none()
        && let Some(pw) = new_password
    {
        entries[idx].passwd.clone_from(pw);
    }

    let modified_gid = entries[idx].gid;

    // groupmod(8): "Users who use the group as their primary group are updated
    // to keep the group as their primary group."
    if let Some(new_gid_val) = parsed_gid
        && new_gid_val != old_gid
        && let Some(passwd) = passwd.as_mut()
    {
        for e in passwd.entries_mut() {
            if e.gid == old_gid {
                e.gid = new_gid_val;
            }
        }
    }

    if let Some(gs) = gshadow.as_mut().and_then(|f| f.find_mut(group_name)) {
        if let Some(name) = new_name {
            gs.name.clone_from(name);
        }
        if let Some(pw) = new_password {
            gs.passwd.clone_from(pw);
        }
    }

    // Every file is validated before any is written, so a value that would
    // corrupt one of them cannot leave the set half applied.
    let mut files: Vec<Box<dyn Commit>> = Vec::new();
    if let Some(passwd) = passwd {
        files.push(Box::new(passwd));
    }
    files.push(Box::new(groups));
    if let Some(gshadow) = gshadow {
        files.push(Box::new(gshadow));
    }
    transaction::commit_all(files)
        .map_err(|e| GroupmodError::CantUpdate(format!("cannot write: {e}")))?;

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
            Arg::new(options::USERS)
                .short('U')
                .long("users")
                .value_name("USERS")
                .help("Set the group's member list (comma-separated)"),
        )
        .arg(
            Arg::new(options::APPEND)
                .short('a')
                .long("append")
                .requires(options::USERS)
                .help("With -U, add the users instead of replacing the member list")
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
