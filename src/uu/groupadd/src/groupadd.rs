// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore groupadd gshadow nscd sysroot

//! `groupadd` -- create a new group.
//!
//! Drop-in replacement for GNU shadow-utils `groupadd(8)`.

use std::fmt;
use std::path::Path;

use clap::{Arg, ArgAction, Command};
use uucore::error::{UError, UResult};

use shadow_core::atomic;
use shadow_core::audit;
use shadow_core::group::{self, GroupEntry};
use shadow_core::gshadow::{self, GshadowEntry};
use shadow_core::lock::FileLock;
use shadow_core::login_defs::LoginDefs;
use shadow_core::nscd;
use shadow_core::sysroot::SysRoot;
use shadow_core::uid_alloc;
use shadow_core::validate;

mod options {
    pub const GROUP: &str = "GROUP";
    pub const FORCE: &str = "force";
    pub const GID: &str = "gid";
    pub const KEY: &str = "key";
    pub const NON_UNIQUE: &str = "non-unique";
    pub const PASSWORD: &str = "password";
    pub const SYSTEM: &str = "system";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
}

mod exit_codes {
    pub const BAD_SYNTAX: i32 = 2;
    pub const BAD_ARGUMENT: i32 = 3;
    pub const GID_IN_USE: i32 = 4;
    pub const GROUP_IN_USE: i32 = 9;
    pub const CANT_UPDATE: i32 = 10;
}

#[derive(Debug)]
enum GroupaddError {
    BadSyntax(String),
    BadArgument(String),
    GidInUse(String),
    GroupInUse(String),
    CantUpdate(String),
    AlreadyPrinted(i32),
}

impl fmt::Display for GroupaddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSyntax(msg)
            | Self::BadArgument(msg)
            | Self::GidInUse(msg)
            | Self::GroupInUse(msg)
            | Self::CantUpdate(msg) => f.write_str(msg),
            Self::AlreadyPrinted(_) => Ok(()),
        }
    }
}

impl std::error::Error for GroupaddError {}

impl UError for GroupaddError {
    fn code(&self) -> i32 {
        match self {
            Self::BadSyntax(_) => exit_codes::BAD_SYNTAX,
            Self::BadArgument(_) => exit_codes::BAD_ARGUMENT,
            Self::GidInUse(_) => exit_codes::GID_IN_USE,
            Self::GroupInUse(_) => exit_codes::GROUP_IN_USE,
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
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let _clean_env = shadow_core::hardening::harden_process();

    let matches = match uu_app().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            if !e.use_stderr() {
                return Ok(());
            }
            return Err(GroupaddError::AlreadyPrinted(exit_codes::BAD_SYNTAX).into());
        }
    };

    if !shadow_core::hardening::caller_is_root() {
        uucore::show_error!("Permission denied.");
        return Err(GroupaddError::AlreadyPrinted(1).into());
    }

    do_groupadd(&matches)
}

/// Core logic, separated from argument parsing to keep `uumain` short.
#[allow(clippy::too_many_lines)]
fn do_groupadd(matches: &clap::ArgMatches) -> UResult<()> {
    let group_name = matches
        .get_one::<String>(options::GROUP)
        .ok_or_else(|| GroupaddError::BadSyntax("group name required".into()))?
        .clone();

    let force = matches.get_flag(options::FORCE);
    let non_unique = matches.get_flag(options::NON_UNIQUE);
    let system = matches.get_flag(options::SYSTEM);
    let password = matches
        .get_one::<String>(options::PASSWORD)
        .cloned()
        .unwrap_or_else(|| "!".to_string());

    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root_dir = matches.get_one::<String>(options::ROOT).map(Path::new);
    let root = SysRoot::new(prefix.or(root_dir));

    // Parse -K KEY=VALUE overrides.
    let key_values: Vec<&String> = matches
        .get_many::<String>(options::KEY)
        .map_or_else(Vec::new, Iterator::collect);
    let mut login_defs_overrides: Vec<(&str, &str)> = Vec::new();
    for kv in &key_values {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| GroupaddError::BadArgument(format!("invalid key=value pair: '{kv}'")))?;
        login_defs_overrides.push((k, v));
    }

    // Validate the group name.
    validate::validate_username(&group_name)
        .map_err(|e| GroupaddError::BadArgument(format!("{e}")))?;

    // Read existing groups.
    let group_path = root.group_path();
    let existing_groups = if group_path.exists() {
        group::read_group_file(&group_path).map_err(|e| {
            GroupaddError::CantUpdate(format!("cannot read {}: {e}", group_path.display()))
        })?
    } else {
        Vec::new()
    };

    // Check if group name already exists.
    if existing_groups.iter().any(|g| g.name == group_name) {
        if force {
            return Ok(());
        }
        return Err(
            GroupaddError::GroupInUse(format!("group '{group_name}' already exists")).into(),
        );
    }

    // Determine GID.
    let gid = determine_gid(
        matches,
        &existing_groups,
        force,
        non_unique,
        system,
        &root,
        &login_defs_overrides,
    )?;

    // Block signals for the duration of the critical section so a SIGINT
    // between lock acquisition and atomic_write cannot leave stale lock files.
    let _signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| GroupaddError::CantUpdate(format!("cannot block signals: {e}")))?;

    // Write to /etc/group.
    write_group_entry(&group_path, &group_name, gid)?;

    // Write to /etc/gshadow.
    write_gshadow_entry(&root.gshadow_path(), &group_name, &password)?;

    nscd::invalidate_cache("group");

    audit::log_user_event("ADD_GROUP", &group_name, gid, true);

    Ok(())
}

/// Determine the GID to use, either from -g or auto-allocated.
fn determine_gid(
    matches: &clap::ArgMatches,
    existing_groups: &[GroupEntry],
    force: bool,
    non_unique: bool,
    system: bool,
    root: &SysRoot,
    overrides: &[(&str, &str)],
) -> Result<u32, GroupaddError> {
    let explicit_gid = matches.get_one::<String>(options::GID);

    if let Some(gid_str) = explicit_gid {
        let gid: u32 = gid_str
            .parse()
            .map_err(|_| GroupaddError::BadArgument(format!("invalid GID '{gid_str}'")))?;

        if !non_unique && existing_groups.iter().any(|g| g.gid == gid) {
            if force {
                allocate_gid(root, existing_groups, system, overrides)
            } else {
                Err(GroupaddError::GidInUse(format!(
                    "GID '{gid}' already exists"
                )))
            }
        } else {
            Ok(gid)
        }
    } else {
        allocate_gid(root, existing_groups, system, overrides)
    }
}

/// Append a new group entry to /etc/group.
fn write_group_entry(group_path: &Path, name: &str, gid: u32) -> Result<(), GroupaddError> {
    let new_group = GroupEntry {
        name: name.to_string(),
        passwd: "x".to_string(),
        gid,
        members: Vec::new(),
    };

    let group_lock = FileLock::acquire(group_path).map_err(|e| {
        GroupaddError::CantUpdate(format!("cannot lock {}: {e}", group_path.display()))
    })?;

    let mut entries = if group_path.exists() {
        group::read_group_file(group_path).map_err(|e| {
            GroupaddError::CantUpdate(format!("cannot read {}: {e}", group_path.display()))
        })?
    } else {
        Vec::new()
    };
    entries.push(new_group);

    atomic::atomic_write(group_path, |f| group::write_group(&entries, f)).map_err(|e| {
        GroupaddError::CantUpdate(format!("cannot write {}: {e}", group_path.display()))
    })?;

    drop(group_lock);
    Ok(())
}

/// Append a new gshadow entry if /etc/gshadow exists.
fn write_gshadow_entry(
    gshadow_path: &Path,
    name: &str,
    password: &str,
) -> Result<(), GroupaddError> {
    if !gshadow_path.exists() {
        return Ok(());
    }

    let new_gshadow = GshadowEntry {
        name: name.to_string(),
        passwd: password.to_string(),
        admins: Vec::new(),
        members: Vec::new(),
    };

    let gshadow_lock = FileLock::acquire(gshadow_path).map_err(|e| {
        GroupaddError::CantUpdate(format!("cannot lock {}: {e}", gshadow_path.display()))
    })?;

    let mut gs_entries = gshadow::read_gshadow_file(gshadow_path).map_err(|e| {
        GroupaddError::CantUpdate(format!("cannot read {}: {e}", gshadow_path.display()))
    })?;
    gs_entries.push(new_gshadow);

    atomic::atomic_write(gshadow_path, |f| gshadow::write_gshadow(&gs_entries, f)).map_err(
        |e| GroupaddError::CantUpdate(format!("cannot write {}: {e}", gshadow_path.display())),
    )?;

    drop(gshadow_lock);
    Ok(())
}

/// Allocate the next available GID from login.defs ranges.
fn allocate_gid(
    root: &SysRoot,
    existing: &[GroupEntry],
    system: bool,
    overrides: &[(&str, &str)],
) -> Result<u32, GroupaddError> {
    let defs = LoginDefs::load(&root.login_defs_path())
        .map_err(|e| GroupaddError::CantUpdate(format!("{e}")))?;

    // Apply -K overrides by creating a synthetic LoginDefs with the override values.
    // We re-read and patch the range if overrides are present.
    let (mut min, mut max) = uid_alloc::gid_range(&defs, system);

    for &(key, val) in overrides {
        match key {
            "GID_MIN" | "SYS_GID_MIN" => {
                if let Ok(v) = val.parse::<u32>() {
                    min = v;
                }
            }
            "GID_MAX" | "SYS_GID_MAX" => {
                if let Ok(v) = val.parse::<u32>() {
                    max = v;
                }
            }
            _ => {}
        }
    }

    uid_alloc::next_gid(existing, min, max)
        .map_err(|e| GroupaddError::BadArgument(format!("cannot allocate GID: {e}")))
}

#[must_use]
pub fn uu_app() -> Command {
    Command::new("groupadd")
        .about("Add a new group entry")
        .override_usage("groupadd [options] GROUP")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::FORCE)
                .short('f')
                .long("force")
                .help("If the group exists, succeed silently; if -g collides, fall back to a free GID")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::GID)
                .short('g')
                .long("gid")
                .value_name("GID")
                .help("Assign GID to the new group"),
        )
        .arg(
            Arg::new(options::KEY)
                .short('K')
                .long("key")
                .value_name("KEY=VALUE")
                .action(ArgAction::Append)
                .help("Override a /etc/login.defs key for this run (KEY=VALUE)"),
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
                .help("crypt(3) hash for the group password field"),
        )
        .arg(
            Arg::new(options::SYSTEM)
                .short('r')
                .long("system")
                .help("Allocate from the system GID range")
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
            Arg::new(options::GROUP)
                .required(true)
                .index(1)
                .help("Group name to create"),
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
        assert!(uu_app().try_get_matches_from(["groupadd"]).is_err());
    }

    #[test]
    fn test_gid_flag() {
        let m = uu_app()
            .try_get_matches_from(["groupadd", "-g", "1001", "testgrp"])
            .expect("valid args");
        assert_eq!(
            m.get_one::<String>(options::GID).map(String::as_str),
            Some("1001")
        );
    }

    #[test]
    fn test_system_flag() {
        let m = uu_app()
            .try_get_matches_from(["groupadd", "-r", "sysgrp"])
            .expect("valid args");
        assert!(m.get_flag(options::SYSTEM));
    }

    #[test]
    fn test_force_flag() {
        let m = uu_app()
            .try_get_matches_from(["groupadd", "-f", "mygrp"])
            .expect("valid args");
        assert!(m.get_flag(options::FORCE));
    }

    #[test]
    fn test_key_values() {
        let m = uu_app()
            .try_get_matches_from(["groupadd", "-K", "GID_MIN=500", "-K", "GID_MAX=999", "grp"])
            .expect("valid args");
        let keys: Vec<&String> = m
            .get_many::<String>(options::KEY)
            .expect("KEY should be present")
            .collect();
        assert_eq!(keys.len(), 2);
    }

    fn skip_unless_root() -> bool {
        !rustix::process::geteuid().is_root()
    }

    #[test]
    fn test_create_group_with_prefix() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("create etc");
        std::fs::write(etc.join("group"), "root:x:0:\n").expect("write group");

        let code = uumain(
            vec![
                "groupadd".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "testgrp".into(),
            ]
            .into_iter(),
        );
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(etc.join("group")).expect("read group");
        assert!(content.contains("testgrp"));
        assert!(content.contains("root:x:0:"));
    }

    #[test]
    fn test_create_group_with_explicit_gid() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("create etc");
        std::fs::write(etc.join("group"), "root:x:0:\n").expect("write group");

        let code = uumain(
            vec![
                "groupadd".into(),
                "-g".into(),
                "5000".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "devgrp".into(),
            ]
            .into_iter(),
        );
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(etc.join("group")).expect("read group");
        assert!(content.contains("devgrp:x:5000:"));
    }

    #[test]
    fn test_duplicate_group_name_fails() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("create etc");
        std::fs::write(etc.join("group"), "mygrp:x:1000:\n").expect("write group");

        let code = uumain(
            vec![
                "groupadd".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "mygrp".into(),
            ]
            .into_iter(),
        );
        assert_ne!(code, 0);
    }

    #[test]
    fn test_force_on_existing_succeeds() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("create etc");
        std::fs::write(etc.join("group"), "mygrp:x:1000:\n").expect("write group");

        let code = uumain(
            vec![
                "groupadd".into(),
                "-f".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "mygrp".into(),
            ]
            .into_iter(),
        );
        assert_eq!(code, 0);
    }
}
