// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore usermod

//! `usermod` — modify a user account.
//!
//! Drop-in replacement for GNU shadow-utils `usermod(8)`.

use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, Command};
use uucore::error::{UError, UResult};

use shadow_core::audit;
use shadow_core::group::{self, GroupEntry};
use shadow_core::gshadow::GshadowEntry;
use shadow_core::passwd::PasswdEntry;
use shadow_core::shadow::{self, ShadowEntry};
use shadow_core::sysroot::SysRoot;
use shadow_core::transaction::{self, Commit, LockedFile};
use shadow_core::{nscd, validate};

mod options {
    pub const COMMENT: &str = "comment";
    pub const HOME: &str = "home";
    pub const MOVE_HOME: &str = "move-home";
    pub const EXPIREDATE: &str = "expiredate";
    pub const INACTIVE: &str = "inactive";
    pub const GID: &str = "gid";
    pub const GROUPS: &str = "groups";
    pub const APPEND: &str = "append";
    pub const REMOVE: &str = "remove";
    pub const LOCK: &str = "lock";
    pub const UNLOCK: &str = "unlock";
    pub const LOGIN: &str = "login";
    pub const SHELL: &str = "shell";
    pub const UID: &str = "uid";
    pub const PASSWORD: &str = "password";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
    pub const USER: &str = "USER";
    pub const ADD_SUBUIDS: &str = "add-subuids";
    pub const DEL_SUBUIDS: &str = "del-subuids";
    pub const ADD_SUBGIDS: &str = "add-subgids";
    pub const DEL_SUBGIDS: &str = "del-subgids";
}

#[derive(Debug)]
enum UsermodError {
    CantUpdate(String),
    BadSyntax(String),
    BadArgument(String),
    UserNotFound(String),
    UidInUse(String),
    NameInUse(String),
    GroupNotFound(String),
    CantUpdateGroup(String),
    CantChownHome(String),
    CantMoveHome(String),
}

impl fmt::Display for UsermodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CantUpdate(msg)
            | Self::BadSyntax(msg)
            | Self::BadArgument(msg)
            | Self::UserNotFound(msg)
            | Self::UidInUse(msg)
            | Self::NameInUse(msg)
            | Self::GroupNotFound(msg)
            | Self::CantUpdateGroup(msg)
            | Self::CantChownHome(msg)
            | Self::CantMoveHome(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for UsermodError {}

impl UError for UsermodError {
    fn code(&self) -> i32 {
        match self {
            Self::CantUpdate(_) => 1,
            Self::BadSyntax(_) => 2,
            Self::BadArgument(_) => 3,
            // usermod(8): 6 covers both "user doesn't exist" and
            // "specified group doesn't exist".
            Self::UserNotFound(_) | Self::GroupNotFound(_) => 6,
            Self::UidInUse(_) => 4,
            Self::NameInUse(_) => 9,
            // usermod(8): 10 = can't update the group file.
            Self::CantUpdateGroup(_) => 10,
            // usermod(8): 12 = unable to complete the home directory change.
            Self::CantChownHome(_) | Self::CantMoveHome(_) => 12,
        }
    }
}

#[uucore::main]
#[allow(clippy::too_many_lines)]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    // usermod(8): 2 for bad syntax, 3 for an argument to an option that is wrong.
    let parse_failure = |e: &clap::Error| match e.kind() {
        clap::error::ErrorKind::ValueValidation => 3,
        _ => 2,
    };
    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, parse_failure)? else {
        return Ok(());
    };

    let Some(login) = matches.get_one::<String>(options::USER) else {
        return Err(shadow_core::cli::AlreadyPrinted(2).into());
    };
    // --root DIR is a real chroot: the account files come from the new root,
    // and so does every absolute path read out of them. Done before anything
    // else, so nothing has resolved a path against the old root yet.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        shadow_core::hardening::chroot_into(std::path::Path::new(chroot_dir))
            .map_err(|e| UsermodError::CantUpdate(e.to_string()))?;
    }

    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);

    if !rustix::process::getuid().is_root() {
        return Err(UsermodError::CantUpdate(shadow_core::os_error::permission_denied()).into());
    }

    // Block signals for the passwd lock→write critical section only.
    // Dropped before the home walk so long-running operations remain interruptible.
    let signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| UsermodError::CantUpdate(format!("cannot block signals: {e}")))?;

    // A value that would add a field or a record to /etc/passwd is rejected
    // before any file is locked or written; exit 3 like other bad arguments.
    for (what, key) in [
        ("comment", options::COMMENT),
        ("home directory", options::HOME),
        ("shell", options::SHELL),
    ] {
        if let Some(value) = matches.get_one::<String>(key) {
            validate::validate_field(what, value)
                .map_err(|e| UsermodError::BadArgument(e.to_string()))?;
        }
    }

    // usermod(8) exit 3. A relative home would be resolved against the directory
    // root runs this from. An empty one is allowed, like upstream: no home.
    if matches
        .get_one::<String>(options::HOME)
        .is_some_and(|home| !home.is_empty() && !home.starts_with('/'))
    {
        return Err(UsermodError::BadArgument("homedir must be an absolute path".into()).into());
    }

    // Subordinate id ranges are validated with the other arguments, before any
    // file is written; usermod(8) exits 3 for an invalid one.
    let subid_changes = parse_subid_changes(&matches)?;

    // Parse the expiry date before anything is written, so a malformed value
    // cannot leave the passwd change committed and the shadow change not.
    // usermod(8) documents YYYY-MM-DD; days since the epoch stays accepted.
    let expire_date = match matches.get_one::<String>(options::EXPIREDATE) {
        Some(exp) => Some(
            shadow_core::date::parse_expire_date(exp)
                .map_err(|e| UsermodError::BadArgument(e.to_string()))?,
        ),
        None => None,
    };

    // Modify /etc/passwd.
    let group_path_for_lookup = root.group_path();
    let passwd_path = root.passwd_path();
    // The transaction locks, then reads, and releases on every path out --
    // including each early return below, where the file is left untouched.
    let mut passwd_file = LockedFile::<PasswdEntry>::open(&passwd_path)
        .map_err(|e| UsermodError::CantUpdate(format!("cannot open passwd: {e}")))?;
    let entries = passwd_file.entries_mut();

    let Some(idx) = entries.iter().position(|e| e.name == *login) else {
        return Err(UsermodError::UserNotFound(format!("user '{login}' does not exist")).into());
    };

    // These come after the lookup, in upstream's order: the first thing a caller
    // hears about is a login that does not exist.
    check_flag_combinations(&matches)?;

    // A hash that would add a field or a record to /etc/shadow. Upstream fails
    // on it when it writes that file, so with the code of a failed write, after
    // it has already written /etc/passwd. Refusing it here writes nothing.
    if let Some(hash) = matches.get_one::<String>(options::PASSWORD) {
        validate::validate_field("password hash", hash)
            .map_err(|e| UsermodError::CantUpdate(e.to_string()))?;
    }

    // What the account looked like, to tell afterwards if anything changed.
    let before = entries[idx].clone();

    // Save the old UID and GID before mutation so we can chown if needed.
    let old_uid = entries[idx].uid;
    let old_primary_gid = entries[idx].gid;
    let old_home = entries[idx].home.clone();

    // Check UID collision before mutating.
    if let Some(&uid) = matches.get_one::<u32>(options::UID) {
        // u32::MAX is (uid_t)-1, the "no change" sentinel of chown/setresuid.
        if uid == u32::MAX {
            return Err(UsermodError::BadArgument(format!("invalid UID '{uid}'")).into());
        }
        if entries.iter().any(|e| e.uid == uid && e.name != *login) {
            return Err(UsermodError::UidInUse(format!("UID {uid} already in use")).into());
        }
        entries[idx].uid = uid;
    }

    if let Some(c) = matches.get_one::<String>(options::COMMENT) {
        entries[idx].gecos.clone_from(c);
    }
    if let Some(h) = matches.get_one::<String>(options::HOME) {
        // One trailing slash goes, as with upstream: a home that scripts compare
        // should not depend on how the command line happened to spell it.
        let h = h.strip_suffix('/').filter(|s| !s.is_empty()).unwrap_or(h);
        h.clone_into(&mut entries[idx].home);
    }
    if let Some(s) = matches.get_one::<String>(options::SHELL) {
        entries[idx].shell.clone_from(s);
    }
    if let Some(group_arg) = matches.get_one::<String>(options::GID) {
        // usermod(8): -g takes a group name or a GID, and the group "must
        // exist". A numeric GID naming no group used to be written through,
        // leaving a primary group that does not exist.
        let groups = if group_path_for_lookup.exists() {
            group::read_group_file(&group_path_for_lookup).unwrap_or_default()
        } else {
            Vec::new()
        };
        let resolved = if let Ok(gid) = group_arg.parse::<u32>() {
            groups.iter().find(|g| g.gid == gid).map(|g| g.gid)
        } else {
            groups.iter().find(|g| g.name == *group_arg).map(|g| g.gid)
        };
        let Some(gid) = resolved else {
            return Err(
                UsermodError::GroupNotFound(format!("group '{group_arg}' does not exist")).into(),
            );
        };
        entries[idx].gid = gid;
    }
    let new_login = matches.get_one::<String>(options::LOGIN);
    if let Some(new_name) = new_login {
        validate::validate_username(new_name)
            .map_err(|e| UsermodError::BadArgument(format!("invalid login name: {e}")))?;
        // usermod(8) exit 9: the new name must not already be taken, or the
        // rename would produce two entries with the same login.
        if entries
            .iter()
            .any(|e| e.name == *new_name && e.name != *login)
        {
            return Err(
                UsermodError::NameInUse(format!("user '{new_name}' already exists")).into(),
            );
        }
        entries[idx].name.clone_from(new_name);
    }

    let new_uid = entries[idx].uid;
    let new_primary_gid = entries[idx].gid;
    let home_for_chown = entries[idx].home.clone();

    // Upstream drops an option whose value is what the account has already, and
    // says so if none is left. These ones it keeps, whatever their value. A home
    // spelled with a trailing slash counts as a different home.
    let mut changing = entries[idx] != before
        || matches
            .get_one::<String>(options::HOME)
            .is_some_and(|home| *home != before.home)
        || !subid_changes.is_empty()
        || matches.contains_id(options::GROUPS)
        || matches.contains_id(options::PASSWORD)
        || matches.get_flag(options::LOCK)
        || matches.get_flag(options::UNLOCK);

    passwd_file
        .commit()
        .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;

    // Restore signals before potentially long-running recursive chown.
    drop(signals);

    // If the UID or the primary group changed, recursively chown the home the
    // account now has, which is the one -d gave if it gave one. A previous home
    // stays as it is, like upstream: nothing was moved, and it may not be this
    // user's to change any more.
    // usermod(8): only files owned by the old UID get the new UID, and only
    // files in the old primary group get the new group.
    // A home that cannot be re-owned is reported at the end, like upstream:
    // the account files are written regardless.
    // With -m the home is not there yet, so the re-own waits for the move below.
    let move_to = matches
        .get_flag(options::MOVE_HOME)
        .then(|| matches.get_one::<String>(options::HOME))
        .flatten()
        .filter(|new_home| **new_home != old_home);
    let home_chown = if move_to.is_none()
        && (new_uid != old_uid || new_primary_gid != old_primary_gid)
        && !home_for_chown.is_empty()
    {
        rechown_home(
            &root.resolve(&home_for_chown),
            (old_uid, new_uid),
            (old_primary_gid, new_primary_gid),
        )
    } else {
        Ok(())
    };

    // Shadow modifications.
    let shadow_path = root.shadow_path();
    let do_lock = matches.get_flag(options::LOCK);
    let do_unlock = matches.get_flag(options::UNLOCK);
    let inactive = matches.get_one::<i64>(options::INACTIVE);
    let new_password = matches.get_one::<String>(options::PASSWORD);

    let login_changing = new_login.is_some();
    if shadow_path.exists()
        && (do_lock
            || do_unlock
            || expire_date.is_some()
            || inactive.is_some()
            || new_password.is_some()
            || login_changing)
    {
        let mut shadow_file = LockedFile::<ShadowEntry>::open(&shadow_path)
            .map_err(|e| UsermodError::CantUpdate(format!("cannot open shadow: {e}")))?;

        let Some(s) = shadow_file.find_mut(login) else {
            return Err(UsermodError::CantUpdate(format!(
                "user '{login}' not found in shadow file"
            ))
            .into());
        };

        if do_lock && !s.passwd.starts_with('!') {
            // Locking twice would prepend a second '!', which a single -U
            // then fails to undo.
            s.lock();
        }
        if do_unlock && !s.unlock() {
            // Like upstream: the account stays locked, which is the point of
            // refusing, and whatever else was asked for still happens.
            uucore::show_error!(
                "unlocking the user's password would result in a passwordless account.\n\
                 You should set a password with usermod -p to unlock this user's password."
            );
        }
        if let Some(parsed) = expire_date {
            changing |= s.expire_date != parsed;
            s.expire_date = parsed;
        }
        if let Some(&i) = inactive {
            let days = if i < 0 { None } else { Some(i) };
            changing |= s.inactive_days != days;
            s.inactive_days = days;
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

        shadow_file
            .commit()
            .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;
    }

    // Rename user in group membership lists when --login changes the name.
    if let Some(new_name) = new_login {
        let group_path = root.group_path();
        if group_path.exists() {
            let mut group_file = LockedFile::<GroupEntry>::open(&group_path)
                .map_err(|e| UsermodError::CantUpdate(format!("cannot open group: {e}")))?;

            for g in group_file.entries_mut() {
                if let Some(m) = g.members.iter_mut().find(|m| **m == *login) {
                    m.clone_from(new_name);
                }
            }

            // Mirror the rename in gshadow's member and admin lists. Leaving
            // it behind is exactly what grpck reports as "members differ", so
            // the two files are committed together.
            let mut files: Vec<Box<dyn Commit>> = vec![Box::new(group_file)];
            let gshadow_path = root.gshadow_path();
            if gshadow_path.exists() {
                let mut gshadow_file =
                    LockedFile::<GshadowEntry>::open(&gshadow_path).map_err(|e| {
                        UsermodError::CantUpdateGroup(format!("cannot open gshadow: {e}"))
                    })?;
                for g in gshadow_file.entries_mut() {
                    for m in g.members.iter_mut().chain(g.admins.iter_mut()) {
                        if *m == *login {
                            m.clone_from(new_name);
                        }
                    }
                }
                files.push(Box::new(gshadow_file));
            }

            transaction::commit_all(files)
                .map_err(|e| UsermodError::CantUpdateGroup(format!("{e}")))?;
        }
    }

    // Group modifications.
    if let Some(groups_str) = matches.get_one::<String>(options::GROUPS) {
        let group_path = root.group_path();
        if group_path.exists() {
            let append = matches.get_flag(options::APPEND);
            // usermod(8): an empty -G list removes every supplementary
            // membership. Splitting "" yielded one empty name, which was then
            // reported as a group that does not exist.
            let new_groups: Vec<&str> = groups_str
                .split(',')
                .map(str::trim)
                .filter(|g| !g.is_empty())
                .collect();

            // The member name to write is the one the account will carry: with
            // -l the rename above already happened, and using the old login
            // added a member that no longer exists.
            let member = new_login.unwrap_or(login);

            let mut group_file = LockedFile::<GroupEntry>::open(&group_path)
                .map_err(|e| UsermodError::CantUpdateGroup(format!("cannot open group: {e}")))?;

            // Validate every requested group first: -G takes names or GIDs,
            // and each must exist (usermod(8) exit 6).
            let mut wanted: Vec<String> = Vec::with_capacity(new_groups.len());
            for gname in &new_groups {
                let found = group_file
                    .entries()
                    .iter()
                    .find(|g| g.name == *gname || gname.parse::<u32>().is_ok_and(|id| g.gid == id))
                    .map(|g| g.name.clone());
                let Some(name) = found else {
                    return Err(UsermodError::GroupNotFound(format!(
                        "group '{gname}' does not exist"
                    ))
                    .into());
                };
                wanted.push(name);
            }

            // -r drops the user from the listed groups only, -a adds it to them,
            // and plain -G makes them the user's whole list.
            let remove = matches.get_flag(options::REMOVE);
            let update = |name: &str, members: &mut Vec<String>| {
                let listed = wanted.iter().any(|w| w == name);
                if (remove && listed) || (!remove && !append) {
                    members.retain(|m| m != login && m != member);
                }
                if listed && !remove && !members.iter().any(|m| m == member) {
                    members.push(member.clone());
                }
            };
            for g in group_file.entries_mut() {
                update(&g.name, &mut g.members);
            }

            // /etc/gshadow carries the same membership lists; leaving it
            // behind is exactly what grpck reports as "members differ".
            let mut files: Vec<Box<dyn Commit>> = vec![Box::new(group_file)];
            let gshadow_path = root.gshadow_path();
            if gshadow_path.exists() {
                let mut gshadow_file =
                    LockedFile::<GshadowEntry>::open(&gshadow_path).map_err(|e| {
                        UsermodError::CantUpdateGroup(format!("cannot open gshadow: {e}"))
                    })?;
                for g in gshadow_file.entries_mut() {
                    update(&g.name, &mut g.members);
                }
                files.push(Box::new(gshadow_file));
            }

            transaction::commit_all(files)
                .map_err(|e| UsermodError::CantUpdateGroup(format!("{e}")))?;
        }
    }

    apply_subid_changes(&root, login, &subid_changes)?;

    // usermod(8) -m: the account files are already updated, as with upstream,
    // when the move itself fails.
    let home_change = if move_to.is_some() {
        move_and_reown_home(
            &root,
            (&old_home, &home_for_chown),
            (old_uid, new_uid),
            (old_primary_gid, new_primary_gid),
        )
    } else {
        home_chown
    };

    if !changing {
        let _ = writeln!(std::io::stdout(), "usermod: no changes");
    }

    nscd::invalidate_cache("passwd");
    nscd::invalidate_cache("group");

    // The account files are written by now, but a home left behind means the
    // change is incomplete; the log has to agree with the exit status.
    audit::log_user_event("MOD_USER", login, new_uid, home_change.is_ok());

    home_change.map_err(Into::into)
}

/// Refuse options that need another one, or exclude one another, and a command
/// line with nothing on it but the login. `-P` and `-R` count as options here,
/// as they do upstream, which answers them with "no changes".
fn check_flag_combinations(matches: &clap::ArgMatches) -> Result<(), UsermodError> {
    let syntax = |msg: &str| Err(UsermodError::BadSyntax(msg.to_owned()));
    let has_groups = matches.contains_id(options::GROUPS);
    let append = matches.get_flag(options::APPEND);
    let remove = matches.get_flag(options::REMOVE);

    if !matches.ids().any(|id| {
        id != options::USER
            && matches.value_source(id.as_str()) == Some(clap::parser::ValueSource::CommandLine)
    }) {
        return syntax("no options");
    }
    if append && !has_groups {
        return syntax("-a flag is only allowed with the -G flag");
    }
    if remove && !has_groups {
        return syntax("-r flag is only allowed with the -G flag");
    }
    if append && remove {
        return syntax("-r and -a are mutually exclusive flags");
    }
    let exclusive = [
        matches.get_flag(options::LOCK),
        matches.get_flag(options::UNLOCK),
        matches.contains_id(options::PASSWORD),
    ];
    if exclusive.iter().filter(|set| **set).count() > 1 {
        return syntax("the -L, -p, and -U flags are exclusive");
    }
    if matches.get_flag(options::MOVE_HOME) && !matches.contains_id(options::HOME) {
        return syntax("-m flag is only allowed with the -d flag");
    }
    Ok(())
}

/// One requested change to `/etc/subuid` or `/etc/subgid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SubIdChange {
    gids: bool,
    remove: bool,
    first: u64,
    last: u64,
}

/// Read `-v`, `-V`, `-w` and `-W`, each of which may be given more than once.
fn parse_subid_changes(matches: &clap::ArgMatches) -> Result<Vec<SubIdChange>, UsermodError> {
    let mut changes = Vec::new();
    for (key, gids, remove) in [
        (options::ADD_SUBUIDS, false, false),
        (options::DEL_SUBUIDS, false, true),
        (options::ADD_SUBGIDS, true, false),
        (options::DEL_SUBGIDS, true, true),
    ] {
        for spec in matches.get_many::<String>(key).into_iter().flatten() {
            let (first, last) = shadow_core::subid::parse_range(spec).ok_or_else(|| {
                UsermodError::BadArgument(format!(
                    "invalid subordinate {} range '{spec}'",
                    if gids { "gid" } else { "uid" }
                ))
            })?;
            changes.push(SubIdChange {
                gids,
                remove,
                first,
                last,
            });
        }
    }
    Ok(changes)
}

/// Apply the subordinate id changes, each file in its own transaction.
///
/// The entries are keyed by the login name as given on the command line. The
/// GNU tool does the same, and does not rename them on `-l` either: a range
/// is a grant to a name, and the administrator who renames the account
/// re-grants it if that is what they meant.
fn apply_subid_changes(
    root: &SysRoot,
    login: &str,
    changes: &[SubIdChange],
) -> Result<(), UsermodError> {
    use shadow_core::subid::{SubIdEntry, add_range, remove_range};

    for gids in [false, true] {
        let mine: Vec<&SubIdChange> = changes.iter().filter(|c| c.gids == gids).collect();
        if mine.is_empty() {
            continue;
        }
        let path = if gids {
            root.subgid_path()
        } else {
            root.subuid_path()
        };
        let mut file = LockedFile::<SubIdEntry>::open_or_empty(&path).map_err(|e| {
            UsermodError::CantUpdate(format!("cannot open {}: {e}", path.display()))
        })?;
        for c in mine {
            if c.remove {
                remove_range(file.entries_mut(), login, c.first, c.last);
            } else {
                add_range(file.entries_mut(), login, c.first, c.last);
            }
        }
        file.commit().map_err(|e| {
            UsermodError::CantUpdate(format!("cannot write {}: {e}", path.display()))
        })?;
    }
    Ok(())
}

/// Do what `-m` asks once the account files are written: move the home, then
/// re-own it at its new path. Nothing is re-owned if the move does not happen.
///
/// The paths are looked at through a symlink, like upstream. A home that is a
/// symlink to a directory is renamed as a link, and then counts as a home that
/// cannot be re-owned. Across filesystems it cannot be opened, so it stays.
fn move_and_reown_home(
    root: &SysRoot,
    (old_home, new_home): (&str, &str),
    owner: (u32, u32),
    group: (u32, u32),
) -> Result<(), UsermodError> {
    use rustix::fs::FileType;

    let old_path = root.resolve(old_home);
    let new_path = root.resolve(new_home);
    if rustix::fs::stat(&new_path).is_ok() {
        return Err(UsermodError::CantMoveHome(format!(
            "directory {new_home} exists"
        )));
    }
    // An empty home resolves to the root of the prefix, which is not a home.
    let old_stat = (!old_home.is_empty())
        .then(|| rustix::fs::stat(&old_path).ok())
        .flatten();
    let Some(old_stat) = old_stat else {
        uucore::show_warning!(
            "The previous home directory ({old_home}) does not exist or is inaccessible. Move cannot be completed."
        );
        return Ok(());
    };
    if FileType::from_raw_mode(old_stat.st_mode) != FileType::Directory {
        return Err(UsermodError::CantMoveHome(format!(
            "The previous home directory ({old_home}) was not a directory. It is not removed and no home directories are created."
        )));
    }
    let is_symlink = std::fs::symlink_metadata(&old_path).is_ok_and(|m| m.is_symlink());
    move_home(&old_path, &new_path).map_err(|_| {
        UsermodError::CantMoveHome(format!("cannot rename directory {old_home} to {new_home}"))
    })?;
    if is_symlink {
        return Err(cant_chown_home());
    }
    if owner.0 != owner.1 || group.0 != group.1 {
        rechown_home(&new_path, owner, group)?;
    }
    Ok(())
}

/// Move a home directory: a rename on one filesystem, otherwise a copy that
/// keeps owners, modes, times and hard links, followed by removal of the old
/// tree. On a failed copy the partial new tree is removed and the old one
/// is left as it was. Like upstream, an old tree that cannot be fully removed
/// only gets a warning.
fn move_home(old: &Path, new: &Path) -> std::io::Result<()> {
    match std::fs::rename(old, new) {
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            copy_home(old, new)?;
            if std::fs::remove_dir_all(old).is_err() {
                uucore::show_warning!(
                    "failed to completely remove old home directory {}",
                    old.display()
                );
            }
            Ok(())
        }
        result => result,
    }
}

/// Copy the home at `old` to `new`, which must not exist, and remove what was
/// copied if that fails.
///
/// This runs as root in a tree the user controls, and `new` can sit in a
/// directory the user owns too. So no path below either of them is ever
/// resolved: every entry on both sides is reached from its parent's descriptor
/// with `O_NOFOLLOW`, and the attributes copied are those of what was opened.
/// Should the user rename `new` away and leave a symlink in its place, the copy
/// carries on in the directory it made.
fn copy_home(old: &Path, new: &Path) -> std::io::Result<()> {
    use rustix::fs::{Mode, OFlags};

    // O_NOFOLLOW only looks at the last component. In "home/" that is not the
    // link, so the kernel would resolve it. components() drops those spellings.
    let old: PathBuf = old.components().collect();
    let new: PathBuf = new.components().collect();
    let (Some(parent), Some(name)) = (new.parent(), new.file_name()) else {
        return Err(std::io::ErrorKind::InvalidInput.into());
    };
    let src = open_dir(rustix::fs::CWD, &old)?;
    let parent = rustix::fs::openat(
        rustix::fs::CWD,
        parent,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    // Root's and 0700 until the very end, so the user cannot reach anything in
    // the copy while it runs, whatever owner and mode its subdirectories have
    // been given by then.
    rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o700))?;
    let copied = open_new_dir(&parent, name).and_then(|dst| copy_tree(src, dst));
    if copied.is_err() {
        let _ = std::fs::remove_dir_all(&new);
    }
    copied
}

/// Open the directory `name` of `dir` for reading, not through a symlink.
fn open_dir<Fd: rustix::fd::AsFd, P: rustix::path::Arg>(
    dir: Fd,
    name: P,
) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(dir, name, flags, Mode::empty())?;
    Ok(std::fs::File::from(fd))
}

/// Open the directory just made at `name`. If the user owns `dir`, what is
/// there now can be one of theirs, and that must not receive the copy.
fn open_new_dir<Fd: rustix::fd::AsFd>(
    dir: Fd,
    name: &std::ffi::OsStr,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt;

    let new = open_dir(dir, name)?;
    let meta = new.metadata()?;
    if meta.uid() != rustix::process::geteuid().as_raw() || meta.mode() & 0o077 != 0 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    Ok(new)
}

/// Open the regular file `name` of `dir` for reading, and stat what was opened.
///
/// It was a regular file when it was looked at, but the user can have swapped
/// it since. `O_NONBLOCK` is there for a fifo, whose open would otherwise wait
/// for a writer the user may never bring, and `O_NOCTTY` for a terminal.
fn open_regular(
    dir: &std::fs::File,
    name: &std::ffi::CStr,
) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    use rustix::fs::{Mode, OFlags};

    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let file = std::fs::File::from(rustix::fs::openat(dir, name, flags, Mode::empty())?);
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok((file, meta))
}

/// A directory being copied.
struct CopyDir {
    src: std::fs::File,
    dst: std::fs::File,
    /// Taken before the directory is read, which changes its access time.
    meta: std::fs::Metadata,
    acl: Option<Vec<u8>>,
    /// The entries still to copy.
    names: Vec<std::ffi::CString>,
}

impl CopyDir {
    fn open(src: std::fs::File, dst: std::fs::File) -> std::io::Result<Self> {
        let meta = src.metadata()?;
        let acl = read_access_acl(&src)?;
        let names = list_names(&src)?;
        Ok(Self {
            src,
            dst,
            meta,
            acl,
            names,
        })
    }
}

/// The names in `dir`. Holds no descriptor once it returns, so a level of a
/// copy costs two, one for each side.
fn list_names(dir: &std::fs::File) -> std::io::Result<Vec<std::ffi::CString>> {
    use rustix::io::Errno;

    let mut buf = [std::mem::MaybeUninit::uninit(); 8192];
    let mut entries = rustix::fs::RawDir::new(dir, &mut buf);
    let mut names = Vec::new();
    while let Some(entry) = entries.next() {
        match entry {
            Ok(entry) => {
                let name = entry.file_name();
                if name != c"." && name != c".." {
                    names.push(name.to_owned());
                }
            }
            // The directory was deleted while it was being read.
            Err(Errno::NOENT) => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(names)
}

/// Copy the directory `src` into the empty directory `dst`, then give `dst` the
/// attributes of `src`, each subdirectory as its own contents are done.
///
/// `links` maps the (device, inode) of a multiply linked source file to its
/// first copy, as a path from `dst`. The stack is explicit: the depth of the
/// tree is the user's to choose, and running out of descriptors on a deep one
/// fails the copy, where running out of stack would kill the process and leave
/// the partial copy behind.
fn copy_tree(src: std::fs::File, dst: std::fs::File) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let top = dst.try_clone()?;
    let mut links = HashMap::new();
    let mut at = PathBuf::new();
    let mut stack = vec![CopyDir::open(src, dst)?];
    while let Some(dir) = stack.last_mut() {
        let Some(name) = dir.names.pop() else {
            if let Some(done) = stack.pop() {
                copy_attributes(&done.dst, &done.meta, done.acl.as_deref())?;
            }
            at.pop();
            continue;
        };
        let name_in_tree = at.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        if let Some(subdir) = copy_entry(dir, &name, &top, &name_in_tree, &mut links)? {
            at = name_in_tree;
            stack.push(subdir);
        }
    }
    Ok(())
}

/// Copy the entry `name` of `dir`. A directory is only made, and handed back for
/// the caller to walk. An entry the user has deleted by now needs no copy.
fn copy_entry(
    dir: &CopyDir,
    name: &std::ffi::CStr,
    top: &std::fs::File,
    name_in_tree: &Path,
    links: &mut HashMap<(u64, u64), PathBuf>,
) -> std::io::Result<Option<CopyDir>> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let handle = match rustix::fs::openat(&dir.src, name, flags, Mode::empty()) {
        Ok(handle) => std::fs::File::from(handle),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let meta = handle.metadata()?;
    let kind = meta.file_type();
    if kind.is_dir() {
        let src = open_dir(&dir.src, name)?;
        rustix::fs::mkdirat(&dir.dst, name, Mode::from_raw_mode(0o700))?;
        let dst = open_dir(&dir.dst, name)?;
        return CopyDir::open(src, dst).map(Some);
    }
    if meta.nlink() > 1
        && let Some(first) = links.get(&(meta.dev(), meta.ino()))
    {
        link_first_copy(top, first, &dir.dst, name)?;
        return Ok(None);
    }
    let meta = if kind.is_symlink() {
        let target = rustix::fs::readlinkat(&handle, c"", Vec::new())?;
        rustix::fs::symlinkat(target.as_c_str(), &dir.dst, name)?;
        copy_attributes_at(&dir.dst, name, &meta)?;
        meta
    } else if kind.is_file() {
        let (mut reader, opened) = open_regular(&dir.src, name)?;
        let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW;
        let mut writer = std::fs::File::from(rustix::fs::openat(
            &dir.dst,
            name,
            flags | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        std::io::copy(&mut reader, &mut writer)?;
        copy_attributes(&writer, &opened, read_access_acl(&reader)?.as_deref())?;
        opened
    } else if kind.is_fifo() || kind.is_char_device() || kind.is_block_device() {
        rustix::fs::mknodat(
            &dir.dst,
            name,
            rustix::fs::FileType::from_raw_mode(meta.mode()),
            Mode::from_raw_mode(0o600),
            meta.rdev(),
        )?;
        copy_attributes_at(&dir.dst, name, &meta)?;
        meta
    } else {
        // A socket belongs to a running process and cannot be copied. Refused
        // like upstream: the old home stays whole, nothing is lost silently.
        return Err(std::io::ErrorKind::Unsupported.into());
    };
    if meta.nlink() > 1 {
        links.insert((meta.dev(), meta.ino()), name_in_tree.to_path_buf());
    }
    Ok(None)
}

/// Link `name` of `dir` to the copy already made at `first`, a path from `top`.
fn link_first_copy(
    top: &std::fs::File,
    first: &Path,
    dir: &std::fs::File,
    name: &std::ffi::CStr,
) -> std::io::Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags};

    let (Some(parents), Some(leaf)) = (first.parent(), first.file_name()) else {
        return Err(std::io::ErrorKind::InvalidData.into());
    };
    let mut from: Option<std::fs::File> = None;
    for part in parents {
        let next = rustix::fs::openat(
            from.as_ref().unwrap_or(top),
            part,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        from = Some(std::fs::File::from(next));
    }
    rustix::fs::linkat(
        from.as_ref().unwrap_or(top),
        leaf,
        dir,
        name,
        AtFlags::empty(),
    )?;
    Ok(())
}

/// The access and modification times in `meta`.
fn timestamps_of(meta: &std::fs::Metadata) -> rustix::fs::Timestamps {
    use std::os::unix::fs::MetadataExt;

    rustix::fs::Timestamps {
        last_access: rustix::fs::Timespec {
            tv_sec: meta.atime(),
            tv_nsec: meta.atime_nsec(),
        },
        last_modification: rustix::fs::Timespec {
            tv_sec: meta.mtime(),
            tv_nsec: meta.mtime_nsec(),
        },
    }
}

/// The extended attribute a POSIX access ACL is stored in. The default ACL of a
/// directory is not kept, as with upstream.
const ACCESS_ACL: &std::ffi::CStr = c"system.posix_acl_access";

/// The access ACL of `file`, if it has one. An ACL has to move with the mode:
/// its mask is stored in the group bits, so a file that kept its mode and lost
/// its ACL gives the owning group what used to be only the mask.
fn read_access_acl(file: &std::fs::File) -> std::io::Result<Option<Vec<u8>>> {
    use rustix::io::Errno;

    let len = match rustix::fs::fgetxattr_query(file, ACCESS_ACL) {
        Ok(len) => len,
        Err(Errno::NODATA | Errno::NOTSUP) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut acl = vec![0; len];
    let len = rustix::fs::fgetxattr(file, ACCESS_ACL, &mut acl[..])?;
    acl.truncate(len);
    Ok(Some(acl))
}

/// Give the open `file` the owner, mode, ACL and times in `meta`. The mode is
/// set after the owner, since chown(2) clears the set-user-ID and set-group-ID
/// bits. A filesystem that cannot hold the ACL fails the copy, as carrying on
/// without it widens what the file gives away.
fn copy_attributes(
    file: &std::fs::File,
    meta: &std::fs::Metadata,
    acl: Option<&[u8]>,
) -> std::io::Result<()> {
    use rustix::fs::Mode;
    use rustix::process::{Gid, Uid};
    use std::os::unix::fs::MetadataExt;

    rustix::fs::fchown(
        file,
        Some(Uid::from_raw(meta.uid())),
        Some(Gid::from_raw(meta.gid())),
    )?;
    rustix::fs::fchmod(file, Mode::from_raw_mode(meta.mode() & 0o7777))?;
    if let Some(acl) = acl {
        rustix::fs::fsetxattr(file, ACCESS_ACL, acl, rustix::fs::XattrFlags::empty())?;
    }
    rustix::fs::futimens(file, &timestamps_of(meta))?;
    Ok(())
}

/// The same for the entry `name` of `dir`, for what cannot be opened without
/// side effects: a symlink, a fifo, a device.
fn copy_attributes_at(
    dir: &std::fs::File,
    name: &std::ffi::CStr,
    meta: &std::fs::Metadata,
) -> std::io::Result<()> {
    use rustix::fs::{AtFlags, Mode};
    use rustix::process::{Gid, Uid};
    use std::os::unix::fs::MetadataExt;

    rustix::fs::chownat(
        dir,
        name,
        Some(Uid::from_raw(meta.uid())),
        Some(Gid::from_raw(meta.gid())),
        AtFlags::SYMLINK_NOFOLLOW,
    )?;
    if !meta.file_type().is_symlink() {
        rustix::fs::chmodat(
            dir,
            name,
            Mode::from_raw_mode(meta.mode() & 0o7777),
            AtFlags::empty(),
        )?;
    }
    rustix::fs::utimensat(dir, name, &timestamps_of(meta), AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(())
}

/// Re-own a home directory after a UID or primary group change: entries
/// owned by the old UID get the new one, entries in the old group get the
/// new group, anything else is left alone.
///
/// Whether the home is the user's is decided through a symlink, like upstream.
/// A home that is missing, a dangling link, or not the user's is left alone.
/// One that is the user's is opened without following a link, however its path
/// is spelled, and if that fails it is not walked: it is a symlink, or not a
/// directory, or it vanished between the two calls, and upstream exits 12 in
/// all three as well. If it was swapped between them for a directory that is
/// not the user's, it is left alone.
///
/// The user owns the tree and can rename, replace or re-link entries in it
/// while this runs as root, so the walk never resolves a path below `home`:
/// each directory is opened relative to its parent's descriptor with
/// `O_NOFOLLOW`, each other entry with `O_PATH | O_NOFOLLOW`, and the ownership
/// test and the change both go through that one descriptor. A symlink swapped
/// in mid-walk is re-owned itself and never followed, and the inode that was
/// checked is the inode that changes. See [`HomeWalk::chown_matching`] for the
/// one thing in the old group that keeps it.
///
/// Every entry is re-owned through the descriptor that found it, directories
/// included, so a directory that cannot be opened still changes hands. Any
/// failure to re-own, open or read does not stop the walk, unlike upstream; it
/// becomes `CantChownHome`, exit 12, once the rest of the tree is done, and
/// the caller raises that after the account files are written. This includes
/// running out of descriptors on a tree deeper than the limit, where the part
/// out of reach stays as it was. An entry deleted or replaced by the user
/// mid-walk is not a failure: nothing can make a walk complete against someone
/// changing the tree under it, and it has nothing left to re-own.
fn rechown_home(home: &Path, owner: (u32, u32), group: (u32, u32)) -> Result<(), UsermodError> {
    use std::rc::Rc;
    use uucore::safe_traversal::{DirFd, SymlinkBehavior};

    // O_NOFOLLOW only looks at the last component. In "home/" or "home/." that
    // is not the link, so the kernel would resolve it and the walk would start
    // wherever it points. components() drops those spellings.
    let home: std::path::PathBuf = home.components().collect();

    if !rustix::fs::stat(&home).is_ok_and(|st| st.st_uid == owner.0) {
        return Ok(());
    }
    let Ok(top) = DirFd::open(&home, SymlinkBehavior::NoFollow) else {
        return Err(cant_chown_home());
    };
    let Ok(top_stat) = rustix::fs::fstat(&top) else {
        return Err(cant_chown_home());
    };
    // Swapped for something else since the check: not the user's any more.
    if top_stat.st_uid != owner.0 {
        return Ok(());
    }

    let mut walk = HomeWalk {
        owner,
        group,
        complete: true,
    };
    walk.chown_matching(&top, &top_stat);

    // Directories still to read, by name under a parent held open. A parent
    // stays open only while children of it wait, so the descriptors held
    // follow the depth of the tree, not its width, and nothing recurses.
    let mut pending: Vec<(Rc<DirFd>, std::ffi::OsString)> = Vec::new();
    walk.queue_entries(&Rc::new(top), &mut pending);
    while let Some((parent, name)) = pending.pop() {
        let dir = match parent.open_subdir(&name, SymlinkBehavior::NoFollow) {
            Ok(dir) => dir,
            Err(e) => {
                use rustix::io::Errno;
                match Errno::from_io_error(&e) {
                    // Deleted since it was listed: the user may do that.
                    Some(Errno::NOENT) => {}
                    // Replaced by something that is not a directory, again the
                    // user's own doing. What is there now is re-owned and not
                    // followed; there is nothing to walk.
                    Some(Errno::NOTDIR | Errno::LOOP) => {
                        walk.reown_entry(&parent, &name);
                    }
                    _ => walk.complete = false,
                }
                continue;
            }
        };
        drop(parent);
        // Already re-owned when it was found, unless the name now holds a
        // directory that was swapped in since.
        let Ok(st) = rustix::fs::fstat(&dir) else {
            walk.complete = false;
            continue;
        };
        walk.chown_matching(&dir, &st);
        walk.queue_entries(&Rc::new(dir), &mut pending);
    }

    if walk.complete {
        Ok(())
    } else {
        Err(cant_chown_home())
    }
}

/// The same message for every way of leaving the home behind, as the only
/// thing the caller can do about it is look at the home.
fn cant_chown_home() -> UsermodError {
    UsermodError::CantChownHome("Failed to change ownership of the home directory".into())
}

/// One run over a home. A failure does not stop it, the rest of the tree is
/// still the user's; it is remembered in `complete` and reported at the end.
struct HomeWalk {
    owner: (u32, u32),
    group: (u32, u32),
    complete: bool,
}

impl HomeWalk {
    /// Re-own every entry of `dir`, and queue the directories to be walked.
    fn queue_entries(
        &mut self,
        dir: &std::rc::Rc<uucore::safe_traversal::DirFd>,
        pending: &mut Vec<(
            std::rc::Rc<uucore::safe_traversal::DirFd>,
            std::ffi::OsString,
        )>,
    ) {
        for name in self.read_names(dir) {
            if self.reown_entry(dir, &name) {
                pending.push((std::rc::Rc::clone(dir), name));
            }
        }
    }

    /// The names in `dir`, as many as could be read.
    ///
    /// `DirFd::read_dir` needs a second descriptor, so it fails outright at the
    /// descriptor limit, and it drops what it read if a later read fails. This
    /// needs none, and whatever came back is still re-owned.
    fn read_names(&mut self, dir: &uucore::safe_traversal::DirFd) -> Vec<std::ffi::OsString> {
        use rustix::io::Errno;
        use std::os::unix::ffi::OsStrExt;

        let mut buf = [std::mem::MaybeUninit::uninit(); 8192];
        let mut entries = rustix::fs::RawDir::new(dir, &mut buf);
        let mut names = Vec::new();
        while let Some(entry) = entries.next() {
            match entry {
                Ok(entry) => {
                    let name = entry.file_name();
                    if name != c"." && name != c".." {
                        names.push(std::ffi::OsStr::from_bytes(name.to_bytes()).to_owned());
                    }
                }
                // The directory was deleted while it was being read.
                Err(Errno::NOENT) => break,
                Err(_) => {
                    self.complete = false;
                    break;
                }
            }
        }
        names
    }

    /// Re-own the entry `name` of `dir` through a descriptor of its own, and
    /// say whether it is a directory. A directory is re-owned here too, before
    /// it is opened: one that cannot be opened then still changes hands, and
    /// this descriptor never followed anything to get to it.
    fn reown_entry(&mut self, dir: &uucore::safe_traversal::DirFd, name: &std::ffi::OsStr) -> bool {
        use rustix::fs::{FileType, Mode, OFlags};
        use rustix::io::Errno;

        let entry = match rustix::fs::openat(
            dir,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(entry) => entry,
            // Deleted since it was listed: the user may do that.
            Err(Errno::NOENT) => return false,
            Err(_) => {
                self.complete = false;
                return false;
            }
        };
        let Ok(st) = rustix::fs::fstat(&entry) else {
            self.complete = false;
            return false;
        };
        self.chown_matching(&entry, &st);
        FileType::from_raw_mode(st.st_mode) == FileType::Directory
    }

    /// Give the file behind `fd` the new UID if it has the old one, and the new
    /// GID if it has the old one. `st` is the `fstat` of this same descriptor,
    /// so the inode checked is the inode changed. `fd` may be an `O_PATH`
    /// descriptor, so the change goes through `fchownat` with `AT_EMPTY_PATH`,
    /// which works on one and, for a symlink, changes the link itself.
    ///
    /// Unlike upstream, the group of a hard link to someone else's file is left
    /// alone. The user can link a file they can write into their home, and it
    /// is one inode: regrouping this name regroups the file where its owner
    /// keeps it, and can take it away from the people its mode was for. A file
    /// the user owns is theirs however many names it has, so it changes as any
    /// other does, with `-g` alone too: skipping those would leave the hard
    /// links every backup tree and package store is full of in the old group.
    fn chown_matching(&mut self, fd: impl rustix::fd::AsFd, st: &rustix::fs::Stat) {
        use rustix::fs::FileType;

        let (old_owner, new_owner) = self.owner;
        let (old_group, new_group) = self.group;
        let someone_elses_link = st.st_nlink > 1
            && st.st_uid != old_owner
            && FileType::from_raw_mode(st.st_mode) != FileType::Directory;
        let set_owner = (old_owner != new_owner && st.st_uid == old_owner)
            .then(|| rustix::process::Uid::from_raw(new_owner));
        let set_group = (old_group != new_group && st.st_gid == old_group && !someone_elses_link)
            .then(|| rustix::process::Gid::from_raw(new_group));
        if set_owner.is_none() && set_group.is_none() {
            return;
        }
        match rustix::fs::chownat(
            &fd,
            c"",
            set_owner,
            set_group,
            rustix::fs::AtFlags::EMPTY_PATH,
        ) {
            // ENOENT: deleted after it was opened, the user may do that.
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(_) => self.complete = false,
        }
    }
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn uu_app() -> Command {
    Command::new("usermod")
        .about("Edit a user account's fields")
        .override_usage("usermod [options] LOGIN")
        .version(shadow_core::cli::VERSION)
        // usermod(8) spells --del-subuids as -V; clap's own -V is given up
        // and --version kept.
        .disable_version_flag(true)
        .arg(
            Arg::new("version")
                .long("version")
                .help("print version")
                .action(ArgAction::Version),
        )
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
            Arg::new(options::MOVE_HOME)
                .short('m')
                .long("move-home")
                .help("Move the contents of the home directory to the new location (use only with -d)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::EXPIREDATE)
                .short('e')
                .long("expiredate")
                .value_name("EXPIRE_DATE")
                .help("Set the account expiration date")
                .allow_hyphen_values(true),
        )
        .arg(
            Arg::new(options::INACTIVE)
                .short('f')
                .long("inactive")
                .value_name("INACTIVE")
                .value_parser(clap::value_parser!(i64))
                .help("Days the password may stay expired before disabling the account")
                .allow_hyphen_values(true),
        )
        .arg(
            Arg::new(options::GID)
                .short('g')
                .long("gid")
                .value_name("GROUP")
                .help("Replace the primary group (name or GID; the group must exist)"),
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
                .help("Add to the supplementary groups instead of replacing them (only effective with -G)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::REMOVE)
                .short('r')
                .long("remove")
                .help("Remove from the supplementary groups given with -G only")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::LOCK)
                .short('L')
                .long("lock")
                .help("Disable login by locking the password")
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
            Arg::new(options::ADD_SUBUIDS)
                .short('v')
                .long("add-subuids")
                .value_name("FIRST-LAST")
                .action(ArgAction::Append)
                .help("add a range of subordinate uids"),
        )
        .arg(
            Arg::new(options::DEL_SUBUIDS)
                .short('V')
                .long("del-subuids")
                .value_name("FIRST-LAST")
                .action(ArgAction::Append)
                .help("remove a range of subordinate uids"),
        )
        .arg(
            Arg::new(options::ADD_SUBGIDS)
                .short('w')
                .long("add-subgids")
                .value_name("FIRST-LAST")
                .action(ArgAction::Append)
                .help("add a range of subordinate gids"),
        )
        .arg(
            Arg::new(options::DEL_SUBGIDS)
                .short('W')
                .long("del-subgids")
                .value_name("FIRST-LAST")
                .action(ArgAction::Append)
                .help("remove a range of subordinate gids"),
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
    fn test_negative_one_inactive_and_expiredate() {
        let m = uu_app()
            .try_get_matches_from(["usermod", "-f", "-1", "-e", "-1", "u"])
            .expect("should parse -f -1 -e -1");
        assert_eq!(m.get_one::<i64>(options::INACTIVE).copied(), Some(-1));
        assert_eq!(
            m.get_one::<String>(options::EXPIREDATE).map(String::as_str),
            Some("-1")
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

    #[test]
    fn test_copy_home_keeps_links_modes_and_times() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

        let src = tempfile::tempdir().expect("tempdir");
        let dst = tempfile::tempdir().expect("tempdir");
        let s = src.path();
        std::fs::create_dir(s.join("d")).expect("mkdir");
        std::fs::write(s.join("d/f"), "data").expect("write");
        std::fs::set_permissions(s.join("d/f"), std::fs::Permissions::from_mode(0o640))
            .expect("chmod");
        std::fs::hard_link(s.join("d/f"), s.join("hard")).expect("link");
        std::os::unix::fs::symlink("d/f", s.join("sym")).expect("symlink");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            s.join("fifo"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .expect("mkfifo");
        let old = rustix::fs::Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: 1_000_000_000,
                tv_nsec: 0,
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: 1_000_000_000,
                tv_nsec: 0,
            },
        };
        for p in ["d/f", "d"] {
            rustix::fs::utimensat(
                rustix::fs::CWD,
                s.join(p),
                &old,
                rustix::fs::AtFlags::empty(),
            )
            .expect("utimensat");
        }

        let d = dst.path().join("new");
        copy_home(s, &d).expect("copy_home");

        let stat = |p: &str| std::fs::symlink_metadata(d.join(p)).expect("stat");
        assert_eq!(
            std::fs::read_to_string(d.join("d/f")).expect("read"),
            "data"
        );
        assert_eq!(stat("d/f").mode() & 0o7777, 0o640);
        assert_eq!(stat("d/f").mtime(), 1_000_000_000);
        assert_eq!(stat("d").mtime(), 1_000_000_000);
        assert_eq!(
            stat("hard").ino(),
            stat("d/f").ino(),
            "hard link should stay a link"
        );
        assert_eq!(
            std::fs::read_link(d.join("sym")).expect("readlink"),
            Path::new("d/f")
        );
        assert!(stat("fifo").file_type().is_fifo());
    }

    /// Make `dir/name/name/...`, `depth` levels of it, without a path that
    /// long ever being given to the kernel.
    fn make_deep(dir: &Path, name: &str, depth: usize) {
        use rustix::fs::{Mode, OFlags};

        let mut at = std::fs::File::open(dir).expect("open");
        for _ in 0..depth {
            rustix::fs::mkdirat(&at, name, Mode::from_raw_mode(0o755)).expect("mkdirat");
            at = std::fs::File::from(
                rustix::fs::openat(
                    &at,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .expect("openat"),
            );
        }
        let f = rustix::fs::openat(
            &at,
            "bottom",
            OFlags::WRONLY | OFlags::CREATE | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .expect("create");
        drop(f);
    }

    /// How many directories the chain `dir/name/name/...` really has.
    fn depth_of(dir: &Path, name: &str) -> usize {
        use rustix::fs::{Mode, OFlags};

        let mut at = std::fs::File::open(dir).expect("open");
        let mut depth = 0;
        while let Ok(next) = rustix::fs::openat(
            &at,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            at = std::fs::File::from(next);
            depth += 1;
        }
        depth
    }

    /// The new path can sit in a directory the user owns, and then they can
    /// rename the copy away and leave a symlink in its place while it runs.
    /// Whatever is copied after that must not land where the link points.
    #[test]
    fn test_copy_home_is_not_redirected_by_a_swapped_path() {
        let src = tempfile::tempdir().expect("tempdir");
        for i in 0..4000 {
            std::fs::write(src.path().join(format!("f{i}")), "x").expect("write");
        }
        let parent = tempfile::tempdir().expect("tempdir");
        let new = parent.path().join("new");
        let aside = parent.path().join("aside");
        let trap = parent.path().join("trap");
        std::fs::create_dir(&trap).expect("mkdir");

        let swapper = {
            let (new, aside, trap) = (new.clone(), aside.clone(), trap.clone());
            std::thread::spawn(move || {
                while std::fs::rename(&new, &aside).is_err() {
                    std::hint::spin_loop();
                }
                std::os::unix::fs::symlink(&trap, &new).expect("symlink");
            })
        };
        let copied = copy_home(src.path(), &new);
        swapper.join().expect("swapper");

        let landed = std::fs::read_dir(&trap).expect("read_dir").count();
        assert_eq!(landed, 0, "{landed} entries went through the link");
        // Swapped before it was even opened, the copy fails instead, which is
        // as good: nothing was written anywhere else.
        if copied.is_ok() {
            let kept = std::fs::read_dir(&aside).expect("read_dir").count();
            assert_eq!(kept, 4000, "everything is in the directory that was made");
        }
    }

    /// A planted directory at the new path is not the one this run made, and
    /// must not receive the copy.
    #[test]
    fn test_open_new_dir_refuses_what_others_can_enter() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().expect("tempdir");
        let planted = parent.path().join("planted");
        std::fs::create_dir(&planted).expect("mkdir");
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let dir = std::fs::File::open(parent.path()).expect("open");
        assert!(open_new_dir(&dir, std::ffi::OsStr::new("planted")).is_err());
    }

    #[test]
    fn test_copy_home_deeper_than_path_max() {
        let src = tempfile::tempdir().expect("tempdir");
        let name = "n".repeat(200);
        make_deep(src.path(), &name, 25);
        let parent = tempfile::tempdir().expect("tempdir");
        let new = parent.path().join("new");

        copy_home(src.path(), &new).expect("copy_home");

        assert_eq!(depth_of(&new, &name), 25);
    }

    /// A home the user controls must not be able to crash this. Runs on a test
    /// thread, with a smaller stack than the main one, so a recursive copy
    /// overflows at this depth, and that takes the whole test binary down.
    #[test]
    fn test_copy_home_does_not_recurse() {
        use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

        // Two descriptors per level. Past the limit the copy fails cleanly.
        let limit = getrlimit(Resource::Nofile);
        if limit.maximum.is_some_and(|hard| hard < 4096) {
            return;
        }
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: limit.maximum.or(Some(1 << 20)),
                maximum: limit.maximum,
            },
        )
        .expect("setrlimit");

        let src = tempfile::tempdir().expect("tempdir");
        make_deep(src.path(), "d", 1500);
        let parent = tempfile::tempdir().expect("tempdir");
        let new = parent.path().join("new");

        copy_home(src.path(), &new).expect("copy_home");

        assert_eq!(depth_of(&new, "d"), 1500);
    }

    /// The user can swap a regular file for a fifo between the two opens, and
    /// opening a fifo for reading waits for a writer the user may never bring.
    #[test]
    fn test_open_regular_does_not_wait_on_a_fifo() {
        let parent = tempfile::tempdir().expect("tempdir");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            parent.path().join("fifo"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .expect("mkfifo");
        let dir = std::fs::File::open(parent.path()).expect("open");

        let (done, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(open_regular(&dir, c"fifo").map(|_| ()));
        });
        let opened = wait
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the open must not block");
        assert!(opened.is_err(), "a fifo is not a regular file");
    }

    #[test]
    fn test_copy_home_keeps_directory_access_times() {
        use std::os::unix::fs::MetadataExt;

        let src = tempfile::tempdir().expect("tempdir");
        let sub = src.path().join("sub");
        std::fs::create_dir(&sub).expect("mkdir");
        std::fs::write(sub.join("f"), "x").expect("write");
        let times = rustix::fs::Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: 1_000_000_000,
                tv_nsec: 0,
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: 1_000_000_000,
                tv_nsec: 0,
            },
        };
        rustix::fs::utimensat(rustix::fs::CWD, &sub, &times, rustix::fs::AtFlags::empty())
            .expect("utimensat");
        let parent = tempfile::tempdir().expect("tempdir");
        let new = parent.path().join("new");

        copy_home(src.path(), &new).expect("copy_home");

        let copied = std::fs::metadata(new.join("sub")).expect("stat");
        assert_eq!(copied.atime(), 1_000_000_000);
        assert_eq!(copied.mtime(), 1_000_000_000);
    }

    /// An ACL's mask lives in the group bits of the mode. A file that lost its
    /// ACL but kept its mode gives the owning group what only the mask was.
    #[test]
    fn test_copy_home_keeps_the_access_acl() {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::tempdir().expect("tempdir");
        let file = src.path().join("f");
        std::fs::write(&file, "x").expect("write");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        // user::rwx user:1234:r-- group::--- mask::r-- other::---
        // The same for the directory, which its owner has to be able to enter.
        let entry = |tag: u16, perm: u16, id: u32| {
            [
                tag.to_le_bytes().as_slice(),
                perm.to_le_bytes().as_slice(),
                id.to_le_bytes().as_slice(),
            ]
            .concat()
        };
        let acl = [
            2u32.to_le_bytes().to_vec(),
            entry(0x01, 7, u32::MAX),
            entry(0x02, 4, 1234),
            entry(0x04, 0, u32::MAX),
            entry(0x10, 4, u32::MAX),
            entry(0x20, 0, u32::MAX),
        ]
        .concat();
        let set = |path: &Path| {
            rustix::fs::setxattr(
                path,
                "system.posix_acl_access",
                &acl,
                rustix::fs::XattrFlags::empty(),
            )
        };
        if set(&file).is_err() || set(src.path()).is_err() {
            return; // No ACLs on this filesystem.
        }
        let parent = tempfile::tempdir().expect("tempdir");
        let new = parent.path().join("new");

        copy_home(src.path(), &new).expect("copy_home");

        for path in [new.join("f"), new.clone()] {
            let mut got = vec![0; acl.len() + 64];
            let n = rustix::fs::getxattr(&path, "system.posix_acl_access", &mut got[..])
                .expect("the ACL is there");
            assert_eq!(&got[..n], &acl[..], "{}", path.display());
        }
    }

    /// Ubuntu's usermod refuses the whole move over a socket, and leaves the
    /// old home as it was. Dropping it and exiting 0 would lose it silently.
    #[test]
    fn test_copy_home_refuses_a_socket() {
        let src = tempfile::tempdir().expect("tempdir");
        let _socket = std::os::unix::net::UnixListener::bind(src.path().join("s")).expect("bind");
        let parent = tempfile::tempdir().expect("tempdir");
        let new = parent.path().join("new");

        assert!(copy_home(src.path(), &new).is_err());
        assert!(!new.exists(), "the partial copy is removed");
        assert!(src.path().join("s").exists(), "the old home is left");
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
