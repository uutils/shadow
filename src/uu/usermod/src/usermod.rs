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
use std::os::unix::fs::DirBuilderExt;
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
    BadArgument(String),
    UserNotFound(String),
    UidInUse(String),
    NameInUse(String),
    GroupNotFound(String),
    CantUpdateGroup(String),
    CantMoveHome(String),
}

impl fmt::Display for UsermodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CantUpdate(msg)
            | Self::BadArgument(msg)
            | Self::UserNotFound(msg)
            | Self::UidInUse(msg)
            | Self::NameInUse(msg)
            | Self::GroupNotFound(msg)
            | Self::CantUpdateGroup(msg)
            | Self::CantMoveHome(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for UsermodError {}

impl UError for UsermodError {
    fn code(&self) -> i32 {
        match self {
            Self::CantUpdate(_) => 1,
            Self::BadArgument(_) => 3,
            // usermod(8): 6 covers both "user doesn't exist" and
            // "specified group doesn't exist".
            Self::UserNotFound(_) | Self::GroupNotFound(_) => 6,
            Self::UidInUse(_) => 4,
            Self::NameInUse(_) => 9,
            // usermod(8): 10 = can't update the group file.
            Self::CantUpdateGroup(_) => 10,
            // usermod(8): 12 = unable to complete the move of the home directory.
            Self::CantMoveHome(_) => 12,
        }
    }
}

#[uucore::main]
#[allow(clippy::too_many_lines)]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 2)? else {
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
    // Dropped before recursive_chown so long-running operations remain interruptible.
    let signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| UsermodError::CantUpdate(format!("cannot block signals: {e}")))?;

    // A value that would add a field or a record to /etc/passwd is rejected
    // before any file is locked or written; exit 3 like other bad arguments.
    for (what, key) in [
        ("comment", options::COMMENT),
        ("home directory", options::HOME),
        ("shell", options::SHELL),
        ("password hash", options::PASSWORD),
    ] {
        if let Some(value) = matches.get_one::<String>(key) {
            validate::validate_field(what, value)
                .map_err(|e| UsermodError::BadArgument(e.to_string()))?;
        }
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

    // Save the old UID, GID and home dir before mutation so we can chown if needed.
    let old_uid = entries[idx].uid;
    let old_primary_gid = entries[idx].gid;
    let home_for_chown = entries[idx].home.clone();
    let home_is_changing = matches.get_one::<String>(options::HOME).is_some();

    // Check UID collision before mutating.
    if let Some(&uid) = matches.get_one::<u32>(options::UID) {
        if entries.iter().any(|e| e.uid == uid && e.name != *login) {
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

    passwd_file
        .commit()
        .map_err(|e| UsermodError::CantUpdate(format!("{e}")))?;

    // Restore signals before potentially long-running recursive chown.
    drop(signals);

    // If the UID or the primary group changed and the home directory was not
    // explicitly moved, recursively chown the existing home directory.
    // usermod(8): only files owned by the old UID get the new UID, and only
    // files in the old primary group get the new group.
    if (new_uid != old_uid || new_primary_gid != old_primary_gid)
        && !home_is_changing
        && !home_for_chown.is_empty()
    {
        rechown_home(
            &root.resolve(&home_for_chown),
            (old_uid, new_uid),
            (old_primary_gid, new_primary_gid),
        );
    }

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
            return Err(UsermodError::BadArgument(format!(
                "unlocking '{login}' would leave the account without a password"
            ))
            .into());
        }
        if let Some(parsed) = expire_date {
            s.expire_date = parsed;
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

            if !append {
                for g in group_file.entries_mut() {
                    g.members.retain(|m| m != login && m != member);
                }
            }
            for gname in &wanted {
                if let Some(g) = group_file.find_mut(gname)
                    && !g.members.iter().any(|m| m == member)
                {
                    g.members.push(member.clone());
                }
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
                if !append {
                    for g in gshadow_file.entries_mut() {
                        g.members.retain(|m| m != login && m != member);
                    }
                }
                for gname in &wanted {
                    if let Some(g) = gshadow_file.find_mut(gname)
                        && !g.members.iter().any(|m| m == member)
                    {
                        g.members.push(member.clone());
                    }
                }
                files.push(Box::new(gshadow_file));
            }

            transaction::commit_all(files)
                .map_err(|e| UsermodError::CantUpdateGroup(format!("{e}")))?;
        }
    }

    apply_subid_changes(&root, login, &subid_changes)?;

    // usermod(8) -m: the account files are already updated, as with GNU,
    // when the move itself fails.
    if matches.get_flag(options::MOVE_HOME)
        && let Some(new_home) = matches.get_one::<String>(options::HOME)
        && *new_home != home_for_chown
        && !home_for_chown.is_empty()
    {
        let old_path = root.resolve(&home_for_chown);
        let new_path = root.resolve(new_home);
        if !std::fs::symlink_metadata(&old_path).is_ok_and(|m| m.is_dir()) {
            uucore::show_warning!(
                "The previous home directory ({home_for_chown}) does not exist or is inaccessible. Move cannot be completed."
            );
        } else if std::fs::symlink_metadata(&new_path).is_ok() {
            return Err(UsermodError::CantMoveHome(format!("directory {new_home} exists")).into());
        } else {
            move_home(&old_path, &new_path).map_err(|_| {
                UsermodError::CantMoveHome(format!(
                    "cannot rename directory {home_for_chown} to {new_home}"
                ))
            })?;
            if new_uid != old_uid || new_primary_gid != old_primary_gid {
                rechown_home(
                    &new_path,
                    (old_uid, new_uid),
                    (old_primary_gid, new_primary_gid),
                );
            }
        }
    }

    nscd::invalidate_cache("passwd");
    nscd::invalidate_cache("group");

    audit::log_user_event("MOD_USER", login, new_uid, true);

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

/// Re-own a home directory after a UID or primary group change. Like GNU,
/// only a directory the user owns is walked, and a symlinked home is not
/// followed.
fn rechown_home(home: &Path, owner: (u32, u32), group: (u32, u32)) {
    use std::os::unix::fs::MetadataExt;

    if std::fs::symlink_metadata(home).is_ok_and(|m| m.is_dir() && m.uid() == owner.0) {
        recursive_chown(home, owner, group);
    }
}

/// Move a home directory: a rename on one filesystem, otherwise a copy that
/// keeps owners, modes, times and hard links, followed by removal of the old
/// tree. On a failed copy the partial new tree is removed and the old one
/// is left as it was. Like GNU, an old tree that cannot be fully removed
/// only gets a warning.
fn move_home(old: &Path, new: &Path) -> std::io::Result<()> {
    use rustix::fs::{Mode, OFlags};

    match std::fs::rename(old, new) {
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            let src = std::fs::File::from(rustix::fs::openat(
                rustix::fs::CWD,
                old,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            // Root-owned and 0700 until copy_tree gives it the old home's
            // attributes last, so the user cannot reach the copy meanwhile.
            std::fs::DirBuilder::new().mode(0o700).create(new)?;
            if let Err(e) = copy_tree(&src, new, &mut HashMap::new()) {
                let _ = std::fs::remove_dir_all(new);
                return Err(e);
            }
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

/// Copy the directory open as `src` into the existing directory `dst`, then
/// give `dst` the attributes of `src`. `links` maps the (device, inode) of a
/// multiply linked source file to its first copy.
///
/// The user owns the source tree and can swap any entry for a symlink while
/// it is copied, so every entry is opened relative to its directory with
/// `O_NOFOLLOW`, and the attributes copied are those of what was opened.
fn copy_tree(
    src: &std::fs::File,
    dst: &Path,
    links: &mut HashMap<(u64, u64), PathBuf>,
) -> std::io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};

    let open = |name: &std::ffi::CStr, flags: OFlags| -> std::io::Result<std::fs::File> {
        let fd = rustix::fs::openat(
            src,
            name,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(std::fs::File::from(fd))
    };
    for entry in rustix::fs::Dir::read_from(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let to = dst.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        let handle = open(name, OFlags::PATH)?;
        let meta = handle.metadata()?;
        let kind = meta.file_type();
        if kind.is_dir() {
            let dir = open(name, OFlags::RDONLY | OFlags::DIRECTORY)?;
            std::fs::DirBuilder::new().mode(0o700).create(&to)?;
            copy_tree(&dir, &to, links)?;
            continue;
        }
        let id = (meta.dev(), meta.ino());
        if meta.nlink() > 1
            && let Some(first) = links.get(&id)
        {
            std::fs::hard_link(first, &to)?;
            continue;
        }
        let meta = if kind.is_symlink() {
            let target = rustix::fs::readlinkat(&handle, c"", Vec::new())?;
            std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(target.to_bytes()), &to)?;
            meta
        } else if kind.is_file() {
            let mut reader = open(name, OFlags::RDONLY)?;
            let opened = reader.metadata()?;
            if !opened.is_file() {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let mut writer = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&to)?;
            std::io::copy(&mut reader, &mut writer)?;
            opened
        } else if kind.is_fifo() || kind.is_char_device() || kind.is_block_device() {
            rustix::fs::mknodat(
                rustix::fs::CWD,
                &to,
                rustix::fs::FileType::from_raw_mode(meta.mode()),
                Mode::from_raw_mode(0o600),
                meta.rdev(),
            )?;
            meta
        } else {
            // Sockets belong to a running process and cannot be copied.
            continue;
        };
        if meta.nlink() > 1 {
            links.insert(id, to.clone());
        }
        copy_attributes(&to, &meta)?;
    }
    // Last, so that copying the entries does not change the times.
    copy_attributes(dst, &src.metadata()?)
}

/// Give `path` the owner, mode and times in `meta`. The mode is set after the
/// owner, since chown(2) clears the set-user-ID and set-group-ID bits.
fn copy_attributes(path: &Path, meta: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    std::os::unix::fs::lchown(path, Some(meta.uid()), Some(meta.gid()))?;
    if !meta.file_type().is_symlink() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(meta.mode() & 0o7777))?;
    }
    let time = |sec: i64, nsec: i64| rustix::fs::Timespec {
        tv_sec: sec,
        tv_nsec: nsec,
    };
    rustix::fs::utimensat(
        rustix::fs::CWD,
        path,
        &rustix::fs::Timestamps {
            last_access: time(meta.atime(), meta.atime_nsec()),
            last_modification: time(meta.mtime(), meta.mtime_nsec()),
        },
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )?;
    Ok(())
}

/// Recursively chown all files and directories under `path`: those owned by
/// the old UID get the new UID, and those whose group is the old GID get the
/// new GID. Other owners and groups are left untouched.
///
/// Uses `fchownat` with `AT_SYMLINK_NOFOLLOW` so symlinks themselves are
/// re-owned without following them.
fn recursive_chown(path: &Path, owner: (u32, u32), group: (u32, u32)) {
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if let Ok(meta) = std::fs::symlink_metadata(&entry_path) {
                chown_matching(&entry_path, &meta, owner, group);
                if meta.is_dir() {
                    recursive_chown(&entry_path, owner, group);
                }
            }
        }
    }
    // Also chown the directory itself.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        chown_matching(path, &meta, owner, group);
    }
}

/// Give `path` the new UID if it has the old one, and the new GID if it has
/// the old one.
fn chown_matching(path: &Path, meta: &std::fs::Metadata, owner: (u32, u32), group: (u32, u32)) {
    use std::os::unix::fs::MetadataExt;

    let (old_owner, new_owner) = owner;
    let (old_group, new_group) = group;
    let set_owner = (old_owner != new_owner && meta.uid() == old_owner)
        .then(|| rustix::process::Uid::from_raw(new_owner));
    let set_group = (old_group != new_group && meta.gid() == old_group)
        .then(|| rustix::process::Gid::from_raw(new_group));
    if set_owner.is_some() || set_group.is_some() {
        let _ = rustix::fs::chownat(
            rustix::fs::CWD,
            path,
            set_owner,
            set_group,
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
                .requires(options::HOME)
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
                .requires(options::GROUPS)
                .help("Add to the supplementary groups instead of replacing them (only effective with -G)")
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
    fn test_lock_unlock_conflict() {
        assert!(
            uu_app()
                .try_get_matches_from(["usermod", "-L", "-U", "u"])
                .is_err()
        );
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
    fn test_copy_tree_keeps_links_modes_and_times() {
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

        let src_dir = std::fs::File::open(s).expect("open");
        copy_tree(&src_dir, dst.path(), &mut HashMap::new()).expect("copy_tree");

        let d = dst.path();
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
