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
    BadArgument(String),
    UserNotFound(String),
    UidInUse(String),
    NameInUse(String),
    GroupNotFound(String),
    CantUpdateGroup(String),
    CantChownHome(String),
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
            | Self::CantChownHome(msg) => f.write_str(msg),
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
            // usermod(8): 12 = unable to complete the home directory change.
            Self::CantChownHome(_) => 12,
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
    // Dropped before the home walk so long-running operations remain interruptible.
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

    // Save the old UID and GID before mutation so we can chown if needed.
    let old_uid = entries[idx].uid;
    let old_primary_gid = entries[idx].gid;

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
    let home_chown = if (new_uid != old_uid || new_primary_gid != old_primary_gid)
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

    nscd::invalidate_cache("passwd");
    nscd::invalidate_cache("group");

    // The account files are written by now, but a home left behind means the
    // change is incomplete; the log has to agree with the exit status.
    audit::log_user_event("MOD_USER", login, new_uid, home_chown.is_ok());

    home_chown.map_err(Into::into)
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
            Arg::new(options::REMOVE)
                .short('r')
                .long("remove")
                .requires(options::GROUPS)
                .conflicts_with(options::APPEND)
                .help("Remove from the supplementary groups given with -G only")
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
    fn test_remove_needs_groups_and_excludes_append() {
        assert!(
            uu_app()
                .try_get_matches_from(["usermod", "-r", "-G", "sudo", "u"])
                .is_ok()
        );
        assert!(
            uu_app()
                .try_get_matches_from(["usermod", "-r", "u"])
                .is_err()
        );
        assert!(
            uu_app()
                .try_get_matches_from(["usermod", "-a", "-r", "-G", "sudo", "u"])
                .is_err()
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
