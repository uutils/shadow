// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore pwconv pwunconv grpconv grpunconv gshadow chroot fchown fchmod sysroot lstchg

//! `pwconv`, `pwunconv`, `grpconv`, `grpunconv` — convert between shadowed
//! and unshadowed account files.
//!
//! Drop-in replacements for the GNU shadow-utils tools of the same names.
//! `pwconv` moves password hashes out of the world-readable `/etc/passwd`
//! into `/etc/shadow`, creating it if need be, and reconciles the two: a
//! passwd line with no shadow line gets one, a shadow line with no passwd
//! line is dropped. `pwunconv` merges the hashes back and removes
//! `/etc/shadow`. `grpconv` and `grpunconv` do the same for `/etc/group` and
//! `/etc/gshadow`.
//!
//! The four are one engine with a selector; the other three crates are the
//! selector.

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use clap::{Arg, Command};

use shadow_core::error::ShadowError;
use shadow_core::group::GroupEntry;
use shadow_core::gshadow::GshadowEntry;
use shadow_core::login_defs::LoginDefs;
use shadow_core::passwd::PasswdEntry;
use shadow_core::shadow::ShadowEntry;
use shadow_core::sysroot::SysRoot;
use shadow_core::transaction::{self, Commit, LockedFile, Record};

use uucore::error::{UError, UResult};

mod options {
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
}

/// The placeholder in `/etc/passwd` and `/etc/group` that says the real
/// field lives in the shadow file.
const SHADOWED: &str = "x";

/// The mode a freshly created shadow file gets, and the group that may read
/// it. This is how the distributions ship `/etc/shadow`: readable by the
/// `shadow` group so PAM helpers can check passwords without being root.
const SHADOW_FILE_MODE: u32 = 0o640;
const SHADOW_GROUP: &str = "shadow";

/// Which of the four tools was invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Pwconv,
    Pwunconv,
    Grpconv,
    Grpunconv,
}

impl Tool {
    fn name(self) -> &'static str {
        match self {
            Self::Pwconv => "pwconv",
            Self::Pwunconv => "pwunconv",
            Self::Grpconv => "grpconv",
            Self::Grpunconv => "grpunconv",
        }
    }

    fn about(self) -> &'static str {
        match self {
            Self::Pwconv => "Move password hashes from /etc/passwd into /etc/shadow",
            Self::Pwunconv => "Move password hashes from /etc/shadow back into /etc/passwd",
            Self::Grpconv => "Move group passwords from /etc/group into /etc/gshadow",
            Self::Grpunconv => "Move group passwords from /etc/gshadow back into /etc/group",
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors the four tools can produce, with the exit codes pwconv(8) documents.
#[derive(Debug)]
enum ConvError {
    /// Exit 1 — insufficient privileges.
    PermissionDenied(String),
    /// Exit 1 — the files could not be updated.
    CantUpdate(String),
    /// Exit 3 — the `--root` directory could not be entered.
    CantChroot(String),
    /// Exit 5 — an account file is locked by another tool.
    FileBusy(String),
}

impl fmt::Display for ConvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg)
            | Self::CantUpdate(msg)
            | Self::CantChroot(msg)
            | Self::FileBusy(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ConvError {}

impl UError for ConvError {
    fn code(&self) -> i32 {
        match self {
            Self::PermissionDenied(_) | Self::CantUpdate(_) => 1,
            Self::CantChroot(_) => 3,
            Self::FileBusy(_) => 5,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Entry point for the `pwconv` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    run(Tool::Pwconv, args)
}

/// Build the clap `Command` for `pwconv`.
#[must_use]
pub fn uu_app() -> Command {
    app(Tool::Pwconv)
}

/// Run any of the four tools.
pub fn run(tool: Tool, args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    let Some(matches) = shadow_core::cli::parse_args(app(tool), args, |_| 2)? else {
        return Ok(());
    };

    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        shadow_core::hardening::chroot_into(Path::new(chroot_dir))
            .map_err(|e| ConvError::CantChroot(e.to_string()))?;
    }
    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);

    if !shadow_core::hardening::caller_is_root() {
        return Err(ConvError::PermissionDenied(shadow_core::os_error::permission_denied()).into());
    }

    match tool {
        Tool::Pwconv => pwconv(&root),
        Tool::Pwunconv => pwunconv(&root),
        Tool::Grpconv => grpconv(&root),
        Tool::Grpunconv => grpunconv(&root),
    }
}

/// Build the clap `Command` for any of the four tools.
#[must_use]
pub fn app(tool: Tool) -> Command {
    Command::new(tool.name())
        .about(tool.about())
        .override_usage(format!("{} [options]", tool.name()))
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .help("chroot into CHROOT_DIR before converting")
                .value_name("CHROOT_DIR"),
        )
        .arg(
            Arg::new(options::PREFIX)
                .short('P')
                .long("prefix")
                .help("directory prefix")
                .value_name("PREFIX_DIR"),
        )
}

// ---------------------------------------------------------------------------
// pwconv / pwunconv
// ---------------------------------------------------------------------------

fn pwconv(root: &SysRoot) -> UResult<()> {
    let passwd_path = root.passwd_path();
    let shadow_path = root.shadow_path();
    let creating = !shadow_path.exists();

    let mut passwd = open::<PasswdEntry>(&passwd_path)?;
    let mut shadow = open_or_empty::<ShadowEntry>(&shadow_path)?;

    let defs = LoginDefs::load(&root.login_defs_path()).unwrap_or_default();
    let today = shadow_core::shadow::days_since_epoch()
        .map_err(|e| ConvError::CantUpdate(format!("cannot determine the current date: {e}")))?;

    reconcile_shadow(passwd.entries_mut(), shadow.entries_mut(), today, &defs);

    // shadow first, then passwd. The hashes are copied into shadow and only
    // then replaced by `x` in passwd, so a failure between the two writes
    // leaves the hashes where they were rather than nowhere. Both files are
    // validated before either is written.
    let files: Vec<Box<dyn Commit>> = vec![Box::new(shadow), Box::new(passwd)];
    transaction::commit_all(files)
        .map_err(|e| ConvError::CantUpdate(format!("cannot write: {e}")))?;

    if creating {
        let shadow_gid = shadow_group_gid(&root.group_path());
        set_shadow_file_permissions(&shadow_path, shadow_gid)?;
    }
    shadow_core::nscd::invalidate_cache("passwd");
    Ok(())
}

/// Bring `shadow` in line with `passwd`, moving every hash across.
fn reconcile_shadow(
    passwd: &mut [PasswdEntry],
    shadow: &mut Vec<ShadowEntry>,
    today: i64,
    defs: &LoginDefs,
) {
    // A shadow line for an account that no longer exists is stale, and a
    // stale line with a live hash is a password nobody can use but anyone
    // with the file could crack.
    let live: HashSet<&str> = passwd.iter().map(|p| p.name.as_str()).collect();
    shadow.retain(|s| live.contains(s.name.as_str()));

    for entry in passwd.iter_mut() {
        match shadow.iter_mut().find(|s| s.name == entry.name) {
            Some(existing) => {
                // A real hash in passwd is newer than whatever shadow holds:
                // it got there through a tool or an edit that did not know
                // about shadow. It wins, and the change is dated.
                if entry.passwd != SHADOWED {
                    existing.passwd.clone_from(&entry.passwd);
                    existing.last_change = Some(today);
                }
            }
            None => shadow.push(ShadowEntry {
                name: entry.name.clone(),
                // Copied as it stands. An `x` here means the hash was lost
                // before this ran, and an `x` in the hash field matches no
                // password, which is the honest state of that account.
                passwd: entry.passwd.clone(),
                last_change: Some(today),
                min_age: defs.get_i64("PASS_MIN_DAYS"),
                max_age: defs.get_i64("PASS_MAX_DAYS"),
                warn_days: defs.get_i64("PASS_WARN_AGE"),
                inactive_days: None,
                expire_date: None,
                reserved: String::new(),
            }),
        }
        entry.passwd = SHADOWED.to_string();
    }
}

fn pwunconv(root: &SysRoot) -> UResult<()> {
    let passwd_path = root.passwd_path();
    let shadow_path = root.shadow_path();
    if !shadow_path.exists() {
        // Nothing to unshadow: the system is already in the requested state.
        return Ok(());
    }

    let mut passwd = open::<PasswdEntry>(&passwd_path)?;
    let shadow = open::<ShadowEntry>(&shadow_path)?;

    for entry in passwd.entries_mut() {
        // An account with no shadow line keeps whatever passwd holds; there
        // is no hash to bring back.
        if let Some(line) = shadow.find(&entry.name) {
            entry.passwd.clone_from(&line.passwd);
        }
    }

    // passwd first, then the removal. Between the two the hashes exist twice,
    // which is recoverable; the other order would have a moment with none.
    passwd
        .commit()
        .map_err(|e| ConvError::CantUpdate(format!("cannot write: {e}")))?;
    remove_while_locked(&shadow_path)?;
    drop(shadow);

    shadow_core::nscd::invalidate_cache("passwd");
    Ok(())
}

// ---------------------------------------------------------------------------
// grpconv / grpunconv
// ---------------------------------------------------------------------------

fn grpconv(root: &SysRoot) -> UResult<()> {
    let group_path = root.group_path();
    let gshadow_path = root.gshadow_path();
    let creating = !gshadow_path.exists();

    let mut group = open::<GroupEntry>(&group_path)?;
    let mut gshadow = open_or_empty::<GshadowEntry>(&gshadow_path)?;

    reconcile_gshadow(group.entries_mut(), gshadow.entries_mut());

    // gshadow first, for the reason pwconv writes shadow first.
    let shadow_gid = shadow_group_gid_from(group.entries());
    let files: Vec<Box<dyn Commit>> = vec![Box::new(gshadow), Box::new(group)];
    transaction::commit_all(files)
        .map_err(|e| ConvError::CantUpdate(format!("cannot write: {e}")))?;

    if creating {
        set_shadow_file_permissions(&gshadow_path, shadow_gid)?;
    }
    shadow_core::nscd::invalidate_cache("group");
    Ok(())
}

/// Bring `gshadow` in line with `group`, moving every password across.
fn reconcile_gshadow(group: &mut [GroupEntry], gshadow: &mut Vec<GshadowEntry>) {
    let live: HashSet<&str> = group.iter().map(|g| g.name.as_str()).collect();
    gshadow.retain(|gs| live.contains(gs.name.as_str()));

    for entry in group.iter_mut() {
        match gshadow.iter_mut().find(|gs| gs.name == entry.name) {
            Some(existing) => {
                if entry.passwd != SHADOWED {
                    existing.passwd.clone_from(&entry.passwd);
                }
            }
            None => gshadow.push(GshadowEntry {
                name: entry.name.clone(),
                passwd: entry.passwd.clone(),
                admins: Vec::new(),
                // The new line starts from the membership /etc/group records,
                // so the two files agree from the first moment.
                members: entry.members.clone(),
            }),
        }
        entry.passwd = SHADOWED.to_string();
    }
}

fn grpunconv(root: &SysRoot) -> UResult<()> {
    let group_path = root.group_path();
    let gshadow_path = root.gshadow_path();
    if !gshadow_path.exists() {
        return Ok(());
    }

    let mut group = open::<GroupEntry>(&group_path)?;
    let gshadow = open::<GshadowEntry>(&gshadow_path)?;

    for entry in group.entries_mut() {
        if let Some(line) = gshadow.find(&entry.name) {
            entry.passwd.clone_from(&line.passwd);
        }
    }

    group
        .commit()
        .map_err(|e| ConvError::CantUpdate(format!("cannot write: {e}")))?;
    remove_while_locked(&gshadow_path)?;
    drop(gshadow);

    shadow_core::nscd::invalidate_cache("group");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn open<T: Record>(path: &Path) -> Result<LockedFile<T>, ConvError> {
    LockedFile::<T>::open(path).map_err(|e| lock_error(path, e))
}

fn open_or_empty<T: Record>(path: &Path) -> Result<LockedFile<T>, ConvError> {
    LockedFile::<T>::open_or_empty(path).map_err(|e| lock_error(path, e))
}

/// pwconv(8) reserves exit 5 for a locked file, so contention is told apart
/// from every other way an open can fail.
fn lock_error(path: &Path, e: ShadowError) -> ConvError {
    match e {
        ShadowError::Lock(_) => {
            ConvError::FileBusy(format!("cannot lock {}; try again later", path.display()))
        }
        other => ConvError::CantUpdate(format!("cannot open {}: {other}", path.display())),
    }
}

/// Remove a file whose lock the caller still holds.
///
/// The caller keeps its `LockedFile` alive across this call, so no other tool
/// can slip in between the last read of the file and its removal. A file that
/// is already gone is the state that was wanted.
fn remove_while_locked(path: &Path) -> Result<(), ConvError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ConvError::CantUpdate(format!(
            "cannot remove {}: {e}",
            path.display()
        ))),
    }
}

/// The GID of the `shadow` group in the tree being converted, if it has one.
///
/// Looked up in that tree's own group file rather than through the name
/// service: under `--prefix` or `--root` the host's `shadow` group says
/// nothing about the target's.
fn shadow_group_gid(group_path: &Path) -> Option<u32> {
    let entries = shadow_core::records::read_entries::<GroupEntry>(group_path).ok()?;
    shadow_group_gid_from(&entries)
}

fn shadow_group_gid_from(groups: &[GroupEntry]) -> Option<u32> {
    groups
        .iter()
        .find(|g| g.name == SHADOW_GROUP)
        .map(|g| g.gid)
}

/// Give a shadow file created by this run the layout the distributions ship:
/// `0640 root:shadow`, or `0600 root:root` where there is no `shadow` group.
///
/// The atomic writer creates a new file `0600` and owned by the process, which
/// is the safe default for a file whose owner it does not know; here the owner
/// is known. Through a descriptor opened `O_NOFOLLOW`, as the home-directory
/// code does, so a symlink swapped in under `/etc` is not followed.
fn set_shadow_file_permissions(path: &Path, shadow_gid: Option<u32>) -> Result<(), ConvError> {
    use rustix::fs::{Mode, OFlags};

    let Some(gid) = shadow_gid else {
        return Ok(());
    };
    let file = rustix::fs::open(path, OFlags::RDONLY | OFlags::NOFOLLOW, Mode::empty())
        .map_err(|e| ConvError::CantUpdate(format!("cannot open {}: {e}", path.display())))?;
    rustix::fs::fchown(
        &file,
        Some(rustix::fs::Uid::ROOT),
        Some(rustix::fs::Gid::from_raw(gid)),
    )
    .map_err(|e| ConvError::CantUpdate(format!("cannot set owner of {}: {e}", path.display())))?;
    rustix::fs::fchmod(&file, Mode::from_raw_mode(SHADOW_FILE_MODE))
        .map_err(|e| ConvError::CantUpdate(format!("cannot set mode of {}: {e}", path.display())))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn passwd(name: &str, hash: &str) -> PasswdEntry {
        PasswdEntry {
            name: name.to_string(),
            passwd: hash.to_string(),
            uid: 1000,
            gid: 1000,
            gecos: String::new(),
            home: format!("/home/{name}"),
            shell: "/bin/sh".to_string(),
        }
    }

    fn shadow(name: &str, hash: &str, last_change: i64) -> ShadowEntry {
        ShadowEntry {
            name: name.to_string(),
            passwd: hash.to_string(),
            last_change: Some(last_change),
            min_age: Some(0),
            max_age: Some(99999),
            warn_days: Some(7),
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        }
    }

    fn defs(text: &str) -> LoginDefs {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("login.defs");
        std::fs::write(&path, text).expect("write");
        LoginDefs::load(&path).expect("load")
    }

    #[test]
    fn test_apps_build() {
        for tool in [Tool::Pwconv, Tool::Pwunconv, Tool::Grpconv, Tool::Grpunconv] {
            app(tool).debug_assert();
        }
    }

    /// An operand is a usage error: none of the four takes one.
    #[test]
    fn test_no_operands_are_accepted() {
        assert!(
            app(Tool::Pwconv)
                .try_get_matches_from(["pwconv", "extra"])
                .is_err()
        );
        assert!(app(Tool::Pwconv).try_get_matches_from(["pwconv"]).is_ok());
    }

    /// A hash in passwd moves to shadow and passwd is left with `x`; a new
    /// shadow line is dated today and takes its aging from login.defs.
    #[test]
    fn test_pwconv_moves_hashes_and_dates_new_lines() {
        let mut pw = vec![passwd("alice", "$6$salt$hash")];
        let mut sh = Vec::new();
        let d = defs("PASS_MIN_DAYS 7\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 14\n");
        reconcile_shadow(&mut pw, &mut sh, 20000, &d);

        assert_eq!(pw[0].passwd, "x");
        assert_eq!(sh.len(), 1);
        assert_eq!(sh[0].name, "alice");
        assert_eq!(sh[0].passwd, "$6$salt$hash");
        assert_eq!(sh[0].last_change, Some(20000));
        assert_eq!(sh[0].min_age, Some(7));
        assert_eq!(sh[0].max_age, Some(90));
        assert_eq!(sh[0].warn_days, Some(14));
        assert_eq!(sh[0].inactive_days, None);
        assert_eq!(sh[0].expire_date, None);
    }

    /// A hash in passwd beside an existing shadow line is the newer of the
    /// two: it replaces the shadow hash and the change is dated. An `x`
    /// leaves the shadow line, aging included, alone.
    #[test]
    fn test_pwconv_existing_line() {
        let mut pw = vec![passwd("alice", "$6$new$hash"), passwd("bob", "x")];
        let mut sh = vec![
            shadow("alice", "$6$old$hash", 19000),
            shadow("bob", "$6$b$b", 19000),
        ];
        reconcile_shadow(&mut pw, &mut sh, 20000, &LoginDefs::default());

        let alice = sh.iter().find(|s| s.name == "alice").expect("alice");
        assert_eq!(alice.passwd, "$6$new$hash");
        assert_eq!(alice.last_change, Some(20000));
        assert_eq!(alice.max_age, Some(99999), "aging must be kept");

        let bob = sh.iter().find(|s| s.name == "bob").expect("bob");
        assert_eq!(bob.passwd, "$6$b$b");
        assert_eq!(
            bob.last_change,
            Some(19000),
            "an untouched line keeps its date"
        );
    }

    /// A shadow line for an account that is not in passwd is dropped.
    #[test]
    fn test_pwconv_drops_orphan_shadow_lines() {
        let mut pw = vec![passwd("alice", "x")];
        let mut sh = vec![
            shadow("alice", "$6$a$a", 19000),
            shadow("ghost", "$6$g$g", 19000),
        ];
        reconcile_shadow(&mut pw, &mut sh, 20000, &LoginDefs::default());
        assert_eq!(sh.len(), 1);
        assert_eq!(sh[0].name, "alice");
    }

    /// Running twice changes nothing the second time.
    #[test]
    fn test_pwconv_is_idempotent() {
        let mut pw = vec![passwd("alice", "$6$salt$hash")];
        let mut sh = Vec::new();
        let d = LoginDefs::default();
        reconcile_shadow(&mut pw, &mut sh, 20000, &d);
        let (pw_once, sh_once) = (pw.clone(), sh.clone());
        reconcile_shadow(&mut pw, &mut sh, 20001, &d);
        assert_eq!(pw, pw_once);
        assert_eq!(sh, sh_once, "a second run must not re-date the line");
    }

    /// A new gshadow line inherits the membership /etc/group records.
    #[test]
    fn test_grpconv_new_line_carries_the_members() {
        let mut gr = vec![GroupEntry {
            name: "team".to_string(),
            passwd: "$6$t$t".to_string(),
            gid: 5000,
            members: vec!["alice".to_string(), "bob".to_string()],
        }];
        let mut gs = Vec::new();
        reconcile_gshadow(&mut gr, &mut gs);
        assert_eq!(gr[0].passwd, "x");
        assert_eq!(gs[0].passwd, "$6$t$t");
        assert!(gs[0].admins.is_empty());
        assert_eq!(gs[0].members, vec!["alice".to_string(), "bob".to_string()]);
    }

    /// An existing gshadow line keeps its administrators and members; only
    /// a real password in /etc/group moves across.
    #[test]
    fn test_grpconv_existing_line_keeps_admins() {
        let mut gr = vec![GroupEntry {
            name: "team".to_string(),
            passwd: "$6$new$new".to_string(),
            gid: 5000,
            members: vec!["alice".to_string()],
        }];
        let mut gs = vec![GshadowEntry {
            name: "team".to_string(),
            passwd: "$6$old$old".to_string(),
            admins: vec!["carol".to_string()],
            members: vec!["alice".to_string()],
        }];
        reconcile_gshadow(&mut gr, &mut gs);
        assert_eq!(gs[0].passwd, "$6$new$new");
        assert_eq!(gs[0].admins, vec!["carol".to_string()]);
    }

    #[test]
    fn test_shadow_group_lookup_uses_the_given_tree() {
        let groups = vec![
            GroupEntry {
                name: "root".into(),
                passwd: "x".into(),
                gid: 0,
                members: vec![],
            },
            GroupEntry {
                name: "shadow".into(),
                passwd: "x".into(),
                gid: 42,
                members: vec![],
            },
        ];
        assert_eq!(shadow_group_gid_from(&groups), Some(42));
        assert_eq!(shadow_group_gid_from(&groups[..1]), None);
    }

    /// The codes are the interface pwconv(8) documents.
    #[test]
    fn test_exit_codes() {
        assert_eq!(ConvError::PermissionDenied("x".into()).code(), 1);
        assert_eq!(ConvError::CantUpdate("x".into()).code(), 1);
        assert_eq!(ConvError::CantChroot("x".into()).code(), 3);
        assert_eq!(ConvError::FileBusy("x".into()).code(), 5);
    }
}
