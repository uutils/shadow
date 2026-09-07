// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore vipw vigr gshadow chroot pwck grpck fchown sysroot

//! `vipw` — edit the password, group, shadow or gshadow file under a lock.
//!
//! Drop-in replacement for GNU shadow-utils `vipw(8)` and `vigr(8)`. It takes
//! the same lock every other tool in the suite takes, hands the administrator
//! a copy of the file in their editor, and installs the result atomically --
//! so a hand edit cannot interleave with a `useradd` running at the same time,
//! and a crash mid-write cannot leave a half-written `/etc/passwd`.
//!
//! `vigr` is this tool with `/etc/group` as its default; the GNU suite ships
//! it as a symlink. It lives in its own crate, which calls [`run`].

use std::fmt;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, Command};

use shadow_core::error::ShadowError;
use shadow_core::group::GroupEntry;
use shadow_core::gshadow::GshadowEntry;
use shadow_core::passwd::PasswdEntry;
use shadow_core::shadow::ShadowEntry;
use shadow_core::sysroot::SysRoot;
use shadow_core::transaction::Record;

use uucore::error::{UError, UResult};

mod options {
    pub const GROUP: &str = "group";
    pub const PASSWD: &str = "passwd";
    pub const SHADOW: &str = "shadow";
    pub const QUIET: &str = "quiet";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
}

/// The editor when neither `VISUAL` nor `EDITOR` names one.
const DEFAULT_EDITOR: &str = "vi";

/// Which of the two entry points was invoked. The only difference is the
/// file edited when neither `-p` nor `-g` is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// Defaults to `/etc/passwd`.
    Vipw,
    /// Defaults to `/etc/group`.
    Vigr,
}

impl Tool {
    fn name(self) -> &'static str {
        match self {
            Self::Vipw => "vipw",
            Self::Vigr => "vigr",
        }
    }
}

/// Which file is being edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Database {
    Passwd,
    Shadow,
    Group,
    Gshadow,
}

impl Database {
    fn select(tool: Tool, group: bool, passwd: bool, shadow: bool) -> Self {
        let group_db = group || (tool == Tool::Vigr && !passwd);
        match (group_db, shadow) {
            (false, false) => Self::Passwd,
            (false, true) => Self::Shadow,
            (true, false) => Self::Group,
            (true, true) => Self::Gshadow,
        }
    }

    fn path(self, root: &SysRoot) -> PathBuf {
        match self {
            Self::Passwd => root.passwd_path(),
            Self::Shadow => root.shadow_path(),
            Self::Group => root.group_path(),
            Self::Gshadow => root.gshadow_path(),
        }
    }

    /// The file that usually has to change alongside this one, and the
    /// command that edits it. Printed after a successful edit, as the GNU
    /// tool does, because a passwd line without its shadow line is an account
    /// nobody can log into.
    fn companion(self) -> (&'static str, &'static str) {
        match self {
            Self::Passwd => ("/etc/shadow", "vipw -s"),
            Self::Shadow => ("/etc/passwd", "vipw"),
            Self::Group => ("/etc/gshadow", "vigr -s"),
            Self::Gshadow => ("/etc/group", "vigr"),
        }
    }

    /// Parse the edited file as this database, refusing anything the rest of
    /// the suite could not read back.
    fn check(self, path: &Path) -> Result<(), ShadowError> {
        match self {
            Self::Passwd => check_as::<PasswdEntry>(path),
            Self::Shadow => check_as::<ShadowEntry>(path),
            Self::Group => check_as::<GroupEntry>(path),
            Self::Gshadow => check_as::<GshadowEntry>(path),
        }
    }
}

/// Every entry has to parse, and every parsed entry has to pass the same
/// field checks the other tools apply before they write.
fn check_as<T: Record>(path: &Path) -> Result<(), ShadowError> {
    let (entries, _layout) = shadow_core::records::read_with_layout::<T>(path)?;
    for entry in &entries {
        entry.validate_fields()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that `vipw` and `vigr` can produce.
#[derive(Debug)]
enum VipwError {
    /// Exit 1 — insufficient privileges.
    PermissionDenied(String),
    /// Exit 1 — an unexpected runtime failure.
    UnexpectedFailure(String),
    /// Exit 1 — could not acquire the lock.
    FileBusy(String),
    /// Exit 1 — the editor did not exit successfully; nothing was installed.
    EditorFailed(String),
    /// Exit 1 — the edited file does not parse; it is kept for the caller.
    InvalidResult(String),
    /// Exit 3 — the `--root` directory could not be entered.
    CantChroot(String),
}

impl fmt::Display for VipwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg)
            | Self::UnexpectedFailure(msg)
            | Self::FileBusy(msg)
            | Self::EditorFailed(msg)
            | Self::InvalidResult(msg)
            | Self::CantChroot(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for VipwError {}

impl UError for VipwError {
    fn code(&self) -> i32 {
        match self {
            Self::PermissionDenied(_)
            | Self::UnexpectedFailure(_)
            | Self::FileBusy(_)
            | Self::EditorFailed(_)
            | Self::InvalidResult(_) => 1,
            Self::CantChroot(_) => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Entry point for the `vipw` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    run(Tool::Vipw, args)
}

/// Build the clap `Command` for `vipw`.
#[must_use]
pub fn uu_app() -> Command {
    app(Tool::Vipw)
}

/// Run either tool.
pub fn run(tool: Tool, args: impl uucore::Args) -> UResult<()> {
    // The editor is an interactive child that inherits this process's
    // limits and environment, so only core dumps are suppressed: a raised
    // RLIMIT_FSIZE would follow the editor, and a sanitized environment would
    // take TERM and the editor's own configuration away from it.
    shadow_core::hardening::suppress_core_dumps();

    let Some(matches) = shadow_core::cli::parse_args(app(tool), args, |_| 2)? else {
        return Ok(());
    };

    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        shadow_core::hardening::chroot_into(Path::new(chroot_dir))
            .map_err(|e| VipwError::CantChroot(e.to_string()))?;
    }
    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);

    if !shadow_core::hardening::caller_is_root() {
        return Err(VipwError::PermissionDenied(shadow_core::os_error::permission_denied()).into());
    }

    let database = Database::select(
        tool,
        matches.get_flag(options::GROUP),
        matches.get_flag(options::PASSWD),
        matches.get_flag(options::SHADOW),
    );
    let quiet = matches.get_flag(options::QUIET);

    edit(tool, database, &root, quiet)
}

/// Build the clap `Command` for either tool.
#[must_use]
pub fn app(tool: Tool) -> Command {
    let (about, default) = match tool {
        Tool::Vipw => ("Edit the password file under a lock", "passwd"),
        Tool::Vigr => ("Edit the group file under a lock", "group"),
    };
    Command::new(tool.name())
        .about(about)
        .override_usage(format!("{} [options]", tool.name()))
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::GROUP)
                .short('g')
                .long("group")
                .help("edit the group database")
                .conflicts_with(options::PASSWD)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::PASSWD)
                .short('p')
                .long("passwd")
                .help("edit the passwd database")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::SHADOW)
                .short('s')
                .long("shadow")
                .help(format!(
                    "edit the shadow counterpart of the {default} database"
                ))
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::QUIET)
                .short('q')
                .long("quiet")
                .help("do not report an unchanged file or suggest the companion edit")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .help("chroot into CHROOT_DIR before editing")
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
// The edit
// ---------------------------------------------------------------------------

/// Lock, copy, edit, check, install.
fn edit(tool: Tool, database: Database, root: &SysRoot, quiet: bool) -> UResult<()> {
    let target = database.path(root);
    let shown = target.display();

    // Held for the whole edit. A Ctrl-C aimed at the editor must not kill
    // this process and leave the lock file and the working copy behind; the
    // editor itself gets a clean mask when it is spawned.
    let _signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| VipwError::UnexpectedFailure(e.to_string()))?;

    let _lock = shadow_core::lock::FileLock::acquire(&target).map_err(|e| match e {
        ShadowError::Lock(_) => {
            VipwError::FileBusy(format!("cannot lock {shown}: try again later"))
        }
        other => VipwError::UnexpectedFailure(format!("cannot lock {shown}: {other}")),
    })?;

    let original = std::fs::read(&target)
        .map_err(|e| VipwError::UnexpectedFailure(format!("cannot open {shown}: {e}")))?;
    let meta = std::fs::metadata(&target)
        .map_err(|e| VipwError::UnexpectedFailure(format!("cannot stat {shown}: {e}")))?;

    let edit_path = edit_path_for(&target);
    write_working_copy(&edit_path, &original, &meta)
        .map_err(|e| VipwError::UnexpectedFailure(e.to_string()))?;

    let editor = choose_editor(
        std::env::var("VISUAL").ok().as_deref(),
        std::env::var("EDITOR").ok().as_deref(),
    );
    let status = run_editor(&editor, &edit_path);

    let status = match status {
        Ok(status) if status.success() => status,
        Ok(status) => {
            let _ = std::fs::remove_file(&edit_path);
            let code = status
                .code()
                .map_or_else(|| "a signal".to_string(), |c| c.to_string());
            uucore::show_error!("{editor} returned with status {code}");
            return Err(VipwError::EditorFailed(format!("{shown} is unchanged")).into());
        }
        Err(e) => {
            let _ = std::fs::remove_file(&edit_path);
            return Err(VipwError::EditorFailed(format!(
                "cannot run {editor}: {e}; {shown} is unchanged"
            ))
            .into());
        }
    };
    debug_assert!(status.success());

    let edited = std::fs::read(&edit_path).map_err(|e| {
        VipwError::UnexpectedFailure(format!("cannot read {}: {e}", edit_path.display()))
    })?;

    // Compared by content, not by timestamp. The GNU tool compares
    // modification times in whole seconds, so an edit saved within the same
    // second as the copy was made is silently thrown away.
    if edited == original {
        let _ = std::fs::remove_file(&edit_path);
        if !quiet {
            let _ = writeln!(std::io::stderr(), "{}: {shown} is unchanged", tool.name());
        }
        return Ok(());
    }

    // The working copy is kept on failure: the administrator's edit may be
    // ten minutes of work, and losing it teaches them to use a raw editor
    // next time, which is the outcome this tool exists to prevent.
    if let Err(e) = database.check(&edit_path) {
        uucore::show_error!("{}: {e}", edit_path.display());
        return Err(VipwError::InvalidResult(format!(
            "the edited copy is kept at {}; {shown} is unchanged",
            edit_path.display()
        ))
        .into());
    }

    shadow_core::atomic::atomic_write(&target, |w| w.write_all(&edited).map_err(ShadowError::Io))
        .map_err(|e| VipwError::UnexpectedFailure(format!("cannot write {shown}: {e}")))?;
    let _ = std::fs::remove_file(&edit_path);

    if !quiet {
        let (companion, command) = database.companion();
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "You have modified {shown}.");
        let _ = writeln!(out, "You may need to modify {companion} for consistency.");
        let _ = writeln!(out, "Please use the command '{command}' to do so.");
    }
    Ok(())
}

/// The working copy sits next to the file it copies, as `passwd.edit`, so it
/// is on the same filesystem and under the same directory permissions.
fn edit_path_for(target: &Path) -> PathBuf {
    let mut name = target.file_name().unwrap_or_default().to_os_string();
    name.push(".edit");
    target.with_file_name(name)
}

/// Write the working copy with the original's mode and ownership.
///
/// The mode is applied at creation under a zeroed umask, so there is no moment
/// at which a copy of `/etc/shadow` is more readable than `/etc/shadow`. A
/// stale copy left by a crashed run is replaced.
fn write_working_copy(
    edit_path: &Path,
    contents: &[u8],
    meta: &std::fs::Metadata,
) -> Result<(), ShadowError> {
    let _umask = shadow_core::atomic::UmaskGuard::zero();
    let mode = meta.mode() & 0o7777;
    let open = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(edit_path)
    };
    let mut file = match open() {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(edit_path)
                .map_err(|e| ShadowError::IoPath(e, edit_path.to_owned()))?;
            open().map_err(|e| ShadowError::IoPath(e, edit_path.to_owned()))?
        }
        Err(e) => return Err(ShadowError::IoPath(e, edit_path.to_owned())),
    };
    rustix::fs::fchown(
        &file,
        Some(rustix::fs::Uid::from_raw(meta.uid())),
        Some(rustix::fs::Gid::from_raw(meta.gid())),
    )
    .map_err(|e| ShadowError::IoPath(e.into(), edit_path.to_owned()))?;
    file.write_all(contents)
        .map_err(|e| ShadowError::IoPath(e, edit_path.to_owned()))?;
    file.sync_all()
        .map_err(|e| ShadowError::IoPath(e, edit_path.to_owned()))
}

/// `VISUAL`, then `EDITOR`, then `vi`; an empty value counts as unset.
fn choose_editor(visual: Option<&str>, editor: Option<&str>) -> String {
    [visual, editor]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .unwrap_or(DEFAULT_EDITOR)
        .to_string()
}

/// Run the editor on the working copy and wait for it.
///
/// The editor string goes through the shell so `EDITOR="emacs -nw"` works, as
/// it does everywhere else; the path is passed as a positional argument rather
/// than spliced into the command line.
fn run_editor(editor: &str, path: &Path) -> std::io::Result<std::process::ExitStatus> {
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg(editor)
        .arg(path);
    shadow_core::process::spawn_with_signals_unblocked(&mut cmd)?.wait()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apps_build() {
        app(Tool::Vipw).debug_assert();
        app(Tool::Vigr).debug_assert();
    }

    /// vigr is vipw with the group file as the default; the flags then select
    /// the same four files from either.
    #[test]
    fn test_database_selection() {
        use Database::{Group, Gshadow, Passwd, Shadow};
        assert_eq!(Database::select(Tool::Vipw, false, false, false), Passwd);
        assert_eq!(Database::select(Tool::Vipw, false, false, true), Shadow);
        assert_eq!(Database::select(Tool::Vigr, false, false, false), Group);
        assert_eq!(Database::select(Tool::Vigr, false, false, true), Gshadow);
        assert_eq!(Database::select(Tool::Vipw, true, false, false), Group);
        assert_eq!(Database::select(Tool::Vipw, true, false, true), Gshadow);
        assert_eq!(Database::select(Tool::Vigr, false, true, false), Passwd);
        assert_eq!(Database::select(Tool::Vigr, false, true, true), Shadow);
    }

    #[test]
    fn test_group_and_passwd_conflict() {
        assert!(
            app(Tool::Vipw)
                .try_get_matches_from(["vipw", "-g", "-p"])
                .is_err()
        );
        assert!(
            app(Tool::Vipw)
                .try_get_matches_from(["vipw", "-g", "-s"])
                .is_ok()
        );
    }

    /// The hint names the file that has to change alongside, and the command
    /// for it is by database, not by which name this tool was invoked under.
    #[test]
    fn test_companion_hints() {
        assert_eq!(Database::Passwd.companion(), ("/etc/shadow", "vipw -s"));
        assert_eq!(Database::Shadow.companion(), ("/etc/passwd", "vipw"));
        assert_eq!(Database::Group.companion(), ("/etc/gshadow", "vigr -s"));
        assert_eq!(Database::Gshadow.companion(), ("/etc/group", "vigr"));
    }

    #[test]
    fn test_editor_preference() {
        assert_eq!(choose_editor(Some("code -w"), Some("nano")), "code -w");
        assert_eq!(choose_editor(None, Some("nano")), "nano");
        assert_eq!(choose_editor(None, None), "vi");
        // Empty and blank values are unset, not editors called "".
        assert_eq!(choose_editor(Some(""), Some("nano")), "nano");
        assert_eq!(choose_editor(Some("  "), Some("")), "vi");
    }

    #[test]
    fn test_edit_path_sits_beside_the_target() {
        assert_eq!(
            edit_path_for(Path::new("/etc/passwd")),
            PathBuf::from("/etc/passwd.edit")
        );
        assert_eq!(
            edit_path_for(Path::new("/mnt/root/etc/gshadow")),
            PathBuf::from("/mnt/root/etc/gshadow.edit")
        );
    }

    /// The working copy takes the original's mode and replaces a stale one.
    #[test]
    fn test_working_copy_mode_and_stale_replacement() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("shadow");
        std::fs::write(&target, "root:!:1::::::\n").expect("write");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        let meta = std::fs::metadata(&target).expect("stat");

        let edit = edit_path_for(&target);
        std::fs::write(&edit, "stale junk\n").expect("stale");

        write_working_copy(&edit, b"root:!:1::::::\n", &meta).expect("copy");
        assert_eq!(std::fs::read(&edit).expect("read"), b"root:!:1::::::\n");
        let mode = std::fs::metadata(&edit).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o640,
            "the copy must not be more readable than the original"
        );
    }

    /// The check is the same one every other tool applies before writing:
    /// a line that does not parse is refused, a line that does is accepted.
    #[test]
    fn test_check_accepts_valid_and_refuses_broken_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("passwd");
        std::fs::write(&good, "# comment\nroot:x:0:0:root:/root:/bin/sh\n").expect("write");
        assert!(Database::Passwd.check(&good).is_ok());

        let bad = dir.path().join("passwd.bad");
        std::fs::write(&bad, "root:x:0:0:root:/root:/bin/sh\nbroken line\n").expect("write");
        assert!(Database::Passwd.check(&bad).is_err());
    }

    #[test]
    fn test_exit_codes() {
        assert_eq!(VipwError::PermissionDenied("x".into()).code(), 1);
        assert_eq!(VipwError::UnexpectedFailure("x".into()).code(), 1);
        assert_eq!(VipwError::FileBusy("x".into()).code(), 1);
        assert_eq!(VipwError::EditorFailed("x".into()).code(), 1);
        assert_eq!(VipwError::InvalidResult("x".into()).code(), 1);
        assert_eq!(VipwError::CantChroot("x".into()).code(), 3);
    }
}
