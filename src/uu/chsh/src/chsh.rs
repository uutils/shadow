// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chroot seteuid sigprocmask

//! `chsh` — change login shell.
//!
//! Drop-in replacement for GNU shadow-utils `chsh(1)`.
//! Changes the login shell field in `/etc/passwd`.

use std::fmt;
use std::io::{self, BufRead, Write as _};
use std::path::Path;

use clap::{Arg, ArgAction, Command};

use shadow_core::lock::FileLock;
use shadow_core::passwd::{self, PasswdEntry};
use shadow_core::sysroot::SysRoot;
use shadow_core::{atomic, nscd};

use uucore::error::{UError, UResult};

mod options {
    pub const USER: &str = "user";
    pub const SHELL: &str = "shell";
    pub const LIST_SHELLS: &str = "list-shells";
    pub const ROOT: &str = "root";
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ChshError {
    /// Exit 1 — general error.
    Error(String),
}

impl fmt::Display for ChshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ChshError {}

impl UError for ChshError {
    fn code(&self) -> i32 {
        match self {
            Self::Error(_) => 1,
        }
    }
}

// Hardening functions are now centralized in shadow_core::hardening.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_target_user(matches: &clap::ArgMatches) -> Result<String, ChshError> {
    if let Some(user) = matches.get_one::<String>(options::USER) {
        return Ok(user.clone());
    }
    shadow_core::hardening::current_username().map_err(|e| ChshError::Error(e.to_string()))
}

fn do_chroot(dir: &str) -> Result<(), ChshError> {
    if !shadow_core::hardening::caller_is_root() {
        return Err(ChshError::Error("only root may use --root".into()));
    }

    let path = std::path::Path::new(dir);
    rustix::process::chroot(path)
        .map_err(|e| ChshError::Error(format!("cannot chroot to '{dir}': {e}")))?;

    rustix::process::chdir("/")
        .map_err(|e| ChshError::Error(format!("cannot chdir to / after chroot: {e}")))?;

    Ok(())
}

/// Read valid shells from `/etc/shells`.
///
/// Returns a list of absolute paths. Lines starting with `#` and blank
/// lines are skipped, matching the format specification from shells(5).
fn read_shells(path: &Path) -> Result<Vec<String>, ChshError> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // If /etc/shells does not exist, return empty list.
            return Ok(Vec::new());
        }
        Err(e) => {
            return Err(ChshError::Error(format!(
                "cannot read {}: {e}",
                path.display()
            )));
        }
    };

    let reader = io::BufReader::new(file);
    let mut shells = Vec::new();

    for line in reader.lines() {
        let line =
            line.map_err(|e| ChshError::Error(format!("error reading {}: {e}", path.display())))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        shells.push(trimmed.to_string());
    }

    Ok(shells)
}

/// The account's current login shell.
fn current_shell(root: &SysRoot, user: &str) -> Result<String, ChshError> {
    let entries = passwd::read_passwd_file(&root.passwd_path())
        .map_err(|e| ChshError::Error(format!("cannot read passwd: {e}")))?;
    entries
        .iter()
        .find(|e| e.name == user)
        .map(|e| e.shell.clone())
        .ok_or_else(|| ChshError::Error(format!("user '{user}' does not exist")))
}

/// Whether the user's *current* login shell is listed in `/etc/shells`.
///
/// A user whose shell is not listed is a restricted account (shells(5)); such
/// an account may not change its shell. A user with no passwd entry, or whose
/// current shell cannot be read, is treated as restricted (fail closed). An
/// empty current shell means the default `/bin/sh`, which is not restricted.
fn current_shell_is_listed(root: &SysRoot, user: &str) -> bool {
    let Ok(shell) = current_shell(root, user) else {
        return false;
    };
    if shell.is_empty() {
        return true;
    }
    match read_shells(&root.shells_path()) {
        Ok(shells) if shells.is_empty() => shell == "/bin/sh",
        Ok(shells) => shells.contains(&shell),
        Err(_) => false,
    }
}

/// Prompt for a new login shell, showing the current one -- what chsh(1) does
/// when no `-s` option is given. `None` means the answer was empty or repeated
/// the current value, so there is nothing to change. Selecting the system
/// default (an empty field) is only possible with `-s ''`, since an empty
/// answer here means "keep what I have".
fn prompt_for_shell(root: &SysRoot, user: &str) -> Result<Option<String>, ChshError> {
    let current = current_shell(root, user)?;
    let _ = writeln!(
        io::stderr(),
        "Changing the login shell for {user}\nEnter the new value, or press ENTER for the default"
    );
    let answer = shadow_core::tty::prompt_line(&format!("\tLogin Shell [{current}]: "))
        .map_err(|e| ChshError::Error(format!("cannot read from the terminal: {e}")))?;
    if answer.is_empty() || answer == current {
        return Ok(None);
    }
    Ok(Some(answer))
}

/// Check that a shell may be set: an absolute path that exists, and, for a
/// caller who is not root, one listed in `/etc/shells`.
///
/// **The order of the two tests matters.** `chsh` is installed setuid-root, so
/// `Path::exists` answers with root's view of the filesystem. Testing
/// existence first turns the tool into an oracle for paths the caller cannot
/// otherwise stat: `chsh -s /root/.ssh/id_ed25519` would answer "is not listed
/// in /etc/shells" for a file that exists and "does not exist" for one that
/// does not. For a non-root caller the membership test therefore runs first,
/// and it discloses nothing, `/etc/shells` being world-readable.
///
/// An empty shell is accepted from anyone: passwd(5) gives the field no
/// meaning of its own, and `login` falls back to `/bin/sh`, so it selects the
/// system default rather than naming a program.
fn validate_shell(shell: &str, shells_path: &Path, caller_is_root: bool) -> Result<(), ChshError> {
    if shell.is_empty() {
        return Ok(());
    }

    if !shell.starts_with('/') {
        return Err(ChshError::Error(format!(
            "'{shell}' is not an absolute path"
        )));
    }

    if !caller_is_root {
        let valid_shells = read_shells(shells_path)?;
        // An empty or missing /etc/shells leaves only /bin/sh implicitly valid.
        let listed = if valid_shells.is_empty() {
            shell == "/bin/sh"
        } else {
            valid_shells.iter().any(|s| s == shell)
        };
        if !listed {
            return Err(ChshError::Error(format!(
                "'{shell}' is not listed in {}",
                shells_path.display()
            )));
        }
    }

    if !Path::new(shell).exists() {
        return Err(ChshError::Error(format!("'{shell}' does not exist")));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Atomic passwd mutation
// ---------------------------------------------------------------------------

fn mutate_passwd<F>(root: &SysRoot, username: &str, mutate: F) -> UResult<()>
where
    F: FnOnce(&mut PasswdEntry) -> Result<(), String>,
{
    // euid 0 is all the lock and the atomic write need. setuid(0) would also
    // change the *real* uid, after which caller_is_root() -- deliberately real
    // uid based -- would answer true for every caller.

    let _signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| ChshError::Error(e.to_string()))?;

    let passwd_path = root.passwd_path();

    let lock = FileLock::acquire(&passwd_path).map_err(|_| {
        ChshError::Error(format!(
            "cannot lock {}: try again later",
            passwd_path.display()
        ))
    })?;

    let (mut entries, layout) = match passwd::read_passwd_with_layout(&passwd_path) {
        Ok(e) => e,
        Err(e) => {
            drop(lock);
            return Err(
                ChshError::Error(format!("cannot read {}: {e}", passwd_path.display())).into(),
            );
        }
    };

    let Some(entry) = entries.iter_mut().find(|e| e.name == username) else {
        drop(lock);
        return Err(ChshError::Error(format!(
            "user '{username}' does not exist in {}",
            passwd_path.display()
        ))
        .into());
    };

    if let Err(msg) = mutate(entry) {
        drop(lock);
        return Err(ChshError::Error(msg).into());
    }

    let write_result = atomic::atomic_write(&passwd_path, |file| {
        passwd::write_passwd_with_layout(&entries, &layout, file)?;
        Ok(())
    });

    if let Err(e) = write_result {
        drop(lock);
        return Err(
            ChshError::Error(format!("failed to write {}: {e}", passwd_path.display())).into(),
        );
    }

    drop(lock);
    nscd::invalidate_cache("passwd");

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 1)? else {
        return Ok(());
    };

    // Handle --root / -R: chroot before anything else.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        do_chroot(chroot_dir)?;
    }

    let root = SysRoot::default();

    // Handle -l / --list-shells: print valid shells and exit.
    if matches.get_flag(options::LIST_SHELLS) {
        let shells = read_shells(&root.shells_path())?;
        if shells.is_empty() {
            uucore::show_error!("no shells found in {}", root.shells_path().display());
        } else {
            let mut out = io::stdout().lock();
            for shell in &shells {
                let _ = writeln!(out, "{shell}");
            }
        }
        return Ok(());
    }

    let target_user = resolve_target_user(&matches)?;

    // A non-root caller may only change their own shell, and only if the
    // account is not restricted. Authentication is deferred until the new
    // value has been checked, so nobody types a password only to be told the
    // shell was refused.
    let caller = if shadow_core::hardening::caller_is_root() {
        None
    } else {
        let user = shadow_core::hardening::current_username()
            .map_err(|e| ChshError::Error(e.to_string()))?;
        if user != target_user {
            return Err(ChshError::Error("you may only change your own login shell".into()).into());
        }
        // chsh(1): an account whose current shell is not in /etc/shells is
        // restricted and may not change it. Otherwise a deliberately confined
        // account (e.g. /bin/rbash, kept out of /etc/shells) could escape.
        if !current_shell_is_listed(&root, &user) {
            return Err(
                ChshError::Error(format!("you may not change the shell for '{user}'")).into(),
            );
        }
        Some(user)
    };

    let new_shell = if let Some(shell) = matches.get_one::<String>(options::SHELL) {
        shell.clone()
    } else if let Some(shell) = prompt_for_shell(&root, &target_user)? {
        shell
    } else {
        return Ok(());
    };

    // Check the value before taking the lock and before asking for a password.
    validate_shell(&new_shell, &root.shells_path(), caller.is_none())?;

    if let Some(user) = &caller {
        authenticate_caller(user)?;
    }

    mutate_passwd(&root, &target_user, move |entry| {
        entry.shell = new_shell;
        Ok(())
    })?;

    uucore::show_error!("shell changed for '{target_user}'");
    Ok(())
}

// ---------------------------------------------------------------------------
// Caller authentication
// ---------------------------------------------------------------------------

/// Require the caller to authenticate before a non-root change is applied.
///
/// The tool is installed setuid-root, so the real UID check above establishes
/// *who may be changed*; this establishes *who is asking*. Without it, anyone
/// with access to an unlocked session could alter that user's account.
/// Distributions ship a PAM service for this (`/etc/pam.d/chsh`), where
/// `pam_rootok` lets root through and `common-auth` prompts everyone else.
///
/// Privileges are dropped to the real UID for the conversation so PAM modules
/// see the actual caller, and restored when the guard falls out of scope.
#[cfg(feature = "pam")]
fn authenticate_caller(user: &str) -> Result<(), ChshError> {
    use shadow_core::pam::{ConvMode, PamContext};

    let mut pam = PamContext::new("chsh", user, ConvMode::Tty)
        .map_err(|e| ChshError::Error(e.to_string()))?;

    let _priv_drop = shadow_core::process::PrivDrop::drop_to(rustix::process::getuid().as_raw())
        .map_err(|e| ChshError::Error(format!("cannot drop privileges: {e}")))?;

    pam.authenticate(0)
        .map_err(|e| ChshError::Error(e.to_string()))?;
    pam.acct_mgmt(0)
        .map_err(|e| ChshError::Error(e.to_string()))?;
    Ok(())
}

/// Without PAM there is no way to verify the caller, so refuse rather than
/// silently applying an unauthenticated change to a setuid-root tool.
#[cfg(not(feature = "pam"))]
fn authenticate_caller(_user: &str) -> Result<(), ChshError> {
    Err(ChshError::Error(
        "PAM support is not compiled in — cannot authenticate; run as root".into(),
    ))
}

/// Build the clap `Command` for `chsh`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("chsh")
        .about("Set a user's login shell")
        .override_usage("chsh [options] [LOGIN]")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::SHELL)
                .short('s')
                .long("shell")
                .help("path of the new shell")
                .value_name("SHELL"),
        )
        .arg(
            Arg::new(options::LIST_SHELLS)
                .short('l')
                .long("list-shells")
                .help("list entries in /etc/shells and exit")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .help("chroot into CHROOT_DIR before applying changes")
                .value_name("CHROOT_DIR"),
        )
        .arg(
            Arg::new(options::USER)
                .help("User whose shell to set")
                .index(1),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    // -----------------------------------------------------------------------
    // Shell list parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_read_shells_parses_correctly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("shells");
        std::fs::write(
            &path,
            "# /etc/shells: valid login shells\n/bin/sh\n/bin/bash\n\n# comment\n/usr/bin/zsh\n",
        )
        .expect("write");
        let shells = read_shells(&path).expect("read_shells");
        assert_eq!(shells, vec!["/bin/sh", "/bin/bash", "/usr/bin/zsh"]);
    }

    #[test]
    fn test_read_shells_missing_file_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonexistent");
        let shells = read_shells(&path).expect("read_shells");
        assert!(shells.is_empty());
    }

    #[test]
    fn test_read_shells_empty_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("shells");
        std::fs::write(&path, "").expect("write");
        let shells = read_shells(&path).expect("read_shells");
        assert!(shells.is_empty());
    }

    // -----------------------------------------------------------------------
    // Clap validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_help_does_not_error() {
        let result = uu_app().try_get_matches_from(["chsh", "--help"]);
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(!err.use_stderr());
    }

    #[test]
    fn test_shell_flag_parses() {
        let matches = uu_app()
            .try_get_matches_from(["chsh", "-s", "/bin/zsh"])
            .expect("should parse");
        assert_eq!(
            matches
                .get_one::<String>(options::SHELL)
                .map(String::as_str),
            Some("/bin/zsh")
        );
    }

    #[test]
    fn test_list_shells_flag_parses() {
        let matches = uu_app()
            .try_get_matches_from(["chsh", "-l"])
            .expect("should parse");
        assert!(matches.get_flag(options::LIST_SHELLS));
    }

    // -----------------------------------------------------------------------
    // Shell validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_shell_rejects_relative_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shells_path = dir.path().join("shells");
        std::fs::write(&shells_path, "/bin/sh\n").expect("write");
        assert!(validate_shell("bin/sh", &shells_path, false).is_err());
        assert!(validate_shell("bin/sh", &shells_path, true).is_err());
    }

    /// An empty shell field is the system default, not a missing program.
    #[test]
    fn test_validate_shell_accepts_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shells_path = dir.path().join("shells");
        std::fs::write(&shells_path, "/bin/sh\n").expect("write");
        validate_shell("", &shells_path, false).expect("empty shell is the default");
        validate_shell("", &shells_path, true).expect("empty shell is the default");
    }

    /// Setuid-root, `Path::exists` sees what root sees. A non-root caller must
    /// therefore be told "not listed" for any unlisted path, whether or not it
    /// exists, so the tool cannot be used to probe the filesystem.
    #[test]
    fn test_validate_shell_does_not_leak_existence_to_non_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shells_path = dir.path().join("shells");
        std::fs::write(&shells_path, "/bin/sh\n").expect("write");

        let secret = dir.path().join("secret");
        std::fs::write(&secret, "").expect("write");
        let existing = secret.to_string_lossy().into_owned();
        let missing = dir.path().join("absent").to_string_lossy().into_owned();

        let for_existing =
            validate_shell(&existing, &shells_path, false).expect_err("unlisted shell");
        let for_missing =
            validate_shell(&missing, &shells_path, false).expect_err("unlisted shell");
        assert!(
            format!("{for_existing}").contains("is not listed"),
            "existence must not be reported: {for_existing}"
        );
        assert!(
            format!("{for_missing}").contains("is not listed"),
            "existence must not be reported: {for_missing}"
        );
    }

    /// Root bypasses /etc/shells but still may not set a shell that is absent.
    #[test]
    fn test_validate_shell_root_bypasses_listing_but_not_existence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shells_path = dir.path().join("shells");
        std::fs::write(&shells_path, "/bin/sh\n").expect("write");

        let unlisted = dir.path().join("custom");
        std::fs::write(&unlisted, "").expect("write");
        let unlisted = unlisted.to_string_lossy().into_owned();
        validate_shell(&unlisted, &shells_path, true).expect("root may set an unlisted shell");

        let missing = dir.path().join("absent").to_string_lossy().into_owned();
        let err = validate_shell(&missing, &shells_path, true).expect_err("absent shell");
        assert!(format!("{err}").contains("does not exist"), "{err}");
    }

    // -----------------------------------------------------------------------
    // Restricted-account check
    // -----------------------------------------------------------------------

    #[test]
    fn test_current_shell_is_listed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("etc");
        std::fs::write(etc.join("shells"), "/bin/sh\n/bin/bash\n").unwrap();
        std::fs::write(
            etc.join("passwd"),
            "free:x:1000:1000::/home/free:/bin/bash\n\
             restricted:x:1001:1001::/home/r:/bin/rbash\n\
             defaulted:x:1002:1002::/home/d:\n",
        )
        .unwrap();
        let root = SysRoot::new(Some(dir.path()));

        assert!(current_shell_is_listed(&root, "free"), "listed shell");
        assert!(
            !current_shell_is_listed(&root, "restricted"),
            "shell not in /etc/shells is restricted"
        );
        assert!(
            current_shell_is_listed(&root, "defaulted"),
            "empty shell means the default /bin/sh"
        );
        assert!(
            !current_shell_is_listed(&root, "ghost"),
            "unknown user fails closed"
        );
    }

    // -----------------------------------------------------------------------
    // Caller authentication
    // -----------------------------------------------------------------------

    /// A setuid-root tool must fail closed: with no way to authenticate the
    /// caller, it refuses rather than applying an unverified change.
    #[test]
    #[cfg(not(feature = "pam"))]
    fn test_authenticate_caller_fails_closed_without_pam() {
        let err = authenticate_caller("someone").expect_err("must refuse without PAM");
        assert!(
            format!("{err}").contains("cannot authenticate"),
            "unexpected message: {err}"
        );
    }
}
