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
    /// Sentinel for errors already printed by clap.
    AlreadyPrinted(i32),
}

impl fmt::Display for ChshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(msg) => f.write_str(msg),
            Self::AlreadyPrinted(_) => Ok(()),
        }
    }
}

impl std::error::Error for ChshError {}

impl UError for ChshError {
    fn code(&self) -> i32 {
        match self {
            Self::Error(_) => 1,
            Self::AlreadyPrinted(code) => *code,
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

/// Check if a shell is valid: must be an absolute path, must exist as a
/// regular file, and must be listed in `/etc/shells` (unless caller is root).
fn validate_shell(shell: &str, shells_path: &Path) -> Result<(), ChshError> {
    if !shell.starts_with('/') {
        return Err(ChshError::Error(format!(
            "'{shell}' is not an absolute path"
        )));
    }

    let path = Path::new(shell);
    if !path.exists() {
        return Err(ChshError::Error(format!("'{shell}' does not exist")));
    }

    // Root can set any existing shell, bypassing the /etc/shells check.
    if shadow_core::hardening::caller_is_root() {
        return Ok(());
    }

    let valid_shells = read_shells(shells_path)?;

    // If /etc/shells is empty or missing, only /bin/sh is implicitly valid.
    if valid_shells.is_empty() {
        if shell == "/bin/sh" {
            return Ok(());
        }
        return Err(ChshError::Error(format!(
            "'{shell}' is not listed in {}",
            shells_path.display()
        )));
    }

    if !valid_shells.iter().any(|s| s == shell) {
        return Err(ChshError::Error(format!(
            "'{shell}' is not listed in {}",
            shells_path.display()
        )));
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
    if rustix::process::geteuid().is_root() {
        let _ = shadow_core::process::setuid(0);
    }

    let _signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| ChshError::Error(e.to_string()))?;

    let passwd_path = root.passwd_path();

    let lock = FileLock::acquire(&passwd_path).map_err(|_| {
        ChshError::Error(format!(
            "cannot lock {}: try again later",
            passwd_path.display()
        ))
    })?;

    let mut entries = match passwd::read_passwd_file(&passwd_path) {
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
        passwd::write_passwd(&entries, file)?;
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
    let _clean_env = shadow_core::hardening::harden_process();

    let matches = match uu_app().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            if !e.use_stderr() {
                return Ok(());
            }
            return Err(ChshError::AlreadyPrinted(1).into());
        }
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

    // Non-root users can only change their own shell.
    if !shadow_core::hardening::caller_is_root() {
        let current_user = shadow_core::hardening::current_username()
            .map_err(|e| ChshError::Error(e.to_string()))?;
        if current_user != target_user {
            return Err(ChshError::Error("you may only change your own login shell".into()).into());
        }
    }

    let Some(new_shell) = matches.get_one::<String>(options::SHELL) else {
        return Err(ChshError::Error("no shell specified; use -s SHELL".into()).into());
    };

    // Validate the shell before acquiring the lock.
    validate_shell(new_shell, &root.shells_path())?;

    let shell_clone = new_shell.clone();
    mutate_passwd(&root, &target_user, move |entry| {
        entry.shell = shell_clone;
        Ok(())
    })?;

    uucore::show_error!("shell changed for '{target_user}'");
    Ok(())
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
        let result = validate_shell("bin/sh", &shells_path);
        assert!(result.is_err());
    }
}
