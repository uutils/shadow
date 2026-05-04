// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chpasswd chroot sigprocmask yescrypt

//! `chpasswd` — update passwords in batch mode.
//!
//! Drop-in replacement for GNU shadow-utils `chpasswd(8)`.
//! Reads `username:password` pairs from stdin and updates `/etc/shadow`.

use std::fmt;
use std::io::{self, BufRead};
use std::path::Path;

use clap::{Arg, ArgAction, Command};

use shadow_core::lock::FileLock;
use shadow_core::shadow::{self};
use shadow_core::sysroot::SysRoot;
use shadow_core::{atomic, nscd};

use uucore::error::{UError, UResult};

mod options {
    pub const CRYPT_METHOD: &str = "crypt-method";
    pub const ENCRYPTED: &str = "encrypted";
    pub const MD5: &str = "md5";
    pub const ROOT: &str = "root";
    pub const SHA_ROUNDS: &str = "sha-rounds";
}

// ---------------------------------------------------------------------------
// Error type — implements uucore::error::UError
// ---------------------------------------------------------------------------

/// Errors that the `chpasswd` utility can produce.
///
/// GNU `chpasswd(8)` exits 1 for all errors.
#[derive(Debug)]
enum ChpasswdError {
    /// Exit 1 — insufficient privileges.
    PermissionDenied(String),
    /// Exit 1 — an unexpected runtime failure.
    UnexpectedFailure(String),
    /// Exit 1 — could not acquire the shadow lock file.
    FileBusy(String),
    /// Exit 1 — invalid input line.
    InvalidInput(String),
    /// Sentinel used when the error has already been printed (e.g. by clap).
    AlreadyPrinted(i32),
}

impl fmt::Display for ChpasswdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg)
            | Self::UnexpectedFailure(msg)
            | Self::FileBusy(msg)
            | Self::InvalidInput(msg) => f.write_str(msg),
            Self::AlreadyPrinted(_) => Ok(()),
        }
    }
}

impl std::error::Error for ChpasswdError {}

impl UError for ChpasswdError {
    fn code(&self) -> i32 {
        match self {
            Self::PermissionDenied(_)
            | Self::UnexpectedFailure(_)
            | Self::FileBusy(_)
            | Self::InvalidInput(_) => 1,
            Self::AlreadyPrinted(code) => *code,
        }
    }
}

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------

/// A parsed `username:password` pair from stdin.
///
/// The password field uses `Zeroizing` to ensure it is scrubbed from
/// memory when dropped, preventing password leaks via core dumps or
/// heap inspection.
struct PasswordPair {
    username: String,
    password: zeroize::Zeroizing<String>,
}

/// Parse a single input line into a `username:password` pair.
///
/// The format is `username:password` where username cannot be empty
/// and the password is everything after the first colon (may be empty
/// only if the `-e` flag is used).
fn parse_input_line(line: &str, line_number: usize) -> Result<PasswordPair, ChpasswdError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(ChpasswdError::InvalidInput(format!(
            "line {line_number}: empty line"
        )));
    }

    let colon_pos = trimmed.find(':').ok_or_else(|| {
        ChpasswdError::InvalidInput(format!("line {line_number}: missing ':' separator"))
    })?;

    let username = &trimmed[..colon_pos];
    let password = &trimmed[colon_pos + 1..];

    if username.is_empty() {
        return Err(ChpasswdError::InvalidInput(format!(
            "line {line_number}: empty username"
        )));
    }

    Ok(PasswordPair {
        username: username.to_string(),
        password: zeroize::Zeroizing::new(password.to_string()),
    })
}

/// Read all `username:password` pairs from stdin.
fn read_pairs_from_stdin() -> Result<Vec<PasswordPair>, ChpasswdError> {
    let stdin = io::stdin();
    let reader = stdin.lock();
    let mut pairs = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line
            .map_err(|e| ChpasswdError::UnexpectedFailure(format!("error reading stdin: {e}")))?;

        // Skip empty lines.
        if line.trim().is_empty() {
            continue;
        }

        pairs.push(parse_input_line(&line, idx + 1)?);
    }

    if pairs.is_empty() {
        return Err(ChpasswdError::InvalidInput(
            "no username:password pairs provided on stdin".into(),
        ));
    }

    Ok(pairs)
}

/// Compute the current day since epoch (for `last_change` field).
fn days_since_epoch() -> Result<i64, ChpasswdError> {
    shadow_core::shadow::days_since_epoch().map_err(|e| {
        ChpasswdError::UnexpectedFailure(format!("cannot determine current date: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the `chpasswd` utility.
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
            return Err(ChpasswdError::AlreadyPrinted(1).into());
        }
    };

    // Handle --root / -R: chroot before anything else.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        do_chroot(chroot_dir)?;
    }

    let root = SysRoot::default();

    // chpasswd always requires root.
    if !shadow_core::hardening::caller_is_root() {
        return Err(ChpasswdError::PermissionDenied("Permission denied.".into()).into());
    }

    let is_encrypted = matches.get_flag(options::ENCRYPTED);
    let use_md5 = matches.get_flag(options::MD5);
    let crypt_method = matches.get_one::<String>(options::CRYPT_METHOD);

    // Reject -m unconditionally — MD5 is insecure.
    if use_md5 {
        return Err(ChpasswdError::UnexpectedFailure(
            "MD5 is insecure and not supported; use -c SHA512 instead".into(),
        )
        .into());
    }

    // Validate --sha-rounds range.
    let sha_rounds = match matches.get_one::<i64>(options::SHA_ROUNDS).copied() {
        Some(r @ 1..=i64::MAX) => match u32::try_from(r) {
            Ok(v) => Some(v),
            Err(_) => {
                return Err(ChpasswdError::UnexpectedFailure(format!(
                    "invalid value for --sha-rounds '{r}': must be between 1 and {}",
                    u32::MAX
                ))
                .into());
            }
        },
        Some(r) => {
            return Err(ChpasswdError::UnexpectedFailure(format!(
                "invalid value for --sha-rounds '{r}': must be between 1 and {}",
                u32::MAX
            ))
            .into());
        }
        None => None,
    };

    // Determine the hashing method for plaintext mode.
    let hash_config = if is_encrypted {
        None
    } else {
        let method = resolve_crypt_method(crypt_method.map(String::as_str))?;
        if sha_rounds.is_some() && method == shadow_core::crypt::CryptMethod::Yescrypt {
            return Err(ChpasswdError::UnexpectedFailure(
                "--sha-rounds is not supported with YESCRYPT".into(),
            )
            .into());
        }
        Some((method, sha_rounds))
    };

    // Read all pairs from stdin before acquiring locks.
    let pairs = read_pairs_from_stdin()?;

    // Apply all password changes in a single locked transaction.
    apply_password_changes(&root, &pairs, hash_config.as_ref())
}

/// Build the clap `Command` for `chpasswd`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("chpasswd")
        .about("Read user:password pairs from stdin and apply them")
        .override_usage("chpasswd [options]")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::CRYPT_METHOD)
                .short('c')
                .long("crypt-method")
                .help("hashing scheme to apply (SHA256, SHA512, YESCRYPT, ...)")
                .value_name("METHOD")
                .value_parser(["SHA256", "SHA512", "YESCRYPT", "DES", "MD5"]),
        )
        .arg(
            Arg::new(options::ENCRYPTED)
                .short('e')
                .long("encrypted")
                .help("treat input passwords as already hashed")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::MD5)
                .short('m')
                .long("md5")
                .help("hash with MD5 (legacy; do not use for new accounts)")
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
            Arg::new(options::SHA_ROUNDS)
                .short('s')
                .long("sha-rounds")
                .help("iteration count when hashing with SHA-2")
                .value_name("ROUNDS")
                .value_parser(clap::value_parser!(i64)),
        )
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

/// Apply all password changes to `/etc/shadow` in a single locked transaction.
///
/// When `hash_config` is `Some`, plaintext passwords are hashed via crypt(3).
/// When `None`, passwords are assumed to be pre-encrypted (`-e` mode).
fn apply_password_changes(
    root: &SysRoot,
    pairs: &[PasswordPair],
    hash_config: Option<&(shadow_core::crypt::CryptMethod, Option<u32>)>,
) -> UResult<()> {
    // Consolidate real + effective UID to root for file operations.
    if rustix::process::geteuid().is_root() {
        let _ = shadow_core::process::setuid(0);
    }

    // Block signals for the entire critical section.
    let _signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| ChpasswdError::UnexpectedFailure(e.to_string()))?;

    let shadow_path = root.shadow_path();

    // Acquire lock.
    let lock = FileLock::acquire(&shadow_path).map_err(|_| {
        ChpasswdError::FileBusy(format!(
            "cannot lock {}: try again later",
            shadow_path.display()
        ))
    })?;

    // Read current entries.
    let mut entries = match shadow::read_shadow_file(&shadow_path) {
        Ok(e) => e,
        Err(e) => {
            drop(lock);
            return Err(ChpasswdError::UnexpectedFailure(format!(
                "Cannot open {}: {e}",
                shadow_path.display()
            ))
            .into());
        }
    };

    let today = days_since_epoch()?;

    // Apply each pair.
    for pair in pairs {
        let Some(entry) = entries.iter_mut().find(|e| e.name == pair.username) else {
            drop(lock);
            return Err(ChpasswdError::InvalidInput(format!(
                "user '{}' does not exist in {}",
                pair.username,
                shadow_path.display()
            ))
            .into());
        };

        // Hash plaintext passwords or use pre-encrypted value directly.
        let hash = if let Some((method, rounds)) = hash_config {
            shadow_core::crypt::hash_password(&pair.password, *method, *rounds).map_err(|e| {
                ChpasswdError::UnexpectedFailure(format!(
                    "failed to hash password for '{}': {e}",
                    pair.username
                ))
            })?
        } else {
            pair.password.to_string()
        };

        entry.passwd = hash;
        entry.last_change = Some(today);
    }

    // Write back atomically.
    let write_result = atomic::atomic_write(&shadow_path, |file| {
        shadow::write_shadow(&entries, file)?;
        Ok(())
    });

    if let Err(e) = write_result {
        drop(lock);
        return Err(ChpasswdError::UnexpectedFailure(format!(
            "failed to write {}: {e}",
            shadow_path.display()
        ))
        .into());
    }

    // Release lock and invalidate caches.
    drop(lock);
    nscd::invalidate_cache("shadow");

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map `-c` flag to a `CryptMethod`.
fn resolve_crypt_method(
    method: Option<&str>,
) -> Result<shadow_core::crypt::CryptMethod, ChpasswdError> {
    use shadow_core::crypt::CryptMethod;

    match method {
        Some("SHA256") => Ok(CryptMethod::Sha256),
        Some("SHA512") | None => Ok(CryptMethod::Sha512),
        Some("YESCRYPT") => Ok(CryptMethod::Yescrypt),
        Some("MD5" | "DES") => Err(ChpasswdError::UnexpectedFailure(
            "MD5 and DES are insecure and not supported for plaintext hashing".into(),
        )),
        Some(other) => Err(ChpasswdError::UnexpectedFailure(format!(
            "unknown crypt method: {other}"
        ))),
    }
}

/// Perform `chroot(2)` into the specified directory.
fn do_chroot(dir: &str) -> Result<(), ChpasswdError> {
    if !shadow_core::hardening::caller_is_root() {
        return Err(ChpasswdError::PermissionDenied(
            "only root may use --root".into(),
        ));
    }

    let path = Path::new(dir);
    rustix::process::chroot(path)
        .map_err(|e| ChpasswdError::UnexpectedFailure(format!("cannot chroot to '{dir}': {e}")))?;

    rustix::process::chdir("/").map_err(|e| {
        ChpasswdError::UnexpectedFailure(format!("cannot chdir to / after chroot: {e}"))
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Basic clap / app tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    #[test]
    fn test_encrypted_flag() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-e"])
            .expect("should parse -e flag");
        assert!(m.get_flag(options::ENCRYPTED));
    }

    #[test]
    fn test_md5_flag() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-m"])
            .expect("should parse -m flag");
        assert!(m.get_flag(options::MD5));
    }

    #[test]
    fn test_crypt_method_valid() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-c", "SHA512"])
            .expect("should parse -c SHA512");
        assert_eq!(
            m.get_one::<String>(options::CRYPT_METHOD)
                .map(String::as_str),
            Some("SHA512")
        );
    }

    #[test]
    fn test_crypt_method_invalid() {
        let result = uu_app().try_get_matches_from(["chpasswd", "-c", "INVALID"]);
        assert!(result.is_err(), "invalid crypt method should fail");
    }

    #[test]
    fn test_sha_rounds_flag() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-s", "5000"])
            .expect("should parse -s 5000");
        assert_eq!(m.get_one::<i64>(options::SHA_ROUNDS).copied(), Some(5000));
    }

    #[test]
    fn test_root_flag() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-R", "/mnt/chroot"])
            .expect("should parse -R flag");
        assert_eq!(
            m.get_one::<String>(options::ROOT).map(String::as_str),
            Some("/mnt/chroot")
        );
    }

    #[test]
    fn test_combined_flags() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-e", "-R", "/mnt"])
            .expect("should parse combined flags");
        assert!(m.get_flag(options::ENCRYPTED));
        assert_eq!(
            m.get_one::<String>(options::ROOT).map(String::as_str),
            Some("/mnt")
        );
    }

    #[test]
    fn test_all_crypt_methods() {
        for method in &["SHA256", "SHA512", "YESCRYPT", "DES", "MD5"] {
            let m = uu_app()
                .try_get_matches_from(["chpasswd", "-c", method])
                .unwrap_or_else(|_| panic!("should parse -c {method}"));
            assert_eq!(
                m.get_one::<String>(options::CRYPT_METHOD)
                    .map(String::as_str),
                Some(*method)
            );
        }
    }

    // -----------------------------------------------------------------------
    // Input parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_input_line_valid() {
        let pair = parse_input_line("testuser:$6$hash", 1).expect("should parse");
        assert_eq!(pair.username, "testuser");
        assert_eq!(&*pair.password, "$6$hash");
    }

    #[test]
    fn test_parse_input_line_empty_password() {
        let pair = parse_input_line("testuser:", 1).expect("should parse empty password");
        assert_eq!(pair.username, "testuser");
        assert_eq!(&*pair.password, "");
    }

    #[test]
    fn test_parse_input_line_password_with_colons() {
        // The password itself may contain colons (e.g., in a hash).
        let pair = parse_input_line("testuser:$6$salt:hash:rest", 1).expect("should parse");
        assert_eq!(pair.username, "testuser");
        // Only the first colon is the separator; rest is password.
        assert_eq!(&*pair.password, "$6$salt:hash:rest");
    }

    #[test]
    fn test_parse_input_line_missing_colon() {
        let result = parse_input_line("nocolon", 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_input_line_empty_username() {
        let result = parse_input_line(":password", 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_input_line_empty_line() {
        let result = parse_input_line("", 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_input_line_whitespace_only() {
        let result = parse_input_line("   ", 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_input_line_leading_whitespace() {
        let pair = parse_input_line("  testuser:$6$hash  ", 1).expect("should handle whitespace");
        assert_eq!(pair.username, "testuser");
        assert_eq!(&*pair.password, "$6$hash");
    }

    // -----------------------------------------------------------------------
    // Error code tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_errors_exit_one() {
        use uucore::error::UError;

        assert_eq!(ChpasswdError::PermissionDenied("test".into()).code(), 1);
        assert_eq!(ChpasswdError::UnexpectedFailure("test".into()).code(), 1);
        assert_eq!(ChpasswdError::FileBusy("test".into()).code(), 1);
        assert_eq!(ChpasswdError::InvalidInput("test".into()).code(), 1);
    }

    #[test]
    fn test_already_printed_preserves_code() {
        use uucore::error::UError;

        assert_eq!(ChpasswdError::AlreadyPrinted(1).code(), 1);
        assert_eq!(ChpasswdError::AlreadyPrinted(2).code(), 2);
    }

    #[test]
    fn test_error_display() {
        let err = ChpasswdError::PermissionDenied("no access".into());
        assert_eq!(format!("{err}"), "no access");

        let err = ChpasswdError::InvalidInput("bad line".into());
        assert_eq!(format!("{err}"), "bad line");

        let err = ChpasswdError::AlreadyPrinted(1);
        assert_eq!(format!("{err}"), "");
    }

    #[test]
    fn test_error_is_std_error() {
        let err = ChpasswdError::UnexpectedFailure("fail".into());
        let _: &dyn std::error::Error = &err;
    }

    // -----------------------------------------------------------------------
    // days_since_epoch sanity test
    // -----------------------------------------------------------------------

    #[test]
    fn test_days_since_epoch_reasonable() {
        let days = days_since_epoch().expect("system clock should work in tests");
        // Should be at least 2024-01-01 (~19723 days) and less than 2100-01-01 (~47482 days).
        assert!(
            days > 19700,
            "days since epoch should be > 19700, got {days}"
        );
        assert!(
            days < 47500,
            "days since epoch should be < 47500, got {days}"
        );
    }
}
