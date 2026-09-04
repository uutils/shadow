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
    pub const PREFIX: &str = "prefix";
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
}

impl fmt::Display for ChpasswdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg)
            | Self::UnexpectedFailure(msg)
            | Self::FileBusy(msg)
            | Self::InvalidInput(msg) => f.write_str(msg),
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
    /// Input line the pair came from, for error messages.
    line_number: usize,
}

/// Parse a single input line into a `username:password` pair.
///
/// The format is `username:password`. The username may not be empty, and the
/// password is everything after the first colon, **verbatim** — trailing
/// whitespace is part of the password, so the line is not trimmed; only a
/// trailing CR from CRLF input is removed.
fn parse_input_line(line: &str, line_number: usize) -> Result<PasswordPair, ChpasswdError> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() {
        return Err(ChpasswdError::InvalidInput(format!(
            "line {line_number}: empty line"
        )));
    }

    let colon_pos = line.find(':').ok_or_else(|| {
        ChpasswdError::InvalidInput(format!("line {line_number}: missing ':' separator"))
    })?;

    let username = &line[..colon_pos];
    let password = &line[colon_pos + 1..];

    if username.is_empty() {
        return Err(ChpasswdError::InvalidInput(format!(
            "line {line_number}: empty username"
        )));
    }

    Ok(PasswordPair {
        username: username.to_string(),
        password: zeroize::Zeroizing::new(password.to_string()),
        line_number,
    })
}

/// Refuse an empty password in plaintext mode.
///
/// Hashing `""` produces a perfectly valid hash, and the account then logs in
/// with a bare Enter. Only `-e`, which takes a pre-computed field, may carry
/// an empty value (`!`/`*` style locks are written that way).
fn reject_empty_plaintext(pairs: &[PasswordPair], plaintext: bool) -> Result<(), ChpasswdError> {
    if !plaintext {
        return Ok(());
    }
    match pairs.iter().find(|p| p.password.is_empty()) {
        Some(pair) => Err(ChpasswdError::InvalidInput(format!(
            "line {}: no password supplied for '{}'",
            pair.line_number, pair.username
        ))),
        None => Ok(()),
    }
}

/// Read all `username:password` pairs from stdin.
fn read_pairs_from_stdin() -> Result<Vec<PasswordPair>, ChpasswdError> {
    let stdin = io::stdin();
    let reader = stdin.lock();
    let mut pairs = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        // Every input line carries a password. Own it in a Zeroizing so the
        // buffer is scrubbed when it drops, rather than left in freed heap for
        // a core dump or the next allocation to expose.
        let line =
            zeroize::Zeroizing::new(line.map_err(|e| {
                ChpasswdError::UnexpectedFailure(format!("error reading stdin: {e}"))
            })?);

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
    shadow_core::hardening::harden_process();

    // chpasswd(8) exits 2 for invalid command syntax; every other failure is 1.
    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 2)? else {
        return Ok(());
    };

    // Handle --root / -R: chroot before anything else.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        do_chroot(chroot_dir)?;
    }

    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);

    // chpasswd always requires root.
    if !shadow_core::hardening::caller_is_root() {
        return Err(
            ChpasswdError::PermissionDenied(shadow_core::os_error::permission_denied()).into(),
        );
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
        let method = resolve_crypt_method(crypt_method.map(String::as_str), &root)?;
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

    reject_empty_plaintext(&pairs, hash_config.is_some())?;

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
            // chpasswd(8): "the -c, -e, and -m flags are exclusive".
            Arg::new(options::ENCRYPTED)
                .short('e')
                .long("encrypted")
                .help("treat input passwords as already hashed")
                .conflicts_with_all([options::CRYPT_METHOD, options::MD5])
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::MD5)
                .short('m')
                .long("md5")
                .help("rejected: MD5 is insecure and unsupported (use -c SHA512)")
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
            // chpasswd(8): "the -s flag is only allowed with the -c flag". A
            // rounds count is meaningless without a scheme that takes one, and
            // silently ignoring it wrote a password the caller did not ask for.
            Arg::new(options::SHA_ROUNDS)
                .short('s')
                .long("sha-rounds")
                .help("iteration count when hashing with SHA-2 (requires -c)")
                .value_name("ROUNDS")
                .requires(options::CRYPT_METHOD)
                .value_parser(clap::value_parser!(i64)),
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
    // Hash before taking the lock. crypt(3) with yescrypt or a high SHA
    // rounds= count is deliberately slow, and a batch of them held the
    // /etc/shadow lock (with signals blocked) for the whole run.
    let mut hashed: Vec<(&str, String)> = Vec::with_capacity(pairs.len());
    for pair in pairs {
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
        hashed.push((pair.username.as_str(), hash));
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
    let (mut entries, layout) = match shadow::read_shadow_with_layout(&shadow_path) {
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

    // Index by name once. A linear scan per pair made the critical section --
    // held with signals blocked -- quadratic in a batch the size of the file.
    let index: std::collections::HashMap<&str, usize> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.name.as_str(), i))
        .collect();

    // Resolve every pair before writing any, so an unknown account in the
    // middle of a batch leaves the file untouched rather than half-applied.
    let mut targets = Vec::with_capacity(hashed.len());
    for (username, hash) in hashed {
        let Some(&i) = index.get(username) else {
            drop(lock);
            return Err(ChpasswdError::InvalidInput(format!(
                "user '{username}' does not exist in {}",
                shadow_path.display()
            ))
            .into());
        };
        targets.push((i, hash));
    }

    for (i, hash) in targets {
        let Some(entry) = entries.get_mut(i) else {
            drop(lock);
            return Err(ChpasswdError::UnexpectedFailure(
                "shadow entry vanished between indexing and writing".into(),
            )
            .into());
        };
        entry.passwd = hash;
        entry.last_change = Some(today);
    }

    // Write back atomically.
    let write_result = atomic::atomic_write(&shadow_path, |file| {
        shadow::write_shadow_with_layout(&entries, &layout, file)?;
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

/// The hashing scheme to use, from `-c` or, absent that, from login.defs.
///
/// chpasswd(8) takes its default from `ENCRYPT_METHOD` in login.defs, which is
/// how a distribution chooses the scheme for the whole system -- Debian sets
/// YESCRYPT, and hard-coding SHA512 quietly wrote weaker hashes than the rest
/// of the system was configured to produce. SHA512 remains the fallback when
/// the file names nothing usable.
fn resolve_crypt_method(
    method: Option<&str>,
    root: &SysRoot,
) -> Result<shadow_core::crypt::CryptMethod, ChpasswdError> {
    match method {
        Some(name) => parse_crypt_method(name).ok_or_else(|| {
            ChpasswdError::UnexpectedFailure(match name {
                "MD5" | "DES" => {
                    "MD5 and DES are insecure and not supported for plaintext hashing".into()
                }
                other => format!("unknown crypt method: {other}"),
            })
        }),
        None => Ok(default_crypt_method(root)),
    }
}

/// Map a login.defs / `-c` method name to a `CryptMethod`.
///
/// `None` for a name that is not supported, including the insecure ones.
fn parse_crypt_method(name: &str) -> Option<shadow_core::crypt::CryptMethod> {
    use shadow_core::crypt::CryptMethod;

    match name {
        "SHA256" => Some(CryptMethod::Sha256),
        "SHA512" => Some(CryptMethod::Sha512),
        "YESCRYPT" => Some(CryptMethod::Yescrypt),
        _ => None,
    }
}

/// The system's configured hashing scheme, or SHA-512 if there is none.
///
/// An unreadable login.defs, a missing `ENCRYPT_METHOD`, or one naming a scheme
/// this build will not write (MD5, DES) all fall back rather than fail: the
/// caller asked to set a password, not to audit the configuration.
fn default_crypt_method(root: &SysRoot) -> shadow_core::crypt::CryptMethod {
    shadow_core::login_defs::LoginDefs::load(&root.login_defs_path())
        .ok()
        .and_then(|d| d.get("ENCRYPT_METHOD").and_then(parse_crypt_method))
        .unwrap_or(shadow_core::crypt::CryptMethod::Sha512)
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

    /// `-s` needs `-c`, so the value is read from the pair of them.
    #[test]
    fn test_sha_rounds_flag() {
        let m = uu_app()
            .try_get_matches_from(["chpasswd", "-c", "SHA512", "-s", "5000"])
            .expect("should parse -c SHA512 -s 5000");
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
    fn test_reject_empty_plaintext() {
        let pairs = vec![
            parse_input_line("alice:secret", 1).expect("parses"),
            parse_input_line("bob:", 2).expect("parses"),
        ];
        // -e mode: an empty field is a deliberate lock, allowed.
        assert!(reject_empty_plaintext(&pairs, false).is_ok());
        // Plaintext mode: hashing "" would let bob log in with a bare Enter.
        let err = reject_empty_plaintext(&pairs, true).expect_err("must refuse");
        assert!(
            format!("{err}").contains("line 2") && format!("{err}").contains("bob"),
            "message should name the offending line: {err}"
        );
    }

    /// Whitespace is data, not noise: the password is everything after the
    /// first colon, so a trailing space belongs to it. Trimming it silently
    /// set a different password than the caller supplied.
    #[test]
    fn test_parse_input_line_preserves_whitespace() {
        let pair = parse_input_line("  testuser:$6$hash  ", 1).expect("parses");
        assert_eq!(pair.username, "  testuser");
        assert_eq!(&*pair.password, "$6$hash  ");

        // CRLF input loses only the carriage return.
        let pair = parse_input_line("alice:secret\r", 2).expect("parses");
        assert_eq!(&*pair.password, "secret");
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

        assert_eq!(shadow_core::cli::AlreadyPrinted(1).code(), 1);
        assert_eq!(shadow_core::cli::AlreadyPrinted(2).code(), 2);
    }

    #[test]
    fn test_error_display() {
        let err = ChpasswdError::PermissionDenied("no access".into());
        assert_eq!(format!("{err}"), "no access");

        let err = ChpasswdError::InvalidInput("bad line".into());
        assert_eq!(format!("{err}"), "bad line");

        let err = shadow_core::cli::AlreadyPrinted(1);
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

    // -----------------------------------------------------------------------
    // Crypt method selection
    // -----------------------------------------------------------------------

    fn defs_root(contents: &str) -> (tempfile::TempDir, SysRoot) {
        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("etc");
        std::fs::write(etc.join("login.defs"), contents).expect("write");
        let root = SysRoot::new(Some(dir.path()));
        (dir, root)
    }

    /// The default scheme is the system's, not a hard-coded one: Debian sets
    /// YESCRYPT, and writing SHA-512 there produced weaker hashes than every
    /// other tool on the host.
    #[test]
    fn test_default_method_comes_from_login_defs() {
        use shadow_core::crypt::CryptMethod;

        let (_d, root) = defs_root("ENCRYPT_METHOD YESCRYPT\n");
        assert_eq!(default_crypt_method(&root), CryptMethod::Yescrypt);

        let (_d, root) = defs_root("ENCRYPT_METHOD SHA256\n");
        assert_eq!(default_crypt_method(&root), CryptMethod::Sha256);
    }

    /// A configuration this build will not honour must not stop a password
    /// change; SHA-512 is the fallback.
    #[test]
    fn test_default_method_falls_back_to_sha512() {
        use shadow_core::crypt::CryptMethod;

        for defs in [
            "",
            "ENCRYPT_METHOD MD5\n",
            "ENCRYPT_METHOD DES\n",
            "# nothing\n",
        ] {
            let (_d, root) = defs_root(defs);
            assert_eq!(
                default_crypt_method(&root),
                CryptMethod::Sha512,
                "unexpected fallback for {defs:?}"
            );
        }

        // An absent login.defs is not an error either.
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            default_crypt_method(&SysRoot::new(Some(dir.path()))),
            CryptMethod::Sha512
        );
    }

    /// `-c` wins over the configured default, and names the tool refuses stay
    /// refused rather than silently falling back.
    #[test]
    fn test_explicit_method_overrides_and_rejects() {
        use shadow_core::crypt::CryptMethod;

        let (_d, root) = defs_root("ENCRYPT_METHOD YESCRYPT\n");
        assert_eq!(
            resolve_crypt_method(Some("SHA256"), &root).expect("SHA256"),
            CryptMethod::Sha256
        );
        for bad in ["MD5", "DES", "BCRYPT", "nonsense"] {
            assert!(
                resolve_crypt_method(Some(bad), &root).is_err(),
                "'{bad}' should be refused"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Flag combinations chpasswd(8) rejects
    // -----------------------------------------------------------------------

    /// A rounds count without a scheme, and a scheme with pre-hashed input,
    /// are both usage errors rather than options that quietly do nothing.
    #[test]
    fn test_exclusive_and_dependent_flags() {
        for args in [
            vec!["chpasswd", "-s", "5000"],
            vec!["chpasswd", "-e", "-c", "SHA512"],
            vec!["chpasswd", "-e", "-m"],
        ] {
            assert!(
                uu_app().try_get_matches_from(args.clone()).is_err(),
                "{args:?} should be a usage error"
            );
        }
        // The combinations that are allowed still parse.
        for args in [
            vec!["chpasswd", "-c", "SHA512", "-s", "5000"],
            vec!["chpasswd", "-e"],
            vec!["chpasswd"],
        ] {
            assert!(
                uu_app().try_get_matches_from(args.clone()).is_ok(),
                "{args:?} should parse"
            );
        }
    }
}
