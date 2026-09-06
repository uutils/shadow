// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chgpasswd chpasswd gshadow chroot nscd sysroot yescrypt

//! `chgpasswd` — update group passwords in batch mode.
//!
//! Drop-in replacement for GNU shadow-utils `chgpasswd(8)`. Reads
//! `group:password` pairs from stdin and updates `/etc/gshadow`, or
//! `/etc/group` on a system that has no gshadow file.
//!
//! It is `chpasswd(8)`'s counterpart for groups, and follows the same rule:
//! every line is resolved before any is written, so a batch naming one group
//! that does not exist changes nothing at all.

use std::fmt;
use std::io::{self, BufRead};
use std::path::Path;

use clap::{Arg, ArgAction, Command};

use shadow_core::group::GroupEntry;
use shadow_core::gshadow::GshadowEntry;
use shadow_core::nscd;
use shadow_core::sysroot::SysRoot;
use shadow_core::transaction::{self, Commit, LockedFile};

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
// Error type
// ---------------------------------------------------------------------------

/// Errors that the `chgpasswd` utility can produce.
///
/// GNU `chgpasswd(8)` exits 1 for a failure, 2 for invalid command syntax and
/// 3 for a chroot directory it cannot enter.
#[derive(Debug)]
enum ChgpasswdError {
    /// Exit 1 — insufficient privileges.
    PermissionDenied(String),
    /// Exit 1 — an unexpected runtime failure.
    UnexpectedFailure(String),
    /// Exit 1 — could not acquire a lock on an account file.
    FileBusy(String),
    /// Exit 1 — invalid input line.
    InvalidInput(String),
    /// Exit 3 — the `--root` directory could not be entered.
    CantChroot(String),
}

impl fmt::Display for ChgpasswdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg)
            | Self::UnexpectedFailure(msg)
            | Self::FileBusy(msg)
            | Self::InvalidInput(msg)
            | Self::CantChroot(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ChgpasswdError {}

impl UError for ChgpasswdError {
    fn code(&self) -> i32 {
        match self {
            Self::PermissionDenied(_)
            | Self::UnexpectedFailure(_)
            | Self::FileBusy(_)
            | Self::InvalidInput(_) => 1,
            Self::CantChroot(_) => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------

/// A parsed `group:password` pair from stdin.
///
/// The password field is `Zeroizing` so it is scrubbed when dropped rather
/// than left in freed heap for a core dump to expose.
struct PasswordPair {
    group: String,
    password: zeroize::Zeroizing<String>,
    /// Input line the pair came from, for error messages.
    line_number: usize,
}

/// Parse one input line into a `group:password` pair.
///
/// The password is everything after the first colon, **verbatim**: a hash may
/// contain colons, and trailing whitespace is part of a password, so the line
/// is not trimmed. Only a trailing CR from CRLF input is removed.
fn parse_input_line(line: &str, line_number: usize) -> Result<PasswordPair, ChgpasswdError> {
    let line = line.strip_suffix('\r').unwrap_or(line);

    // A line with no colon carries no password, which is how the GNU tool
    // words it -- and a blank line is that same case, not something to skip.
    let Some(colon_pos) = line.find(':') else {
        return Err(ChgpasswdError::InvalidInput(format!(
            "line {line_number}: missing new password"
        )));
    };

    let group = &line[..colon_pos];
    let password = &line[colon_pos + 1..];

    if group.is_empty() {
        return Err(ChgpasswdError::InvalidInput(format!(
            "line {line_number}: missing group name"
        )));
    }

    Ok(PasswordPair {
        group: group.to_string(),
        password: zeroize::Zeroizing::new(password.to_string()),
        line_number,
    })
}

/// Read every `group:password` pair from stdin.
///
/// Empty input is not an error: `chgpasswd < /dev/null` succeeds having done
/// nothing, which is what the GNU tool does and what a script driving it from
/// a possibly-empty list depends on.
fn read_pairs_from_stdin() -> Result<Vec<PasswordPair>, ChgpasswdError> {
    let stdin = io::stdin();
    let reader = stdin.lock();
    let mut pairs = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        // Every line carries a password; own it in a Zeroizing so the buffer
        // is scrubbed when it drops.
        let line =
            zeroize::Zeroizing::new(line.map_err(|e| {
                ChgpasswdError::UnexpectedFailure(format!("error reading stdin: {e}"))
            })?);
        pairs.push(parse_input_line(&line, idx + 1)?);
    }

    Ok(pairs)
}

/// Refuse an empty password in plaintext mode.
///
/// Hashing `""` produces a valid hash, and the group then accepts a bare
/// Enter from any non-member. Only `-e`, which takes a pre-computed field, may
/// carry an empty value -- that is how a `!` lock is written.
fn reject_empty_plaintext(pairs: &[PasswordPair], plaintext: bool) -> Result<(), ChgpasswdError> {
    if !plaintext {
        return Ok(());
    }
    match pairs.iter().find(|p| p.password.is_empty()) {
        Some(pair) => Err(ChgpasswdError::InvalidInput(format!(
            "line {}: no password supplied for '{}'",
            pair.line_number, pair.group
        ))),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    // chgpasswd(8) exits 2 for invalid command syntax; other failures are 1.
    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 2)? else {
        return Ok(());
    };

    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        shadow_core::hardening::chroot_into(Path::new(chroot_dir))
            .map_err(|e| ChgpasswdError::CantChroot(e.to_string()))?;
    }

    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);

    if !shadow_core::hardening::caller_is_root() {
        return Err(
            ChgpasswdError::PermissionDenied(shadow_core::os_error::permission_denied()).into(),
        );
    }

    let is_encrypted = matches.get_flag(options::ENCRYPTED);
    let crypt_method = matches.get_one::<String>(options::CRYPT_METHOD);

    if matches.get_flag(options::MD5) {
        return Err(ChgpasswdError::UnexpectedFailure(
            "MD5 is insecure and not supported; use -c SHA512 instead".into(),
        )
        .into());
    }

    let sha_rounds = parse_sha_rounds(matches.get_one::<i64>(options::SHA_ROUNDS).copied())?;

    let hash_config = if is_encrypted {
        None
    } else {
        let method = resolve_crypt_method(crypt_method.map(String::as_str), &root)?;
        if sha_rounds.is_some() && method == shadow_core::crypt::CryptMethod::Yescrypt {
            return Err(ChgpasswdError::UnexpectedFailure(
                "--sha-rounds is not supported with YESCRYPT".into(),
            )
            .into());
        }
        Some((method, sha_rounds))
    };

    let pairs = read_pairs_from_stdin()?;
    reject_empty_plaintext(&pairs, hash_config.is_some())?;

    if pairs.is_empty() {
        return Ok(());
    }

    apply_password_changes(&root, &pairs, hash_config.as_ref())
}

/// Validate `--sha-rounds`, which must fit a `u32` to reach crypt(3).
fn parse_sha_rounds(value: Option<i64>) -> Result<Option<u32>, ChgpasswdError> {
    let Some(rounds) = value else {
        return Ok(None);
    };
    u32::try_from(rounds).map(Some).map_err(|_| {
        ChgpasswdError::UnexpectedFailure(format!(
            "invalid value for --sha-rounds '{rounds}': must be between 1 and {}",
            u32::MAX
        ))
    })
}

/// Build the clap `Command` for `chgpasswd`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("chgpasswd")
        .about("Read group:password pairs from stdin and apply them")
        .override_usage("chgpasswd [options]")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::CRYPT_METHOD)
                .short('c')
                .long("crypt-method")
                .help("hashing scheme to apply (SHA256, SHA512, YESCRYPT, ...)")
                .value_name("METHOD")
                .value_parser(["SHA256", "SHA512", "YESCRYPT", "DES", "MD5", "NONE"]),
        )
        .arg(
            // chgpasswd(8): the -c, -e and -m flags are exclusive.
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
            // A rounds count without a scheme that takes one is meaningless,
            // and ignoring it silently wrote a password the caller did not ask
            // for.
            Arg::new(options::SHA_ROUNDS)
                .short('s')
                .long("sha-rounds")
                .help("iteration count when hashing with SHA-2 (requires -c)")
                .value_name("ROUNDS")
                .requires(options::CRYPT_METHOD)
                .value_parser(clap::value_parser!(i64).range(1..)),
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

/// Apply every group password change in one locked transaction.
fn apply_password_changes(
    root: &SysRoot,
    pairs: &[PasswordPair],
    hash_config: Option<&(shadow_core::crypt::CryptMethod, Option<u32>)>,
) -> UResult<()> {
    // Hash before taking any lock. crypt(3) with yescrypt or a high rounds=
    // count is deliberately slow, and a batch of them would otherwise hold the
    // account-file locks, with signals blocked, for the whole run.
    let mut hashed: Vec<(&str, String)> = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let hash = match hash_config {
            Some((method, rounds)) => {
                shadow_core::crypt::hash_password(&pair.password, *method, *rounds).map_err(
                    |e| {
                        ChgpasswdError::UnexpectedFailure(format!(
                            "failed to hash password for '{}': {e}",
                            pair.group
                        ))
                    },
                )?
            }
            None => pair.password.to_string(),
        };
        hashed.push((pair.group.as_str(), hash));
    }

    let group_path = root.group_path();
    let gshadow_path = root.gshadow_path();
    // A system with no gshadow keeps group passwords in /etc/group itself, and
    // chgpasswd must not conjure the file into existence: creating it would
    // change how every other tool on the host reads group passwords.
    let gshadow_exists = gshadow_path.exists();

    let mut group_file = open_locked::<GroupEntry>(&group_path)?;
    let mut gshadow_file = if gshadow_exists {
        Some(open_locked::<GshadowEntry>(&gshadow_path)?)
    } else {
        None
    };

    // Resolve every line before writing any, so one unknown group in the
    // middle of a batch leaves both files untouched rather than half applied.
    let index: std::collections::HashMap<&str, usize> = group_file
        .entries()
        .iter()
        .enumerate()
        .map(|(i, e)| (e.name.as_str(), i))
        .collect();

    let mut targets = Vec::with_capacity(hashed.len());
    for ((name, hash), pair) in hashed.iter().zip(pairs) {
        let Some(&i) = index.get(name) else {
            return Err(ChgpasswdError::InvalidInput(format!(
                "line {}: group '{name}' does not exist",
                pair.line_number
            ))
            .into());
        };
        targets.push((i, name, hash));
    }

    for (i, name, hash) in targets {
        match gshadow_file.as_mut() {
            // With a gshadow file the hash belongs there, and /etc/group
            // carries the `x` placeholder that says so.
            Some(gshadow) => {
                let members = group_file.entries()[i].members.clone();
                group_file.entries_mut()[i].passwd = "x".to_string();
                set_gshadow_password(gshadow.entries_mut(), name, &members, hash);
            }
            None => group_file.entries_mut()[i].passwd.clone_from(hash),
        }
    }

    // Both files are validated before either is written, so a value that would
    // corrupt one cannot leave the pair disagreeing. A commit that would write
    // the same bytes writes nothing.
    let mut files: Vec<Box<dyn Commit>> = vec![Box::new(group_file)];
    if let Some(gshadow) = gshadow_file {
        files.push(Box::new(gshadow));
    }
    transaction::commit_all(files)
        .map_err(|e| ChgpasswdError::UnexpectedFailure(format!("cannot write: {e}")))?;

    nscd::invalidate_cache("group");

    Ok(())
}

/// Lock and read an account file, mapping contention to its own error.
fn open_locked<T>(path: &Path) -> Result<LockedFile<T>, ChgpasswdError>
where
    T: shadow_core::transaction::Record,
{
    LockedFile::<T>::open(path).map_err(|e| match e {
        shadow_core::error::ShadowError::Lock(_) => {
            ChgpasswdError::FileBusy(format!("cannot lock {}: try again later", path.display()))
        }
        other => {
            ChgpasswdError::UnexpectedFailure(format!("cannot open {}: {other}", path.display()))
        }
    })
}

/// Set a group's password in gshadow, adding the line if it is missing.
///
/// A group present in `/etc/group` with no gshadow line is an inconsistency
/// grpck reports; setting a password on it is a reasonable way to fix it, so
/// the line is created rather than the change refused.
fn set_gshadow_password(
    entries: &mut Vec<GshadowEntry>,
    name: &str,
    members: &[String],
    hash: &str,
) {
    if let Some(entry) = entries.iter_mut().find(|g| g.name == name) {
        entry.passwd = hash.to_string();
        return;
    }
    entries.push(GshadowEntry {
        name: name.to_string(),
        passwd: hash.to_string(),
        admins: Vec::new(),
        members: members.to_vec(),
    });
}

// ---------------------------------------------------------------------------
// Crypt method selection
// ---------------------------------------------------------------------------

/// The hashing scheme to use, from `-c` or, absent that, from login.defs.
///
/// The default is the system's, not a hard-coded one: Debian sets YESCRYPT,
/// and hard-coding SHA-512 would quietly write weaker hashes than the rest of
/// the host produces.
fn resolve_crypt_method(
    method: Option<&str>,
    root: &SysRoot,
) -> Result<shadow_core::crypt::CryptMethod, ChgpasswdError> {
    match method {
        Some(name) => parse_crypt_method(name).ok_or_else(|| {
            ChgpasswdError::UnexpectedFailure(match name {
                // GNU accepts NONE and stores the password as clear text. A
                // readable group password in /etc/gshadow is worth no more
                // than no password at all, and `-e` already covers writing a
                // field verbatim when that is genuinely what is wanted.
                "NONE" => "NONE would store the password unhashed and is not supported; \
                           use -e to write a field verbatim"
                    .into(),
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
fn default_crypt_method(root: &SysRoot) -> shadow_core::crypt::CryptMethod {
    shadow_core::login_defs::LoginDefs::load(&root.login_defs_path())
        .ok()
        .and_then(|d| d.get("ENCRYPT_METHOD").and_then(parse_crypt_method))
        .unwrap_or(shadow_core::crypt::CryptMethod::Sha512)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    // -----------------------------------------------------------------------
    // Input parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_input_line_valid() {
        let pair = parse_input_line("staff:$6$hash", 1).expect("should parse");
        assert_eq!(pair.group, "staff");
        assert_eq!(&*pair.password, "$6$hash");
    }

    /// Only the first colon separates: a hash contains them.
    #[test]
    fn test_parse_input_line_password_with_colons() {
        let pair = parse_input_line("staff:$6$salt:hash:rest", 1).expect("should parse");
        assert_eq!(pair.group, "staff");
        assert_eq!(&*pair.password, "$6$salt:hash:rest");
    }

    /// A line with no colon supplies no password, and a blank line is that
    /// same case rather than something to skip over.
    #[test]
    fn test_lines_without_a_password_are_refused() {
        for line in ["nocolon", "", "   "] {
            let err = parse_input_line(line, 4).err().expect("should be refused");
            assert!(
                format!("{err}").contains("line 4: missing new password"),
                "unexpected message for {line:?}: {err}"
            );
        }
    }

    #[test]
    fn test_parse_input_line_empty_group() {
        let err = parse_input_line(":password", 2)
            .err()
            .expect("should be refused");
        assert!(format!("{err}").contains("line 2"));
    }

    /// Whitespace is data: the password is everything after the first colon,
    /// so trimming it would set a different password than was supplied.
    #[test]
    fn test_parse_input_line_preserves_whitespace() {
        let pair = parse_input_line("staff:$6$hash  ", 1).expect("parses");
        assert_eq!(&*pair.password, "$6$hash  ");

        // CRLF input loses only the carriage return.
        let pair = parse_input_line("staff:secret\r", 2).expect("parses");
        assert_eq!(&*pair.password, "secret");
    }

    #[test]
    fn test_reject_empty_plaintext() {
        let pairs = vec![
            parse_input_line("staff:secret", 1).expect("parses"),
            parse_input_line("wheel:", 2).expect("parses"),
        ];
        // -e mode: an empty field is a deliberate lock, allowed.
        assert!(reject_empty_plaintext(&pairs, false).is_ok());
        let err = reject_empty_plaintext(&pairs, true).expect_err("must refuse");
        assert!(
            format!("{err}").contains("line 2") && format!("{err}").contains("wheel"),
            "message should name the offending line: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // gshadow entry handling
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_gshadow_password_updates_in_place() {
        let mut entries = vec![GshadowEntry {
            name: "staff".to_string(),
            passwd: "!".to_string(),
            admins: vec!["alice".to_string()],
            members: vec!["bob".to_string()],
        }];
        set_gshadow_password(&mut entries, "staff", &[], "$6$new");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].passwd, "$6$new");
        // Setting a password must not disturb who administers or belongs to
        // the group.
        assert_eq!(entries[0].admins, vec!["alice".to_string()]);
        assert_eq!(entries[0].members, vec!["bob".to_string()]);
    }

    #[test]
    fn test_set_gshadow_password_adds_a_missing_line() {
        let mut entries = Vec::new();
        let members = vec!["carol".to_string()];
        set_gshadow_password(&mut entries, "staff", &members, "$6$new");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "staff");
        assert_eq!(entries[0].passwd, "$6$new");
        // The new line inherits the membership /etc/group already records.
        assert_eq!(entries[0].members, members);
        assert!(entries[0].admins.is_empty());
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

    #[test]
    fn test_default_method_comes_from_login_defs() {
        use shadow_core::crypt::CryptMethod;

        let (_d, root) = defs_root("ENCRYPT_METHOD YESCRYPT\n");
        assert_eq!(default_crypt_method(&root), CryptMethod::Yescrypt);

        let (_d, root) = defs_root("ENCRYPT_METHOD SHA256\n");
        assert_eq!(default_crypt_method(&root), CryptMethod::Sha256);
    }

    #[test]
    fn test_default_method_falls_back_to_sha512() {
        use shadow_core::crypt::CryptMethod;

        for defs in ["", "ENCRYPT_METHOD MD5\n", "ENCRYPT_METHOD DES\n"] {
            let (_d, root) = defs_root(defs);
            assert_eq!(default_crypt_method(&root), CryptMethod::Sha512);
        }
    }

    /// The schemes this build refuses stay refused rather than silently
    /// falling back to something else.
    #[test]
    fn test_insecure_methods_are_refused() {
        let (_d, root) = defs_root("ENCRYPT_METHOD YESCRYPT\n");
        for bad in ["MD5", "DES", "NONE", "BCRYPT", "nonsense"] {
            assert!(
                resolve_crypt_method(Some(bad), &root).is_err(),
                "'{bad}' should be refused"
            );
        }
    }

    /// NONE is refused for a different reason than the weak hashes, and the
    /// message has to say which, or an operator will just try `-c MD5` next.
    #[test]
    fn test_none_explains_itself() {
        let (_d, root) = defs_root("");
        let err = resolve_crypt_method(Some("NONE"), &root).expect_err("refused");
        assert!(format!("{err}").contains("unhashed"), "{err}");
        assert!(format!("{err}").contains("-e"), "{err}");
    }

    // -----------------------------------------------------------------------
    // Flags
    // -----------------------------------------------------------------------

    #[test]
    fn test_exclusive_and_dependent_flags() {
        for args in [
            vec!["chgpasswd", "-s", "5000"],
            vec!["chgpasswd", "-e", "-c", "SHA512"],
            vec!["chgpasswd", "-e", "-m"],
            vec!["chgpasswd", "-c", "BOGUS"],
            vec!["chgpasswd", "-c", "SHA512", "-s", "0"],
        ] {
            assert!(
                uu_app().try_get_matches_from(args.clone()).is_err(),
                "{args:?} should be a usage error"
            );
        }
        for args in [
            vec!["chgpasswd", "-c", "SHA512", "-s", "5000"],
            vec!["chgpasswd", "-e"],
            vec!["chgpasswd"],
        ] {
            assert!(
                uu_app().try_get_matches_from(args.clone()).is_ok(),
                "{args:?} should parse"
            );
        }
    }

    #[test]
    fn test_sha_rounds_must_fit_a_u32() {
        assert_eq!(parse_sha_rounds(None).expect("none"), None);
        assert_eq!(parse_sha_rounds(Some(5000)).expect("ok"), Some(5000));
        assert!(parse_sha_rounds(Some(i64::from(u32::MAX) + 1)).is_err());
    }

    // -----------------------------------------------------------------------
    // Exit codes
    // -----------------------------------------------------------------------

    /// The codes are the interface: 1 for a failure, 3 for a chroot that
    /// cannot be entered.
    #[test]
    fn test_exit_codes() {
        use uucore::error::UError;

        assert_eq!(ChgpasswdError::PermissionDenied("x".into()).code(), 1);
        assert_eq!(ChgpasswdError::UnexpectedFailure("x".into()).code(), 1);
        assert_eq!(ChgpasswdError::FileBusy("x".into()).code(), 1);
        assert_eq!(ChgpasswdError::InvalidInput("x".into()).code(), 1);
        assert_eq!(ChgpasswdError::CantChroot("x".into()).code(), 3);
    }

    #[test]
    fn test_error_display_and_is_std_error() {
        let err = ChgpasswdError::InvalidInput("bad line".into());
        assert_eq!(format!("{err}"), "bad line");
        let _: &dyn std::error::Error = &err;
    }
}
