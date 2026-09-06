// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore newusers gshadow chroot nscd sysroot yescrypt gecos

//! `newusers` — create or update users in batch.
//!
//! Drop-in replacement for GNU shadow-utils `newusers(8)`. Reads lines of
//! seven colon-separated fields from stdin and creates the accounts they
//! describe, or updates them where they already exist.
//!
//! Every line is parsed and every account resolved before anything is written,
//! so a batch with one bad line leaves the system exactly as it was. That is
//! the property that makes it safe to feed this tool a generated file.

use std::fmt;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, Command};

use shadow_core::group::GroupEntry;
use shadow_core::login_defs::LoginDefs;
use shadow_core::passwd::PasswdEntry;
use shadow_core::shadow::ShadowEntry;
use shadow_core::sysroot::SysRoot;
use shadow_core::transaction::{self, Commit, LockedFile};
use shadow_core::uid_alloc::{self, Scope};

use uucore::error::{UError, UResult};

mod options {
    pub const SYSTEM: &str = "system";
    pub const BADNAME: &str = "badname";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
    pub const CRYPT_METHOD: &str = "crypt-method";
}

/// The number of colon-separated fields every input line must have.
const FIELD_COUNT: usize = 7;

/// The mode a new home directory is created with.
const HOME_MODE: u32 = 0o700;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that the `newusers` utility can produce.
#[derive(Debug)]
enum NewusersError {
    /// Exit 1 — insufficient privileges.
    PermissionDenied(String),
    /// Exit 1 — an unexpected runtime failure.
    UnexpectedFailure(String),
    /// Exit 1 — could not acquire a lock on an account file.
    FileBusy(String),
    /// Exit 1 — an input line could not be used.
    InvalidInput(String),
    /// Exit 3 — the `--root` directory could not be entered.
    CantChroot(String),
}

impl fmt::Display for NewusersError {
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

impl std::error::Error for NewusersError {}

impl UError for NewusersError {
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
// Input
// ---------------------------------------------------------------------------

/// One input line: `name:password:uid:gid:gecos:home:shell`.
struct Line {
    name: String,
    password: zeroize::Zeroizing<String>,
    /// Empty means "allocate one".
    uid: String,
    /// Empty means "a group of the user's own"; otherwise a name or a number.
    gid: String,
    gecos: String,
    /// Empty means the account gets no home directory.
    home: String,
    shell: String,
    number: usize,
}

/// Split one line into its seven fields.
///
/// Exactly seven: six or eight are both "invalid line" to the GNU tool, and a
/// line that lost a field to a stray colon would otherwise be read as a
/// different account than the one intended.
fn parse_line(line: &str, number: usize) -> Result<Line, NewusersError> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() != FIELD_COUNT {
        return Err(NewusersError::InvalidInput(format!(
            "line {number}: invalid line"
        )));
    }
    Ok(Line {
        name: fields[0].to_string(),
        password: zeroize::Zeroizing::new(fields[1].to_string()),
        uid: fields[2].to_string(),
        gid: fields[3].to_string(),
        gecos: fields[4].to_string(),
        home: fields[5].to_string(),
        shell: fields[6].to_string(),
        number,
    })
}

/// Read every line from stdin.
///
/// Empty input succeeds having done nothing, which is what a script driving
/// this tool from a possibly-empty list depends on.
fn read_lines() -> Result<Vec<Line>, NewusersError> {
    let stdin = io::stdin();
    let mut lines = Vec::new();
    for (idx, line) in stdin.lock().lines().enumerate() {
        let line =
            zeroize::Zeroizing::new(line.map_err(|e| {
                NewusersError::UnexpectedFailure(format!("error reading stdin: {e}"))
            })?);
        lines.push(parse_line(&line, idx + 1)?);
    }
    Ok(lines)
}

/// Check every field that will reach an account file.
///
/// `relaxed` is `--badname`: it drops the portability rules on the login name
/// while keeping the checks that stop a name from corrupting the file, which
/// is what makes the flag safe to offer at all.
fn validate(line: &Line, relaxed: bool) -> Result<(), NewusersError> {
    let bad = |e: shadow_core::error::ShadowError| {
        NewusersError::InvalidInput(format!("line {}: {e}", line.number))
    };

    if relaxed {
        // A colon would add a field, a newline would add a record, and a name
        // starting with `-` is read as an option by everything downstream.
        // None of those is a matter of taste.
        shadow_core::validate::validate_field("username", &line.name).map_err(bad)?;
        if line.name.is_empty() || line.name.starts_with('-') {
            return Err(NewusersError::InvalidInput(format!(
                "line {}: invalid user name '{}'",
                line.number, line.name
            )));
        }
    } else {
        shadow_core::validate::validate_username(&line.name).map_err(bad)?;
    }

    shadow_core::validate::validate_field("GECOS", &line.gecos).map_err(bad)?;
    shadow_core::validate::validate_field("home directory", &line.home).map_err(bad)?;
    shadow_core::validate::validate_field("shell", &line.shell).map_err(bad)?;

    // An empty password would be hashed into something a bare Enter matches,
    // which is an account anyone can log into rather than one with no
    // password. GNU hands the empty field to PAM, which refuses it after the
    // account has already been created.
    if line.password.is_empty() {
        return Err(NewusersError::InvalidInput(format!(
            "line {}: no password supplied for '{}'",
            line.number, line.name
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 2)? else {
        return Ok(());
    };

    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        shadow_core::hardening::chroot_into(Path::new(chroot_dir))
            .map_err(|e| NewusersError::CantChroot(e.to_string()))?;
    }

    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root = SysRoot::new(prefix);

    if !shadow_core::hardening::caller_is_root() {
        return Err(
            NewusersError::PermissionDenied(shadow_core::os_error::permission_denied()).into(),
        );
    }

    let system = matches.get_flag(options::SYSTEM);
    let relaxed = matches.get_flag(options::BADNAME);
    let defs = LoginDefs::load(&root.login_defs_path()).unwrap_or_default();
    let method = resolve_crypt_method(
        matches
            .get_one::<String>(options::CRYPT_METHOD)
            .map(String::as_str),
        &defs,
    )?;

    let lines = read_lines()?;
    for line in &lines {
        validate(line, relaxed)?;
    }
    if lines.is_empty() {
        return Ok(());
    }

    apply(&root, &defs, &lines, system, method)
}

/// Build the clap `Command` for `newusers`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("newusers")
        .about("Create or update users in batch from stdin")
        .override_usage("newusers [options]")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::SYSTEM)
                .short('r')
                .long("system")
                .help("create system accounts")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::BADNAME)
                .short('b')
                .long("badname")
                .help("allow names that fail the portability rules")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::CRYPT_METHOD)
                .short('c')
                .long("crypt-method")
                .help("hashing scheme to apply (SHA256, SHA512, YESCRYPT)")
                .value_name("METHOD")
                .value_parser(["SHA256", "SHA512", "YESCRYPT", "DES", "MD5", "NONE"]),
        )
        .arg(
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .help("chroot into CHROOT_DIR before applying changes")
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
// Applying the batch
// ---------------------------------------------------------------------------

/// A home directory to create once the account files are safely written.
struct PendingHome {
    path: PathBuf,
    uid: u32,
    gid: u32,
}

/// Resolve and apply every line in one transaction.
fn apply(
    root: &SysRoot,
    defs: &LoginDefs,
    lines: &[Line],
    system: bool,
    method: shadow_core::crypt::CryptMethod,
) -> UResult<()> {
    // Hash before taking any lock: crypt(3) is deliberately slow, and a batch
    // of them would otherwise hold every account file, with signals blocked,
    // for the whole run.
    let mut hashes = Vec::with_capacity(lines.len());
    for line in lines {
        hashes.push(
            shadow_core::crypt::hash_password(&line.password, method, None).map_err(|e| {
                NewusersError::UnexpectedFailure(format!(
                    "line {}: cannot hash the password for '{}': {e}",
                    line.number, line.name
                ))
            })?,
        );
    }

    let scope = Scope::for_prefix(root.is_prefixed());
    let mut passwd = open::<PasswdEntry>(&root.passwd_path())?;
    let mut shadow = open::<ShadowEntry>(&root.shadow_path())?;
    let mut group = open::<GroupEntry>(&root.group_path())?;

    let today = shadow_core::shadow::days_since_epoch().map_err(|e| {
        NewusersError::UnexpectedFailure(format!("cannot determine the current date: {e}"))
    })?;
    let (uid_min, uid_max) = uid_alloc::uid_range(defs, system);
    let (gid_min, gid_max) = uid_alloc::gid_range(defs, system);

    let mut homes = Vec::new();

    for (line, hash) in lines.iter().zip(hashes) {
        let existing = passwd.entries().iter().position(|e| e.name == line.name);

        let uid = match (line.uid.as_str(), existing) {
            // An empty field on an existing account keeps the ID it has;
            // reallocating would orphan every file the account owns.
            ("", Some(i)) => passwd.entries()[i].uid,
            ("", None) => uid_alloc::next_uid(passwd.entries(), uid_min, uid_max, scope)
                .map_err(|e| line_error(line, &e.to_string()))?,
            (given, _) => parse_id(given)
                .ok_or_else(|| line_error(line, &format!("invalid user ID '{given}'")))?,
        };

        let gid = resolve_gid(&mut group, line, uid, gid_min, gid_max, scope)?;

        match existing {
            Some(i) => {
                let entry = &mut passwd.entries_mut()[i];
                entry.uid = uid;
                entry.gid = gid;
                entry.gecos.clone_from(&line.gecos);
                entry.home.clone_from(&line.home);
                entry.shell.clone_from(&line.shell);
            }
            None => passwd.entries_mut().push(PasswdEntry {
                name: line.name.clone(),
                passwd: "x".to_string(),
                uid,
                gid,
                gecos: line.gecos.clone(),
                home: line.home.clone(),
                shell: line.shell.clone(),
            }),
        }

        set_shadow(&mut shadow, &line.name, hash, today, defs);

        if !line.home.is_empty() {
            homes.push(PendingHome {
                path: root.resolve(&line.home),
                uid,
                gid,
            });
        }
    }

    // Every file is validated before any is written, so a value that would
    // corrupt one cannot leave the set disagreeing.
    let files: Vec<Box<dyn Commit>> = vec![Box::new(passwd), Box::new(shadow), Box::new(group)];
    transaction::commit_all(files)
        .map_err(|e| NewusersError::UnexpectedFailure(format!("cannot write: {e}")))?;

    shadow_core::nscd::invalidate_cache("passwd");
    shadow_core::nscd::invalidate_cache("group");

    // Homes come after the commit. A home that cannot be created is worth
    // reporting, but the accounts are already correct and rolling them back
    // would be a bigger surprise than a missing directory.
    create_homes(root, &homes)?;

    for line in lines {
        shadow_core::audit::log_user_event("ADD_USER", &line.name, 0, true);
    }

    Ok(())
}

/// Wrap a message with the line it came from.
fn line_error(line: &Line, message: &str) -> NewusersError {
    NewusersError::InvalidInput(format!("line {}: {message}", line.number))
}

/// A field that must be a plain unsigned number, with no sign or padding.
fn parse_id(value: &str) -> Option<u32> {
    if value.chars().all(|c| c.is_ascii_digit()) && !value.is_empty() {
        value.parse().ok()
    } else {
        None
    }
}

/// Work out the group for one line, creating it where the field asks for one
/// that does not exist yet.
fn resolve_gid(
    group: &mut LockedFile<GroupEntry>,
    line: &Line,
    uid: u32,
    gid_min: u32,
    gid_max: u32,
    scope: Scope,
) -> Result<u32, NewusersError> {
    // A number names a group directly. If no group has it, one is created
    // carrying the user's name -- otherwise the account would be left pointing
    // at a group that does not exist, which is what the GNU tool does here and
    // what grpck then reports.
    if let Some(gid) = parse_id(&line.gid) {
        if !group.entries().iter().any(|g| g.gid == gid) {
            push_group(group, &line.name, gid);
        }
        return Ok(gid);
    }

    // A name must already exist. GNU silently falls back to the user's own ID
    // and leaves no group behind at all, so the account ends up with a
    // dangling GID; naming a group that is not there is a mistake worth
    // reporting rather than papering over.
    if !line.gid.is_empty() {
        return match group.entries().iter().find(|g| g.name == line.gid) {
            Some(found) => Ok(found.gid),
            None => Err(line_error(
                line,
                &format!("group '{}' does not exist", line.gid),
            )),
        };
    }

    // An empty field asks for a group of the user's own. Reuse it if a group
    // of that name is already there, so a second run over the same input does
    // not fail.
    if let Some(found) = group.entries().iter().find(|g| g.name == line.name) {
        return Ok(found.gid);
    }
    // Matching the UID keeps user-private groups readable at a glance, which
    // is the convention every distribution follows; falling back to the
    // allocator when it is taken keeps that a preference, not a requirement.
    let gid = if group.entries().iter().any(|g| g.gid == uid) {
        uid_alloc::next_gid(group.entries(), gid_min, gid_max, scope)
            .map_err(|e| line_error(line, &e.to_string()))?
    } else {
        uid
    };
    push_group(group, &line.name, gid);
    Ok(gid)
}

/// Add a group with no members: the user's primary group is recorded in
/// `/etc/passwd`, not in the member list.
fn push_group(group: &mut LockedFile<GroupEntry>, name: &str, gid: u32) {
    group.entries_mut().push(GroupEntry {
        name: name.to_string(),
        passwd: "x".to_string(),
        gid,
        members: Vec::new(),
    });
}

/// Write the account's hash and aging fields.
fn set_shadow(
    shadow: &mut LockedFile<ShadowEntry>,
    name: &str,
    hash: String,
    today: i64,
    defs: &LoginDefs,
) {
    if let Some(entry) = shadow.entries_mut().iter_mut().find(|e| e.name == name) {
        entry.passwd = hash;
        entry.last_change = Some(today);
        return;
    }
    shadow.entries_mut().push(ShadowEntry {
        name: name.to_string(),
        passwd: hash,
        last_change: Some(today),
        min_age: defs.get_i64("PASS_MIN_DAYS"),
        max_age: defs.get_i64("PASS_MAX_DAYS"),
        warn_days: defs.get_i64("PASS_WARN_AGE"),
        inactive_days: None,
        expire_date: None,
        reserved: String::new(),
    });
}

/// Create the home directories the batch asked for.
fn create_homes(root: &SysRoot, homes: &[PendingHome]) -> UResult<()> {
    if homes.is_empty() {
        return Ok(());
    }
    let skel = root.skel_path();
    for home in homes {
        let outcome = shadow_core::home::create(&home.path, &skel, home.uid, home.gid, HOME_MODE)
            .map_err(|e| NewusersError::UnexpectedFailure(e.to_string()))?;
        if outcome == shadow_core::home::Outcome::AlreadyExisted {
            uucore::show_warning!(
                "home directory '{}' already exists -- not copying from skel directory",
                home.path.display()
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Lock and read an account file, mapping contention to its own error.
fn open<T>(path: &Path) -> Result<LockedFile<T>, NewusersError>
where
    T: transaction::Record,
{
    LockedFile::<T>::open_or_empty(path).map_err(|e| match e {
        shadow_core::error::ShadowError::Lock(_) => {
            NewusersError::FileBusy(format!("cannot lock {}: try again later", path.display()))
        }
        other => {
            NewusersError::UnexpectedFailure(format!("cannot open {}: {other}", path.display()))
        }
    })
}

/// The hashing scheme, from `-c` or the system's configuration.
fn resolve_crypt_method(
    method: Option<&str>,
    defs: &LoginDefs,
) -> Result<shadow_core::crypt::CryptMethod, NewusersError> {
    match method {
        Some(name) => parse_crypt_method(name).ok_or_else(|| {
            NewusersError::UnexpectedFailure(match name {
                "NONE" => "NONE would store the password unhashed and is not supported".into(),
                "MD5" | "DES" => "MD5 and DES are insecure and not supported".into(),
                other => format!("unknown crypt method: {other}"),
            })
        }),
        None => Ok(defs
            .get("ENCRYPT_METHOD")
            .and_then(parse_crypt_method)
            .unwrap_or(shadow_core::crypt::CryptMethod::Sha512)),
    }
}

/// Map a scheme name to a `CryptMethod`, refusing the ones this build will not
/// write.
fn parse_crypt_method(name: &str) -> Option<shadow_core::crypt::CryptMethod> {
    use shadow_core::crypt::CryptMethod;

    match name {
        "SHA256" => Some(CryptMethod::Sha256),
        "SHA512" => Some(CryptMethod::Sha512),
        "YESCRYPT" => Some(CryptMethod::Yescrypt),
        _ => None,
    }
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

    #[test]
    fn test_parse_line_takes_seven_fields() {
        let line = parse_line("alice:pw:1000:1000:Alice:/home/alice:/bin/sh", 1).expect("parses");
        assert_eq!(line.name, "alice");
        assert_eq!(&*line.password, "pw");
        assert_eq!(line.uid, "1000");
        assert_eq!(line.gid, "1000");
        assert_eq!(line.gecos, "Alice");
        assert_eq!(line.home, "/home/alice");
        assert_eq!(line.shell, "/bin/sh");
    }

    /// Six fields or eight are both wrong. A line that lost one to a stray
    /// colon would otherwise describe a different account than intended.
    #[test]
    fn test_wrong_field_count_is_refused() {
        for bad in [
            "alice:pw:1000",
            "alice:pw:1000:1000:Alice:/home/alice",
            "alice:pw:1000:1000:Alice:/home/alice:/bin/sh:extra",
            "",
            "alice",
        ] {
            let err = parse_line(bad, 3).err().expect("should be refused");
            assert!(
                format!("{err}").contains("line 3: invalid line"),
                "unexpected message for {bad:?}: {err}"
            );
        }
    }

    /// Every field may be empty except the count of them.
    #[test]
    fn test_all_optional_fields_may_be_empty() {
        let line = parse_line("alice:pw:::::", 1).expect("parses");
        assert_eq!(line.name, "alice");
        assert!(line.uid.is_empty());
        assert!(line.gid.is_empty());
        assert!(line.home.is_empty());
    }

    fn line(spec: &str) -> Line {
        parse_line(spec, 1).expect("parses")
    }

    /// An empty password would be hashed into something a bare Enter matches.
    #[test]
    fn test_empty_password_is_refused() {
        let err = validate(&line("alice::1000:1000:::"), false).expect_err("refused");
        assert!(format!("{err}").contains("no password supplied"), "{err}");
    }

    /// A field carrying a colon or a newline would add a field or a record.
    #[test]
    fn test_fields_that_would_corrupt_the_file_are_refused() {
        assert!(validate(&line("alice:pw:1000:1000:a\nb:/h:/bin/sh"), false).is_err());
        assert!(validate(&line("alice:pw:1000:1000::/h:/bin/sh"), false).is_ok());
    }

    /// `--badname` drops the portability rules but keeps the ones that stop a
    /// name from corrupting the file or being read as an option.
    #[test]
    fn test_badname_relaxes_only_the_portability_rules() {
        // Both are refused by the portability rules and both turn up on real
        // systems: a name starting with a digit, and the domain-qualified form
        // an Active Directory join produces. Neither can corrupt a file.
        for odd in ["3dprint:pw:1000:1000:::", "alice@corp:pw:1000:1000:::"] {
            assert!(
                validate(&line(odd), false).is_err(),
                "the strict rules should refuse {odd:?}"
            );
            assert!(
                validate(&line(odd), true).is_ok(),
                "--badname should allow {odd:?}"
            );
        }

        for hostile in ["-flag:pw:1000:1000:::", ":pw:1000:1000:::"] {
            assert!(
                validate(&line(hostile), true).is_err(),
                "--badname must not allow {hostile:?}"
            );
        }
    }

    /// IDs are plain numbers: a sign or a trailing letter is a typo, and
    /// silently taking the leading digits would create the wrong account.
    #[test]
    fn test_parse_id() {
        assert_eq!(parse_id("1000"), Some(1000));
        assert_eq!(parse_id("0"), Some(0));
        for bad in ["", "-1", "+1", "10x", " 10", "1 0", "99999999999999"] {
            assert_eq!(parse_id(bad), None, "{bad:?} should not parse");
        }
    }

    #[test]
    fn test_crypt_methods_that_are_refused() {
        let defs = LoginDefs::default();
        for bad in ["NONE", "MD5", "DES", "BCRYPT"] {
            assert!(resolve_crypt_method(Some(bad), &defs).is_err(), "{bad}");
        }
        assert!(resolve_crypt_method(Some("SHA512"), &defs).is_ok());
        // No -c and no configuration falls back rather than failing.
        assert!(resolve_crypt_method(None, &defs).is_ok());
    }

    #[test]
    fn test_exit_codes() {
        use uucore::error::UError;

        assert_eq!(NewusersError::PermissionDenied("x".into()).code(), 1);
        assert_eq!(NewusersError::UnexpectedFailure("x".into()).code(), 1);
        assert_eq!(NewusersError::FileBusy("x".into()).code(), 1);
        assert_eq!(NewusersError::InvalidInput("x".into()).code(), 1);
        assert_eq!(NewusersError::CantChroot("x".into()).code(), 3);
    }
}
