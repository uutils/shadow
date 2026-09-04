// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore gecos chroot seteuid sigprocmask

//! `chfn` — change user finger (GECOS) information.
//!
//! Drop-in replacement for GNU shadow-utils `chfn(1)`.
//! Modifies the GECOS field of `/etc/passwd`.

use std::fmt;

use clap::{Arg, ArgAction, Command};

use shadow_core::lock::FileLock;
use shadow_core::passwd::{self, PasswdEntry};
use shadow_core::sysroot::SysRoot;
use shadow_core::{atomic, nscd};

use uucore::error::{UError, UResult};

mod options {
    pub const USER: &str = "user";
    pub const FULL_NAME: &str = "full-name";
    pub const ROOM: &str = "room";
    pub const WORK_PHONE: &str = "work-phone";
    pub const HOME_PHONE: &str = "home-phone";
    pub const OTHER: &str = "other";
    pub const ROOT: &str = "root";
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ChfnError {
    /// Exit 1 — insufficient privileges or general error.
    Error(String),
}

impl fmt::Display for ChfnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ChfnError {}

impl UError for ChfnError {
    fn code(&self) -> i32 {
        match self {
            Self::Error(_) => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// GECOS field handling
// ---------------------------------------------------------------------------

/// Parsed GECOS sub-fields. The GECOS field format is:
/// `Full Name,Room,Work Phone,Home Phone,Other`
struct Gecos {
    full_name: String,
    room: String,
    work_phone: String,
    home_phone: String,
    other: String,
}

impl Gecos {
    /// Parse a GECOS string into sub-fields.
    fn parse(gecos: &str) -> Self {
        let mut parts = gecos.splitn(5, ',');
        Self {
            full_name: parts.next().unwrap_or_default().to_string(),
            room: parts.next().unwrap_or_default().to_string(),
            work_phone: parts.next().unwrap_or_default().to_string(),
            home_phone: parts.next().unwrap_or_default().to_string(),
            other: parts.next().unwrap_or_default().to_string(),
        }
    }

    /// Serialize back to a GECOS string.
    fn to_gecos_string(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.full_name, self.room, self.work_phone, self.home_phone, self.other
        )
    }
}

// ---------------------------------------------------------------------------
// Security hardening
// ---------------------------------------------------------------------------

// Hardening functions are now centralized in shadow_core::hardening.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the target username from args or current user.
fn resolve_target_user(matches: &clap::ArgMatches) -> Result<String, ChfnError> {
    if let Some(user) = matches.get_one::<String>(options::USER) {
        return Ok(user.clone());
    }
    shadow_core::hardening::current_username().map_err(|e| ChfnError::Error(e.to_string()))
}

/// Validate a GECOS sub-field. Colons, newlines and other control characters
/// are forbidden everywhere (they would break the record); commas and equal
/// signs are additionally forbidden in every field except "other", the last
/// sub-field (chfn(1): the other fields "should not contain any comma or equal
/// sign"). `allow_comma` is true only for the "other" field.
fn validate_gecos_field(value: &str, field_name: &str, allow_comma: bool) -> Result<(), ChfnError> {
    shadow_core::validate::validate_field(field_name, value)
        .map_err(|e| ChfnError::Error(e.to_string()))?;
    if !allow_comma && (value.contains(',') || value.contains('=')) {
        return Err(ChfnError::Error(format!(
            "{field_name}: must not contain ',' or '='"
        )));
    }
    Ok(())
}

/// The GECOS fields a non-root caller may change, from `CHFN_RESTRICT` in
/// login.defs. `yes` means `rwh`; an explicit letter set is taken verbatim;
/// unset (or unreadable) means none — chfn(1)/login.defs(5): "If not
/// specified, only the superuser can make any changes." Letters: `f` full
/// name, `r` room, `w` work phone, `h` home phone.
fn chfn_restrict(root: &SysRoot) -> String {
    shadow_core::login_defs::LoginDefs::load(&root.login_defs_path())
        .ok()
        .map_or_else(String::new, |d| match d.get("CHFN_RESTRICT") {
            Some("yes") => "rwh".to_string(),
            Some(set) => set.to_string(),
            None => String::new(),
        })
}

/// Perform `chroot(2)` into the specified directory.
fn do_chroot(dir: &str) -> Result<(), ChfnError> {
    if !shadow_core::hardening::caller_is_root() {
        return Err(ChfnError::Error("only root may use --root".into()));
    }

    let path = std::path::Path::new(dir);
    rustix::process::chroot(path)
        .map_err(|e| ChfnError::Error(format!("cannot chroot to '{dir}': {e}")))?;

    rustix::process::chdir("/")
        .map_err(|e| ChfnError::Error(format!("cannot chdir to / after chroot: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Atomic passwd mutation
// ---------------------------------------------------------------------------

/// Lock the passwd file, read entries, apply a mutation to one user's entry,
/// write back atomically, invalidate nscd cache.
fn mutate_passwd<F>(root: &SysRoot, username: &str, mutate: F) -> UResult<()>
where
    F: FnOnce(&mut PasswdEntry) -> Result<(), String>,
{
    // Consolidate real + effective UID to root for file operations.
    if rustix::process::geteuid().is_root() {
        let _ = shadow_core::process::setuid(0);
    }

    let _signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| ChfnError::Error(e.to_string()))?;

    let passwd_path = root.passwd_path();

    let lock = FileLock::acquire(&passwd_path).map_err(|_| {
        ChfnError::Error(format!(
            "cannot lock {}: try again later",
            passwd_path.display()
        ))
    })?;

    let (mut entries, layout) = match passwd::read_passwd_with_layout(&passwd_path) {
        Ok(e) => e,
        Err(e) => {
            drop(lock);
            return Err(
                ChfnError::Error(format!("cannot read {}: {e}", passwd_path.display())).into(),
            );
        }
    };

    let Some(entry) = entries.iter_mut().find(|e| e.name == username) else {
        drop(lock);
        return Err(ChfnError::Error(format!(
            "user '{username}' does not exist in {}",
            passwd_path.display()
        ))
        .into());
    };

    if let Err(msg) = mutate(entry) {
        drop(lock);
        return Err(ChfnError::Error(msg).into());
    }

    let write_result = atomic::atomic_write(&passwd_path, |file| {
        passwd::write_passwd_with_layout(&entries, &layout, file)?;
        Ok(())
    });

    if let Err(e) = write_result {
        drop(lock);
        return Err(
            ChfnError::Error(format!("failed to write {}: {e}", passwd_path.display())).into(),
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

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 1)? else {
        return Ok(());
    };

    // Handle --root / -R: chroot before anything else.
    if let Some(chroot_dir) = matches.get_one::<String>(options::ROOT) {
        do_chroot(chroot_dir)?;
    }

    let root = SysRoot::default();

    let target_user = resolve_target_user(&matches)?;

    // Non-root users can only change their own info, and must prove they are
    // who they claim before anything is written.
    if !shadow_core::hardening::caller_is_root() {
        let current_user = shadow_core::hardening::current_username()
            .map_err(|e| ChfnError::Error(e.to_string()))?;
        if current_user != target_user {
            return Err(
                ChfnError::Error("you may only change your own finger information".into()).into(),
            );
        }
        authenticate_caller(&current_user)?;
    }

    // At least one field flag must be present (we require flags, no interactive mode).
    let has_full_name = matches.contains_id(options::FULL_NAME);
    let has_room = matches.contains_id(options::ROOM);
    let has_work_phone = matches.contains_id(options::WORK_PHONE);
    let has_home_phone = matches.contains_id(options::HOME_PHONE);
    let has_other = matches.contains_id(options::OTHER);

    if !has_full_name && !has_room && !has_work_phone && !has_home_phone && !has_other {
        return Err(ChfnError::Error(
            "no flags specified; use -f, -r, -w, -h, or -o to change finger information".into(),
        )
        .into());
    }

    // Collect and validate the new values.
    let new_full_name = matches.get_one::<String>(options::FULL_NAME);
    let new_room = matches.get_one::<String>(options::ROOM);
    let new_work_phone = matches.get_one::<String>(options::WORK_PHONE);
    let new_home_phone = matches.get_one::<String>(options::HOME_PHONE);
    let new_other = matches.get_one::<String>(options::OTHER);

    // Validate sub-fields before acquiring the lock.
    if let Some(v) = new_full_name {
        validate_gecos_field(v, "full name", false)?;
    }
    if let Some(v) = new_room {
        validate_gecos_field(v, "room number", false)?;
    }
    if let Some(v) = new_work_phone {
        validate_gecos_field(v, "work phone", false)?;
    }
    if let Some(v) = new_home_phone {
        validate_gecos_field(v, "home phone", false)?;
    }
    if let Some(v) = new_other {
        validate_gecos_field(v, "other", true)?;
    }

    // Non-root users may not set the "other" field, and may change the rest
    // only within CHFN_RESTRICT (login.defs). Root is unrestricted.
    if !shadow_core::hardening::caller_is_root() {
        if new_other.is_some() {
            return Err(ChfnError::Error("only root may change the 'other' field".into()).into());
        }
        let allowed = chfn_restrict(&root);
        for (present, letter, name) in [
            (has_full_name, 'f', "full name"),
            (has_room, 'r', "room number"),
            (has_work_phone, 'w', "work phone"),
            (has_home_phone, 'h', "home phone"),
        ] {
            if present && !allowed.contains(letter) {
                return Err(ChfnError::Error(format!(
                    "you may not change the {name} (restricted by CHFN_RESTRICT)"
                ))
                .into());
            }
        }
    }

    mutate_passwd(&root, &target_user, |entry| {
        let mut gecos = Gecos::parse(&entry.gecos);

        if let Some(v) = new_full_name {
            gecos.full_name.clone_from(v);
        }
        if let Some(v) = new_room {
            gecos.room.clone_from(v);
        }
        if let Some(v) = new_work_phone {
            gecos.work_phone.clone_from(v);
        }
        if let Some(v) = new_home_phone {
            gecos.home_phone.clone_from(v);
        }
        if let Some(v) = new_other {
            gecos.other.clone_from(v);
        }

        entry.gecos = gecos.to_gecos_string();
        Ok(())
    })?;

    uucore::show_error!("changed user '{target_user}' information");
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
/// Distributions ship a PAM service for this (`/etc/pam.d/chfn`), where
/// `pam_rootok` lets root through and `common-auth` prompts everyone else.
///
/// Privileges are dropped to the real UID for the conversation so PAM modules
/// see the actual caller, and restored when the guard falls out of scope.
#[cfg(feature = "pam")]
fn authenticate_caller(user: &str) -> Result<(), ChfnError> {
    use shadow_core::pam::{ConvMode, PamContext};

    let mut pam = PamContext::new("chfn", user, ConvMode::Tty)
        .map_err(|e| ChfnError::Error(e.to_string()))?;

    let _priv_drop = shadow_core::process::PrivDrop::drop_to(rustix::process::getuid().as_raw())
        .map_err(|e| ChfnError::Error(format!("cannot drop privileges: {e}")))?;

    pam.authenticate(0)
        .map_err(|e| ChfnError::Error(e.to_string()))?;
    pam.acct_mgmt(0)
        .map_err(|e| ChfnError::Error(e.to_string()))?;
    Ok(())
}

/// Without PAM there is no way to verify the caller, so refuse rather than
/// silently applying an unauthenticated change to a setuid-root tool.
#[cfg(not(feature = "pam"))]
fn authenticate_caller(_user: &str) -> Result<(), ChfnError> {
    Err(ChfnError::Error(
        "PAM support is not compiled in — cannot authenticate; run as root".into(),
    ))
}

/// Build the clap `Command` for `chfn`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("chfn")
        .about("Edit a user's GECOS (finger) fields")
        .override_usage("chfn [options] [LOGIN]")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .disable_help_flag(true)
        .arg(
            Arg::new("help")
                .long("help")
                .help("display this help message and exit")
                .action(ArgAction::Help),
        )
        .arg(
            Arg::new(options::FULL_NAME)
                .short('f')
                .long("full-name")
                .help("set the user's full name")
                .value_name("FULL_NAME"),
        )
        .arg(
            Arg::new(options::ROOM)
                .short('r')
                .long("room")
                .help("set the user's room number")
                .value_name("ROOM"),
        )
        .arg(
            Arg::new(options::WORK_PHONE)
                .short('w')
                .long("work-phone")
                .help("set the user's work phone")
                .value_name("WORK_PHONE"),
        )
        .arg(
            Arg::new(options::HOME_PHONE)
                .short('h')
                .long("home-phone")
                .help("set the user's home phone")
                .value_name("HOME_PHONE"),
        )
        .arg(
            Arg::new(options::OTHER)
                .short('o')
                .long("other")
                .help("set the trailing GECOS field")
                .value_name("OTHER"),
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
                .help("User whose GECOS fields to edit")
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
    // GECOS parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gecos_parse_full() {
        let g = Gecos::parse("John Doe,Room 101,555-1234,555-5678,extra info");
        assert_eq!(g.full_name, "John Doe");
        assert_eq!(g.room, "Room 101");
        assert_eq!(g.work_phone, "555-1234");
        assert_eq!(g.home_phone, "555-5678");
        assert_eq!(g.other, "extra info");
    }

    #[test]
    fn test_gecos_parse_partial() {
        let g = Gecos::parse("John Doe");
        assert_eq!(g.full_name, "John Doe");
        assert_eq!(g.room, "");
        assert_eq!(g.work_phone, "");
        assert_eq!(g.home_phone, "");
        assert_eq!(g.other, "");
    }

    #[test]
    fn test_gecos_parse_empty() {
        let g = Gecos::parse("");
        assert_eq!(g.full_name, "");
        assert_eq!(g.to_gecos_string(), ",,,,");
    }

    #[test]
    fn test_gecos_roundtrip() {
        let original = "John Doe,Room 101,555-1234,555-5678,extra info";
        let g = Gecos::parse(original);
        assert_eq!(g.to_gecos_string(), original);
    }

    #[test]
    fn test_gecos_partial_update() {
        let mut g = Gecos::parse("John Doe,Room 101,555-1234,555-5678,");
        g.full_name = "Jane Doe".to_string();
        assert_eq!(g.to_gecos_string(), "Jane Doe,Room 101,555-1234,555-5678,");
    }

    // -----------------------------------------------------------------------
    // Validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_gecos_field_rejects_colon() {
        assert!(validate_gecos_field("foo:bar", "test", false).is_err());
    }

    #[test]
    fn test_validate_gecos_field_rejects_newline() {
        assert!(validate_gecos_field("foo\nbar", "test", false).is_err());
    }

    #[test]
    fn test_validate_gecos_field_rejects_null() {
        assert!(validate_gecos_field("foo\0bar", "test", false).is_err());
    }

    #[test]
    fn test_validate_gecos_field_rejects_comma_when_not_allowed() {
        assert!(validate_gecos_field("foo,bar", "test", false).is_err());
    }

    #[test]
    fn test_validate_gecos_field_allows_comma_when_allowed() {
        assert!(validate_gecos_field("foo,bar", "test", true).is_ok());
    }

    #[test]
    fn test_validate_gecos_field_accepts_normal() {
        assert!(validate_gecos_field("John Doe", "test", false).is_ok());
    }

    #[test]
    fn test_validate_gecos_field_rejects_equal_sign() {
        assert!(validate_gecos_field("a=b", "test", false).is_err());
        // The trailing "other" field may contain '=' and ','.
        assert!(validate_gecos_field("a=b,c", "other", true).is_ok());
    }

    #[test]
    fn test_validate_gecos_field_rejects_control_char() {
        assert!(validate_gecos_field("foo\tbar", "test", false).is_err());
        assert!(validate_gecos_field("foo\x1bbar", "test", true).is_err());
    }

    #[test]
    fn test_chfn_restrict_reading() {
        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("etc");
        let root = SysRoot::new(Some(dir.path()));

        std::fs::write(etc.join("login.defs"), "CHFN_RESTRICT rwh\n").unwrap();
        assert_eq!(chfn_restrict(&root), "rwh");

        std::fs::write(etc.join("login.defs"), "CHFN_RESTRICT yes\n").unwrap();
        assert_eq!(chfn_restrict(&root), "rwh");

        std::fs::write(etc.join("login.defs"), "UID_MIN 1000\n").unwrap();
        assert_eq!(chfn_restrict(&root), "", "unset means nothing for non-root");
    }

    // -----------------------------------------------------------------------
    // Clap validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_help_does_not_error() {
        let result = uu_app().try_get_matches_from(["chfn", "--help"]);
        // --help causes a DisplayHelp error in clap, which is not a usage error
        assert!(result.is_err());
        let err = result.expect_err("expected error");
        assert!(!err.use_stderr());
    }

    #[test]
    fn test_no_flags_parses_ok() {
        // clap itself does not reject this — our uumain logic does
        let result = uu_app().try_get_matches_from(["chfn"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_full_name_flag_parses() {
        let matches = uu_app()
            .try_get_matches_from(["chfn", "-f", "New Name"])
            .expect("should parse");
        assert_eq!(
            matches
                .get_one::<String>(options::FULL_NAME)
                .map(String::as_str),
            Some("New Name")
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
