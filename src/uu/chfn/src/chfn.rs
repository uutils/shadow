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
use std::io::Write as _;

use clap::{Arg, ArgAction, Command};

use shadow_core::nscd;
use shadow_core::passwd::{self, PasswdEntry};
use shadow_core::sysroot::SysRoot;
use shadow_core::transaction::LockedFile;

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

    /// The four sub-fields `CHFN_RESTRICT` governs, in `FIELDS` order.
    fn restrictable(&self) -> [&str; 4] {
        [
            &self.full_name,
            &self.room,
            &self.work_phone,
            &self.home_phone,
        ]
    }

    /// Serialize back to a GECOS string.
    fn to_gecos_string(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.full_name, self.room, self.work_phone, self.home_phone, self.other
        )
    }
}

/// The GECOS fields a non-root caller may be allowed to change: the
/// `CHFN_RESTRICT` letter that governs each, the name used in diagnostics, and
/// the label chfn(1) prints when prompting. The last sub-field ("other") is
/// root-only in every configuration and so is not listed here.
const FIELDS: [(char, &str, &str); 4] = [
    ('f', "full name", "Full Name"),
    ('r', "room number", "Room Number"),
    ('w', "work phone", "Work Phone"),
    ('h', "home phone", "Home Phone"),
];

/// The sub-fields this run changes. `None` leaves a sub-field as it is, which
/// is what both an omitted option and an empty answer at a prompt mean.
struct Changes {
    /// The restrictable fields, in `FIELDS` order.
    fields: [Option<String>; 4],
    /// The last sub-field, which only root may set.
    other: Option<String>,
}

impl Changes {
    /// Read the requested changes from the command line or, when no field
    /// option is given, by prompting -- chfn(1) then "prompts the user with
    /// the current values for all of the fields". `allowed` is `None` for root
    /// and otherwise the `CHFN_RESTRICT` letter set: a field the caller may not
    /// change is never prompted for, rather than prompted for and then refused.
    fn collect(
        matches: &clap::ArgMatches,
        root: &SysRoot,
        user: &str,
        allowed: Option<&str>,
    ) -> Result<Self, ChfnError> {
        let names = [
            options::FULL_NAME,
            options::ROOM,
            options::WORK_PHONE,
            options::HOME_PHONE,
        ];
        let fields = names.map(|name| matches.get_one::<String>(name).cloned());
        let other = matches.get_one::<String>(options::OTHER).cloned();

        if fields.iter().any(Option::is_some) || other.is_some() {
            return Ok(Self { fields, other });
        }

        if let Some(set) = allowed
            && !FIELDS.iter().any(|(letter, _, _)| set.contains(*letter))
        {
            return Err(ChfnError::Error(
                "you may not change any of your finger information (restricted by CHFN_RESTRICT)"
                    .into(),
            ));
        }

        let current = current_gecos(root, user)?;
        let _ = writeln!(
            std::io::stderr(),
            "Changing the user information for {user}\nEnter the new value, or press ENTER for the default"
        );

        let mut fields: [Option<String>; 4] = Self::default_fields();
        for (i, ((letter, _, label), value)) in
            FIELDS.iter().zip(current.restrictable()).enumerate()
        {
            if allowed.is_some_and(|set| !set.contains(*letter)) {
                continue;
            }
            fields[i] = prompt_field(label, value)?;
        }

        Ok(Self {
            fields,
            other: None,
        })
    }

    /// An all-`None` field array; `[None; 4]` needs `Copy`, which `String` is not.
    fn default_fields() -> [Option<String>; 4] {
        [const { None }; 4]
    }

    /// Whether there is nothing to write.
    fn is_empty(&self) -> bool {
        self.fields.iter().all(Option::is_none) && self.other.is_none()
    }

    /// Reject values that would corrupt the record, before any lock is taken
    /// and before the caller is asked for a password.
    fn validate(&self) -> Result<(), ChfnError> {
        for (value, (_, name, _)) in self.fields.iter().zip(FIELDS) {
            if let Some(v) = value {
                validate_gecos_field(v, name, false)?;
            }
        }
        if let Some(v) = &self.other {
            validate_gecos_field(v, "other", true)?;
        }
        Ok(())
    }

    /// Enforce `CHFN_RESTRICT` on a non-root caller.
    fn check_permitted(&self, allowed: &str) -> Result<(), ChfnError> {
        if self.other.is_some() {
            return Err(ChfnError::Error(
                "only root may change the 'other' field".into(),
            ));
        }
        for (value, (letter, name, _)) in self.fields.iter().zip(FIELDS) {
            if value.is_some() && !allowed.contains(letter) {
                return Err(ChfnError::Error(format!(
                    "you may not change the {name} (restricted by CHFN_RESTRICT)"
                )));
            }
        }
        Ok(())
    }

    /// Overwrite the sub-fields this run changes, leaving the others alone.
    fn apply(&self, gecos: &mut Gecos) {
        let targets = [
            &mut gecos.full_name,
            &mut gecos.room,
            &mut gecos.work_phone,
            &mut gecos.home_phone,
        ];
        for (target, value) in targets.into_iter().zip(&self.fields) {
            if let Some(v) = value {
                target.clone_from(v);
            }
        }
        if let Some(v) = &self.other {
            gecos.other.clone_from(v);
        }
    }
}

// ---------------------------------------------------------------------------
// Security hardening
// ---------------------------------------------------------------------------

// Hardening functions are now centralized in shadow_core::hardening.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The account's current GECOS sub-fields, for the interactive prompts.
fn current_gecos(root: &SysRoot, user: &str) -> Result<Gecos, ChfnError> {
    let entries = passwd::read_passwd_file(&root.passwd_path())
        .map_err(|e| ChfnError::Error(format!("cannot read passwd: {e}")))?;
    entries
        .iter()
        .find(|e| e.name == user)
        .map(|e| Gecos::parse(&e.gecos))
        .ok_or_else(|| ChfnError::Error(format!("user '{user}' does not exist")))
}

/// Prompt for one field, showing its current value; an empty answer keeps it.
fn prompt_field(label: &str, current: &str) -> Result<Option<String>, ChfnError> {
    let answer = shadow_core::tty::prompt_line(&format!("\t{label} [{current}]: "))
        .map_err(|e| ChfnError::Error(format!("cannot read from the terminal: {e}")))?;
    if answer.is_empty() {
        Ok(None)
    } else {
        Ok(Some(answer))
    }
}

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

// ---------------------------------------------------------------------------
// Atomic passwd mutation
// ---------------------------------------------------------------------------

/// Lock the passwd file, read entries, apply a mutation to one user's entry,
/// write back atomically, invalidate nscd cache.
fn mutate_passwd<F>(root: &SysRoot, username: &str, mutate: F) -> UResult<()>
where
    F: FnOnce(&mut PasswdEntry) -> Result<(), String>,
{
    // euid 0 is all the lock and the atomic write need. Calling setuid(0)
    // here would also change the *real* uid, after which caller_is_root() --
    // which is deliberately real-uid based -- would answer true for everyone.
    let passwd_path = root.passwd_path();

    // The transaction locks, then reads, and releases on every path out --
    // including the two error returns below, where the file is left untouched.
    let mut passwd = LockedFile::<PasswdEntry>::open(&passwd_path)
        .map_err(|e| ChfnError::Error(format!("cannot open {}: {e}", passwd_path.display())))?;

    let Some(entry) = passwd.find_mut(username) else {
        return Err(ChfnError::Error(format!(
            "user '{username}' does not exist in {}",
            passwd_path.display()
        ))
        .into());
    };
    mutate(entry).map_err(ChfnError::Error)?;

    passwd
        .commit()
        .map_err(|e| ChfnError::Error(format!("failed to write {}: {e}", passwd_path.display())))?;

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
        shadow_core::hardening::chroot_into(std::path::Path::new(chroot_dir))
            .map_err(|e| ChfnError::Error(e.to_string()))?;
    }

    let root = SysRoot::default();

    let target_user = resolve_target_user(&matches)?;

    // A non-root caller may only change their own information, and only the
    // fields CHFN_RESTRICT lists. The identity check comes first;
    // authentication is deferred until the change is known to be valid and
    // permitted, so nobody types a password only to have the value refused.
    let caller = if shadow_core::hardening::caller_is_root() {
        None
    } else {
        let user = shadow_core::hardening::current_username()
            .map_err(|e| ChfnError::Error(e.to_string()))?;
        if user != target_user {
            return Err(
                ChfnError::Error("you may only change your own finger information".into()).into(),
            );
        }
        Some(user)
    };
    let allowed = caller.as_ref().map(|_| chfn_restrict(&root));

    let changes = Changes::collect(&matches, &root, &target_user, allowed.as_deref())?;
    if changes.is_empty() {
        // Every prompt was answered with ENTER: nothing to do, and nothing to
        // report as an error.
        return Ok(());
    }
    changes.validate()?;
    if let Some(set) = &allowed {
        changes.check_permitted(set)?;
    }

    // The change is valid and permitted; now prove who is asking.
    if let Some(user) = &caller {
        authenticate_caller(user)?;
    }

    mutate_passwd(&root, &target_user, |entry| {
        let mut gecos = Gecos::parse(&entry.gecos);
        changes.apply(&mut gecos);
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
