// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore gecos chroot sysroot nologin gshadow subuid subgid nscd skel
// spell-checker:ignore useradd groupadd expiredate

//! `useradd` -- create a new user account.
//!
//! Drop-in replacement for GNU shadow-utils `useradd(8)`.
//!
//! Creates a new user account by writing to `/etc/passwd`, `/etc/shadow`,
//! and optionally `/etc/group`, `/etc/gshadow`. Can create the home
//! directory and populate it from `/etc/skel`.

use std::fmt;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use clap::{Arg, ArgAction, Command};

use shadow_core::atomic;
use shadow_core::audit;
use shadow_core::group::{self, GroupEntry};
use shadow_core::gshadow::{self, GshadowEntry};
use shadow_core::lock::FileLock;
use shadow_core::login_defs::{self, LoginDefs};
use shadow_core::nscd;
use shadow_core::passwd::{self, PasswdEntry};
use shadow_core::shadow::{self, ShadowEntry};
use shadow_core::skel;
use shadow_core::sysroot::SysRoot;
use shadow_core::uid_alloc;
use shadow_core::validate;

use uucore::error::{UError, UResult};

// ---------------------------------------------------------------------------
// Option name constants
// ---------------------------------------------------------------------------

mod options {
    pub const LOGIN: &str = "LOGIN";
    pub const COMMENT: &str = "comment";
    pub const HOME_DIR: &str = "home-dir";
    pub const EXPIRE_DATE: &str = "expiredate";
    pub const INACTIVE: &str = "inactive";
    pub const GID: &str = "gid";
    pub const GROUPS: &str = "groups";
    pub const KEY: &str = "key";
    pub const CREATE_HOME: &str = "create-home";
    pub const NO_CREATE_HOME: &str = "no-create-home";
    pub const SKEL: &str = "skel";
    pub const NO_USER_GROUP: &str = "no-user-group";
    pub const NON_UNIQUE: &str = "non-unique";
    pub const PASSWORD: &str = "password";
    pub const SYSTEM: &str = "system";
    pub const ROOT: &str = "root";
    pub const SHELL: &str = "shell";
    pub const UID: &str = "uid";
    pub const USER_GROUP: &str = "user-group";
    pub const DEFAULTS: &str = "defaults";
    pub const BASE_DIR: &str = "base-dir";
    pub const PREFIX: &str = "prefix";
}

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/// Exit code constants for `useradd(8)`.
///
/// Kept as documentation. The canonical mapping lives in [`UseraddError::code`].
#[cfg(test)]
mod exit_codes {
    pub const CANNOT_UPDATE_PASSWD: i32 = 1;
    pub const BAD_SYNTAX: i32 = 2;
    pub const BAD_ARGUMENT: i32 = 3;
    pub const UID_IN_USE: i32 = 4;
    pub const GROUP_NOT_EXIST: i32 = 6;
    pub const USERNAME_IN_USE: i32 = 9;
    pub const CANNOT_UPDATE_GROUP: i32 = 10;
    pub const CANNOT_CREATE_HOME: i32 = 12;
}

// ---------------------------------------------------------------------------
// Error type -- implements uucore::error::UError
// ---------------------------------------------------------------------------

/// Errors that the `useradd` utility can produce.
///
/// Each variant maps to a specific exit code matching GNU `useradd(8)`.
#[derive(Debug)]
enum UseraddError {
    /// Exit 1 -- cannot update password file.
    CannotUpdatePasswd(String),
    /// Exit 2 -- invalid command syntax.
    BadSyntax(String),
    /// Exit 3 -- invalid argument to option.
    BadArgument(String),
    /// Exit 4 -- UID already in use (and `-o` not specified).
    UidInUse(String),
    /// Exit 6 -- specified group does not exist.
    GroupNotExist(String),
    /// Exit 9 -- username already in use.
    UsernameInUse(String),
    /// Exit 10 -- cannot update group file.
    CannotUpdateGroup(String),
    /// Exit 12 -- cannot create home directory.
    CannotCreateHome(String),
}

impl fmt::Display for UseraddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotUpdatePasswd(msg)
            | Self::BadSyntax(msg)
            | Self::BadArgument(msg)
            | Self::UidInUse(msg)
            | Self::GroupNotExist(msg)
            | Self::UsernameInUse(msg)
            | Self::CannotUpdateGroup(msg)
            | Self::CannotCreateHome(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for UseraddError {}

impl UError for UseraddError {
    fn code(&self) -> i32 {
        match self {
            Self::CannotUpdatePasswd(_) => 1,
            Self::BadSyntax(_) => 2,
            Self::BadArgument(_) => 3,
            Self::UidInUse(_) => 4,
            Self::GroupNotExist(_) => 6,
            Self::UsernameInUse(_) => 9,
            Self::CannotUpdateGroup(_) => 10,
            Self::CannotCreateHome(_) => 12,
        }
    }
}

// ---------------------------------------------------------------------------
// Parsed options
// ---------------------------------------------------------------------------

/// Collected options for the `useradd` operation.
#[allow(clippy::struct_excessive_bools)]
struct UseraddOptions {
    login: String,
    comment: String,
    home_dir: Option<String>,
    shell: String,
    uid: Option<u32>,
    gid: Option<String>,
    groups: Vec<String>,
    create_home: bool,
    skel_dir: String,
    system: bool,
    non_unique: bool,
    password: String,
    inactive: Option<i64>,
    expire_date: Option<i64>,
    create_user_group: bool,
    login_defs_overrides: Vec<(String, String)>,
    /// `-b`: base directory the home is created under.
    base_dir: Option<String>,
    root: SysRoot,
}

// Hardening functions are now centralized in shadow_core::hardening.

// ---------------------------------------------------------------------------
// Date parsing
// ---------------------------------------------------------------------------

/// Parse a `YYYY-MM-DD` date string into days since the Unix epoch.
///
/// Returns `None` for empty strings or `-1` (which means "no expiry").
fn parse_expire_date(s: &str) -> Result<Option<i64>, UseraddError> {
    shadow_core::date::parse_expire_date(s).map_err(|e| UseraddError::BadArgument(e.to_string()))
}

/// Current date as days since epoch — delegates to shadow-core.
fn today_days_since_epoch() -> Result<i64, UseraddError> {
    shadow_core::shadow::days_since_epoch().map_err(|e| {
        UseraddError::CannotUpdatePasswd(format!("cannot determine current date: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the `useradd` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let _clean_env = shadow_core::hardening::harden_process();

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 2)? else {
        return Ok(());
    };

    // Only root can add users.
    if !shadow_core::hardening::caller_is_root() {
        uucore::show_error!("{}", shadow_core::os_error::permission_denied());
        return Err(shadow_core::cli::AlreadyPrinted(1).into());
    }

    // Handle --defaults mode (show defaults and exit).
    if matches.get_flag(options::DEFAULTS) {
        return cmd_defaults(&matches);
    }

    let opts = parse_options(&matches)?;
    do_useradd(&opts)
}

// ---------------------------------------------------------------------------
// --defaults mode
// ---------------------------------------------------------------------------

/// Handle `useradd -D` -- print default values.
fn cmd_defaults(matches: &clap::ArgMatches) -> UResult<()> {
    write_defaults(matches, &mut std::io::stdout().lock())
}

/// One key from `/etc/default/useradd`, the file `useradd -D` maintains.
///
/// It takes precedence over `login.defs` for the keys it holds (`GROUP`,
/// `HOME`, `INACTIVE`, `EXPIRE`, `SHELL`, `SKEL`, `CREATE_MAIL_SPOOL`), which
/// login.defs does not define. An unreadable file yields no value.
fn useradd_default(root: &SysRoot, key: &str) -> Option<String> {
    login_defs::read_useradd_defaults(&root.useradd_defaults_path())
        .ok()?
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
}

/// Load login.defs under `-R`, apply `-K` overrides, and write the `useradd -D` report.
fn write_defaults(matches: &clap::ArgMatches, out: &mut dyn std::io::Write) -> UResult<()> {
    let root_dir = matches
        .get_one::<String>(options::PREFIX)
        .or_else(|| matches.get_one::<String>(options::ROOT));
    let root = SysRoot::new(root_dir.map(Path::new));
    let mut defs = LoginDefs::load(&root.login_defs_path())
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;
    apply_login_defs_overrides(&mut defs, &parse_login_defs_overrides(matches)?);

    let stored = login_defs::read_useradd_defaults(&root.useradd_defaults_path())
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;
    let stored_value = |key: &str| -> Option<String> {
        stored
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    };

    // useradd(8): with -D, a value-carrying option *changes* the default and
    // saves it; with no such option, the current defaults are printed.
    // /etc/default/useradd holds these keys; login.defs is the fallback.
    let mut values: Vec<(String, String)> = vec![
        (
            "GROUP".into(),
            matches
                .get_one::<String>(options::GID)
                .cloned()
                .or_else(|| stored_value("GROUP"))
                .unwrap_or_else(|| "100".into()),
        ),
        (
            "HOME".into(),
            matches
                .get_one::<String>(options::BASE_DIR)
                .cloned()
                .or_else(|| stored_value("HOME"))
                .or_else(|| defs.get("HOME").map(ToOwned::to_owned))
                .unwrap_or_else(|| "/home".into()),
        ),
        (
            "INACTIVE".into(),
            matches
                .get_one::<String>(options::INACTIVE)
                .cloned()
                .or_else(|| stored_value("INACTIVE"))
                .or_else(|| defs.get("INACTIVE").map(ToOwned::to_owned))
                .unwrap_or_else(|| "-1".into()),
        ),
        (
            "EXPIRE".into(),
            matches
                .get_one::<String>(options::EXPIRE_DATE)
                .cloned()
                .or_else(|| stored_value("EXPIRE"))
                .or_else(|| defs.get("EXPIRE").map(ToOwned::to_owned))
                .unwrap_or_default(),
        ),
        (
            "SHELL".into(),
            matches
                .get_one::<String>(options::SHELL)
                .cloned()
                .or_else(|| stored_value("SHELL"))
                .or_else(|| defs.get("SHELL").map(ToOwned::to_owned))
                .unwrap_or_default(),
        ),
        (
            "SKEL".into(),
            matches
                .get_one::<String>(options::SKEL)
                .cloned()
                .or_else(|| stored_value("SKEL"))
                .or_else(|| defs.get("SKEL").map(ToOwned::to_owned))
                .unwrap_or_else(|| "/etc/skel".into()),
        ),
        (
            "CREATE_MAIL_SPOOL".into(),
            stored_value("CREATE_MAIL_SPOOL")
                .or_else(|| defs.get("CREATE_MAIL_SPOOL").map(ToOwned::to_owned))
                .unwrap_or_else(|| "no".into()),
        ),
    ];
    values.sort_by(|a, b| a.0.cmp(&b.0));

    // A setter was given: persist instead of printing.
    let setting = [
        options::GID,
        options::BASE_DIR,
        options::INACTIVE,
        options::EXPIRE_DATE,
        options::SHELL,
        options::SKEL,
    ]
    .iter()
    .any(|opt| matches.contains_id(opt) && matches.get_one::<String>(opt).is_some());

    if setting {
        login_defs::write_useradd_defaults(&root.useradd_defaults_path(), &values)
            .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;
        return Ok(());
    }

    for (key, value) in &values {
        let _ = writeln!(out, "{key}={value}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Option parsing
// ---------------------------------------------------------------------------

/// Parse CLI arguments into `UseraddOptions`.
fn bad_argument(e: &shadow_core::error::ShadowError) -> UseraddError {
    UseraddError::BadArgument(e.to_string())
}

/// `-d` and `-k` name directories that are created, chowned and copied as
/// root, so beyond the field rules they must be absolute and must not climb
/// with `..`.
fn validate_directory_arg(what: &str, path: &str) -> Result<(), UseraddError> {
    validate::validate_field(what, path).map_err(|e| bad_argument(&e))?;
    let climbs = Path::new(path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir));
    if !path.starts_with('/') || climbs {
        return Err(UseraddError::BadArgument(format!(
            "invalid {what} '{path}': must be an absolute path without '..'"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn parse_options(matches: &clap::ArgMatches) -> Result<UseraddOptions, UseraddError> {
    let login = matches
        .get_one::<String>(options::LOGIN)
        .ok_or_else(|| UseraddError::BadSyntax("login name required".into()))?
        .clone();

    let root_dir = matches
        .get_one::<String>(options::PREFIX)
        .or_else(|| matches.get_one::<String>(options::ROOT));
    let root = SysRoot::new(root_dir.map(Path::new));

    let comment = matches
        .get_one::<String>(options::COMMENT)
        .cloned()
        .unwrap_or_default();

    let home_dir = matches.get_one::<String>(options::HOME_DIR).cloned();
    let base_dir = matches.get_one::<String>(options::BASE_DIR).cloned();

    // Apply -K overrides before reading defaults so CREATE_HOME, SKEL, etc.
    // match the overridden values when flags are not given.
    let login_defs_overrides = parse_login_defs_overrides(matches)?;
    let mut defs = LoginDefs::load(&root.login_defs_path())
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;
    apply_login_defs_overrides(&mut defs, &login_defs_overrides);

    let shell = matches
        .get_one::<String>(options::SHELL)
        .cloned()
        .or_else(|| useradd_default(&root, "SHELL"))
        .or_else(|| defs.get("SHELL").map(ToOwned::to_owned))
        .unwrap_or_else(|| "/bin/sh".to_string());

    let uid = match matches.get_one::<String>(options::UID) {
        Some(s) => {
            let val = s
                .parse::<u32>()
                .map_err(|_| UseraddError::BadArgument(format!("invalid UID '{s}'")))?;
            // u32::MAX is (uid_t)-1, the "no change" sentinel of chown and
            // setresuid; an account must never hold it.
            if val == u32::MAX {
                return Err(UseraddError::BadArgument(format!("invalid UID '{s}'")));
            }
            Some(val)
        }
        None => None,
    };

    let gid = matches.get_one::<String>(options::GID).cloned();

    let groups: Vec<String> = matches
        .get_one::<String>(options::GROUPS)
        .map(|g| {
            g.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // Determine create-home: -m sets it, -M clears it, default depends on login.defs
    let explicit_create = matches.get_flag(options::CREATE_HOME);
    let explicit_no_create = matches.get_flag(options::NO_CREATE_HOME);
    let system = matches.get_flag(options::SYSTEM);
    let create_home = if explicit_create {
        true
    } else if explicit_no_create || system {
        // useradd(8): -r "will not create a home directory ... regardless of
        // CREATE_HOME" (verified against shadow-utils).
        false
    } else {
        defs.get("CREATE_HOME")
            .is_some_and(|v| v.eq_ignore_ascii_case("yes"))
    };

    let skel_dir = matches
        .get_one::<String>(options::SKEL)
        .cloned()
        .or_else(|| useradd_default(&root, "SKEL"))
        .or_else(|| defs.get("SKEL").map(ToOwned::to_owned))
        .unwrap_or_else(|| "/etc/skel".to_string());

    let non_unique = matches.get_flag(options::NON_UNIQUE);

    let password = matches
        .get_one::<String>(options::PASSWORD)
        .cloned()
        .unwrap_or_else(|| "!".to_string());

    // Everything that lands in a passwd or shadow field is checked before a
    // single file is touched: a `:` would add a field and a newline a whole
    // record. The shadow-core writers refuse the same characters again.
    validate::validate_field("comment", &comment).map_err(|e| bad_argument(&e))?;
    validate::validate_field("shell", &shell).map_err(|e| bad_argument(&e))?;
    validate::validate_field("password", &password).map_err(|e| bad_argument(&e))?;
    if let Some(dir) = &home_dir {
        validate_directory_arg("home directory", dir)?;
    }
    validate_directory_arg("skeleton directory", &skel_dir)?;

    let inactive = match matches.get_one::<String>(options::INACTIVE) {
        Some(s) => {
            let val = s
                .parse::<i64>()
                .map_err(|_| UseraddError::BadArgument(format!("invalid inactive value '{s}'")))?;
            if val < 0 { None } else { Some(val) }
        }
        None => defs.get_i64("INACTIVE").filter(|&v| v >= 0),
    };

    let expire_date = match matches.get_one::<String>(options::EXPIRE_DATE) {
        Some(s) => parse_expire_date(s)?,
        None => defs
            .get("EXPIRE")
            .filter(|s| !s.is_empty())
            .map(parse_expire_date)
            .transpose()?
            .flatten(),
    };

    // Determine user group creation: -U forces it, -N disables it.
    // Default: create user group unless -g was specified or -N given.
    let explicit_user_group = matches.get_flag(options::USER_GROUP);
    let explicit_no_user_group = matches.get_flag(options::NO_USER_GROUP);
    let create_user_group = if explicit_no_user_group {
        false
    } else if explicit_user_group || gid.is_none() {
        // Default behavior: create user group when no -g specified.
        // USERGROUPS_ENAB in login.defs controls this default.
        let usergroups_enab = defs.get("USERGROUPS_ENAB").unwrap_or("yes");
        usergroups_enab.eq_ignore_ascii_case("yes")
    } else {
        false
    };

    Ok(UseraddOptions {
        login,
        comment,
        home_dir,
        shell,
        uid,
        gid,
        groups,
        create_home,
        skel_dir,
        system,
        non_unique,
        password,
        inactive,
        expire_date,
        create_user_group,
        login_defs_overrides,
        base_dir,
        root,
    })
}

// ---------------------------------------------------------------------------
// Core useradd logic
// ---------------------------------------------------------------------------

/// Execute the useradd operation.
#[allow(clippy::too_many_lines)]
fn do_useradd(opts: &UseraddOptions) -> UResult<()> {
    // Step 1: Validate username.
    validate::validate_username(&opts.login)
        .map_err(|e| UseraddError::BadArgument(format!("{e}")))?;

    // Step 2: Block signals for the lock→write critical section only.
    // Dropped after file writes complete so home creation remains interruptible.
    let signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("cannot block signals: {e}")))?;

    // Acquire locks BEFORE reading so concurrent useradd cannot
    // silently overwrite entries added between our read and write.
    let passwd_path = opts.root.passwd_path();
    let passwd_lock = FileLock::acquire(&passwd_path)
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("cannot lock passwd: {e}")))?;

    let group_path = opts.root.group_path();
    let group_lock = FileLock::acquire(&group_path)
        .map_err(|e| UseraddError::CannotUpdateGroup(format!("cannot lock group: {e}")))?;

    // Step 3: Read passwd under lock and check username not already in use.
    let (passwd_entries, passwd_layout) = passwd::read_passwd_with_layout(&passwd_path)
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    if passwd_entries.iter().any(|e| e.name == opts.login) {
        drop(group_lock);
        drop(passwd_lock);
        return Err(
            UseraddError::UsernameInUse(format!("user '{}' already exists", opts.login)).into(),
        );
    }

    // Step 4: Load login.defs and apply -K overrides before allocation and
    // shadow aging fields that are taken from the table.
    let mut defs = LoginDefs::load(&opts.root.login_defs_path())
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;
    apply_login_defs_overrides(&mut defs, &opts.login_defs_overrides);

    // Step 5: Determine UID.
    let uid = determine_uid(opts, &passwd_entries, &defs)?;

    // Step 6: Read group entries under lock (needed for GID resolution and
    // user group creation).
    let (mut group_entries, group_layout) = group::read_group_with_layout(&group_path)
        .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

    // Step 7: Determine primary GID.
    let (gid, new_group) = determine_gid(opts, uid, &group_entries, &defs)?;

    // Step 8: Read gshadow entries.
    let gshadow_path = opts.root.gshadow_path();
    let (mut gshadow_entries, gshadow_layout) = if gshadow_path.exists() {
        gshadow::read_gshadow_with_layout(&gshadow_path)
            .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?
    } else {
        (Vec::new(), gshadow::Layout::default())
    };

    // Step 9: Validate supplementary groups exist.
    for grp_name in &opts.groups {
        // -G takes the same forms as -g: a group name or a GID.
        let known = group_entries
            .iter()
            .any(|g| g.name == *grp_name || grp_name.parse::<u32>().is_ok_and(|id| g.gid == id));
        if !known {
            drop(group_lock);
            drop(passwd_lock);
            return Err(
                UseraddError::GroupNotExist(format!("group '{grp_name}' does not exist")).into(),
            );
        }
    }

    // Step 10: Determine home directory path.
    let home_dir = opts.home_dir.clone().unwrap_or_else(|| {
        // useradd(8): -b overrides the HOME default, which itself comes from
        // /etc/default/useradd before login.defs.
        let home_base = opts
            .base_dir
            .clone()
            .or_else(|| useradd_default(&opts.root, "HOME"))
            .or_else(|| defs.get("HOME").map(ToOwned::to_owned))
            .unwrap_or_else(|| "/home".to_string());
        format!("{home_base}/{}", opts.login)
    });

    // -------------------------------------------------------------------
    // Begin mutations. From here, partial state is left on failure
    // (matching GNU behavior). Locks are held throughout.
    // -------------------------------------------------------------------

    // Step 11: Create user group if needed (group lock already held).
    if let Some(ref new_grp) = new_group {
        write_new_group(&group_path, &mut group_entries, &group_layout, new_grp)?;
        if gshadow_path.exists() {
            // Acquire gshadow lock — group.lock does NOT protect gshadow.
            let _gs_lock = FileLock::acquire(&gshadow_path).map_err(|e| {
                UseraddError::CannotUpdateGroup(format!("cannot lock gshadow: {e}"))
            })?;
            write_new_gshadow(
                &gshadow_path,
                &mut gshadow_entries,
                &gshadow_layout,
                new_grp,
            )?;
        }
    }

    // Step 12: Write /etc/passwd entry (lock already held).
    let passwd_entry = PasswdEntry {
        name: opts.login.clone(),
        passwd: "x".to_string(),
        uid,
        gid,
        gecos: opts.comment.clone(),
        home: home_dir.clone(),
        shell: opts.shell.clone(),
    };
    write_passwd_entry(&passwd_path, &passwd_entries, &passwd_layout, &passwd_entry)?;

    // Step 13: Write /etc/shadow entry (passwd+group locks still held).
    let shadow_path = opts.root.shadow_path();
    // useradd(8): a system account is "created with no aging information in
    // /etc/shadow" -- verified against shadow-utils, which writes
    // `svc:!:20700::::::` for -r and the full policy for a regular account.
    let shadow_entry = if opts.system {
        ShadowEntry {
            name: opts.login.clone(),
            passwd: opts.password.clone(),
            last_change: Some(today_days_since_epoch()?),
            min_age: None,
            max_age: None,
            warn_days: None,
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        }
    } else {
        ShadowEntry {
            name: opts.login.clone(),
            passwd: opts.password.clone(),
            last_change: Some(today_days_since_epoch()?),
            min_age: defs.get_i64("PASS_MIN_DAYS").or(Some(0)),
            max_age: defs.get_i64("PASS_MAX_DAYS").or(Some(99999)),
            warn_days: defs.get_i64("PASS_WARN_AGE").or(Some(7)),
            inactive_days: opts.inactive,
            expire_date: opts.expire_date,
            reserved: String::new(),
        }
    };
    write_shadow_entry(&shadow_path, &shadow_entry)?;

    // Release locks and signal blocker now that passwd, group, and shadow writes are complete.
    // Subsequent steps (subid, supplementary groups, home creation) are individually
    // crash-safe and may be long-running, so signals should be interruptible.
    drop(group_lock);
    drop(passwd_lock);
    drop(signals);

    // Step 14: Allocate subordinate UID/GID ranges for rootless containers.
    // Only done when the relevant file exists (matching GNU shadow-utils behavior).
    // useradd(8) allocates subordinate ranges for regular accounts only;
    // verified that shadow-utils leaves /etc/subuid untouched for -r.
    let subuid_path = opts.root.subuid_path();
    if !opts.system
        && subuid_path.exists()
        && let Err(e) = append_subid_entry(&subuid_path, &opts.login, 65_536)
    {
        uucore::show_error!("warning: failed to add subordinate UID range: {e}");
    }
    let subgid_path = opts.root.subgid_path();
    if !opts.system
        && subgid_path.exists()
        && let Err(e) = append_subid_entry(&subgid_path, &opts.login, 65_536)
    {
        uucore::show_error!("warning: failed to add subordinate GID range: {e}");
    }

    // Step 15: Add to supplementary groups.
    if !opts.groups.is_empty() {
        add_to_supplementary_groups(opts, &group_path, &gshadow_path)?;
    }

    // Step 16: Create home directory and copy skel.
    if opts.create_home {
        let resolved_home = opts.root.resolve(&home_dir);
        let resolved_skel = opts.root.resolve(&opts.skel_dir);
        // login.defs(5) HOME_MODE sets the mode of a new home directory;
        // shadow-utils ships 0700 and we fall back to the same.
        let home_mode = defs
            .get("HOME_MODE")
            .and_then(|v| u32::from_str_radix(v.trim_start_matches("0o"), 8).ok())
            .unwrap_or(0o700);
        create_home_directory(&resolved_home, &resolved_skel, uid, gid, home_mode)?;
    }

    // Step 17: Invalidate nscd caches.
    nscd::invalidate_cache("passwd");
    nscd::invalidate_cache("group");

    // Step 18: Audit log.
    audit::log_user_event("ADD_USER", &opts.login, uid, true);

    Ok(())
}

// ---------------------------------------------------------------------------
// login.defs -K overrides
// ---------------------------------------------------------------------------

/// Collect `-K`/`--key` pairs; each value must be non-empty `KEY=VALUE`.
fn parse_login_defs_overrides(
    matches: &clap::ArgMatches,
) -> Result<Vec<(String, String)>, UseraddError> {
    matches
        .get_many::<String>(options::KEY)
        .into_iter()
        .flatten()
        .map(|kv| {
            login_defs::parse_override(kv)
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .map_err(|e| UseraddError::BadArgument(e.to_string()))
        })
        .collect()
}

/// Merge `-K` overrides into `defs` so later lookups use the new values.
fn apply_login_defs_overrides(defs: &mut LoginDefs, overrides: &[(String, String)]) {
    defs.apply_overrides(overrides.iter().map(|(k, v)| (k.as_str(), v.as_str())));
}

// ---------------------------------------------------------------------------
// UID determination
// ---------------------------------------------------------------------------

/// Determine the UID for the new user.
fn determine_uid(
    opts: &UseraddOptions,
    passwd_entries: &[PasswdEntry],
    defs: &LoginDefs,
) -> Result<u32, UseraddError> {
    if let Some(requested_uid) = opts.uid {
        // Check if UID is already in use.
        if !opts.non_unique && passwd_entries.iter().any(|e| e.uid == requested_uid) {
            return Err(UseraddError::UidInUse(format!(
                "UID {requested_uid} is not unique"
            )));
        }
        Ok(requested_uid)
    } else {
        let (min, max) = uid_alloc::uid_range(defs, opts.system);
        uid_alloc::next_uid(passwd_entries, min, max)
            .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))
    }
}

// ---------------------------------------------------------------------------
// GID determination
// ---------------------------------------------------------------------------

/// Determine the primary GID for the new user.
///
/// Returns `(gid, Option<GroupEntry>)` where the second element is `Some` if
/// a new user group needs to be created.
fn determine_gid(
    opts: &UseraddOptions,
    uid: u32,
    group_entries: &[GroupEntry],
    defs: &LoginDefs,
) -> Result<(u32, Option<GroupEntry>), UseraddError> {
    // If -g was specified, resolve it to a GID.
    if let Some(ref gid_arg) = opts.gid {
        let gid = resolve_group(gid_arg, group_entries)?;
        return Ok((gid, None));
    }

    // Create a user group with the same name as the user.
    if opts.create_user_group {
        // Verify no group with this name already exists.
        if group_entries.iter().any(|g| g.name == opts.login) {
            return Err(UseraddError::UsernameInUse(format!(
                "group '{}' already exists -- if you want to add this user to that \
                 group, use -g",
                opts.login
            )));
        }

        // Allocate a GID. Prefer same as UID if available.
        let gid = if group_entries.iter().any(|g| g.gid == uid) {
            let (min, max) = uid_alloc::gid_range(defs, opts.system);
            uid_alloc::next_gid(group_entries, min, max)
                .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?
        } else {
            uid
        };

        let new_group = GroupEntry {
            name: opts.login.clone(),
            passwd: "x".to_string(),
            gid,
            members: Vec::new(),
        };

        return Ok((gid, Some(new_group)));
    }

    // No -g and no user group creation: use default group (typically 100).
    let default_gid = defs
        .get_i64("USERS_GID")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(100);
    Ok((default_gid, None))
}

/// Resolve a group argument (name or numeric GID) to a GID.
fn resolve_group(gid_arg: &str, group_entries: &[GroupEntry]) -> Result<u32, UseraddError> {
    // useradd(8): the group given to -g or -G "must exist", named either way.
    // A numeric GID naming no group used to be accepted, leaving the account
    // pointing at a group that does not exist.
    let found = if let Ok(gid) = gid_arg.parse::<u32>() {
        group_entries.iter().find(|g| g.gid == gid).map(|g| g.gid)
    } else {
        group_entries
            .iter()
            .find(|g| g.name == gid_arg)
            .map(|g| g.gid)
    };

    found.ok_or_else(|| UseraddError::GroupNotExist(format!("group '{gid_arg}' does not exist")))
}

// ---------------------------------------------------------------------------
// File writers
// ---------------------------------------------------------------------------

/// Append a new group entry to `/etc/group`.
///
/// Caller must hold the group file lock.
fn write_new_group(
    group_path: &Path,
    group_entries: &mut Vec<GroupEntry>,
    layout: &group::Layout,
    new_group: &GroupEntry,
) -> UResult<()> {
    group_entries.push(new_group.clone());

    atomic::atomic_write(group_path, |f| {
        group::write_group_with_layout(group_entries, layout, f)
    })
    .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

    Ok(())
}

/// Append a new gshadow entry to `/etc/gshadow`.
///
/// Caller must hold the gshadow file lock (or the group file lock
/// if gshadow is protected by the same lock scheme).
fn write_new_gshadow(
    gshadow_path: &Path,
    gshadow_entries: &mut Vec<GshadowEntry>,
    layout: &gshadow::Layout,
    new_group: &GroupEntry,
) -> UResult<()> {
    gshadow_entries.push(GshadowEntry {
        name: new_group.name.clone(),
        passwd: "!".to_string(),
        admins: Vec::new(),
        members: Vec::new(),
    });

    atomic::atomic_write(gshadow_path, |f| {
        gshadow::write_gshadow_with_layout(gshadow_entries, layout, f)
    })
    .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

    Ok(())
}

/// Append a new passwd entry to `/etc/passwd`.
///
/// Caller must hold the passwd file lock.
fn write_passwd_entry(
    passwd_path: &Path,
    existing: &[PasswdEntry],
    layout: &passwd::Layout,
    new_entry: &PasswdEntry,
) -> UResult<()> {
    let mut entries: Vec<PasswdEntry> = existing.to_vec();
    entries.push(new_entry.clone());

    atomic::atomic_write(passwd_path, |f| {
        passwd::write_passwd_with_layout(&entries, layout, f)
    })
    .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    Ok(())
}

/// Append a new shadow entry to `/etc/shadow` with proper locking.
fn write_shadow_entry(shadow_path: &Path, new_entry: &ShadowEntry) -> UResult<()> {
    let _lock = FileLock::acquire(shadow_path)
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    // Read existing entries; if the file does not exist, start fresh.
    let (mut entries, layout) = if shadow_path.exists() {
        shadow::read_shadow_with_layout(shadow_path)
            .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?
    } else {
        (Vec::new(), shadow::Layout::default())
    };

    entries.push(new_entry.clone());

    atomic::atomic_write(shadow_path, |f| {
        shadow::write_shadow_with_layout(&entries, &layout, f)
    })
    .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    Ok(())
}

/// Whether `-G` named this group, by name or by GID.
fn group_requested(requested: &[String], name: &str, gid: u32) -> bool {
    requested
        .iter()
        .any(|g| g == name || g.parse::<u32>().is_ok_and(|id| id == gid))
}

/// The gshadow file carries no GID, so only the name can be matched there.
fn gs_group_requested(requested: &[String], name: &str) -> bool {
    requested.iter().any(|g| g == name)
}

/// Add the user to supplementary groups in `/etc/group` and `/etc/gshadow`.
fn add_to_supplementary_groups(
    opts: &UseraddOptions,
    group_path: &Path,
    gshadow_path: &Path,
) -> UResult<()> {
    let _lock = FileLock::acquire(group_path)
        .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

    let (mut entries, layout) = group::read_group_with_layout(group_path)
        .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

    for entry in &mut entries {
        if group_requested(&opts.groups, &entry.name, entry.gid)
            && !entry.members.contains(&opts.login)
        {
            entry.members.push(opts.login.clone());
        }
    }

    atomic::atomic_write(group_path, |f| {
        group::write_group_with_layout(&entries, &layout, f)
    })
    .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

    // Also update gshadow if it exists.
    if gshadow_path.exists() {
        let _gs_lock = FileLock::acquire(gshadow_path)
            .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

        let (mut gs_entries, gs_layout) = gshadow::read_gshadow_with_layout(gshadow_path)
            .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

        for entry in &mut gs_entries {
            if gs_group_requested(&opts.groups, &entry.name) && !entry.members.contains(&opts.login)
            {
                entry.members.push(opts.login.clone());
            }
        }

        atomic::atomic_write(gshadow_path, |f| {
            gshadow::write_gshadow_with_layout(&gs_entries, &gs_layout, f)
        })
        .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Subordinate ID allocation
// ---------------------------------------------------------------------------

/// Append a subordinate ID entry to a subuid/subgid file.
///
/// Skips the write if the user already has an entry in the file.
/// Uses file locking and atomic writes for crash safety.
fn append_subid_entry(path: &Path, name: &str, count: u64) -> UResult<()> {
    use shadow_core::subid::{self, SubIdEntry};

    let lock = FileLock::acquire(path).map_err(|e| {
        UseraddError::CannotUpdatePasswd(format!("cannot lock {}: {e}", path.display()))
    })?;

    let (mut entries, layout) = match subid::read_subid_with_layout(path) {
        Ok(e) => e,
        Err(e) => {
            uucore::show_error!("warning: cannot read {}: {e}", path.display());
            return Err(UseraddError::CannotUpdatePasswd(format!(
                "cannot read {}: {e}",
                path.display()
            ))
            .into());
        }
    };

    // Don't add a duplicate entry.
    if entries.iter().any(|e| e.name == name) {
        drop(lock);
        return Ok(());
    }

    // Find next available range by starting after the highest existing end.
    // Clamp to at least 100_000 even if existing entries are below that threshold.
    let start = entries
        .iter()
        .map(|e| e.start.saturating_add(e.count))
        .max()
        .unwrap_or(100_000)
        .max(100_000);

    entries.push(SubIdEntry {
        name: name.to_string(),
        start,
        count,
    });

    atomic::atomic_write(path, |f| {
        subid::write_subid_with_layout(&entries, &layout, f)
    })
    .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    drop(lock);
    Ok(())
}

// ---------------------------------------------------------------------------
// Home directory creation
// ---------------------------------------------------------------------------

/// Create the home directory and copy skeleton files.
///
/// Paths must already be resolved through `SysRoot` by the caller.
fn create_home_directory(
    home_path: &Path,
    skel_path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> UResult<()> {
    // The kernel does not reset umask across setuid, so a caller-controlled
    // inherited umask may still be in effect in our process. A non-zero umask
    // can mask off requested permission bits, so even mkdir(0o700) is not
    // guaranteed to result in 0o700 unless we clear it first (e.g., umask
    // 0o700 would mask the user RWX bits and leave the dir at 0o000).
    // Forcing umask to 0 makes the requested mode exact, regardless of caller
    // environment; umask can only make the result less permissive than the
    // mode we requested, never more. Scoped to the mkdir call only — chown
    // doesn't need it, and copy_skel manages its own umask internally.
    // useradd(8) -b: with -m the base directory is created if it is missing,
    // so a home under a path that does not exist yet works. Ancestors get the
    // conventional 0755 and stay root-owned; only the home itself takes `mode`
    // and the user's ownership.
    if let Some(parent) = home_path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        let _umask = shadow_core::atomic::UmaskGuard::zero();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(parent)
            .map_err(|e| {
                UseraddError::CannotCreateHome(format!(
                    "cannot create directory '{}': {e}",
                    parent.display()
                ))
            })?;
    }

    let mkdir_result = {
        let _umask = shadow_core::atomic::UmaskGuard::zero();
        std::fs::DirBuilder::new().mode(mode).create(home_path)
    };

    // Use DirBuilder::mode() so mkdir(2) is called with 0o700 atomically.
    // Use create (not recursive) to avoid TOCTOU between exists() and mkdir().
    match mkdir_result {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            uucore::show_warning!(
                "home directory '{}' already exists -- not copying from skel directory",
                home_path.display()
            );
            return Ok(());
        }
        Err(e) => {
            return Err(UseraddError::CannotCreateHome(format!(
                "cannot create directory '{}': {e}",
                home_path.display()
            ))
            .into());
        }
    }

    // Change ownership through a descriptor opened with O_NOFOLLOW rather
    // than by path: between the mkdir above and this call, anyone able to
    // write the parent (a home under /tmp or a shared base directory) could
    // swap the directory for a symlink and have us hand them the target.
    {
        use rustix::fs::{Mode, OFlags};
        let dir = rustix::fs::open(
            home_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|e| {
            UseraddError::CannotCreateHome(format!("cannot open '{}': {e}", home_path.display()))
        })?;
        rustix::fs::fchown(
            &dir,
            Some(rustix::fs::Uid::from_raw(uid)),
            Some(rustix::fs::Gid::from_raw(gid)),
        )
        .map_err(|e| {
            UseraddError::CannotCreateHome(format!(
                "cannot set ownership on '{}': {e}",
                home_path.display()
            ))
        })?;
    }

    // Copy skeleton directory contents.
    skel::copy_skel(skel_path, home_path, uid, gid).map_err(|e| {
        UseraddError::CannotCreateHome(format!(
            "cannot copy skel '{}' to '{}': {e}",
            skel_path.display(),
            home_path.display()
        ))
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Clap command definition
// ---------------------------------------------------------------------------

/// Build the clap `Command` for `useradd`.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn uu_app() -> Command {
    Command::new("useradd")
        .about("Create a user account, or print/update useradd defaults")
        .override_usage("useradd [options] LOGIN\n       useradd -D [options]")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::LOGIN)
                .help("Login name to create")
                .index(1)
                .required_unless_present(options::DEFAULTS),
        )
        .arg(
            Arg::new(options::COMMENT)
                .short('c')
                .long("comment")
                .value_name("COMMENT")
                .help("GECOS comment for the account"),
        )
        .arg(
            Arg::new(options::HOME_DIR)
                .short('d')
                .long("home-dir")
                .value_name("HOME_DIR")
                .help("Home directory path"),
        )
        .arg(
            Arg::new(options::EXPIRE_DATE)
                .short('e')
                .long("expiredate")
                .value_name("EXPIRE_DATE")
                .help("Account expiration date (YYYY-MM-DD)"),
        )
        .arg(
            Arg::new(options::INACTIVE)
                .short('f')
                .long("inactive")
                .value_name("INACTIVE")
                .help("Days the password may stay expired before the account is disabled"),
        )
        .arg(
            Arg::new(options::GID)
                .short('g')
                .long("gid")
                .value_name("GROUP")
                .help("Primary group (name or numeric GID)"),
        )
        .arg(
            Arg::new(options::GROUPS)
                .short('G')
                .long("groups")
                .value_name("GROUPS")
                .help("Comma-separated supplementary groups"),
        )
        .arg(
            Arg::new(options::KEY)
                .short('K')
                .long("key")
                .value_name("KEY=VALUE")
                .action(ArgAction::Append)
                .help("Override /etc/login.defs defaults (KEY=VALUE; may be repeated)"),
        )
        .arg(
            Arg::new(options::CREATE_HOME)
                .short('m')
                .long("create-home")
                .action(ArgAction::SetTrue)
                .conflicts_with(options::NO_CREATE_HOME)
                .help("Materialise the home directory"),
        )
        .arg(
            Arg::new(options::NO_CREATE_HOME)
                .short('M')
                .long("no-create-home")
                .action(ArgAction::SetTrue)
                .help("Skip home directory creation"),
        )
        .arg(
            Arg::new(options::SKEL)
                .short('k')
                .long("skel")
                .value_name("SKEL_DIR")
                .help("Template directory copied into the new home (default: /etc/skel)"),
        )
        .arg(
            Arg::new(options::NO_USER_GROUP)
                .short('N')
                .long("no-user-group")
                .action(ArgAction::SetTrue)
                .conflicts_with(options::USER_GROUP)
                .help("Skip the matching user-private group"),
        )
        .arg(
            Arg::new(options::NON_UNIQUE)
                .short('o')
                .long("non-unique")
                .action(ArgAction::SetTrue)
                .requires(options::UID)
                .help("Permit a duplicate UID (must accompany -u)"),
        )
        .arg(
            Arg::new(options::PASSWORD)
                .short('p')
                .long("password")
                .value_name("PASSWORD")
                .help("Initial crypt(3) hash for the password field"),
        )
        .arg(
            Arg::new(options::SYSTEM)
                .short('r')
                .long("system")
                .action(ArgAction::SetTrue)
                .help("Allocate from the system UID range"),
        )
        .arg(
            Arg::new(options::BASE_DIR)
                .short('b')
                .long("base-dir")
                .value_name("BASE_DIR")
                .help("Base directory for the new account's home directory"),
        )
        .arg(
            Arg::new(options::PREFIX)
                .short('P')
                .long("prefix")
                .value_name("PREFIX_DIR")
                .help("Locate the system files under PREFIX_DIR instead of /"),
        )
        .arg(
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .value_name("ROOT_DIR")
                .help("Locate the system files under ROOT_DIR instead of /"),
        )
        .arg(
            Arg::new(options::SHELL)
                .short('s')
                .long("shell")
                .value_name("SHELL")
                .help("Login shell path"),
        )
        .arg(
            Arg::new(options::UID)
                .short('u')
                .long("uid")
                .value_name("UID")
                .help("Numeric UID to assign"),
        )
        .arg(
            Arg::new(options::USER_GROUP)
                .short('U')
                .long("user-group")
                .action(ArgAction::SetTrue)
                .help("Also create a matching user-private group (default)"),
        )
        .arg(
            Arg::new(options::DEFAULTS)
                .short('D')
                .long("defaults")
                .action(ArgAction::SetTrue)
                .help("View or edit the saved useradd defaults"),
        )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    // -----------------------------------------------------------------------
    // Clap validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_clap_no_args_fails() {
        let result = uu_app().try_get_matches_from(["useradd"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_clap_login_only() {
        let m = uu_app()
            .try_get_matches_from(["useradd", "testuser"])
            .expect("should parse");
        assert_eq!(
            m.get_one::<String>(options::LOGIN).map(String::as_str),
            Some("testuser")
        );
    }

    #[test]
    fn test_clap_defaults_flag() {
        let m = uu_app()
            .try_get_matches_from(["useradd", "-D"])
            .expect("should parse -D without LOGIN");
        assert!(m.get_flag(options::DEFAULTS));
    }

    #[test]
    fn test_clap_defaults_with_key() {
        let m = uu_app()
            .try_get_matches_from([
                "useradd",
                "-D",
                "-K",
                "HOME=/OVERRIDDEN",
                "-K",
                "SHELL=/bin/zsh",
            ])
            .expect("should parse -D -K");
        assert!(m.get_flag(options::DEFAULTS));
        let keys: Vec<&str> = m
            .get_many::<String>(options::KEY)
            .expect("KEY present")
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["HOME=/OVERRIDDEN", "SHELL=/bin/zsh"]);
    }

    #[test]
    fn test_clap_all_short_flags() {
        let m = uu_app()
            .try_get_matches_from([
                "useradd",
                "-c",
                "Test User",
                "-d",
                "/home/tuser",
                "-e",
                "2030-12-31",
                "-f",
                "30",
                "-g",
                "users",
                "-G",
                "wheel,docker",
                "-m",
                "-k",
                "/etc/skel",
                "-o",
                "-p",
                "$6$hash",
                "-r",
                "-R",
                "/mnt/root",
                "-s",
                "/bin/zsh",
                "-u",
                "1500",
                "testuser",
            ])
            .expect("should parse all short flags");

        assert_eq!(
            m.get_one::<String>(options::COMMENT).map(String::as_str),
            Some("Test User")
        );
        assert_eq!(
            m.get_one::<String>(options::HOME_DIR).map(String::as_str),
            Some("/home/tuser")
        );
        assert_eq!(
            m.get_one::<String>(options::EXPIRE_DATE)
                .map(String::as_str),
            Some("2030-12-31")
        );
        assert_eq!(
            m.get_one::<String>(options::INACTIVE).map(String::as_str),
            Some("30")
        );
        assert_eq!(
            m.get_one::<String>(options::GID).map(String::as_str),
            Some("users")
        );
        assert_eq!(
            m.get_one::<String>(options::GROUPS).map(String::as_str),
            Some("wheel,docker")
        );
        assert!(m.get_flag(options::CREATE_HOME));
        assert_eq!(
            m.get_one::<String>(options::SKEL).map(String::as_str),
            Some("/etc/skel")
        );
        assert!(m.get_flag(options::NON_UNIQUE));
        assert_eq!(
            m.get_one::<String>(options::PASSWORD).map(String::as_str),
            Some("$6$hash")
        );
        assert!(m.get_flag(options::SYSTEM));
        assert_eq!(
            m.get_one::<String>(options::ROOT).map(String::as_str),
            Some("/mnt/root")
        );
        assert_eq!(
            m.get_one::<String>(options::SHELL).map(String::as_str),
            Some("/bin/zsh")
        );
        assert_eq!(
            m.get_one::<String>(options::UID).map(String::as_str),
            Some("1500")
        );
    }

    #[test]
    fn test_clap_long_flags() {
        let m = uu_app()
            .try_get_matches_from([
                "useradd",
                "--comment",
                "Full Name",
                "--home-dir",
                "/opt/user",
                "--shell",
                "/bin/bash",
                "--uid",
                "2000",
                "--create-home",
                "--system",
                "newuser",
            ])
            .expect("should parse long flags");

        assert_eq!(
            m.get_one::<String>(options::COMMENT).map(String::as_str),
            Some("Full Name")
        );
        assert_eq!(
            m.get_one::<String>(options::HOME_DIR).map(String::as_str),
            Some("/opt/user")
        );
        assert_eq!(
            m.get_one::<String>(options::SHELL).map(String::as_str),
            Some("/bin/bash")
        );
        assert_eq!(
            m.get_one::<String>(options::UID).map(String::as_str),
            Some("2000")
        );
        assert!(m.get_flag(options::CREATE_HOME));
        assert!(m.get_flag(options::SYSTEM));
    }

    #[test]
    fn test_clap_create_home_conflict() {
        let result = uu_app().try_get_matches_from(["useradd", "-m", "-M", "user"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_clap_user_group_conflict() {
        let result = uu_app().try_get_matches_from(["useradd", "-U", "-N", "user"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_clap_non_unique_requires_uid() {
        let result = uu_app().try_get_matches_from(["useradd", "-o", "user"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_clap_non_unique_with_uid() {
        let m = uu_app()
            .try_get_matches_from(["useradd", "-o", "-u", "0", "user"])
            .expect("should parse -o -u together");
        assert!(m.get_flag(options::NON_UNIQUE));
        assert_eq!(
            m.get_one::<String>(options::UID).map(String::as_str),
            Some("0")
        );
    }

    #[test]
    fn test_clap_no_create_home() {
        let m = uu_app()
            .try_get_matches_from(["useradd", "-M", "user"])
            .expect("should parse -M");
        assert!(m.get_flag(options::NO_CREATE_HOME));
    }

    #[test]
    fn test_clap_no_user_group() {
        let m = uu_app()
            .try_get_matches_from(["useradd", "-N", "user"])
            .expect("should parse -N");
        assert!(m.get_flag(options::NO_USER_GROUP));
    }

    #[test]
    fn test_clap_key_short_and_long() {
        let m = uu_app()
            .try_get_matches_from([
                "useradd",
                "-K",
                "UID_MIN=9100",
                "--key",
                "UID_MAX=9100",
                "user",
            ])
            .expect("should parse -K/--key");
        let keys: Vec<&str> = m
            .get_many::<String>(options::KEY)
            .expect("KEY present")
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["UID_MIN=9100", "UID_MAX=9100"]);
    }

    // -----------------------------------------------------------------------
    // Date parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_expire_date_valid() {
        let days = parse_expire_date("2025-01-01").expect("valid date");
        assert!(days.is_some());
        // 2025-01-01 is about 20089 days since epoch.
        let d = days.expect("should be Some");
        assert!(d > 19000, "expected > 19000, got {d}");
        assert!(d < 25000, "expected < 25000, got {d}");
    }

    #[test]
    fn test_parse_expire_date_empty() {
        assert_eq!(parse_expire_date("").expect("empty is ok"), None);
    }

    #[test]
    fn test_parse_expire_date_minus_one() {
        assert_eq!(parse_expire_date("-1").expect("-1 is ok"), None);
    }

    #[test]
    fn test_parse_expire_date_invalid_format() {
        assert!(parse_expire_date("2025/01/01").is_err());
    }

    #[test]
    fn test_parse_expire_date_invalid_month() {
        assert!(parse_expire_date("2025-13-01").is_err());
    }

    #[test]
    fn test_parse_expire_date_invalid_day() {
        assert!(parse_expire_date("2025-01-32").is_err());
    }

    #[test]
    fn test_parse_expire_date_pre_epoch() {
        assert!(parse_expire_date("1969-12-31").is_err());
    }

    #[test]
    fn test_parse_expire_date_feb_31() {
        assert!(parse_expire_date("2025-02-31").is_err());
    }

    #[test]
    fn test_parse_expire_date_feb_29_non_leap() {
        assert!(parse_expire_date("2025-02-29").is_err());
    }

    #[test]
    fn test_parse_expire_date_feb_29_leap() {
        assert!(parse_expire_date("2024-02-29").is_ok());
    }

    #[test]
    fn test_parse_expire_date_apr_31() {
        assert!(parse_expire_date("2025-04-31").is_err());
    }

    #[test]
    fn test_parse_expire_date_apr_30() {
        assert!(parse_expire_date("2025-04-30").is_ok());
    }

    // -----------------------------------------------------------------------
    // Username collision detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_username_collision_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = SysRoot::new(Some(dir.path()));

        // Set up /etc/ structure.
        fs::create_dir_all(dir.path().join("etc")).expect("create etc");
        fs::write(
            root.passwd_path(),
            "existing:x:1000:1000::/home/existing:/bin/bash\n",
        )
        .expect("write passwd");
        fs::write(root.shadow_path(), "existing:!:19000:0:99999:7:::\n").expect("write shadow");
        fs::write(root.group_path(), "existing:x:1000:\n").expect("write group");

        let (passwd_entries, _) =
            passwd::read_passwd_with_layout(&root.passwd_path()).expect("read passwd");
        assert!(passwd_entries.iter().any(|e| e.name == "existing"));
    }

    // -----------------------------------------------------------------------
    // UID allocation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_uid_allocation_basic() {
        let entries = vec![
            PasswdEntry {
                name: "root".into(),
                passwd: "x".into(),
                uid: 0,
                gid: 0,
                gecos: String::new(),
                home: "/root".into(),
                shell: "/bin/bash".into(),
            },
            PasswdEntry {
                name: "user1".into(),
                passwd: "x".into(),
                uid: 1000,
                gid: 1000,
                gecos: String::new(),
                home: "/home/user1".into(),
                shell: "/bin/bash".into(),
            },
        ];

        let defs = LoginDefs::load(Path::new("/nonexistent")).expect("empty defs");

        // Regular user allocation should start at UID_MIN (1000 default),
        // skip 1000 (taken), and give 1001.
        let (min, max) = uid_alloc::uid_range(&defs, false);
        let uid = uid_alloc::next_uid(&entries, min, max).expect("should find UID");
        assert_eq!(uid, 1001);
    }

    #[test]
    fn test_uid_allocation_system() {
        let entries = vec![PasswdEntry {
            name: "root".into(),
            passwd: "x".into(),
            uid: 0,
            gid: 0,
            gecos: String::new(),
            home: "/root".into(),
            shell: "/bin/bash".into(),
        }];

        let defs = LoginDefs::load(Path::new("/nonexistent")).expect("empty defs");

        let (min, max) = uid_alloc::uid_range(&defs, true);
        let uid = uid_alloc::next_uid(&entries, min, max).expect("should find UID");
        assert_eq!(uid, 101); // SYS_UID_MIN default
    }

    // -----------------------------------------------------------------------
    // GID resolution tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_group_by_name() {
        let groups = vec![
            GroupEntry {
                name: "users".into(),
                passwd: "x".into(),
                gid: 100,
                members: vec![],
            },
            GroupEntry {
                name: "wheel".into(),
                passwd: "x".into(),
                gid: 10,
                members: vec![],
            },
        ];

        assert_eq!(resolve_group("users", &groups).expect("found"), 100);
        assert_eq!(resolve_group("wheel", &groups).expect("found"), 10);
    }

    #[test]
    fn test_resolve_group_by_gid() {
        let groups = vec![GroupEntry {
            name: "staff".into(),
            passwd: "x".into(),
            gid: 500,
            members: vec![],
        }];
        assert_eq!(resolve_group("500", &groups).expect("numeric"), 500);
        assert_eq!(resolve_group("staff", &groups).expect("by name"), 500);
        // useradd(8): the group must exist, whichever form names it.
        assert!(resolve_group("501", &groups).is_err());
        assert!(resolve_group("nosuch", &groups).is_err());
    }

    #[test]
    fn test_resolve_group_not_found() {
        let groups: Vec<GroupEntry> = vec![];
        assert!(resolve_group("nonexistent", &groups).is_err());
    }

    // -----------------------------------------------------------------------
    // Error code tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_error_codes() {
        assert_eq!(
            UseraddError::CannotUpdatePasswd(String::new()).code(),
            exit_codes::CANNOT_UPDATE_PASSWD
        );
        assert_eq!(
            UseraddError::BadSyntax(String::new()).code(),
            exit_codes::BAD_SYNTAX
        );
        assert_eq!(
            UseraddError::BadArgument(String::new()).code(),
            exit_codes::BAD_ARGUMENT
        );
        assert_eq!(
            UseraddError::UidInUse(String::new()).code(),
            exit_codes::UID_IN_USE
        );
        assert_eq!(
            UseraddError::GroupNotExist(String::new()).code(),
            exit_codes::GROUP_NOT_EXIST
        );
        assert_eq!(
            UseraddError::UsernameInUse(String::new()).code(),
            exit_codes::USERNAME_IN_USE
        );
        assert_eq!(
            UseraddError::CannotUpdateGroup(String::new()).code(),
            exit_codes::CANNOT_UPDATE_GROUP
        );
        assert_eq!(
            UseraddError::CannotCreateHome(String::new()).code(),
            exit_codes::CANNOT_CREATE_HOME
        );
    }

    // -----------------------------------------------------------------------
    // Integration tests with synthetic files (require root)
    // -----------------------------------------------------------------------

    /// Set up a minimal /etc directory tree in a temp dir with the basic
    /// system files.
    fn setup_test_root() -> (tempfile::TempDir, SysRoot) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = SysRoot::new(Some(dir.path()));

        fs::create_dir_all(dir.path().join("etc")).expect("create etc");

        fs::write(root.passwd_path(), "root:x:0:0:root:/root:/bin/bash\n").expect("write passwd");

        fs::write(root.shadow_path(), "root:$6$hash:19000:0:99999:7:::\n").expect("write shadow");

        fs::write(root.group_path(), "root:x:0:\nusers:x:100:\n").expect("write group");

        fs::write(root.gshadow_path(), "root:*::\nusers:!::\n").expect("write gshadow");

        (dir, root)
    }

    /// Skip tests that require root privileges.
    fn skip_unless_root() -> bool {
        !rustix::process::geteuid().is_root()
    }

    #[test]
    fn test_integration_create_user_basic() {
        if skip_unless_root() {
            return;
        }

        let (_dir, root) = setup_test_root();

        let defs = LoginDefs::load(&root.login_defs_path()).expect("defs");

        let (passwd_entries, passwd_layout) =
            passwd::read_passwd_with_layout(&root.passwd_path()).expect("passwd");
        let _group_entries = group::read_group_file(&root.group_path()).expect("group");

        // Allocate UID.
        let (uid_min, uid_max) = uid_alloc::uid_range(&defs, false);
        let uid = uid_alloc::next_uid(&passwd_entries, uid_min, uid_max).expect("uid");
        assert_eq!(uid, 1000);

        // Create passwd entry.
        let new_entry = PasswdEntry {
            name: "testuser".into(),
            passwd: "x".into(),
            uid,
            gid: 100,
            gecos: "Test User".into(),
            home: "/home/testuser".into(),
            shell: "/bin/bash".into(),
        };

        write_passwd_entry(
            &root.passwd_path(),
            &passwd_entries,
            &passwd_layout,
            &new_entry,
        )
        .expect("write passwd");

        // Verify.
        let updated = passwd::read_passwd_file(&root.passwd_path()).expect("re-read");
        assert_eq!(updated.len(), 2);
        assert_eq!(updated[1].name, "testuser");
        assert_eq!(updated[1].uid, 1000);
        assert_eq!(updated[1].gid, 100);
    }

    #[test]
    fn test_integration_create_user_with_group() {
        if skip_unless_root() {
            return;
        }

        let (_dir, root) = setup_test_root();

        let (mut group_entries, group_layout) =
            group::read_group_with_layout(&root.group_path()).expect("group");
        let (mut gshadow_entries, gshadow_layout) =
            gshadow::read_gshadow_with_layout(&root.gshadow_path()).expect("gshadow");

        // Create user group.
        let new_group = GroupEntry {
            name: "newuser".into(),
            passwd: "x".into(),
            gid: 1000,
            members: Vec::new(),
        };

        write_new_group(
            &root.group_path(),
            &mut group_entries,
            &group_layout,
            &new_group,
        )
        .expect("write group");
        write_new_gshadow(
            &root.gshadow_path(),
            &mut gshadow_entries,
            &gshadow_layout,
            &new_group,
        )
        .expect("write gshadow");

        // Verify group.
        let updated_groups = group::read_group_file(&root.group_path()).expect("re-read");
        assert_eq!(updated_groups.len(), 3);
        assert_eq!(updated_groups[2].name, "newuser");
        assert_eq!(updated_groups[2].gid, 1000);

        // Verify gshadow.
        let updated_gshadow = gshadow::read_gshadow_file(&root.gshadow_path()).expect("re-read");
        assert_eq!(updated_gshadow.len(), 3);
        assert_eq!(updated_gshadow[2].name, "newuser");
    }

    #[test]
    fn test_integration_create_shadow_entry() {
        if skip_unless_root() {
            return;
        }

        let (_dir, root) = setup_test_root();

        let shadow_entry = ShadowEntry {
            name: "testuser".into(),
            passwd: "!".into(),
            last_change: Some(20000),
            min_age: Some(0),
            max_age: Some(99999),
            warn_days: Some(7),
            inactive_days: None,
            expire_date: None,
            reserved: String::new(),
        };

        write_shadow_entry(&root.shadow_path(), &shadow_entry).expect("write shadow");

        let updated = shadow::read_shadow_file(&root.shadow_path()).expect("re-read");
        assert_eq!(updated.len(), 2);
        assert_eq!(updated[1].name, "testuser");
        assert_eq!(updated[1].passwd, "!");
    }

    #[test]
    fn test_integration_supplementary_groups() {
        if skip_unless_root() {
            return;
        }

        let (_dir, root) = setup_test_root();

        // Add a "wheel" group.
        let (mut group_entries, group_layout) =
            group::read_group_with_layout(&root.group_path()).expect("group");
        let wheel = GroupEntry {
            name: "wheel".into(),
            passwd: "x".into(),
            gid: 10,
            members: Vec::new(),
        };
        write_new_group(
            &root.group_path(),
            &mut group_entries,
            &group_layout,
            &wheel,
        )
        .expect("add wheel");

        // Now add "testuser" to "wheel" and "users".
        let opts = UseraddOptions {
            login: "testuser".into(),
            comment: String::new(),
            home_dir: None,
            shell: "/bin/bash".into(),
            uid: None,
            gid: None,
            groups: vec!["wheel".into(), "users".into()],
            create_home: false,
            skel_dir: "/etc/skel".into(),
            system: false,
            non_unique: false,
            password: "!".into(),
            inactive: None,
            expire_date: None,
            create_user_group: false,
            login_defs_overrides: Vec::new(),
            base_dir: None,
            root: root.clone(),
        };

        add_to_supplementary_groups(&opts, &root.group_path(), &root.gshadow_path())
            .expect("add to groups");

        // Verify.
        let updated = group::read_group_file(&root.group_path()).expect("re-read");
        let wheel_entry = updated.iter().find(|g| g.name == "wheel").expect("wheel");
        assert!(wheel_entry.members.contains(&"testuser".to_string()));
        let users_entry = updated.iter().find(|g| g.name == "users").expect("users");
        assert!(users_entry.members.contains(&"testuser".to_string()));
    }

    #[test]
    fn test_integration_home_directory_creation() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home/testuser");
        let skel = dir.path().join("skel");

        // Parent of home must exist (create_dir is intentionally used, not create_dir_all).
        fs::create_dir_all(dir.path().join("home")).expect("create home parent");

        // Create skeleton directory with a file.
        fs::create_dir_all(&skel).expect("create skel");
        fs::write(skel.join(".bashrc"), "# bashrc\n").expect("write bashrc");

        create_home_directory(&home, &skel, 1000, 1000, 0o700).expect("create home");

        assert!(home.exists());
        assert!(home.join(".bashrc").exists());

        // Check permissions.
        let meta = fs::metadata(&home).expect("metadata");
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }

    /// Local RAII guard used by the umask regression test.
    struct UmaskRestore(rustix::fs::Mode);
    impl Drop for UmaskRestore {
        fn drop(&mut self) {
            rustix::process::umask(self.0);
        }
    }

    /// Serialize tests that mutate process-global umask. Without this, parallel
    /// cargo test runs can leak umask=0 to unrelated tests creating files.
    static UMASK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_integration_home_directory_ignores_inherited_umask() {
        // Regression test for #157: an inherited umask must not weaken the
        // home directory's final mode. Note that this test asserts the *final*
        // mode after `create_home_directory` returns; it does not directly
        // observe the mkdir(2) syscall, so a pre-fix implementation that did
        // `mkdir(0o777)` followed by `chmod(0o700)` would also pass. The
        // atomicity guarantee — mode set in the mkdir syscall itself, not
        // after — is enforced by inspection of `DirBuilder::mode(0o700)` in
        // the implementation. Catching the window directly would require
        // strace / ptrace / eBPF, which is out of scope for a unit test.
        if skip_unless_root() {
            return;
        }

        // Hold the umask lock for the duration of the test so parallel
        // cargo test runs don't observe our umask=0 in unrelated file ops.
        let _serialize = UMASK_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home/testuser");
        let skel = dir.path().join("skel");
        fs::create_dir_all(dir.path().join("home")).expect("create home parent");
        fs::create_dir_all(&skel).expect("create skel");

        // Set process umask to zero (most permissive setting), then create
        // the home dir. The guard inside create_home_directory also sets
        // umask to zero for the duration of the mkdir; this test asserts the
        // final directory mode. `_restore` puts back the previously active
        // umask when this scope exits.
        let _restore = UmaskRestore(rustix::process::umask(rustix::fs::Mode::empty()));

        create_home_directory(&home, &skel, 1000, 1000, 0o700).expect("create home");

        let meta = fs::metadata(&home).expect("metadata");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o700,
            "home directory must be 0o700 even with permissive umask",
        );
    }

    #[test]
    fn test_integration_home_already_exists() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home/existing");

        fs::create_dir_all(&home).expect("create home");

        // Should succeed with a warning, not copy skel.
        create_home_directory(&home, Path::new("/nonexistent/skel"), 1000, 1000, 0o700)
            .expect("should succeed for existing home");
    }

    // -----------------------------------------------------------------------
    // Determine GID tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_determine_gid_with_explicit_group() {
        let groups = vec![GroupEntry {
            name: "staff".into(),
            passwd: "x".into(),
            gid: 50,
            members: vec![],
        }];
        let defs = LoginDefs::load(Path::new("/nonexistent")).expect("defs");

        let opts = UseraddOptions {
            login: "newuser".into(),
            comment: String::new(),
            home_dir: None,
            shell: "/bin/bash".into(),
            uid: None,
            gid: Some("staff".into()),
            groups: vec![],
            create_home: false,
            skel_dir: "/etc/skel".into(),
            system: false,
            non_unique: false,
            password: "!".into(),
            inactive: None,
            expire_date: None,
            create_user_group: false,
            login_defs_overrides: Vec::new(),
            base_dir: None,
            root: SysRoot::default(),
        };

        let (gid, new_grp) = determine_gid(&opts, 1000, &groups, &defs).expect("should resolve");
        assert_eq!(gid, 50);
        assert!(new_grp.is_none());
    }

    #[test]
    fn test_determine_gid_create_user_group() {
        let groups = vec![GroupEntry {
            name: "root".into(),
            passwd: "x".into(),
            gid: 0,
            members: vec![],
        }];
        let defs = LoginDefs::load(Path::new("/nonexistent")).expect("defs");

        let opts = UseraddOptions {
            login: "alice".into(),
            comment: String::new(),
            home_dir: None,
            shell: "/bin/bash".into(),
            uid: None,
            gid: None,
            groups: vec![],
            create_home: false,
            skel_dir: "/etc/skel".into(),
            system: false,
            non_unique: false,
            password: "!".into(),
            inactive: None,
            expire_date: None,
            create_user_group: true,
            login_defs_overrides: Vec::new(),
            base_dir: None,
            root: SysRoot::default(),
        };

        let (gid, new_grp) =
            determine_gid(&opts, 1000, &groups, &defs).expect("should create user group");
        // UID 1000 is not taken as a GID, so GID should match UID.
        assert_eq!(gid, 1000);
        let grp = new_grp.expect("should have created a group");
        assert_eq!(grp.name, "alice");
        assert_eq!(grp.gid, 1000);
    }

    #[test]
    fn test_determine_gid_user_group_name_collision() {
        let groups = vec![GroupEntry {
            name: "alice".into(),
            passwd: "x".into(),
            gid: 500,
            members: vec![],
        }];
        let defs = LoginDefs::load(Path::new("/nonexistent")).expect("defs");

        let opts = UseraddOptions {
            login: "alice".into(),
            comment: String::new(),
            home_dir: None,
            shell: "/bin/bash".into(),
            uid: None,
            gid: None,
            groups: vec![],
            create_home: false,
            skel_dir: "/etc/skel".into(),
            system: false,
            non_unique: false,
            password: "!".into(),
            inactive: None,
            expire_date: None,
            create_user_group: true,
            login_defs_overrides: Vec::new(),
            base_dir: None,
            root: SysRoot::default(),
        };

        let result = determine_gid(&opts, 1000, &groups, &defs);
        assert!(result.is_err());
    }

    #[test]
    fn test_determine_gid_no_user_group_default() {
        let groups: Vec<GroupEntry> = vec![];
        let defs = LoginDefs::load(Path::new("/nonexistent")).expect("defs");

        let opts = UseraddOptions {
            login: "user".into(),
            comment: String::new(),
            home_dir: None,
            shell: "/bin/bash".into(),
            uid: None,
            gid: None,
            groups: vec![],
            create_home: false,
            skel_dir: "/etc/skel".into(),
            system: false,
            non_unique: false,
            password: "!".into(),
            inactive: None,
            expire_date: None,
            create_user_group: false,
            login_defs_overrides: Vec::new(),
            base_dir: None,
            root: SysRoot::default(),
        };

        let (gid, new_grp) =
            determine_gid(&opts, 1000, &groups, &defs).expect("should use default");
        assert_eq!(gid, 100); // Default USERS_GID.
        assert!(new_grp.is_none());
    }

    // -----------------------------------------------------------------------
    // Determine UID tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_determine_uid_explicit() {
        let entries: Vec<PasswdEntry> = vec![];
        let defs = LoginDefs::load(Path::new("/nonexistent")).expect("defs");

        let opts = UseraddOptions {
            login: "user".into(),
            comment: String::new(),
            home_dir: None,
            shell: "/bin/bash".into(),
            uid: Some(5000),
            gid: None,
            groups: vec![],
            create_home: false,
            skel_dir: "/etc/skel".into(),
            system: false,
            non_unique: false,
            password: "!".into(),
            inactive: None,
            expire_date: None,
            create_user_group: false,
            login_defs_overrides: Vec::new(),
            base_dir: None,
            root: SysRoot::default(),
        };

        let uid = determine_uid(&opts, &entries, &defs).expect("should succeed");
        assert_eq!(uid, 5000);
    }

    #[test]
    fn test_determine_uid_duplicate_rejected() {
        let entries = vec![PasswdEntry {
            name: "existing".into(),
            passwd: "x".into(),
            uid: 5000,
            gid: 5000,
            gecos: String::new(),
            home: "/home/existing".into(),
            shell: "/bin/bash".into(),
        }];
        let defs = LoginDefs::load(Path::new("/nonexistent")).expect("defs");

        let opts = UseraddOptions {
            login: "user".into(),
            comment: String::new(),
            home_dir: None,
            shell: "/bin/bash".into(),
            uid: Some(5000),
            gid: None,
            groups: vec![],
            create_home: false,
            skel_dir: "/etc/skel".into(),
            system: false,
            non_unique: false,
            password: "!".into(),
            inactive: None,
            expire_date: None,
            create_user_group: false,
            login_defs_overrides: Vec::new(),
            base_dir: None,
            root: SysRoot::default(),
        };

        let result = determine_uid(&opts, &entries, &defs);
        assert!(result.is_err());
    }

    #[test]
    fn test_determine_uid_duplicate_allowed_with_non_unique() {
        let entries = vec![PasswdEntry {
            name: "existing".into(),
            passwd: "x".into(),
            uid: 5000,
            gid: 5000,
            gecos: String::new(),
            home: "/home/existing".into(),
            shell: "/bin/bash".into(),
        }];
        let defs = LoginDefs::load(Path::new("/nonexistent")).expect("defs");

        let opts = UseraddOptions {
            login: "user".into(),
            comment: String::new(),
            home_dir: None,
            shell: "/bin/bash".into(),
            uid: Some(5000),
            gid: None,
            groups: vec![],
            create_home: false,
            skel_dir: "/etc/skel".into(),
            system: false,
            non_unique: true,
            password: "!".into(),
            inactive: None,
            expire_date: None,
            create_user_group: false,
            login_defs_overrides: Vec::new(),
            base_dir: None,
            root: SysRoot::default(),
        };

        let uid = determine_uid(&opts, &entries, &defs).expect("should allow duplicate");
        assert_eq!(uid, 5000);
    }

    // -----------------------------------------------------------------------
    // -K / login.defs override tests
    // -----------------------------------------------------------------------

    fn empty_defs() -> LoginDefs {
        LoginDefs::load(Path::new("/nonexistent")).expect("empty defs")
    }

    fn opts_for_uid_alloc(system: bool) -> UseraddOptions {
        UseraddOptions {
            login: "user".into(),
            comment: String::new(),
            home_dir: None,
            shell: "/bin/bash".into(),
            uid: None,
            gid: None,
            groups: vec![],
            create_home: false,
            skel_dir: "/etc/skel".into(),
            system,
            non_unique: false,
            password: "!".into(),
            inactive: None,
            expire_date: None,
            create_user_group: false,
            login_defs_overrides: Vec::new(),
            base_dir: None,
            root: SysRoot::default(),
        }
    }

    #[test]
    fn test_parse_login_defs_overrides_valid() {
        let m = uu_app()
            .try_get_matches_from([
                "useradd",
                "-K",
                "UID_MIN=9100",
                "-K",
                "PASS_MAX_DAYS=-1",
                "user",
            ])
            .expect("parse args");
        let overrides = parse_login_defs_overrides(&m).expect("valid KEY=VALUE");
        assert_eq!(
            overrides,
            vec![
                ("UID_MIN".into(), "9100".into()),
                ("PASS_MAX_DAYS".into(), "-1".into()),
            ]
        );
    }

    #[test]
    fn test_parse_login_defs_overrides_rejects_missing_equals() {
        let m = uu_app()
            .try_get_matches_from(["useradd", "-K", "UID_MIN", "user"])
            .expect("clap accepts raw value");
        let err = parse_login_defs_overrides(&m).expect_err("missing '='");
        assert!(matches!(err, UseraddError::BadArgument(_)));
    }

    #[test]
    fn test_parse_login_defs_overrides_rejects_empty_key() {
        let m = uu_app()
            .try_get_matches_from(["useradd", "-K", "=9100", "user"])
            .expect("clap accepts raw value");
        let err = parse_login_defs_overrides(&m).expect_err("empty key");
        assert!(matches!(err, UseraddError::BadArgument(_)));
    }

    #[test]
    fn test_defaults_honors_key_overrides() {
        let dir = tempfile::tempdir().expect("temp dir");
        let etc = dir.path().join("etc");
        fs::create_dir_all(&etc).expect("etc dir");
        fs::write(etc.join("login.defs"), "HOME /home\nSHELL /bin/sh\n").expect("login.defs");

        let root = dir.path().to_str().expect("utf-8 temp path");
        let m = uu_app()
            .try_get_matches_from([
                "useradd",
                "-R",
                root,
                "-D",
                "-K",
                "HOME=/OVERRIDDEN",
                "-K",
                "SHELL=/bin/zsh",
            ])
            .expect("parse -D -K");

        let mut buf = Vec::new();
        write_defaults(&m, &mut buf).expect("write defaults");
        let output = String::from_utf8(buf).expect("utf-8 defaults output");
        assert!(
            output.lines().any(|l| l == "HOME=/OVERRIDDEN"),
            "expected HOME override in -D output, got: {output}"
        );
        assert!(
            output.lines().any(|l| l == "SHELL=/bin/zsh"),
            "expected SHELL override in -D output, got: {output}"
        );
    }

    #[test]
    fn test_apply_login_defs_overrides_updates_table() {
        let mut defs = empty_defs();
        apply_login_defs_overrides(
            &mut defs,
            &[
                ("UID_MIN".into(), "9100".into()),
                ("PASS_MAX_DAYS".into(), "-1".into()),
            ],
        );
        assert_eq!(defs.get("UID_MIN"), Some("9100"));
        assert_eq!(defs.get_i64("PASS_MAX_DAYS"), Some(-1));
    }

    #[test]
    fn test_determine_uid_honors_uid_range_overrides() {
        let entries: Vec<PasswdEntry> = vec![];
        let mut defs = empty_defs();
        apply_login_defs_overrides(
            &mut defs,
            &[
                ("UID_MIN".into(), "9100".into()),
                ("UID_MAX".into(), "9100".into()),
            ],
        );
        let opts = opts_for_uid_alloc(false);
        let uid = determine_uid(&opts, &entries, &defs).expect("allocate");
        assert_eq!(uid, 9100);
    }

    #[test]
    fn test_determine_uid_honors_sys_uid_range_for_system() {
        let entries: Vec<PasswdEntry> = vec![];
        let mut defs = empty_defs();
        apply_login_defs_overrides(
            &mut defs,
            &[
                ("SYS_UID_MIN".into(), "250".into()),
                ("SYS_UID_MAX".into(), "250".into()),
            ],
        );
        let opts = opts_for_uid_alloc(true);
        let uid = determine_uid(&opts, &entries, &defs).expect("allocate system");
        assert_eq!(uid, 250);
    }

    #[test]
    fn test_determine_uid_sys_override_does_not_affect_regular() {
        let entries: Vec<PasswdEntry> = vec![];
        let mut defs = empty_defs();
        // Only system-range keys: regular allocation still uses UID_MIN default.
        apply_login_defs_overrides(
            &mut defs,
            &[
                ("SYS_UID_MIN".into(), "250".into()),
                ("SYS_UID_MAX".into(), "250".into()),
            ],
        );
        let opts = opts_for_uid_alloc(false);
        let uid = determine_uid(&opts, &entries, &defs).expect("allocate regular");
        assert_eq!(uid, 1000);
    }

    #[test]
    fn test_determine_gid_honors_gid_range_overrides() {
        let groups = vec![GroupEntry {
            name: "taken".into(),
            passwd: "x".into(),
            gid: 9200,
            members: vec![],
        }];
        let mut defs = empty_defs();
        apply_login_defs_overrides(
            &mut defs,
            &[
                ("GID_MIN".into(), "9201".into()),
                ("GID_MAX".into(), "9201".into()),
            ],
        );
        // Prefer same-as-UID is blocked (9200 taken), so allocate from range.
        let opts = UseraddOptions {
            login: "newgrp".into(),
            comment: String::new(),
            home_dir: None,
            shell: "/bin/bash".into(),
            uid: Some(9200),
            gid: None,
            groups: vec![],
            create_home: false,
            skel_dir: "/etc/skel".into(),
            system: false,
            non_unique: false,
            password: "!".into(),
            inactive: None,
            expire_date: None,
            create_user_group: true,
            login_defs_overrides: Vec::new(),
            base_dir: None,
            root: SysRoot::default(),
        };
        let (gid, new_group) = determine_gid(&opts, 9200, &groups, &defs).expect("gid");
        assert_eq!(gid, 9201);
        assert!(new_group.is_some());
    }
}
