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
use std::io::Write as _;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use clap::{Arg, ArgAction, Command};

use shadow_core::atomic;
use shadow_core::audit;
use shadow_core::group::{self, GroupEntry};
use shadow_core::gshadow::{self, GshadowEntry};
use shadow_core::lock::FileLock;
use shadow_core::login_defs::LoginDefs;
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
    /// Sentinel used when the error has already been printed (e.g. by clap).
    AlreadyPrinted(i32),
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
            Self::AlreadyPrinted(_) => Ok(()),
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
            Self::AlreadyPrinted(code) => *code,
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
    if s.is_empty() || s == "-1" {
        return Ok(None);
    }

    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return Err(UseraddError::BadArgument(format!(
            "invalid date '{s}' (expected YYYY-MM-DD)"
        )));
    }

    let year: i64 = parts[0].parse().map_err(|_| {
        UseraddError::BadArgument(format!("invalid date '{s}' (expected YYYY-MM-DD)"))
    })?;
    let month: i64 = parts[1].parse().map_err(|_| {
        UseraddError::BadArgument(format!("invalid date '{s}' (expected YYYY-MM-DD)"))
    })?;
    let day: i64 = parts[2].parse().map_err(|_| {
        UseraddError::BadArgument(format!("invalid date '{s}' (expected YYYY-MM-DD)"))
    })?;

    if !(1..=12).contains(&month) || year < 1970 {
        return Err(UseraddError::BadArgument(format!(
            "invalid date '{s}' (expected YYYY-MM-DD with valid ranges)"
        )));
    }

    let max_day = days_in_month(year, month);
    if !(1..=max_day).contains(&day) {
        return Err(UseraddError::BadArgument(format!(
            "invalid date '{s}' (day {day} out of range for month {month})"
        )));
    }

    // Convert to days since epoch using a simple calendar calculation.
    // This is sufficient for the date ranges used by shadow-utils.
    let days = days_since_epoch(year, month, day);
    Ok(Some(days))
}

/// Calculate days since Unix epoch (1970-01-01) for a given date.
///
/// Uses the algorithm from <https://howardhinnant.github.io/date_algorithms.html>.
fn days_since_epoch(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };

    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Whether `year` is a leap year in the Gregorian calendar.
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Number of days in a given month (1-indexed) for `year`.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        // Month range is already validated before calling this function.
        _ => 0,
    }
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

    let matches = match uu_app().try_get_matches_from(args) {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            if !e.use_stderr() {
                return Ok(());
            }
            return Err(match e.kind() {
                clap::error::ErrorKind::ArgumentConflict
                | clap::error::ErrorKind::MissingRequiredArgument => {
                    UseraddError::AlreadyPrinted(2).into()
                }
                _ => UseraddError::AlreadyPrinted(2).into(),
            });
        }
    };

    // Only root can add users.
    if !shadow_core::hardening::caller_is_root() {
        uucore::show_error!("Permission denied.");
        return Err(UseraddError::AlreadyPrinted(1).into());
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
fn cmd_defaults(_matches: &clap::ArgMatches) -> UResult<()> {
    // Read login.defs for defaults.
    let root = SysRoot::default();
    let defs = LoginDefs::load(&root.login_defs_path())
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    let default_home = defs.get("HOME").unwrap_or("/home");
    let default_inactive = defs.get("INACTIVE").unwrap_or("-1");
    let default_expire = defs.get("EXPIRE").unwrap_or("");
    let default_shell = defs.get("SHELL").unwrap_or("");
    let default_skel = defs.get("SKEL").unwrap_or("/etc/skel");
    let default_create_mail = defs.get("CREATE_MAIL_SPOOL").unwrap_or("no");

    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "GROUP=100");
    let _ = writeln!(out, "HOME={default_home}");
    let _ = writeln!(out, "INACTIVE={default_inactive}");
    let _ = writeln!(out, "EXPIRE={default_expire}");
    let _ = writeln!(out, "SHELL={default_shell}");
    let _ = writeln!(out, "SKEL={default_skel}");
    let _ = writeln!(out, "CREATE_MAIL_SPOOL={default_create_mail}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Option parsing
// ---------------------------------------------------------------------------

/// Parse CLI arguments into `UseraddOptions`.
#[allow(clippy::too_many_lines)]
fn parse_options(matches: &clap::ArgMatches) -> Result<UseraddOptions, UseraddError> {
    let login = matches
        .get_one::<String>(options::LOGIN)
        .ok_or_else(|| UseraddError::BadSyntax("login name required".into()))?
        .clone();

    let root_dir = matches.get_one::<String>(options::ROOT);
    let root = SysRoot::new(root_dir.map(Path::new));

    let comment = matches
        .get_one::<String>(options::COMMENT)
        .cloned()
        .unwrap_or_default();

    let home_dir = matches.get_one::<String>(options::HOME_DIR).cloned();

    let defs = LoginDefs::load(&root.login_defs_path())
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    let shell = matches
        .get_one::<String>(options::SHELL)
        .cloned()
        .unwrap_or_else(|| defs.get("SHELL").unwrap_or("/bin/sh").to_string());

    let uid = match matches.get_one::<String>(options::UID) {
        Some(s) => {
            let val = s
                .parse::<u32>()
                .map_err(|_| UseraddError::BadArgument(format!("invalid UID '{s}'")))?;
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

    let system = matches.get_flag(options::SYSTEM);

    // Determine create-home: -m sets it, -M clears it, default depends on login.defs
    let explicit_create = matches.get_flag(options::CREATE_HOME);
    let explicit_no_create = matches.get_flag(options::NO_CREATE_HOME);
    let create_home = if explicit_create {
        true
    } else if explicit_no_create {
        false
    } else {
        defs.get("CREATE_HOME")
            .is_some_and(|v| v.eq_ignore_ascii_case("yes"))
    };

    let skel_dir = matches
        .get_one::<String>(options::SKEL)
        .cloned()
        .unwrap_or_else(|| defs.get("SKEL").unwrap_or("/etc/skel").to_string());

    let non_unique = matches.get_flag(options::NON_UNIQUE);

    let password = matches
        .get_one::<String>(options::PASSWORD)
        .cloned()
        .unwrap_or_else(|| "!".to_string());

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
    let passwd_entries = passwd::read_passwd_file(&passwd_path)
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    if passwd_entries.iter().any(|e| e.name == opts.login) {
        drop(group_lock);
        drop(passwd_lock);
        return Err(
            UseraddError::UsernameInUse(format!("user '{}' already exists", opts.login)).into(),
        );
    }

    // Step 4: Load login.defs for UID/GID ranges.
    let defs = LoginDefs::load(&opts.root.login_defs_path())
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    // Step 5: Determine UID.
    let uid = determine_uid(opts, &passwd_entries, &defs)?;

    // Step 6: Read group entries under lock (needed for GID resolution and
    // user group creation).
    let mut group_entries = group::read_group_file(&group_path)
        .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

    // Step 7: Determine primary GID.
    let (gid, new_group) = determine_gid(opts, uid, &group_entries, &defs)?;

    // Step 8: Read gshadow entries.
    let gshadow_path = opts.root.gshadow_path();
    let mut gshadow_entries = if gshadow_path.exists() {
        gshadow::read_gshadow_file(&gshadow_path)
            .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?
    } else {
        Vec::new()
    };

    // Step 9: Validate supplementary groups exist.
    for grp_name in &opts.groups {
        if !group_entries.iter().any(|g| g.name == *grp_name) {
            drop(group_lock);
            drop(passwd_lock);
            return Err(
                UseraddError::GroupNotExist(format!("group '{grp_name}' does not exist")).into(),
            );
        }
    }

    // Step 10: Determine home directory path.
    let home_dir = opts.home_dir.clone().unwrap_or_else(|| {
        let home_base = defs.get("HOME").unwrap_or("/home");
        format!("{home_base}/{}", opts.login)
    });

    // -------------------------------------------------------------------
    // Begin mutations. From here, partial state is left on failure
    // (matching GNU behavior). Locks are held throughout.
    // -------------------------------------------------------------------

    // Step 11: Create user group if needed (group lock already held).
    if let Some(ref new_grp) = new_group {
        write_new_group(&group_path, &mut group_entries, new_grp)?;
        if gshadow_path.exists() {
            // Acquire gshadow lock — group.lock does NOT protect gshadow.
            let _gs_lock = FileLock::acquire(&gshadow_path).map_err(|e| {
                UseraddError::CannotUpdateGroup(format!("cannot lock gshadow: {e}"))
            })?;
            write_new_gshadow(&gshadow_path, &mut gshadow_entries, new_grp)?;
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
    write_passwd_entry(&passwd_path, &passwd_entries, &passwd_entry)?;

    // Step 13: Write /etc/shadow entry (passwd+group locks still held).
    let shadow_path = opts.root.shadow_path();
    let shadow_entry = ShadowEntry {
        name: opts.login.clone(),
        passwd: opts.password.clone(),
        last_change: Some(today_days_since_epoch()?),
        min_age: defs.get_i64("PASS_MIN_DAYS").or(Some(0)),
        max_age: defs.get_i64("PASS_MAX_DAYS").or(Some(99999)),
        warn_days: defs.get_i64("PASS_WARN_AGE").or(Some(7)),
        inactive_days: opts.inactive,
        expire_date: opts.expire_date,
        reserved: String::new(),
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
    let subuid_path = opts.root.subuid_path();
    if subuid_path.exists()
        && let Err(e) = append_subid_entry(&subuid_path, &opts.login, 65_536)
    {
        uucore::show_error!("warning: failed to add subordinate UID range: {e}");
    }
    let subgid_path = opts.root.subgid_path();
    if subgid_path.exists()
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
        create_home_directory(&resolved_home, &resolved_skel, uid, gid)?;
    }

    // Step 17: Invalidate nscd caches.
    nscd::invalidate_cache("passwd");
    nscd::invalidate_cache("group");

    // Step 18: Audit log.
    audit::log_user_event("ADD_USER", &opts.login, uid, true);

    Ok(())
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
    // Try as numeric GID first.
    if let Ok(gid) = gid_arg.parse::<u32>() {
        return Ok(gid);
    }

    // Look up by name.
    group_entries
        .iter()
        .find(|g| g.name == gid_arg)
        .map(|g| g.gid)
        .ok_or_else(|| UseraddError::GroupNotExist(format!("group '{gid_arg}' does not exist")))
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
    new_group: &GroupEntry,
) -> UResult<()> {
    group_entries.push(new_group.clone());

    atomic::atomic_write(group_path, |f| group::write_group(group_entries, f))
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
    new_group: &GroupEntry,
) -> UResult<()> {
    gshadow_entries.push(GshadowEntry {
        name: new_group.name.clone(),
        passwd: "!".to_string(),
        admins: Vec::new(),
        members: Vec::new(),
    });

    atomic::atomic_write(gshadow_path, |f| gshadow::write_gshadow(gshadow_entries, f))
        .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

    Ok(())
}

/// Append a new passwd entry to `/etc/passwd`.
///
/// Caller must hold the passwd file lock.
fn write_passwd_entry(
    passwd_path: &Path,
    existing: &[PasswdEntry],
    new_entry: &PasswdEntry,
) -> UResult<()> {
    let mut entries: Vec<PasswdEntry> = existing.to_vec();
    entries.push(new_entry.clone());

    atomic::atomic_write(passwd_path, |f| passwd::write_passwd(&entries, f))
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    Ok(())
}

/// Append a new shadow entry to `/etc/shadow` with proper locking.
fn write_shadow_entry(shadow_path: &Path, new_entry: &ShadowEntry) -> UResult<()> {
    let _lock = FileLock::acquire(shadow_path)
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    // Read existing entries; if the file does not exist, start fresh.
    let mut entries = if shadow_path.exists() {
        shadow::read_shadow_file(shadow_path)
            .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?
    } else {
        Vec::new()
    };

    entries.push(new_entry.clone());

    atomic::atomic_write(shadow_path, |f| shadow::write_shadow(&entries, f))
        .map_err(|e| UseraddError::CannotUpdatePasswd(format!("{e}")))?;

    Ok(())
}

/// Add the user to supplementary groups in `/etc/group` and `/etc/gshadow`.
fn add_to_supplementary_groups(
    opts: &UseraddOptions,
    group_path: &Path,
    gshadow_path: &Path,
) -> UResult<()> {
    let _lock = FileLock::acquire(group_path)
        .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

    let mut entries = group::read_group_file(group_path)
        .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

    for entry in &mut entries {
        if opts.groups.contains(&entry.name) && !entry.members.contains(&opts.login) {
            entry.members.push(opts.login.clone());
        }
    }

    atomic::atomic_write(group_path, |f| group::write_group(&entries, f))
        .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

    // Also update gshadow if it exists.
    if gshadow_path.exists() {
        let _gs_lock = FileLock::acquire(gshadow_path)
            .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

        let mut gs_entries = gshadow::read_gshadow_file(gshadow_path)
            .map_err(|e| UseraddError::CannotUpdateGroup(format!("{e}")))?;

        for entry in &mut gs_entries {
            if opts.groups.contains(&entry.name) && !entry.members.contains(&opts.login) {
                entry.members.push(opts.login.clone());
            }
        }

        atomic::atomic_write(gshadow_path, |f| gshadow::write_gshadow(&gs_entries, f))
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

    let mut entries = match subid::read_subid_file(path) {
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

    atomic::atomic_write(path, |f| subid::write_subid(&entries, f))
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
fn create_home_directory(home_path: &Path, skel_path: &Path, uid: u32, gid: u32) -> UResult<()> {
    // The kernel does not reset umask across setuid, so a caller-controlled
    // inherited umask may still be in effect in our process. A non-zero umask
    // can mask off requested permission bits, so even mkdir(0o700) is not
    // guaranteed to result in 0o700 unless we clear it first (e.g., umask
    // 0o700 would mask the user RWX bits and leave the dir at 0o000).
    // Forcing umask to 0 makes the requested mode exact, regardless of caller
    // environment; umask can only make the result less permissive than the
    // mode we requested, never more. Scoped to the mkdir call only — chown
    // doesn't need it, and copy_skel manages its own umask internally.
    let mkdir_result = {
        let _umask = shadow_core::atomic::UmaskGuard::zero();
        std::fs::DirBuilder::new().mode(0o700).create(home_path)
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

    // The directory is 0o700 owned by root at this point — only root can
    // traverse it, so the chown that follows transfers a private dir.
    std::os::unix::fs::chown(home_path, Some(uid), Some(gid)).map_err(|e| {
        UseraddError::CannotCreateHome(format!(
            "cannot set ownership on '{}': {e}",
            home_path.display()
        ))
    })?;

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
            Arg::new(options::ROOT)
                .short('R')
                .long("root")
                .value_name("CHROOT_DIR")
                .help("Chroot into CHROOT_DIR before applying changes"),
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

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
    }

    #[test]
    fn test_days_in_month_values() {
        assert_eq!(days_in_month(2025, 1), 31);
        assert_eq!(days_in_month(2025, 2), 28);
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2025, 4), 30);
        assert_eq!(days_in_month(2025, 12), 31);
    }

    #[test]
    fn test_days_since_epoch_known_dates() {
        // 1970-01-01 = day 0
        assert_eq!(days_since_epoch(1970, 1, 1), 0);
        // 2000-01-01 = day 10957
        assert_eq!(days_since_epoch(2000, 1, 1), 10957);
        // 1970-01-02 = day 1
        assert_eq!(days_since_epoch(1970, 1, 2), 1);
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

        let passwd_entries = passwd::read_passwd_file(&root.passwd_path()).expect("read passwd");
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
        let groups: Vec<GroupEntry> = vec![];
        assert_eq!(resolve_group("500", &groups).expect("numeric"), 500);
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

        let passwd_entries = passwd::read_passwd_file(&root.passwd_path()).expect("passwd");
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

        write_passwd_entry(&root.passwd_path(), &passwd_entries, &new_entry).expect("write passwd");

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

        let mut group_entries = group::read_group_file(&root.group_path()).expect("group");
        let mut gshadow_entries =
            gshadow::read_gshadow_file(&root.gshadow_path()).expect("gshadow");

        // Create user group.
        let new_group = GroupEntry {
            name: "newuser".into(),
            passwd: "x".into(),
            gid: 1000,
            members: Vec::new(),
        };

        write_new_group(&root.group_path(), &mut group_entries, &new_group).expect("write group");
        write_new_gshadow(&root.gshadow_path(), &mut gshadow_entries, &new_group)
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
        let mut group_entries = group::read_group_file(&root.group_path()).expect("group");
        let wheel = GroupEntry {
            name: "wheel".into(),
            passwd: "x".into(),
            gid: 10,
            members: Vec::new(),
        };
        write_new_group(&root.group_path(), &mut group_entries, &wheel).expect("add wheel");

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

        create_home_directory(&home, &skel, 1000, 1000).expect("create home");

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

        create_home_directory(&home, &skel, 1000, 1000).expect("create home");

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
        create_home_directory(&home, Path::new("/nonexistent/skel"), 1000, 1000)
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
            root: SysRoot::default(),
        };

        let uid = determine_uid(&opts, &entries, &defs).expect("should allow duplicate");
        assert_eq!(uid, 5000);
    }
}
