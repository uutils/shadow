// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore gpasswd gshadow nscd sysroot yescrypt

//! `gpasswd` — administer `/etc/group` and `/etc/gshadow`.
//!
//! Drop-in replacement for GNU shadow-utils `gpasswd(1)`.

use std::fmt;
use std::io::{self, Write as _};
use std::path::Path;

use clap::{Arg, ArgAction, ArgGroup, Command};
use uucore::error::{UError, UResult};

use shadow_core::audit;
use shadow_core::crypt;
use shadow_core::group::GroupEntry;
use shadow_core::gshadow::{self, GshadowEntry};
use shadow_core::login_defs::LoginDefs;
use shadow_core::nscd;
use shadow_core::passwd;
use shadow_core::sysroot::SysRoot;
use shadow_core::transaction::{self, Commit, LockedFile};

mod options {
    pub const GROUP: &str = "GROUP";
    pub const ADD: &str = "add";
    pub const DELETE: &str = "delete";
    pub const ADMINISTRATORS: &str = "administrators";
    pub const MEMBERS: &str = "members";
    pub const REMOVE_PASSWORD: &str = "remove-password";
    pub const RESTRICT: &str = "restrict";
    pub const ROOT: &str = "root";
    pub const PREFIX: &str = "prefix";
}

mod exit_codes {
    pub const FAILURE: i32 = 1;
    pub const BAD_SYNTAX: i32 = 2;
    pub const BAD_ARGUMENT: i32 = 3;
    pub const CANT_UPDATE: i32 = 10;
    pub const GSHADOW_REQUIRED: i32 = 17;
}

#[derive(Debug)]
enum GpasswdError {
    Failure(String),
    BadSyntax(String),
    BadArgument(String),
    CantUpdate(String),
    GshadowRequired(String),
}

impl fmt::Display for GpasswdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failure(msg)
            | Self::BadSyntax(msg)
            | Self::BadArgument(msg)
            | Self::CantUpdate(msg)
            | Self::GshadowRequired(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for GpasswdError {}

impl UError for GpasswdError {
    fn code(&self) -> i32 {
        match self {
            Self::Failure(_) => exit_codes::FAILURE,
            Self::BadSyntax(_) => exit_codes::BAD_SYNTAX,
            Self::BadArgument(_) => exit_codes::BAD_ARGUMENT,
            Self::CantUpdate(_) => exit_codes::CANT_UPDATE,
            Self::GshadowRequired(_) => exit_codes::GSHADOW_REQUIRED,
        }
    }
}

/// Parsed request. `-A` and `-M` may be combined; every other action is exclusive.
struct Request {
    add_user: Option<String>,
    del_user: Option<String>,
    set_admins: Option<Vec<String>>,
    set_members: Option<Vec<String>>,
    remove_password: bool,
    restrict: bool,
    new_password_hash: Option<String>,
}

impl Request {
    fn requires_system_admin(&self) -> bool {
        self.set_admins.is_some() || self.set_members.is_some()
    }
}

fn permission_denied() -> UResult<()> {
    uucore::show_error!("{}", shadow_core::os_error::permission_denied());
    Err(shadow_core::cli::AlreadyPrinted(1).into())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    shadow_core::hardening::harden_process();

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| exit_codes::BAD_SYNTAX)?
    else {
        return Ok(());
    };

    // Unlike groupadd/groupmod, gpasswd is setuid: a non-root group
    // administrator may change membership and the group password.
    do_gpasswd(&matches)
}

/// Core logic, separated from argument parsing to keep `uumain` short.
#[allow(clippy::too_many_lines)]
fn do_gpasswd(matches: &clap::ArgMatches) -> UResult<()> {
    let group_name = matches
        .get_one::<String>(options::GROUP)
        .ok_or_else(|| GpasswdError::BadSyntax("group name required".into()))?
        .clone();

    let add_user = matches.get_one::<String>(options::ADD).cloned();
    let del_user = matches.get_one::<String>(options::DELETE).cloned();
    let set_admins = matches
        .get_one::<String>(options::ADMINISTRATORS)
        .map(|s| parse_user_list(s));
    let set_members = matches
        .get_one::<String>(options::MEMBERS)
        .map(|s| parse_user_list(s));
    let remove_password = matches.get_flag(options::REMOVE_PASSWORD);
    let restrict = matches.get_flag(options::RESTRICT);

    let prefix = matches.get_one::<String>(options::PREFIX).map(Path::new);
    let root_dir = matches.get_one::<String>(options::ROOT).map(Path::new);

    if let Some(dir) = root_dir
        && !dir.is_absolute()
    {
        return Err(GpasswdError::BadArgument(format!(
            "invalid chroot path '{}', only absolute paths are supported.",
            dir.display()
        ))
        .into());
    }

    // Except for -A and -M, the options cannot be combined (gpasswd(1)).
    let exclusive_count = u8::from(add_user.is_some())
        + u8::from(del_user.is_some())
        + u8::from(remove_password)
        + u8::from(restrict)
        + u8::from(set_admins.is_some() || set_members.is_some());
    if exclusive_count > 1 {
        return Err(GpasswdError::BadSyntax("invalid combination of options".into()).into());
    }

    let is_root = shadow_core::hardening::caller_is_root();
    // Non-setuid callers cannot write the databases. Setuid non-root
    // callers are group administrators and are checked after the files
    // are read.
    if !is_root && !rustix::process::geteuid().is_root() {
        return permission_denied();
    }

    let mut req = Request {
        add_user,
        del_user,
        set_admins,
        set_members,
        remove_password,
        restrict,
        new_password_hash: None,
    };

    // -A/-M and --root/--prefix are system-administrator operations.
    if !is_root && (req.requires_system_admin() || prefix.is_some() || root_dir.is_some()) {
        return permission_denied();
    }

    let root = SysRoot::new(prefix.or(root_dir));

    // Hash before taking locks so a slow crypt(3) does not stall writers.
    // Peek gshadow first so a non-admin is not prompted at all.
    if exclusive_count == 0 {
        if !is_root && !caller_is_named_admin(&root.gshadow_path(), &group_name)? {
            return permission_denied();
        }
        req.new_password_hash = Some(prompt_and_hash_password(&root, &group_name)?);
    }

    let group_path = root.group_path();
    let gshadow_path = root.gshadow_path();
    let gshadow_exists = gshadow_path.exists();

    if req.set_admins.is_some() && !gshadow_exists {
        return Err(
            GpasswdError::GshadowRequired("shadow group passwords required for -A".into()).into(),
        );
    }

    // Each transaction locks, then reads, and blocks signals for its lifetime.
    // Both are opened before either is written, so a failed gshadow update
    // cannot leave membership only half applied, and the layout keeps the
    // comments and NIS compatibility lines the files carry -- reading entries
    // only and writing them back would erase every comment in /etc/group.
    let mut group_file = LockedFile::<GroupEntry>::open(&group_path).map_err(|e| {
        GpasswdError::CantUpdate(format!("cannot open {}: {e}", group_path.display()))
    })?;

    let mut gshadow_file = if gshadow_exists {
        Some(
            LockedFile::<GshadowEntry>::open(&gshadow_path).map_err(|e| {
                GpasswdError::CantUpdate(format!("cannot open {}: {e}", gshadow_path.display()))
            })?,
        )
    } else {
        None
    };

    let group_entries = group_file.entries_mut();
    let idx = group_entries
        .iter()
        .position(|g| g.name == group_name)
        .ok_or_else(|| {
            GpasswdError::BadArgument(format!("group '{group_name}' does not exist in /etc/group"))
        })?;

    if !is_root {
        let caller = current_caller_name()?;
        let is_admin = gshadow_file
            .as_ref()
            .and_then(|f| f.find(&group_name))
            .is_some_and(|g| is_group_admin(&caller, &g.admins));
        if !is_admin {
            return permission_denied();
        }
    }

    let passwd_path = root.passwd_path();
    let passwd_entries = if passwd_path.exists() {
        passwd::read_passwd_file(&passwd_path).map_err(|e| {
            GpasswdError::CantUpdate(format!("cannot read {}: {e}", passwd_path.display()))
        })?
    } else {
        Vec::new()
    };
    let user_exists = |name: &str| passwd_entries.iter().any(|p| p.name == name);

    if let Some(ref user) = req.add_user {
        require_user_exists(user, user_exists)?;
    }
    if let Some(ref users) = req.set_members {
        for user in users {
            require_user_exists(user, user_exists)?;
        }
    }
    if let Some(ref users) = req.set_admins {
        for user in users {
            require_user_exists(user, user_exists)?;
        }
    }

    // GNU gpasswd always prints the removing line for -d, then fails if the
    // user is not already a member (including names absent from passwd).
    if let Some(ref user) = req.del_user
        && !group_entries[idx].members.iter().any(|m| m == user)
    {
        let _ = writeln!(io::stdout(), "Removing user {user} from group {group_name}");
        return Err(GpasswdError::BadArgument(format!(
            "user '{user}' is not a member of '{group_name}'"
        ))
        .into());
    }

    let entries = group_file.entries_mut();
    let old_group_passwd = entries[idx].passwd.clone();
    apply_group_changes(&mut entries[idx], &req, gshadow_exists);
    let modified_gid = entries[idx].gid;
    let members_for_gshadow = entries[idx].members.clone();

    if let Some(gshadow_file) = gshadow_file.as_mut() {
        let created = gshadow_file.find(&group_name).is_none();
        let gs = ensure_gshadow_entry(
            gshadow_file.entries_mut(),
            &group_name,
            &members_for_gshadow,
            &old_group_passwd,
        );
        apply_gshadow_changes(gs, &req);
        // The password now lives in gshadow, matching GNU when it creates the
        // line.
        if created {
            group_file.entries_mut()[idx].passwd = "x".to_string();
        }
    }

    // Both files are validated before either is written, so a value that
    // would corrupt one cannot leave the pair disagreeing. A commit that
    // would write the same bytes writes nothing, which is why there is no
    // longer a "did anything change" guard here.
    let mut files: Vec<Box<dyn Commit>> = vec![Box::new(group_file)];
    if let Some(gshadow_file) = gshadow_file {
        files.push(Box::new(gshadow_file));
    }
    transaction::commit_all(files)
        .map_err(|e| GpasswdError::CantUpdate(format!("cannot write: {e}")))?;

    nscd::invalidate_cache("group");
    audit::log_user_event("MOD_GROUP", &group_name, modified_gid, true);

    // GNU prints these on stdout, so a script capturing it keeps working.
    let mut out = io::stdout().lock();
    if let Some(ref user) = req.add_user {
        let _ = writeln!(out, "Adding user {user} to group {group_name}");
    }
    if let Some(ref user) = req.del_user {
        let _ = writeln!(out, "Removing user {user} from group {group_name}");
    }

    Ok(())
}

fn require_user_exists(user: &str, user_exists: impl Fn(&str) -> bool) -> Result<(), GpasswdError> {
    if user_exists(user) {
        Ok(())
    } else {
        Err(GpasswdError::BadArgument(format!(
            "user '{user}' does not exist"
        )))
    }
}

fn is_group_admin(username: &str, admins: &[String]) -> bool {
    admins.iter().any(|a| a == username)
}

fn current_caller_name() -> Result<String, GpasswdError> {
    shadow_core::hardening::current_username()
        .map_err(|e| GpasswdError::CantUpdate(format!("cannot determine caller: {e}")))
}

/// Best-effort admin check used before the password prompt so a non-admin
/// is not asked for a password. The locked path re-checks after re-read.
fn caller_is_named_admin(gshadow_path: &Path, group_name: &str) -> Result<bool, GpasswdError> {
    if !gshadow_path.exists() {
        return Ok(false);
    }
    let caller = current_caller_name()?;
    let entries = gshadow::read_gshadow_file(gshadow_path).map_err(|e| {
        GpasswdError::CantUpdate(format!("cannot read {}: {e}", gshadow_path.display()))
    })?;
    Ok(entries
        .iter()
        .find(|g| g.name == group_name)
        .is_some_and(|g| is_group_admin(&caller, &g.admins)))
}

fn parse_user_list(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn add_unique(list: &mut Vec<String>, user: &str) {
    if !list.iter().any(|m| m == user) {
        list.push(user.to_string());
    }
}

fn apply_group_changes(entry: &mut GroupEntry, req: &Request, has_gshadow: bool) {
    if let Some(ref user) = req.add_user {
        add_unique(&mut entry.members, user);
    }
    if let Some(ref user) = req.del_user {
        entry.members.retain(|m| m != user);
    }
    if let Some(ref members) = req.set_members {
        entry.members.clone_from(members);
    }
    if req.remove_password || req.restrict || req.new_password_hash.is_some() {
        if has_gshadow {
            entry.passwd = "x".to_string();
        } else if req.remove_password {
            entry.passwd.clear();
        } else if req.restrict {
            entry.passwd = "!".to_string();
        } else if let Some(ref hash) = req.new_password_hash {
            entry.passwd.clone_from(hash);
        }
    }
}

fn apply_gshadow_changes(entry: &mut GshadowEntry, req: &Request) {
    if let Some(ref user) = req.add_user {
        add_unique(&mut entry.members, user);
    }
    if let Some(ref user) = req.del_user {
        entry.members.retain(|m| m != user);
    }
    if let Some(ref members) = req.set_members {
        entry.members.clone_from(members);
    }
    if let Some(ref admins) = req.set_admins {
        entry.admins.clone_from(admins);
    }
    if req.remove_password {
        entry.passwd.clear();
    }
    if req.restrict {
        entry.passwd = "!".to_string();
    }
    if let Some(ref hash) = req.new_password_hash {
        entry.passwd.clone_from(hash);
    }
}

fn ensure_gshadow_entry<'a>(
    entries: &'a mut Vec<GshadowEntry>,
    name: &str,
    members: &[String],
    passwd: &str,
) -> &'a mut GshadowEntry {
    if let Some(i) = entries.iter().position(|g| g.name == name) {
        return &mut entries[i];
    }
    entries.push(GshadowEntry {
        name: name.to_string(),
        passwd: passwd.to_string(),
        admins: Vec::new(),
        members: members.to_vec(),
    });
    let i = entries.len() - 1;
    &mut entries[i]
}

/// SHA crypt round count from login.defs, per gpasswd(1).
///
/// Unspecified → libc default (`None`). A single bound is used as-is.
/// If both are set, the higher value is used (the man page's rule when
/// `MIN > MAX`, and the stronger of the two otherwise).
fn sha_crypt_rounds(defs: &LoginDefs) -> Option<u32> {
    const ROUNDS_MIN: i64 = 1000;
    const ROUNDS_MAX: i64 = 999_999_999;
    let clamp = |n: i64| u32::try_from(n.clamp(ROUNDS_MIN, ROUNDS_MAX)).unwrap_or(5000);
    match (
        defs.get_i64("SHA_CRYPT_MIN_ROUNDS"),
        defs.get_i64("SHA_CRYPT_MAX_ROUNDS"),
    ) {
        (None, None) => None,
        (Some(n), None) | (None, Some(n)) => Some(clamp(n)),
        (Some(a), Some(b)) => Some(clamp(a.max(b))),
    }
}

fn crypt_method(defs: &LoginDefs) -> crypt::CryptMethod {
    match defs.get("ENCRYPT_METHOD").unwrap_or("SHA512") {
        "SHA256" => crypt::CryptMethod::Sha256,
        "YESCRYPT" => crypt::CryptMethod::Yescrypt,
        _ => crypt::CryptMethod::Sha512,
    }
}

fn prompt_and_hash_password(root: &SysRoot, group_name: &str) -> Result<String, GpasswdError> {
    // Never println!/eprintln!: they panic when the stream is closed, which a
    // setuid-root tool must not do part way through a change.
    let _ = writeln!(io::stderr(), "Changing the password for group {group_name}");

    // The shared helper blocks SIGINT, SIGQUIT and SIGTSTP for the read, so
    // Ctrl-C at the prompt cannot leave the terminal with echo disabled, and
    // it falls back to stderr and stdin where there is no controlling
    // terminal.
    let read = |prompt: &str| {
        shadow_core::tty::read_password(prompt)
            .map_err(|e| GpasswdError::Failure(format!("cannot read the password: {e}")))
    };

    let password = loop {
        let pass1 = read("New Password: ")?;
        let pass2 = read("Re-enter new password: ")?;
        if *pass1 == *pass2 {
            break pass1;
        }
        // GNU gpasswd retries instead of exiting on a mismatch.
        let _ = writeln!(io::stderr(), "They don't match; try again");
    };

    let defs = LoginDefs::load(&root.login_defs_path())
        .map_err(|e| GpasswdError::CantUpdate(format!("cannot read login.defs: {e}")))?;
    let method = crypt_method(&defs);
    let rounds = match method {
        crypt::CryptMethod::Sha256 | crypt::CryptMethod::Sha512 => sha_crypt_rounds(&defs),
        crypt::CryptMethod::Yescrypt => None,
    };
    crypt::hash_password(&password, method, rounds)
        .map_err(|e| GpasswdError::CantUpdate(format!("cannot hash password: {e}")))
}

#[must_use]
pub fn uu_app() -> Command {
    Command::new("gpasswd")
        .about("Administer group membership and the group password")
        .override_usage("gpasswd [options] group")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        .arg(
            Arg::new(options::ADD)
                .short('a')
                .long("add")
                .value_name("USER")
                .help("Add USER to the named group"),
        )
        .arg(
            Arg::new(options::DELETE)
                .short('d')
                .long("delete")
                .value_name("USER")
                .help("Remove USER from the named group"),
        )
        .arg(
            Arg::new(options::ADMINISTRATORS)
                .short('A')
                .long("administrators")
                .value_name("USER,...")
                .help("Set the list of administrative users"),
        )
        .arg(
            Arg::new(options::MEMBERS)
                .short('M')
                .long("members")
                .value_name("USER,...")
                .help("Set the list of group members"),
        )
        .arg(
            Arg::new(options::REMOVE_PASSWORD)
                .short('r')
                .long("remove-password")
                .help("Remove the password from the named group")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::RESTRICT)
                .short('R')
                .long("restrict")
                .help("Restrict access to the named group (password set to !)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            // GNU gpasswd uses -Q for --root (-R is --restrict).
            Arg::new(options::ROOT)
                .short('Q')
                .long("root")
                .value_name("CHROOT_DIR")
                .help("Locate the system files under CHROOT_DIR instead of /"),
        )
        .arg(
            Arg::new(options::PREFIX)
                .short('P')
                .long("prefix")
                .value_name("PREFIX_DIR")
                .help("Directory prefix"),
        )
        .arg(
            Arg::new(options::GROUP)
                .required(true)
                .index(1)
                .help("Group to administer"),
        )
        .group(
            ArgGroup::new("exclusive")
                .args([
                    options::ADD,
                    options::DELETE,
                    options::REMOVE_PASSWORD,
                    options::RESTRICT,
                ])
                .multiple(false),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    #[test]
    fn test_group_required() {
        assert!(uu_app().try_get_matches_from(["gpasswd"]).is_err());
    }

    #[test]
    fn test_add_flag() {
        let m = uu_app()
            .try_get_matches_from(["gpasswd", "-a", "alice", "devs"])
            .expect("valid args");
        assert_eq!(
            m.get_one::<String>(options::ADD).map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            m.get_one::<String>(options::GROUP).map(String::as_str),
            Some("devs")
        );
    }

    #[test]
    fn test_delete_flag() {
        let m = uu_app()
            .try_get_matches_from(["gpasswd", "-d", "bob", "devs"])
            .expect("valid args");
        assert_eq!(
            m.get_one::<String>(options::DELETE).map(String::as_str),
            Some("bob")
        );
    }

    #[test]
    fn test_members_flag() {
        let m = uu_app()
            .try_get_matches_from(["gpasswd", "-M", "a,b", "devs"])
            .expect("valid args");
        assert_eq!(
            m.get_one::<String>(options::MEMBERS).map(String::as_str),
            Some("a,b")
        );
    }

    #[test]
    fn test_admins_and_members_may_combine() {
        let m = uu_app()
            .try_get_matches_from(["gpasswd", "-A", "alice", "-M", "alice,bob", "devs"])
            .expect("-A and -M may be combined");
        assert_eq!(
            m.get_one::<String>(options::ADMINISTRATORS)
                .map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            m.get_one::<String>(options::MEMBERS).map(String::as_str),
            Some("alice,bob")
        );
    }

    #[test]
    fn test_add_and_restrict_are_exclusive() {
        assert!(
            uu_app()
                .try_get_matches_from(["gpasswd", "-a", "alice", "-R", "devs"])
                .is_err()
        );
    }

    #[test]
    fn test_root_short_flag_is_q() {
        let m = uu_app()
            .try_get_matches_from(["gpasswd", "-Q", "/chroot", "-r", "devs"])
            .expect("valid args");
        assert_eq!(
            m.get_one::<String>(options::ROOT).map(String::as_str),
            Some("/chroot")
        );
        assert!(m.get_flag(options::REMOVE_PASSWORD));
    }

    #[test]
    fn test_parse_user_list() {
        assert_eq!(
            parse_user_list("a,b,c"),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert_eq!(
            parse_user_list("a, b ,c"),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert!(parse_user_list("").is_empty());
        assert!(parse_user_list(",,").is_empty());
    }

    #[test]
    fn test_is_group_admin() {
        let admins = vec!["alice".to_string(), "bob".to_string()];
        assert!(is_group_admin("alice", &admins));
        assert!(!is_group_admin("carol", &admins));
        assert!(!is_group_admin("alice", &[]));
    }

    #[test]
    fn test_sha_crypt_rounds() {
        let empty = LoginDefs::load(Path::new("/nonexistent/login.defs")).expect("missing is ok");
        assert_eq!(sha_crypt_rounds(&empty), None);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("login.defs");
        std::fs::write(
            &path,
            "SHA_CRYPT_MIN_ROUNDS 2000\nSHA_CRYPT_MAX_ROUNDS 8000\n",
        )
        .expect("write login.defs");
        let defs = LoginDefs::load(&path).expect("load");
        assert_eq!(sha_crypt_rounds(&defs), Some(8000));

        std::fs::write(&path, "SHA_CRYPT_MIN_ROUNDS 4000\n").expect("write login.defs");
        let defs = LoginDefs::load(&path).expect("load");
        assert_eq!(sha_crypt_rounds(&defs), Some(4000));
    }

    #[test]
    fn test_add_unique() {
        let mut members = vec!["bob".to_string()];
        add_unique(&mut members, "alice");
        add_unique(&mut members, "alice");
        assert_eq!(members, vec!["bob".to_string(), "alice".to_string()]);
    }

    fn skip_unless_root() -> bool {
        !rustix::process::geteuid().is_root()
    }

    #[test]
    fn test_add_user_integration() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("etc");
        std::fs::write(etc.join("group"), "devs:x:1000:bob\n").expect("group");
        std::fs::write(etc.join("gshadow"), "devs:!::bob\n").expect("gshadow");
        std::fs::write(
            etc.join("passwd"),
            "bob:x:1000:1000::/home/bob:/bin/sh\nalice:x:1001:1001::/home/alice:/bin/sh\n",
        )
        .expect("passwd");

        let code = uumain(
            vec![
                "gpasswd".into(),
                "-a".into(),
                "alice".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "devs".into(),
            ]
            .into_iter(),
        );
        assert_eq!(code, 0);

        let group = std::fs::read_to_string(etc.join("group")).expect("read group");
        assert!(group.contains("alice"), "{group}");
        let gshadow = std::fs::read_to_string(etc.join("gshadow")).expect("read gshadow");
        assert!(gshadow.contains("alice"), "{gshadow}");
    }

    #[test]
    fn test_nonexistent_group_fails() {
        if skip_unless_root() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&etc).expect("etc");
        std::fs::write(etc.join("group"), "root:x:0:\n").expect("group");

        let code = uumain(
            vec![
                "gpasswd".into(),
                "-a".into(),
                "alice".into(),
                "-P".into(),
                dir.path().as_os_str().to_owned(),
                "missing".into(),
            ]
            .into_iter(),
        );
        assert_ne!(code, 0);
    }
}
