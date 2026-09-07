// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore getty hushlogin hushlogins motd utmp wtmp rlogin setcred initgroups pts tcflush TTYGROUP TTYPERM SUPATH

//! `login` — begin a session on the system.
//!
//! Drop-in replacement for `login(1)` as the distributions ship it: shadow's
//! on Ubuntu 20.04 to 24.04 and Debian 12, util-linux's from Debian 13. The
//! two agree on what matters and this implements the set they share, plus the
//! util-linux options that cannot conflict with anything.
//!
//! `login` is what getty runs on a terminal. It prompts for a name and,
//! through PAM, a password; refuses after `LOGIN_RETRIES` failures or
//! `LOGIN_TIMEOUT` seconds; opens the PAM session; records the login in utmp
//! and wtmp; hands the terminal to the user; and runs their login shell with
//! a login environment. When the shell exits it closes the session and
//! records the logout.
//!
//! It is not setuid. getty runs it as root, and it refuses to do anything
//! else: "Cannot possibly work without effective root", as the GNU tool
//! puts it.

// Everything past the argument parser exists for the PAM build: without PAM
// there is no authentication and `run` is a refusal. The workspace denies dead
// code, rightly; in the no-PAM configuration that would deny the whole tool.
#![cfg_attr(not(feature = "pam"), allow(dead_code, unused_imports))]

use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, Command};

use shadow_core::login_defs::LoginDefs;
use shadow_core::passwd::PasswdEntry;

use uucore::error::{UError, UResult};

mod options {
    pub const PRESERVE_ENV: &str = "preserve-environment";
    pub const SKIP_AUTH: &str = "skip-auth";
    pub const HOST: &str = "host";
    pub const PLAIN_PROMPT: &str = "plain-prompt";
    pub const RLOGIN: &str = "rlogin";
    pub const NAME: &str = "name";
}

/// Defaults for the login.defs keys, from login(1).
const DEFAULT_RETRIES: i64 = 3;
const DEFAULT_TIMEOUT: i64 = 60;
const DEFAULT_TTYPERM: u32 = 0o600;
const DEFAULT_TTYGROUP: &str = "tty";
const DEFAULT_ENV_PATH: &str = "/usr/local/bin:/bin:/usr/bin";
const DEFAULT_ENV_SUPATH: &str = "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin";
const DEFAULT_MAIL_DIR: &str = "/var/mail";
const DEFAULT_HUSHLOGIN_FILE: &str = ".hushlogin";
const DEFAULT_SHELL: &str = "/bin/sh";

/// The PAM service both implementations use.
const PAM_SERVICE: &str = "login";

/// Variables a login session inherits from the terminal rather than the
/// profile, and so keeps even when the environment is otherwise discarded.
const KEPT_FROM_CALLER: [&str; 3] = ["TERM", "COLORTERM", "NO_COLOR"];

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors `login` can produce. Every failure exits 1, which is what both
/// implementations do; the variants exist so the message says which it was.
#[derive(Debug)]
enum LoginError {
    /// Not running as root.
    NotRoot,
    /// No controlling terminal, or one that cannot be used.
    NoTerminal(String),
    /// Authentication or account checks failed for good.
    Refused(String),
    /// The session could not be set up.
    Session(String),
    /// Usage.
    Usage(String),
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRoot => f.write_str("Cannot possibly work without effective root"),
            Self::NoTerminal(msg) | Self::Refused(msg) | Self::Session(msg) | Self::Usage(msg) => {
                f.write_str(msg)
            }
        }
    }
}

impl std::error::Error for LoginError {}

impl UError for LoginError {
    fn code(&self) -> i32 {
        match self {
            Self::NotRoot
            | Self::NoTerminal(_)
            | Self::Refused(_)
            | Self::Session(_)
            | Self::Usage(_) => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// What login.defs says, with login(1)'s defaults filled in.
#[derive(Debug, Clone)]
struct Config {
    retries: u32,
    timeout: u64,
    tty_group: String,
    tty_perm: u32,
    env_path: String,
    env_supath: String,
    mail_dir: String,
    default_home: bool,
    hushlogin_file: String,
    motd_files: Vec<PathBuf>,
    plain_prompt: bool,
    fail_delay: u64,
}

impl Config {
    fn from_defs(defs: &LoginDefs) -> Self {
        // ENV_PATH is written `PATH=/a:/b` in login.defs; either spelling is
        // accepted.
        let path_of = |key: &str, default: &str| {
            defs.get(key).map_or_else(
                || default.to_string(),
                |v| v.strip_prefix("PATH=").unwrap_or(v).to_string(),
            )
        };
        let yes = |key: &str, default: bool| {
            defs.get(key)
                .map_or(default, |v| v.eq_ignore_ascii_case("yes"))
        };
        Self {
            retries: u32::try_from(defs.get_i64("LOGIN_RETRIES").unwrap_or(DEFAULT_RETRIES))
                .unwrap_or(1)
                .max(1),
            timeout: u64::try_from(defs.get_i64("LOGIN_TIMEOUT").unwrap_or(DEFAULT_TIMEOUT))
                .unwrap_or(0),
            tty_group: defs.get("TTYGROUP").unwrap_or(DEFAULT_TTYGROUP).to_string(),
            tty_perm: defs
                .get("TTYPERM")
                .and_then(|v| u32::from_str_radix(v.trim_start_matches('0'), 8).ok())
                .unwrap_or(DEFAULT_TTYPERM),
            env_path: path_of("ENV_PATH", DEFAULT_ENV_PATH),
            env_supath: path_of("ENV_SUPATH", DEFAULT_ENV_SUPATH),
            mail_dir: defs.get("MAIL_DIR").unwrap_or(DEFAULT_MAIL_DIR).to_string(),
            default_home: yes("DEFAULT_HOME", true),
            hushlogin_file: defs
                .get("HUSHLOGIN_FILE")
                .unwrap_or(DEFAULT_HUSHLOGIN_FILE)
                .to_string(),
            motd_files: defs
                .get("MOTD_FILE")
                .map(|v| {
                    v.split(':')
                        .filter(|p| !p.is_empty())
                        .map(PathBuf::from)
                        .collect()
                })
                .unwrap_or_default(),
            plain_prompt: yes("LOGIN_PLAIN_PROMPT", false),
            fail_delay: u64::try_from(defs.get_i64("FAIL_DELAY").unwrap_or(0)).unwrap_or(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure pieces, kept separate so they can be tested without a terminal
// ---------------------------------------------------------------------------

/// The prompt: `hostname login: `, or `login: ` when the hostname is
/// suppressed by `-H` or `LOGIN_PLAIN_PROMPT`.
fn prompt_text(hostname: Option<&str>) -> String {
    match hostname {
        Some(h) if !h.is_empty() => format!("{h} login: "),
        _ => "login: ".to_string(),
    }
}

/// The terminal line as utmp records it: the path without `/dev/`.
fn utmp_line(tty: &str) -> &str {
    tty.strip_prefix("/dev/").unwrap_or(tty)
}

/// Whether the greeting -- motd, mail -- is to be suppressed for this account.
///
/// Either the per-user file named by `HUSHLOGIN_FILE` exists in the home
/// directory, or `/etc/hushlogins` lists the user or their shell.
fn is_hushed(home: &Path, hushlogin_file: &str, user: &str, shell: &str, etc: &Path) -> bool {
    if home.join(hushlogin_file).exists() {
        return true;
    }
    std::fs::read_to_string(etc.join("hushlogins"))
        .is_ok_and(|s| s.lines().any(|l| l.trim() == user || l.trim() == shell))
}

/// Build the environment for the shell.
///
/// Without `-p` everything the caller carried is dropped except what a
/// session inherits from the terminal; with it the caller's environment is
/// kept. Either way `HOME`, `SHELL`, `USER`, `LOGNAME`, `PATH` and `MAIL` are
/// set from the account, and whatever the PAM session stack exported is
/// layered on top -- `pam_env`'s locale, `pam_systemd`'s `XDG_*`.
fn build_environment(
    caller: &[(String, String)],
    preserve: bool,
    entry: &PasswdEntry,
    shell: &str,
    home: &str,
    config: &Config,
    pam_env: &[String],
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = if preserve {
        caller.to_vec()
    } else {
        caller
            .iter()
            .filter(|(k, _)| KEPT_FROM_CALLER.contains(&k.as_str()))
            .cloned()
            .collect()
    };
    let mut set = |k: &str, v: String| {
        env.retain(|(key, _)| key != k);
        env.push((k.to_string(), v));
    };
    set("HOME", home.to_string());
    set("SHELL", shell.to_string());
    set("USER", entry.name.clone());
    set("LOGNAME", entry.name.clone());
    set(
        "PATH",
        if entry.uid == 0 {
            config.env_supath.clone()
        } else {
            config.env_path.clone()
        },
    );
    set("MAIL", format!("{}/{}", config.mail_dir, entry.name));
    for kv in pam_env {
        if let Some((k, v)) = kv.split_once('=') {
            set(k, v.to_string());
        }
    }
    env
}

/// The shell to run, and the argv[0] that makes it a login shell.
fn shell_for(entry: &PasswdEntry) -> (String, String) {
    let shell = if entry.shell.is_empty() {
        DEFAULT_SHELL.to_string()
    } else {
        entry.shell.clone()
    };
    let base = Path::new(&shell)
        .file_name()
        .map_or_else(|| "sh".to_string(), |n| n.to_string_lossy().into_owned());
    (shell, format!("-{base}"))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for the `login` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    // Nothing is sanitized: `-p` hands the caller's environment to the shell
    // on purpose, and the shell is an interactive child that must keep its
    // limits. Core dumps are off, since a password passes through here.
    shadow_core::hardening::suppress_core_dumps();

    let Some(matches) = shadow_core::cli::parse_args(uu_app(), args, |_| 1)? else {
        return Ok(());
    };

    if rustix::process::geteuid().as_raw() != 0 {
        return Err(LoginError::NotRoot.into());
    }
    if matches.get_flag(options::RLOGIN) {
        return Err(LoginError::Usage(
            "-r (the rlogin autologin protocol) is not supported".into(),
        )
        .into());
    }

    let request = Request {
        preserve_env: matches.get_flag(options::PRESERVE_ENV),
        skip_auth: matches.get_flag(options::SKIP_AUTH),
        host: matches.get_one::<String>(options::HOST).cloned(),
        plain_prompt: matches.get_flag(options::PLAIN_PROMPT),
        name: matches.get_one::<String>(options::NAME).cloned(),
    };
    if request.skip_auth && request.name.is_none() {
        return Err(LoginError::Usage("-f requires a user name".into()).into());
    }

    run(&request)
}

/// What the command line asked for.
struct Request {
    preserve_env: bool,
    skip_auth: bool,
    host: Option<String>,
    plain_prompt: bool,
    name: Option<String>,
}

/// Build the clap `Command` for `login`.
#[must_use]
pub fn uu_app() -> Command {
    Command::new("login")
        .about("Begin a session on the system")
        .override_usage("login [-p] [-h host] [-H] [[-f] name]")
        .version(shadow_core::cli::VERSION)
        .after_help(shadow_core::cli::AFTER_HELP)
        // `-h` is the remote host, as it has been in every login(1) since
        // telnetd; help is `--help` only.
        .disable_help_flag(true)
        .arg(
            Arg::new("help")
                .long("help")
                .help("display this help and exit")
                .action(ArgAction::Help),
        )
        .arg(
            Arg::new(options::PRESERVE_ENV)
                .short('p')
                .help("preserve the environment")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::SKIP_AUTH)
                .short('f')
                .help("skip authentication: the user is already authenticated (getty autologin)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::HOST)
                .short('h')
                .help("name of the remote host, recorded in utmp and passed to PAM")
                .value_name("host"),
        )
        .arg(
            Arg::new(options::PLAIN_PROMPT)
                .short('H')
                .help("do not show the hostname in the login prompt")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::RLOGIN)
                .short('r')
                .help("rejected: the rlogin autologin protocol is not supported")
                .value_name("host")
                .hide(true)
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::NAME)
                .help("the account to log in")
                .value_name("name"),
        )
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

#[cfg(feature = "pam")]
fn run(request: &Request) -> UResult<()> {
    let tty = shadow_core::tty::name()
        .ok_or_else(|| LoginError::NoTerminal("no controlling terminal; login needs one".into()))?;
    let root = shadow_core::sysroot::SysRoot::default();
    let defs = LoginDefs::load(&root.login_defs_path()).unwrap_or_default();
    let config = Config::from_defs(&defs);

    // The caller's environment, captured before anything below can change it.
    let caller_env: Vec<(String, String)> = std::env::vars().collect();

    if config.timeout > 0 {
        shadow_core::process::exit_after(config.timeout, "Login timed out.");
    }

    let (pam, entry) = authenticate(request, &config, &tty)?;
    start_session(request, &config, &root, &tty, pam, &entry, &caller_env)
}

/// Discard anything typed ahead of a prompt, so a password typed early does
/// not land in the name field in clear -- or in the shell's input later.
#[cfg(feature = "pam")]
fn discard_typeahead() {
    let _ = rustix::termios::tcflush(std::io::stdin(), rustix::termios::QueueSelector::IFlush);
}

/// Prompt for names and passwords until one is accepted or the retries run
/// out. Returns the PAM context, still open, and the account it settled on.
#[cfg(feature = "pam")]
fn authenticate(
    request: &Request,
    config: &Config,
    tty: &str,
) -> Result<(shadow_core::pam::PamContext, PasswdEntry), LoginError> {
    use shadow_core::pam::{ConvMode, PamContext, flags, item_type, return_code};

    let hostname = if request.plain_prompt || config.plain_prompt {
        None
    } else {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|h| h.trim().to_string())
    };
    let prompt = prompt_text(hostname.as_deref());

    let too_many = || {
        LoginError::Refused(format!(
            "maximum number of tries exceeded ({})",
            config.retries
        ))
    };
    // The same words for a wrong password and an unknown name, so a caller
    // cannot tell accounts apart by the answer.
    let incorrect = |login_name: &str| {
        if config.fail_delay > 0 {
            std::thread::sleep(std::time::Duration::from_secs(config.fail_delay));
        }
        let _ = writeln!(std::io::stderr(), "\nLogin incorrect");
        shadow_core::audit::log_user_event("LOGIN", login_name, 0, false);
    };

    let mut name = request.name.clone();
    for attempt in 1..=config.retries {
        let login_name = if let Some(n) = name.take() {
            n
        } else {
            discard_typeahead();
            match shadow_core::tty::prompt_line(&prompt) {
                Ok(n) if !n.trim().is_empty() => n.trim().to_string(),
                Ok(_) => continue,
                Err(e) => {
                    return Err(LoginError::NoTerminal(format!(
                        "cannot read the login name: {e}"
                    )));
                }
            }
        };

        let mut ctx = PamContext::new(PAM_SERVICE, &login_name, ConvMode::Tty)
            .map_err(|e| LoginError::Session(format!("PAM: {e}")))?;
        let _ = ctx.set_item_str(item_type::PAM_TTY, tty);
        if let Some(host) = &request.host {
            let _ = ctx.set_item_str(item_type::PAM_RHOST, host);
        }

        if !request.skip_auth {
            discard_typeahead();
            if ctx.authenticate(0).is_err() {
                incorrect(&login_name);
                if attempt == config.retries {
                    return Err(too_many());
                }
                continue;
            }
        }

        // Aging and locks. nologin for the password path is in the auth
        // stack and has already had its say.
        match ctx.acct_mgmt(0) {
            Ok(()) => {}
            Err(_) if ctx.last_status() == return_code::PAM_NEW_AUTHTOK_REQD => {
                ctx.chauthtok(flags::PAM_CHANGE_EXPIRED_AUTHTOK)
                    .map_err(|e| LoginError::Refused(format!("password change failed: {e}")))?;
            }
            Err(e) => {
                let msg = if ctx.last_status() == return_code::PAM_ACCT_EXPIRED {
                    "Your account has expired; please contact your system administrator."
                        .to_string()
                } else {
                    e.to_string()
                };
                let _ = writeln!(std::io::stderr(), "{msg}");
                return Err(LoginError::Refused("Authentication failure".into()));
            }
        }

        // PAM may have mapped the name to another account.
        let account = ctx.user().unwrap_or(login_name.clone());
        if let Ok(Some(found)) = shadow_core::process::getpwnam(&account) {
            return Ok((ctx, found));
        }
        incorrect(&login_name);
        if attempt == config.retries {
            return Err(too_many());
        }
    }
    Err(LoginError::Refused("Login incorrect".into()))
}

/// Open the session, record it, hand over the terminal, run the shell as the
/// user, and close everything when the shell exits.
#[cfg(feature = "pam")]
fn start_session(
    request: &Request,
    config: &Config,
    root: &shadow_core::sysroot::SysRoot,
    tty: &str,
    mut pam: shadow_core::pam::PamContext,
    entry: &PasswdEntry,
    caller_env: &[(String, String)],
) -> UResult<()> {
    use shadow_core::pam::flags;

    pam.setcred(flags::PAM_ESTABLISH_CRED)
        .map_err(|e| LoginError::Session(format!("cannot establish credentials: {e}")))?;
    pam.open_session(0)
        .map_err(|e| LoginError::Session(format!("cannot open session: {e}")))?;
    let pam_env = pam.environment();

    let record = shadow_core::process::SessionRecord {
        line: utmp_line(tty),
        user: &entry.name,
        host: request.host.as_deref().unwrap_or(""),
        pid: std::process::id().cast_signed(),
    };
    shadow_core::process::record_login(&record);
    shadow_core::audit::log_user_event("LOGIN", &entry.name, entry.uid, true);

    hand_over_terminal(tty, entry, config, root);

    // Home: fall back to `/` when DEFAULT_HOME says so, as both tools do.
    let home = if Path::new(&entry.home).is_dir() {
        entry.home.clone()
    } else if config.default_home {
        let _ = writeln!(std::io::stderr(), "No directory, logging in with HOME=/");
        "/".to_string()
    } else {
        return Err(LoginError::Session(format!("Unable to cd to '{}'", entry.home)).into());
    };

    let (shell, argv0) = shell_for(entry);
    let env = build_environment(
        caller_env,
        request.preserve_env,
        entry,
        &shell,
        &home,
        config,
        &pam_env,
    );

    if !is_hushed(
        Path::new(&home),
        &config.hushlogin_file,
        &entry.name,
        &shell,
        Path::new("/etc"),
    ) {
        for motd in &config.motd_files {
            if let Ok(text) = std::fs::read_to_string(motd) {
                let _ = std::io::stdout().write_all(text.as_bytes());
            }
        }
    }

    // The shell runs as a child, not in this process: the PAM session has to
    // be closed and the logout recorded once it exits, which needs someone
    // left to do it. Signals aimed at the shell must not reach this process
    // meanwhile, and the shell itself gets a clean mask.
    let _signals = shadow_core::hardening::SignalBlocker::block_critical()
        .map_err(|e| LoginError::Session(e.to_string()))?;
    let mut cmd = std::process::Command::new(&shell);
    {
        use std::os::unix::process::CommandExt as _;
        cmd.arg0(&argv0)
            .current_dir(&home)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    }
    let status = shadow_core::process::spawn_as_user(
        &mut cmd,
        entry.uid,
        entry.gid,
        supplementary_groups(entry),
    )
    .and_then(|mut child| child.wait());

    shadow_core::process::record_logout(&record);
    let _ = pam.close_session(0);
    let _ = pam.setcred(flags::PAM_DELETE_CRED);

    match status {
        Ok(_) => Ok(()),
        Err(e) => Err(LoginError::Session(format!("cannot run {shell}: {e}")).into()),
    }
}

/// The supplementary groups the account belongs to, as `initgroups` would
/// compute them, plus the ones PAM's `pam_group` may have added to this
/// process -- which is why the current list is consulted too.
#[cfg(feature = "pam")]
fn supplementary_groups(entry: &PasswdEntry) -> Vec<u32> {
    let mut groups: Vec<u32> =
        shadow_core::records::read_entries::<shadow_core::group::GroupEntry>(Path::new(
            "/etc/group",
        ))
        .map(|gs| {
            gs.iter()
                .filter(|g| g.members.contains(&entry.name))
                .map(|g| g.gid)
                .collect()
        })
        .unwrap_or_default();
    if let Ok(current) = shadow_core::process::getgroups() {
        for g in current {
            if g != entry.gid && !groups.contains(&g) {
                groups.push(g);
            }
        }
    }
    groups
}

/// Give the terminal to the user: owner the account, group `TTYGROUP` where
/// it exists (else the account's primary group), mode `TTYPERM`.
#[cfg(feature = "pam")]
fn hand_over_terminal(
    tty: &str,
    entry: &PasswdEntry,
    config: &Config,
    root: &shadow_core::sysroot::SysRoot,
) {
    use rustix::fs::{Gid, Mode, OFlags, Uid};

    let gid =
        shadow_core::records::read_entries::<shadow_core::group::GroupEntry>(&root.group_path())
            .ok()
            .and_then(|gs| {
                gs.iter()
                    .find(|g| g.name == config.tty_group)
                    .map(|g| g.gid)
            })
            .unwrap_or(entry.gid);
    // Through a descriptor opened O_NOFOLLOW on the path we were handed, so a
    // link planted under /dev cannot redirect the chown.
    if let Ok(fd) = rustix::fs::open(
        tty,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NOCTTY,
        Mode::empty(),
    ) {
        let _ = rustix::fs::fchown(
            &fd,
            Some(Uid::from_raw(entry.uid)),
            Some(Gid::from_raw(gid)),
        );
        let _ = rustix::fs::fchmod(&fd, Mode::from_raw_mode(config.tty_perm));
    }
}

#[cfg(not(feature = "pam"))]
fn run(_request: &Request) -> UResult<()> {
    // A login that cannot authenticate is not a login. The static musl build
    // leaves PAM out on purpose (see docs/PLATFORM-SUPPORT.md), and this
    // applet says so rather than pretending.
    Err(LoginError::Session(
        "PAM support is not compiled in \u{2014} login cannot authenticate".into(),
    )
    .into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, uid: u32, shell: &str) -> PasswdEntry {
        PasswdEntry {
            name: name.to_string(),
            passwd: "x".to_string(),
            uid,
            gid: uid,
            gecos: String::new(),
            home: format!("/home/{name}"),
            shell: shell.to_string(),
        }
    }

    fn defs(text: &str) -> LoginDefs {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("login.defs");
        std::fs::write(&path, text).expect("write");
        LoginDefs::load(&path).expect("load")
    }

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    #[test]
    fn test_prompt_shows_the_hostname_unless_suppressed() {
        assert_eq!(prompt_text(Some("box")), "box login: ");
        assert_eq!(prompt_text(None), "login: ");
        assert_eq!(prompt_text(Some("")), "login: ");
    }

    #[test]
    fn test_utmp_line_drops_dev() {
        assert_eq!(utmp_line("/dev/pts/3"), "pts/3");
        assert_eq!(utmp_line("/dev/tty1"), "tty1");
        assert_eq!(utmp_line("ttyS0"), "ttyS0");
    }

    /// Without `-p` the caller's environment is gone except what the
    /// terminal provides; with it, everything stays. The account variables
    /// are set either way and win over anything the caller carried.
    #[test]
    fn test_environment_is_a_login_environment() {
        let caller = vec![
            ("TERM".to_string(), "xterm".to_string()),
            ("LD_PRELOAD".to_string(), "/evil.so".to_string()),
            ("HOME".to_string(), "/wrong".to_string()),
        ];
        let config = Config::from_defs(&LoginDefs::default());
        let alice = entry("alice", 1000, "/bin/bash");

        let env = build_environment(
            &caller,
            false,
            &alice,
            "/bin/bash",
            "/home/alice",
            &config,
            &[],
        );
        let get = |k: &str| {
            env.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("TERM"), Some("xterm"), "TERM comes from the terminal");
        assert_eq!(
            get("LD_PRELOAD"),
            None,
            "the caller's environment is dropped"
        );
        assert_eq!(get("HOME"), Some("/home/alice"));
        assert_eq!(get("USER"), Some("alice"));
        assert_eq!(get("LOGNAME"), Some("alice"));
        assert_eq!(get("SHELL"), Some("/bin/bash"));
        assert_eq!(get("PATH"), Some(DEFAULT_ENV_PATH));
        assert_eq!(get("MAIL"), Some("/var/mail/alice"));

        let kept = build_environment(
            &caller,
            true,
            &alice,
            "/bin/bash",
            "/home/alice",
            &config,
            &[],
        );
        assert!(
            kept.iter().any(|(k, _)| k == "LD_PRELOAD"),
            "-p keeps the environment"
        );
        assert!(
            kept.iter().any(|(k, v)| k == "HOME" && v == "/home/alice"),
            "-p still sets the account's HOME"
        );
    }

    /// Root gets the superuser path, and PAM's environment is layered last.
    #[test]
    fn test_root_path_and_pam_environment() {
        let config = Config::from_defs(&defs("ENV_SUPATH PATH=/sbin:/bin\nENV_PATH PATH=/bin\n"));
        let env = build_environment(
            &[],
            false,
            &entry("root", 0, "/bin/sh"),
            "/bin/sh",
            "/root",
            &config,
            &["LANG=fr_BE.UTF-8".to_string()],
        );
        let get = |k: &str| {
            env.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("PATH"), Some("/sbin:/bin"));
        assert_eq!(get("LANG"), Some("fr_BE.UTF-8"));
    }

    #[test]
    fn test_shell_defaults_and_login_argv0() {
        assert_eq!(
            shell_for(&entry("a", 1, "")),
            ("/bin/sh".to_string(), "-sh".to_string())
        );
        assert_eq!(
            shell_for(&entry("a", 1, "/usr/bin/zsh")),
            ("/usr/bin/zsh".to_string(), "-zsh".to_string())
        );
    }

    #[test]
    fn test_hushlogin_by_file_and_by_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let etc = dir.path().join("etc");
        std::fs::create_dir_all(&home).expect("home");
        std::fs::create_dir_all(&etc).expect("etc");
        assert!(!is_hushed(&home, ".hushlogin", "alice", "/bin/sh", &etc));
        std::fs::write(home.join(".hushlogin"), "").expect("touch");
        assert!(is_hushed(&home, ".hushlogin", "alice", "/bin/sh", &etc));
        std::fs::remove_file(home.join(".hushlogin")).expect("rm");
        std::fs::write(etc.join("hushlogins"), "bob\n/bin/sh\n").expect("list");
        assert!(
            is_hushed(&home, ".hushlogin", "alice", "/bin/sh", &etc),
            "listed by shell"
        );
        assert!(
            is_hushed(&home, ".hushlogin", "bob", "/bin/bash", &etc),
            "listed by name"
        );
        assert!(!is_hushed(&home, ".hushlogin", "carol", "/bin/bash", &etc));
    }

    /// The login.defs keys, with their defaults and their spellings.
    #[test]
    fn test_config_from_login_defs() {
        let c = Config::from_defs(&LoginDefs::default());
        assert_eq!(c.retries, 3);
        assert_eq!(c.timeout, 60);
        assert_eq!(c.tty_perm, 0o600);
        assert_eq!(c.tty_group, "tty");
        assert!(c.default_home);
        assert!(c.motd_files.is_empty());

        let c = Config::from_defs(&defs(
            "LOGIN_RETRIES 5\nLOGIN_TIMEOUT 0\nTTYPERM 0620\nDEFAULT_HOME no\nMOTD_FILE /etc/motd:/run/motd\nLOGIN_PLAIN_PROMPT yes\nFAIL_DELAY 4\n",
        ));
        assert_eq!(c.retries, 5);
        assert_eq!(c.timeout, 0, "0 disables the timeout");
        assert_eq!(c.tty_perm, 0o620);
        assert!(!c.default_home);
        assert_eq!(
            c.motd_files,
            vec![PathBuf::from("/etc/motd"), PathBuf::from("/run/motd")]
        );
        assert!(c.plain_prompt);
        assert_eq!(c.fail_delay, 4);
    }

    /// `-f` needs a name and `-r` is refused; both are usage errors, not
    /// prompts.
    #[test]
    fn test_flags() {
        let m = uu_app()
            .try_get_matches_from(["login", "-p", "-h", "example.org", "-H", "-f", "alice"])
            .expect("parses");
        assert!(m.get_flag(options::PRESERVE_ENV));
        assert!(m.get_flag(options::SKIP_AUTH));
        assert!(m.get_flag(options::PLAIN_PROMPT));
        assert_eq!(
            m.get_one::<String>(options::HOST).map(String::as_str),
            Some("example.org")
        );
        assert_eq!(
            m.get_one::<String>(options::NAME).map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn test_every_failure_exits_one() {
        for e in [
            LoginError::NotRoot,
            LoginError::NoTerminal("x".into()),
            LoginError::Refused("x".into()),
            LoginError::Session("x".into()),
            LoginError::Usage("x".into()),
        ] {
            assert_eq!(e.code(), 1);
        }
        assert_eq!(
            LoginError::NotRoot.to_string(),
            "Cannot possibly work without effective root"
        );
    }
}
