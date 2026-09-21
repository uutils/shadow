// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Security hardening utilities for setuid-root tools.
//!
//! Every shadow-utils tool runs as setuid-root and must defend against
//! hostile callers. These functions implement the standard hardening
//! steps that all tools share.

/// Suppress core dumps.
///
/// A core dump from an account tool could expose password hashes and, for
/// `chpasswd` or the PAM conversation, plaintext passwords. `RLIMIT_CORE=0`
/// is not enough on its own: the kernel ignores it when cores are piped to a
/// handler (core(5)), which is how systemd-coredump and apport collect them.
/// `PR_SET_DUMPABLE` is what actually stops the dump. A setuid exec already
/// clears the flag; the root-run tools start dumpable.
pub fn suppress_core_dumps() {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

    let _ = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    );
    let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
}

/// Raise `RLIMIT_FSIZE` to prevent truncated file writes.
///
/// A malicious caller could `ulimit -f 1` before invoking a setuid-root
/// tool, causing `/etc/shadow` to be truncated mid-write.
pub fn raise_file_size_limit() {
    use rustix::process::{Resource, Rlimit, setrlimit};

    let _ = setrlimit(
        Resource::Fsize,
        Rlimit {
            current: None,
            maximum: None,
        },
    );
}

/// The fixed `PATH` every tool runs with, and hands to what it spawns.
pub const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Decide which of the caller's variables the tool itself keeps.
///
/// The process starts with whatever the caller exported, and a setuid tool
/// cannot treat that as data it chose: the PAM stack, the NSS modules and
/// the crypt library all run in this process and read the environment
/// directly. The dynamic loader already drops `LD_*` and friends for a setuid
/// program; this drops everything else too, and keeps only what has a known
/// reader here:
///
/// - `TERM` and `NO_COLOR`, which decide how prompts and errors are drawn;
/// - `LANG`, `LANGUAGE` and `LC_*`, which choose the language of messages,
///   including PAM's;
/// - `TZ`, so `chage -l` prints dates in the caller's zone -- but only when
///   it names a zone. glibc also accepts a path, absolute or via `..`, and
///   reads that file with the process's privilege; such a value is dropped;
/// - `VISUAL` and `EDITOR`, which `vipw` and `vigr` read to choose an editor.
///
/// `PATH` is not kept but fixed, to [`SAFE_PATH`]. Anything else -- `HOME`,
/// `USER`, `IFS`, `CDPATH`, a `PAM_*` variable, a `KRB5_*` one -- is gone
/// before the first line of the tool runs. The function is pure so it can be
/// tested without touching the real environment.
pub fn own_environment<I>(vars: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut env = vec![("PATH".to_string(), SAFE_PATH.to_string())];
    for (k, v) in vars {
        let keep = match k.as_str() {
            "TERM" | "NO_COLOR" | "LANG" | "LANGUAGE" | "VISUAL" | "EDITOR" => true,
            "TZ" => !(v.starts_with(':') || v.starts_with('/') || v.contains("..")),
            _ => k.starts_with("LC_"),
        };
        if keep {
            env.push((k, v));
        }
    }
    env
}

/// Build a sanitized environment for child process spawning.
///
/// Returns safe key-value pairs: a fixed `PATH` plus the caller's `TERM`,
/// `LANG` and `LC_*`. Pass the returned Vec to
/// `Command::env_clear().envs(...)` when spawning subprocesses. After
/// [`harden_process`] the process environment is already the allow-list of
/// [`own_environment`]; this is the narrower subset a child needs, and the
/// tools that never call `harden_process` (`newgrp`, `sg`, `login`) rely on
/// it filtering the caller's full environment.
pub fn sanitized_env() -> Vec<(String, String)> {
    let mut env = vec![("PATH".to_string(), SAFE_PATH.to_string())];
    for (k, v) in std::env::vars() {
        if k == "TERM" || k == "LANG" || k.starts_with("LC_") {
            env.push((k, v));
        }
    }
    env
}

/// Restrict filesystem access via Landlock (Linux 5.13+).
///
/// Best-effort: silently does nothing on kernels without Landlock support.
/// `writable` paths get full access, `readable` paths read-only, `exec_paths`
/// read and execute; everything else is denied. The restriction inherits into
/// child processes and applies to shared objects `dlopen` loads later, and
/// `restrict_self` sets `no_new_privs` — which strips the setuid/setgid bits
/// from any helper exec'd afterwards. Do not apply it before a PAM
/// conversation: PAM `dlopen`s its modules and execs setgid helpers such as
/// `unix_chkpwd`. A path that does not exist is skipped, not an error.
#[cfg(all(feature = "landlock", target_os = "linux"))]
pub fn apply_landlock(
    writable: &[&std::path::Path],
    readable: &[&std::path::Path],
    exec_paths: &[&std::path::Path],
) {
    use landlock::{
        ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, path_beneath_rules,
    };

    // V5 is the maximum ABI we request; Ruleset's default CompatLevel
    // (BestEffort) automatically downgrades to whatever the running
    // kernel actually supports, so this is safe on older kernels.
    let abi = ABI::V5;
    let all_access = AccessFs::from_all(abi);
    let read_access = AccessFs::from_read(abi);
    let exec_access = AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir;

    let result = Ruleset::default()
        .handle_access(all_access)
        .and_then(Ruleset::create)
        .and_then(|rs| rs.add_rules(path_beneath_rules(writable, all_access)))
        .and_then(|rs| rs.add_rules(path_beneath_rules(readable, read_access)))
        .and_then(|rs| rs.add_rules(path_beneath_rules(exec_paths, exec_access)))
        .and_then(landlock::RulesetCreated::restrict_self);

    // Best-effort: silently ignore errors (unsupported kernel, etc.)
    let _ = result;
}

/// No-op on non-Linux or when the `landlock` feature is disabled.
#[cfg(not(all(feature = "landlock", target_os = "linux")))]
pub fn apply_landlock(
    _writable: &[&std::path::Path],
    _readable: &[&std::path::Path],
    _exec_paths: &[&std::path::Path],
) {
}

/// Run all standard hardening steps for a setuid-root tool.
///
/// Call at the top of `uumain`, before any argument parsing and before
/// anything could start a thread: the environment is rewritten in place,
/// which is only sound while the process is single-threaded.
///
/// After this the process environment is exactly what [`own_environment`]
/// allows, so the PAM stack, the NSS modules and the crypt library -- which
/// run inside this process and read the environment themselves -- see the
/// tool's environment, not the caller's. Children get the narrower
/// [`sanitized_env`] where they are spawned.
pub fn harden_process() {
    suppress_core_dumps();
    raise_file_size_limit();
    let keep = own_environment(std::env::vars());
    crate::process::replace_environment(&keep);
}

/// Enter `dir` with `chroot(2)`, then make it the working directory.
///
/// This is what `--root DIR` means in every tool that offers it: the account
/// files come from the new root, and so does every absolute path read out of
/// them -- a home directory, a shell, a skeleton directory. `--prefix` is the
/// weaker relative: it prepends the directory to the files the tool opens and
/// leaves absolute paths inside those files alone.
///
/// Chrooting needs root, and it is refused for anyone else: a setuid-root
/// binary pointed at a tree of the caller's choosing would read and write
/// account files they control.
///
/// # Errors
///
/// Returns `ShadowError::Validation` if the caller is not root, and
/// `ShadowError::IoPath` if the chroot or the following `chdir` fails.
pub fn chroot_into(dir: &std::path::Path) -> Result<(), crate::error::ShadowError> {
    if !caller_is_root() {
        return Err(crate::error::ShadowError::Validation(
            "only root may use --root".into(),
        ));
    }

    rustix::process::chroot(dir)
        .map_err(|e| crate::error::ShadowError::IoPath(e.into(), dir.to_owned()))?;

    // Without this the working directory is still outside the new root, which
    // is a documented way back out of a chroot.
    rustix::process::chdir("/")
        .map_err(|e| crate::error::ShadowError::IoPath(e.into(), std::path::PathBuf::from("/")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------

/// Check whether the *real* caller is root (not just setuid-root).
///
/// Uses `getuid()` (real UID). When a tool is installed setuid-root,
/// `geteuid()` is 0 for all callers, but the real UID identifies who
/// actually invoked the program.
pub fn caller_is_root() -> bool {
    rustix::process::getuid().is_root()
}

/// Return the current user's username from the real UID.
pub fn current_username() -> Result<String, crate::error::ShadowError> {
    let uid = rustix::process::getuid().as_raw();
    lookup_username_by_uid(uid)
}

/// Look up a username by UID via NSS (`getpwuid_r`).
pub fn lookup_username_by_uid(uid: u32) -> Result<String, crate::error::ShadowError> {
    lookup_passwd_entry_by_uid(uid).map(|e| e.name)
}

/// Look up a passwd entry by UID via NSS (`getpwuid_r`).
///
/// Uses the system name-service switch, so it works with LDAP, SSSD,
/// systemd-homed, and other backends — not just `/etc/passwd`.
pub fn lookup_passwd_entry_by_uid(
    uid: u32,
) -> Result<crate::passwd::PasswdEntry, crate::error::ShadowError> {
    match crate::process::getpwuid(uid) {
        Ok(Some(entry)) => Ok(entry),
        Ok(None) => Err(crate::error::ShadowError::Other(
            format!("no passwd entry for uid {uid}").into(),
        )),
        Err(e) => Err(crate::error::ShadowError::Other(
            format!("NSS lookup failed for uid {uid}: {e}").into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Signal blocking
// ---------------------------------------------------------------------------

/// RAII guard that blocks critical signals during file modifications.
///
/// Prevents `SIGINT`/`SIGTERM`/`SIGHUP` from interrupting a
/// lock-modify-write sequence, which could leave password files in an
/// inconsistent state or holding a stale lock. The original signal mask
/// is restored when the guard is dropped.
pub struct SignalBlocker {
    saved: crate::process::SavedSigSet,
}

impl SignalBlocker {
    /// Block `SIGINT`, `SIGTERM`, `SIGHUP` to prevent partial file writes.
    pub fn block_critical() -> Result<Self, crate::error::ShadowError> {
        let saved = crate::process::block_critical_signals().map_err(|e| {
            crate::error::ShadowError::Other(format!("cannot block signals: {e}").into())
        })?;

        Ok(Self { saved })
    }
}

impl Drop for SignalBlocker {
    fn drop(&mut self) {
        let _ = crate::process::restore_signals(&self.saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn path_is_fixed_whatever_the_caller_set() {
        let env = own_environment(pairs(&[("PATH", "/tmp/evil:/usr/bin")]));
        assert_eq!(get(&env, "PATH"), Some(SAFE_PATH));
        assert_eq!(env.len(), 1);
    }

    #[test]
    fn only_the_listed_readers_survive() {
        let env = own_environment(pairs(&[
            ("TERM", "xterm"),
            ("NO_COLOR", "1"),
            ("LANG", "fr_BE.UTF-8"),
            ("LANGUAGE", "fr"),
            ("LC_MESSAGES", "C"),
            ("VISUAL", "vim"),
            ("EDITOR", "nano"),
            ("HOME", "/home/x"),
            ("USER", "x"),
            ("IFS", " "),
            ("CDPATH", "."),
            ("PAM_USER", "root"),
            ("KRB5CCNAME", "/tmp/k"),
            ("LD_PRELOAD", "/tmp/x.so"),
            ("LCD", "not LC_"),
        ]));
        let kept: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            kept,
            [
                "PATH",
                "TERM",
                "NO_COLOR",
                "LANG",
                "LANGUAGE",
                "LC_MESSAGES",
                "VISUAL",
                "EDITOR"
            ]
        );
    }

    // The real thing, in a real process: the test binary re-runs itself as a
    // child with a marker variable, the child calls `harden_process` and
    // prints what its environment is afterwards, and the parent reads that.
    // Nothing here touches the environment of the test runner itself.
    #[test]
    fn harden_process_replaces_the_environment_of_this_process() {
        const MARK: &str = "SHADOW_CORE_HARDEN_CHILD";
        if std::env::var_os(MARK).is_some() {
            harden_process();
            let mut out = String::new();
            for (k, v) in std::env::vars() {
                out.push_str(&k);
                out.push('=');
                out.push_str(&v);
                out.push('\n');
            }
            let _ = std::io::stdout().write_all(out.as_bytes());
            std::process::exit(0);
        }
        let exe = std::env::current_exe().expect("test binary path");
        let output = std::process::Command::new(exe)
            .arg("hardening::tests::harden_process_replaces_the_environment_of_this_process")
            .arg("--exact")
            .arg("--nocapture")
            .env(MARK, "1")
            .env("SHADOW_TEST_CANARY", "leaked")
            .env("PATH", "/tmp/evil:/usr/bin")
            .env("TERM", "vt100")
            .env("TZ", ":/etc/shadow")
            .env("LC_ALL", "C")
            .output()
            .expect("re-run the test binary");
        let seen = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = seen.lines().collect();
        assert!(
            !lines.iter().any(|l| l.starts_with("SHADOW_TEST_CANARY=")),
            "{seen}"
        );
        assert!(
            !lines.iter().any(|l| l.starts_with(&format!("{MARK}="))),
            "{seen}"
        );
        assert!(
            !lines.iter().any(|l| l.starts_with("TZ=")),
            "a TZ path survived: {seen}"
        );
        assert!(
            lines.contains(&format!("PATH={SAFE_PATH}").as_str()),
            "{seen}"
        );
        assert!(lines.contains(&"TERM=vt100"), "{seen}");
        assert!(lines.contains(&"LC_ALL=C"), "{seen}");
    }

    #[test]
    fn tz_is_kept_as_a_zone_name_and_dropped_as_a_path() {
        for (value, kept) in [
            ("Europe/Brussels", true),
            ("UTC", true),
            ("CET-1CEST,M3.5.0,M10.5.0/3", true),
            (":/etc/shadow", false),
            ("/etc/shadow", false),
            ("../../etc/shadow", false),
            ("Europe/../../etc/shadow", false),
        ] {
            let env = own_environment(pairs(&[("TZ", value)]));
            assert_eq!(get(&env, "TZ").is_some(), kept, "TZ={value}");
        }
    }
}
