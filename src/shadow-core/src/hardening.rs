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

/// Build a sanitized environment for child process spawning.
///
/// Returns safe key-value pairs: a fixed `PATH` plus the caller's `TERM`,
/// `LANG` and `LC_*`. The current process environment is NOT modified
/// (`set_var` is unsafe in edition 2024); pass the returned Vec to
/// `Command::env_clear().envs(...)` when spawning subprocesses so that
/// `LD_PRELOAD`, `IFS`, `CDPATH` and friends never reach a child.
pub fn sanitized_env() -> Vec<(String, String)> {
    let mut env = Vec::new();
    env.push((
        "PATH".to_string(),
        "/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
    ));
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
/// Call at the top of `uumain`, before any argument parsing.
///
/// This does **not** touch the process's own environment, and the name should
/// not be read as promising that: the in-process PAM and NSS modules still see
/// what the caller set. It used to return a sanitized environment that every
/// one of its thirteen callers threw away, which read as though the
/// environment had been dealt with. Children are given a clean environment
/// where they are spawned, by [`sanitized_env`].
pub fn harden_process() {
    suppress_core_dumps();
    raise_file_size_limit();
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
