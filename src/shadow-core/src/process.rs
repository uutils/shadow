// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore setuid seteuid setgid initgroups sigprocmask getpwuid getgrgid

//! Process-level POSIX wrappers for setuid-root tools.
//!
//! These functions call libc directly because rustix intentionally does not
//! provide process-wide `setuid`/`setgid` or per-thread `sigprocmask` (they
//! require libc coordination for thread safety). The `libc` crate is already
//! a dependency for PAM FFI.
//!
//! This is one of the few modules that permits `unsafe` — all unsafe is
//! confined to well-understood POSIX C library calls.

use std::ffi::{CStr, CString};
use std::io;

// ---------------------------------------------------------------------------
// UID / GID manipulation (process-wide via libc)
// ---------------------------------------------------------------------------

/// `setuid(uid)` — set the real and effective user ID of the calling process.
///
/// This calls the libc `setuid()` which is process-wide (unlike the raw
/// syscall which is per-thread on Linux).
pub fn setuid(uid: u32) -> io::Result<()> {
    // SAFETY: setuid is a standard POSIX function. The only precondition
    // is that uid is a valid UID value, which u32 always satisfies.
    let ret = unsafe { libc::setuid(uid) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `seteuid(uid)` — set the effective user ID of the calling process.
///
/// This calls the libc `seteuid()` which is process-wide.
pub fn seteuid(uid: u32) -> io::Result<()> {
    // SAFETY: seteuid is a standard POSIX function.
    let ret = unsafe { libc::seteuid(uid) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `setgid(gid)` — set the real and effective group ID of the calling process.
///
/// This calls the libc `setgid()` which is process-wide.
pub fn setgid(gid: u32) -> io::Result<()> {
    // SAFETY: setgid is a standard POSIX function.
    let ret = unsafe { libc::setgid(gid) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `initgroups(user, gid)` — initialize the supplementary group list.
///
/// Sets the supplementary groups for `user` plus `gid`.
pub fn initgroups(user: &CStr, gid: u32) -> io::Result<()> {
    // SAFETY: initgroups is a standard POSIX function. `user` is a valid
    // null-terminated CStr.
    let ret = unsafe { libc::initgroups(user.as_ptr(), gid) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `getgroups()` — the process's current supplementary group list.
pub fn getgroups() -> io::Result<Vec<u32>> {
    // SAFETY: a null buffer with size 0 asks getgroups for the count only,
    // which is the documented way to size the real call.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let len = usize::try_from(count).unwrap_or(0);
    let mut groups: Vec<libc::gid_t> = vec![0; len];
    // SAFETY: the buffer holds exactly `count` gid_t, which is the size passed.
    let filled = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if filled < 0 {
        return Err(io::Error::last_os_error());
    }
    groups.truncate(usize::try_from(filled).unwrap_or(0));
    Ok(groups)
}

/// `setgroups(groups)` — replace the process's supplementary group list.
///
/// Requires `CAP_SETGID`, so a setuid-root tool must call this before it gives
/// the privilege back.
pub fn setgroups(groups: &[u32]) -> io::Result<()> {
    // SAFETY: the pointer and length describe `groups` exactly, and setgroups
    // only reads from it.
    let ret = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ---------------------------------------------------------------------------
// Sessions: utmp/wtmp, controlling terminals, watchdogs
// ---------------------------------------------------------------------------

unsafe extern "C" {
    // In glibc and musl alike; not in the libc crate's bindings. musl's is a
    // no-op, which is the documented state of utmp there.
    fn updwtmpx(file: *const libc::c_char, ut: *const libc::utmpx);
}

/// Where login records go for `last(1)`.
const WTMP_FILE: &CStr = c"/var/log/wtmp";

/// Copy `s` into a fixed C char array, truncating; the tail stays zero.
fn fill(dst: &mut [libc::c_char], s: &str) {
    for (d, b) in dst.iter_mut().zip(s.bytes()) {
        // c_char is i8 on x86 and u8 on arm; both hold a byte bit for bit.
        #[allow(clippy::cast_possible_wrap)]
        {
            *d = b as libc::c_char;
        }
    }
}

/// A login or logout event for the accounting files.
#[derive(Debug, Clone)]
pub struct SessionRecord<'a> {
    /// The terminal, without `/dev/` (`pts/3`, `tty1`).
    pub line: &'a str,
    /// The account name; empty for a logout.
    pub user: &'a str,
    /// The remote host, or empty.
    pub host: &'a str,
    /// The pid of the session leader.
    pub pid: i32,
}

/// Record a login in utmp and wtmp, so `who(1)` and `last(1)` see it.
///
/// Best effort: a machine without utmp -- musl, or a system that moved to
/// wtmpdb -- is a normal machine, and a failure to record a session must not
/// stop the session. The `ut_id` is the tail of the line, which is what init
/// and getty use, so the slot is the one they will later mark dead.
pub fn record_login(rec: &SessionRecord<'_>) {
    write_utmp(rec, libc::USER_PROCESS);
}

/// Record the end of a session in utmp and wtmp.
pub fn record_logout(rec: &SessionRecord<'_>) {
    let ended = SessionRecord {
        user: "",
        host: "",
        ..rec.clone()
    };
    write_utmp(&ended, libc::DEAD_PROCESS);
}

fn write_utmp(rec: &SessionRecord<'_>, ut_type: libc::c_short) {
    // SAFETY: utmpx is a plain C struct of integers and char arrays; all-zero
    // is a valid value, and every field written below is written in bounds.
    let mut ut: libc::utmpx = unsafe { std::mem::zeroed() };
    ut.ut_type = ut_type;
    ut.ut_pid = rec.pid;
    fill(&mut ut.ut_line, rec.line);
    let id_start = rec.line.len().saturating_sub(4);
    fill(&mut ut.ut_id, &rec.line[id_start..]);
    fill(&mut ut.ut_user, rec.user);
    fill(&mut ut.ut_host, rec.host);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // glibc keeps a 32-bit tv_sec in utmpx on 64-bit hosts for compatibility;
    // musl uses a full timeval. The cast follows whichever the target has.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    {
        ut.ut_tv.tv_sec = now as _;
    }

    // SAFETY: standard utmpx API; `ut` is fully initialized and outlives the
    // calls. pututxline copies the record. Failures are deliberately ignored:
    // see the doc comment on record_login.
    unsafe {
        libc::setutxent();
        libc::pututxline(&raw const ut);
        libc::endutxent();
        updwtmpx(WTMP_FILE.as_ptr(), &raw const ut);
    }
}

/// Spawn `cmd` as a new session with `tty` as its controlling terminal.
///
/// This is what getty does before it runs `login`, and what a test has to do
/// to run `login` the way getty would. The child becomes a session leader and
/// claims the terminal; nothing else about the process changes.
pub fn spawn_with_controlling_tty(
    cmd: &mut std::process::Command,
    tty: std::os::unix::io::RawFd,
) -> io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt as _;

    // SAFETY: runs in the forked child before exec, and calls only setsid and
    // ioctl, both async-signal-safe; `tty` is a descriptor the parent opened
    // and keeps open across the fork.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(tty, libc::TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Spawn `cmd` as `uid`:`gid` with the given supplementary groups, and a
/// clean signal mask.
///
/// The order is the one that works: supplementary groups and the primary
/// group while still root, then the uid, after which nothing can be changed
/// back. `std::process::Command` offers the same through `uid`, `gid` and
/// `groups`, but `groups` is not stable, and half of the drop through one API
/// and half through another is how the order gets wrong.
pub fn spawn_as_user(
    cmd: &mut std::process::Command,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
) -> io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt as _;

    // SAFETY: runs in the forked child before exec and calls only
    // sigprocmask, setgroups, setgid and setuid, all async-signal-safe;
    // `groups` was allocated by the parent and is only read here.
    unsafe {
        cmd.pre_exec(move || {
            let mut empty: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&raw mut empty) != 0
                || libc::sigprocmask(libc::SIG_SETMASK, &raw const empty, std::ptr::null_mut()) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// End the process after `seconds` unless it has exec'd or exited by then.
///
/// `login(1)` gives a caller `LOGIN_TIMEOUT` seconds to get through the
/// prompts, so an abandoned getty line does not hold a half-open session for
/// ever. A successful login execs the shell, which replaces the process,
/// thread included; a failed one exits on its own. Only a stalled prompt is
/// left for this to end.
pub fn exit_after(seconds: u64, message: &'static str) {
    use std::io::Write as _;

    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(seconds));
        let _ = writeln!(io::stderr(), "{message}");
        // SAFETY: _exit terminates the process without unwinding or running
        // destructors, which is what a watchdog wants: nothing here holds a
        // lock or a half-written file.
        unsafe { libc::_exit(0) };
    });
}

/// Look up an account by name through NSS (`getpwnam_r`).
///
/// Like [`getpwuid`], so a directory user can log in where `/etc/passwd` has
/// never heard of them.
pub fn getpwnam(name: &str) -> io::Result<Option<crate::passwd::PasswdEntry>> {
    let name_c = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: getpwnam_r writes into `pwd` and `buf`, both sized and live for
    // the call; `result` points at `pwd` on success or is null.
    let rc = unsafe {
        libc::getpwnam_r(
            name_c.as_ptr(),
            &raw mut pwd,
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            &raw mut result,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if result.is_null() {
        return Ok(None);
    }
    // SAFETY: on success every string pointer in `pwd` points into `buf`,
    // which is still alive, and is null-terminated.
    let field = |p: *const libc::c_char| unsafe {
        if p.is_null() {
            String::new()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    };
    Ok(Some(crate::passwd::PasswdEntry {
        name: field(pwd.pw_name),
        passwd: field(pwd.pw_passwd),
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        gecos: field(pwd.pw_gecos),
        home: field(pwd.pw_dir),
        shell: field(pwd.pw_shell),
    }))
}

// ---------------------------------------------------------------------------
// exec
// ---------------------------------------------------------------------------

/// `execv(path, argv)` — replace the current process image.
///
/// On success this function never returns. On failure it returns an error.
pub fn execv(path: &CStr, argv: &[&CStr]) -> io::Error {
    // Build a null-terminated array of pointers for execv.
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    // SAFETY: execv is a standard POSIX function. The argv array is
    // null-terminated and all CStr pointers are valid.
    unsafe {
        libc::execv(path.as_ptr(), argv_ptrs.as_ptr());
    }
    // execv only returns on error.
    io::Error::last_os_error()
}

/// `execve(path, argv, envp)` — replace the process image with a chosen
/// environment.
///
/// `execv` passes the caller's environment through, which is right for
/// `newgrp` without `-`, where the man page says the current environment is
/// kept. `newgrp -` must instead hand the shell a login environment, and
/// `std::env::set_var` is `unsafe` (and process-global) in edition 2024, so
/// the environment is built as data and passed here.
///
/// On success this never returns. On failure it returns the error.
pub fn execve(path: &CStr, argv: &[&CStr], envp: &[&CStr]) -> io::Error {
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut env_ptrs: Vec<*const libc::c_char> = envp.iter().map(|s| s.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());

    // SAFETY: execve is a standard POSIX function. Both arrays are
    // null-terminated and every pointer comes from a live CStr borrowed for
    // the duration of the call.
    unsafe {
        libc::execve(path.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
    }
    io::Error::last_os_error()
}

// ---------------------------------------------------------------------------
// Signal blocking (per-thread via libc sigprocmask)
// ---------------------------------------------------------------------------

/// A saved signal mask, used by [`block_critical_signals`] and
/// [`restore_signals`].
///
/// Wraps a `libc::sigset_t`.
pub struct SavedSigSet {
    set: libc::sigset_t,
}

/// Block `SIGINT`, `SIGQUIT`, `SIGTERM`, `SIGHUP` and return the previous mask.
///
/// Calls `sigprocmask`, which modifies the *calling thread's* signal mask.
/// For single-threaded shadow-rs tools this is effectively process-wide.
///
/// Prevents these signals from interrupting a lock-modify-write sequence.
pub fn block_critical_signals() -> io::Result<SavedSigSet> {
    // SAFETY: sigemptyset, sigaddset, and sigprocmask are standard POSIX
    // functions. We initialize the sigset_t with sigemptyset before use.
    unsafe {
        let mut block_set: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&raw mut block_set) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::sigaddset(&raw mut block_set, libc::SIGINT) != 0 {
            return Err(io::Error::last_os_error());
        }
        // SIGQUIT too: Ctrl-\ at a password prompt would otherwise kill the
        // process without unwinding, leaving the terminal with echo off.
        if libc::sigaddset(&raw mut block_set, libc::SIGQUIT) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::sigaddset(&raw mut block_set, libc::SIGTERM) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::sigaddset(&raw mut block_set, libc::SIGHUP) != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut old_set: libc::sigset_t = std::mem::zeroed();
        let ret = libc::sigprocmask(libc::SIG_BLOCK, &raw const block_set, &raw mut old_set);
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(SavedSigSet { set: old_set })
    }
}

/// Spawn `cmd` with an empty signal mask in the child.
///
/// A tool that blocks `SIGINT` and friends while it holds a lock -- so that a
/// Ctrl-C cannot leave the lock behind -- passes that mask on to every child
/// it starts, and an interactive program started under it, an editor say,
/// then cannot be interrupted at all. The child gets a clean mask; the parent
/// keeps its own.
pub fn spawn_with_signals_unblocked(
    cmd: &mut std::process::Command,
) -> io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt as _;

    // SAFETY: the closure runs in the forked child before exec. It calls only
    // sigemptyset and sigprocmask, both async-signal-safe, and touches nothing
    // else: no allocation, no locks, no Rust state shared with the parent.
    unsafe {
        cmd.pre_exec(|| {
            let mut empty: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&raw mut empty) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::sigprocmask(libc::SIG_SETMASK, &raw const empty, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Restore a previously saved signal mask.
pub fn restore_signals(saved: &SavedSigSet) -> io::Result<()> {
    // SAFETY: sigprocmask with SIG_SETMASK restores a previously captured mask.
    let ret = unsafe {
        libc::sigprocmask(
            libc::SIG_SETMASK,
            &raw const saved.set,
            std::ptr::null_mut(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ---------------------------------------------------------------------------
// NSS user lookup (getpwuid_r)
// ---------------------------------------------------------------------------

/// Look up a user by UID via `getpwuid_r` (NSS-backed).
///
/// Unlike reading `/etc/passwd` directly, this goes through the name service
/// switch and so sees LDAP, SSSD and systemd-homed accounts as well.
///
/// The result is a [`crate::passwd::PasswdEntry`], the same type the file
/// parser produces: an NSS entry and a file entry describe the same account,
/// and a second struct for it only bought a field-by-field copy at every call.
///
/// Returns `None` if no user exists for the given UID.
/// Returns `Err` on system errors (e.g., I/O failure in NSS backend).
pub fn getpwuid(uid: u32) -> io::Result<Option<crate::passwd::PasswdEntry>> {
    // Start with a 1 KiB buffer; grow on ERANGE.
    const MAX_BUF: usize = 1024 * 1024;
    let mut buf_size: usize = 1024;

    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf: Vec<u8> = vec![0u8; buf_size];
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        // SAFETY: getpwuid_r is a POSIX thread-safe function. We pass a
        // properly sized buffer and a zeroed passwd struct. The result
        // pointer tells us whether an entry was found.
        let ret = unsafe {
            libc::getpwuid_r(
                uid,
                &raw mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf_size,
                &raw mut result,
            )
        };

        if ret == libc::ERANGE {
            // Buffer too small — double and retry.
            buf_size = buf_size.saturating_mul(2);
            if buf_size > MAX_BUF {
                return Err(io::Error::other(
                    "getpwuid_r: ERANGE persists beyond 1 MiB buffer cap",
                ));
            }
            continue;
        }

        if ret != 0 {
            return Err(io::Error::from_raw_os_error(ret));
        }

        if result.is_null() {
            // No entry found for this UID.
            return Ok(None);
        }

        // SAFETY: getpwuid_r succeeded and `result` is non-null, so `pwd`
        // is populated. String fields should point into `buf`, but some NSS
        // backends may return null for optional fields — guard defensively.
        let entry = unsafe {
            let str_field = |ptr: *const libc::c_char| -> String {
                if ptr.is_null() {
                    String::new()
                } else {
                    CStr::from_ptr(ptr).to_string_lossy().into_owned()
                }
            };
            crate::passwd::PasswdEntry {
                name: str_field(pwd.pw_name),
                passwd: str_field(pwd.pw_passwd),
                uid: pwd.pw_uid,
                gid: pwd.pw_gid,
                gecos: str_field(pwd.pw_gecos),
                home: str_field(pwd.pw_dir),
                shell: str_field(pwd.pw_shell),
            }
        };

        return Ok(Some(entry));
    }
}

/// Whether NSS knows a group with this GID.
///
/// The companion to [`getpwuid`] for the allocator: only existence is asked
/// for, so no entry is built and the caller needs no group type.
pub fn gid_exists(gid: u32) -> io::Result<bool> {
    const MAX_BUF: usize = 1024 * 1024;
    let mut buf_size: usize = 1024;

    loop {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf: Vec<u8> = vec![0u8; buf_size];
        let mut result: *mut libc::group = std::ptr::null_mut();

        // SAFETY: getgrgid_r is a POSIX thread-safe function. The buffer is
        // sized by `buf_size` and the group struct is zeroed before the call.
        let ret = unsafe {
            libc::getgrgid_r(
                gid,
                &raw mut grp,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf_size,
                &raw mut result,
            )
        };

        if ret == libc::ERANGE {
            buf_size = buf_size.saturating_mul(2);
            if buf_size > MAX_BUF {
                return Err(io::Error::other(
                    "getgrgid_r: ERANGE persists beyond 1 MiB buffer cap",
                ));
            }
            continue;
        }

        if ret != 0 {
            return Err(io::Error::from_raw_os_error(ret));
        }

        return Ok(!result.is_null());
    }
}

// ---------------------------------------------------------------------------
// AT_EXECFN validation (multicall setuid hardening)
// ---------------------------------------------------------------------------

/// Verify that `argv[0]` matches `AT_EXECFN` (the kernel-recorded executable path).
///
/// In setuid context, an attacker can spoof `argv[0]` to route a multicall
/// binary to a different tool than the one the symlink points to. `AT_EXECFN`
/// from the ELF auxiliary vector records the real path the kernel executed,
/// which cannot be spoofed from userspace.
///
/// Returns `true` if the basenames match, `false` if they differ.
pub fn verify_argv0_matches_execfn(argv0: &str) -> bool {
    let execfn = rustix::param::linux_execfn();
    let execfn = execfn.to_string_lossy();

    let argv0_base = std::path::Path::new(argv0)
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let execfn_base = std::path::Path::new(execfn.as_ref())
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();

    argv0_base == execfn_base
}

// ---------------------------------------------------------------------------
// Privilege dropping
// ---------------------------------------------------------------------------

/// RAII guard that drops the effective UID and restores it when dropped.
///
/// A setuid-root tool should run its PAM conversation as the real caller, so
/// that PAM modules see the actual user rather than root. Restoration happens
/// in `Drop`, so it also covers the early-return and error paths.
pub struct PrivDrop {
    original_euid: u32,
}

impl PrivDrop {
    /// Drop the effective UID to `uid`, restoring the previous value on drop.
    ///
    /// # Errors
    ///
    /// Returns the `seteuid` failure if privileges cannot be dropped. Callers
    /// must treat that as fatal rather than continuing as root.
    pub fn drop_to(uid: u32) -> io::Result<Self> {
        let original_euid = rustix::process::geteuid().as_raw();
        if original_euid != uid {
            seteuid(uid)?;
        }
        Ok(Self { original_euid })
    }
}

impl Drop for PrivDrop {
    fn drop(&mut self) {
        if let Err(e) = seteuid(self.original_euid) {
            // Drop cannot report an error, and carrying on with the wrong
            // effective UID is worse than being noisy about it.
            uucore::show_error!(
                "CRITICAL: failed to restore euid to {}: {e}",
                self.original_euid
            );
        }
    }
}
