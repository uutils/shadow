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

use std::ffi::CStr;
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
