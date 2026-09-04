// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore auditd auditctl audisp

//! Audit logging for shadow-rs tools.
//!
//! Account operations -- creating and deleting users and groups, changing
//! passwords and group membership -- are recorded so an administrator can see
//! afterwards what changed and who changed it.
//!
//! Everything here is best effort and silent on failure. A machine with no
//! syslog and no `auditd` is a normal machine, and a failure to record an
//! event must never stop the operation the caller asked for.
//!
//! **Implementation note**: records go to syslog over `/dev/log` and, where
//! `auditctl` is installed, to the audit subsystem through it. Native
//! `libaudit` bindings would remove the second subprocess; they are not used
//! yet because the netlink protocol needs its own careful handling in a
//! setuid-root process.

use std::io::Write as _;
use std::os::unix::net::UnixDatagram;

/// The syslog socket every logging daemon on Linux listens on.
const SYSLOG_SOCKET: &str = "/dev/log";

/// syslog priority for `auth.info`: facility 4 (auth) times 8, plus severity 6.
const AUTH_INFO: u8 = 4 * 8 + 6;

/// Log a user account event to syslog and the audit subsystem.
///
/// `event_type` should be one of: `ADD_USER`, `DEL_USER`, `MOD_USER`,
/// `ADD_GROUP`, `DEL_GROUP`, `MOD_GROUP`, `CHNG_PASSWD`.
///
/// Silently succeeds if neither syslog nor auditd is available.
pub fn log_user_event(event_type: &str, username: &str, uid: u32, result: bool) {
    let success = if result { "success" } else { "failed" };
    let terminal = crate::tty::name().unwrap_or_else(|| "?".to_string());
    let msg = format!(
        "op={event_type} acct=\"{username}\" uid={uid} exe=\"shadow-rs\" \
         terminal={terminal} res={success}"
    );

    syslog(&msg);

    // auditd's own record, which ausearch can correlate. Only useful where
    // auditctl is installed and the caller has CAP_AUDIT_WRITE.
    let _ = std::process::Command::new("/sbin/auditctl")
        .arg("-m")
        .arg(format!(
            "shadow-rs: {event_type} user={username} uid={uid} res={success}"
        ))
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .status();
}

/// Send one line to the local syslog daemon.
///
/// Writing the datagram directly replaces forking `/usr/bin/logger` per event.
/// A setuid-root tool should spawn as little as it can: the fork inherited the
/// process state, depended on a binary being installed at a fixed path, and
/// blocked the caller waiting for it, all to write a few dozen bytes to a
/// socket.
///
/// The wire format is RFC 3164's: `<PRI>TAG[PID]: MESSAGE`, with no timestamp,
/// which the daemon fills in itself.
fn syslog(message: &str) {
    let Ok(socket) = UnixDatagram::unbound() else {
        return;
    };
    let mut line = Vec::with_capacity(message.len() + 32);
    let _ = write!(
        line,
        "<{AUTH_INFO}>shadow-rs[{}]: {message}",
        std::process::id()
    );
    // Unconnected send: no daemon, a full socket or a stream-mode /dev/log all
    // fail here, and all of them are conditions to carry on through.
    let _ = socket.send_to(&line, SYSLOG_SOCKET);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// auth.info is the priority shadow tools have always logged at, and the
    /// number is what a syslog daemon parses, so it is worth pinning.
    #[test]
    fn test_auth_info_priority() {
        assert_eq!(AUTH_INFO, 38);
    }

    /// A machine with no syslog daemon is a normal machine: recording an event
    /// must never fail the operation that produced it.
    #[test]
    fn test_logging_without_a_daemon_is_silent() {
        syslog("op=TEST acct=\"nobody\" res=success");
    }
}
