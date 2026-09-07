// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore nscd sssd

//! `nscd` (Name Service Cache Daemon) cache invalidation.
//!
//! After modifying `/etc/passwd`, `/etc/shadow`, or `/etc/group`,
//! the `nscd` cache must be invalidated so lookups reflect the changes.
//! Also supports `sssd` cache invalidation.

use std::process::Command;

use crate::hardening;

/// Invalidate the `nscd` and `sssd` caches for the given database.
///
/// The `database` should be one of `"passwd"`, `"shadow"`, or `"group"`.
///
/// Silently succeeds if `nscd`/`sssd` is not installed or not running —
/// this matches GNU shadow-utils behavior.
///
/// Subprocesses are spawned with a sanitized environment to prevent the
/// caller's full (potentially tainted) env from leaking into child processes
/// running in a setuid context.
pub fn invalidate_cache(database: &str) {
    let safe_env = hardening::sanitized_env();

    // Use absolute paths to avoid PATH-based lookups in setuid context.
    if let Some(nscd_db) = nscd_database(database) {
        let _ = Command::new("/usr/sbin/nscd")
            .arg("-i")
            .arg(nscd_db)
            .env_clear()
            .envs(safe_env.iter().map(|(k, v)| (k, v)))
            .status();
    }

    // sssd: sss_cache with the appropriate flag
    let flag = match database {
        "passwd" | "shadow" => "-U",
        "group" => "-G",
        _ => return,
    };
    let _ = Command::new("/usr/sbin/sss_cache")
        .arg(flag)
        .env_clear()
        .envs(safe_env.iter().map(|(k, v)| (k, v)))
        .status();
}

/// The nscd cache that a change to `database` can leave stale, if any.
///
/// nscd caches `passwd`, `group`, `hosts`, `services` and `netgroup`. It has
/// never cached `shadow` -- the entries it holds carry the `x` placeholder --
/// so a password change leaves nothing of nscd's stale, and asking it to
/// invalidate `shadow` only made every `passwd` and `chage` print *nscd:
/// 'shadow' is not a known database* on the user's terminal.
fn nscd_database(database: &str) -> Option<&str> {
    match database {
        "passwd" | "group" | "hosts" | "services" | "netgroup" => Some(database),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_is_not_an_nscd_database() {
        assert_eq!(nscd_database("passwd"), Some("passwd"));
        assert_eq!(nscd_database("group"), Some("group"));
        assert_eq!(nscd_database("shadow"), None);
        assert_eq!(nscd_database("gshadow"), None);
    }
}
