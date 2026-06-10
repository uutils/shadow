// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Error text sourced from the operating system instead of hardcoded.
//!
//! Wording for conditions that map to a libc `errno` is taken from
//! `strerror` (via [`std::io::Error`]) rather than carried as a string
//! literal in our tree. This keeps the text matching the host OS and lets
//! glibc translate it on localized systems — the same way GNU coreutils
//! renders system errors (e.g. `cat: /tmp: Is a directory`). See issue #159.

/// The operating system's message for a raw `errno`.
///
/// For example `EACCES` renders as "Permission denied" on English locales
/// and the translated equivalent elsewhere. On targets whose libc does not
/// translate (musl), this is the untranslated English text.
#[must_use]
pub fn strerror(errno: i32) -> String {
    std::io::Error::from_raw_os_error(errno).to_string()
}

/// The OS message for `EACCES` ("Permission denied"), sourced from libc.
#[must_use]
pub fn permission_denied() -> String {
    strerror(libc::EACCES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_denied_is_nonempty_and_os_sourced() {
        // We assert the shape, not the exact text: the wording comes from the
        // host libc and may be localized, so hardcoding it would defeat the
        // purpose of this module.
        let msg = permission_denied();
        assert!(!msg.is_empty());
        // Same value libc would give for EACCES directly.
        assert_eq!(msg, strerror(libc::EACCES));
    }
}
