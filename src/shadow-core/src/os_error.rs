// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Error text sourced from the operating system instead of hardcoded.
//!
//! Wording for conditions that map to a libc `errno` is taken from the OS
//! (libc's `strerror`, surfaced through [`std::io::Error`]) rather than
//! carried as a string literal in our tree. This keeps the text matching the
//! host OS and lets glibc translate it on localized systems — the same way
//! GNU coreutils renders system errors (e.g. `cat: /tmp: Is a directory`).
//! See issue #159.

/// The OS message for `EACCES` ("Permission denied"), sourced from libc.
///
/// Rendered as "Permission denied" on English locales and the translated
/// equivalent elsewhere; on a libc that does not translate (musl) it is the
/// untranslated English text. `strip_errno` (the helper uucore uses for its
/// own I/O errors) drops the " (os error N)" suffix that `io::Error`'s
/// `Display` appends, leaving the bare OS message — matching coreutils output.
#[must_use]
pub fn permission_denied() -> String {
    uucore::error::strip_errno(&std::io::Error::from_raw_os_error(libc::EACCES))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_denied_is_bare_os_message() {
        let msg = permission_denied();
        // Non-empty, and the bare OS text — not Rust's "... (os error 13)"
        // rendering (the regression that suffix-stripping prevents). We assert
        // the shape, not the exact wording, since libc may localize it.
        assert!(!msg.is_empty());
        assert!(!msg.contains("(os error"), "got: {msg:?}");
    }
}
