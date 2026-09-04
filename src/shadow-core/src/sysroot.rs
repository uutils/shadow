// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chroot sysroot

//! System root path resolver for `--prefix` support.
//!
//! `--prefix DIR` prepends DIR to every file path the tool touches, without a
//! `chroot` syscall.
//!
//! `--root DIR` is the stronger relative and does not come through here at
//! all: every tool that offers it calls `chroot(2)` before anything else, so
//! an absolute path stored in a record -- a home directory, a shell, a
//! skeleton directory -- resolves inside the new root too. Eight of the
//! thirteen tools used to fold `--root` into this resolver instead, which made
//! `useradd -R /mnt/target -m` create the home on the *host* (#270).

use std::path::{Path, PathBuf};

/// Resolves file paths relative to an optional prefix directory.
#[derive(Debug, Clone)]
pub struct SysRoot {
    prefix: PathBuf,
}

impl SysRoot {
    /// Create a new `SysRoot` with the given prefix.
    ///
    /// If `prefix` is `None`, paths resolve against the real root `/`.
    #[must_use]
    pub fn new(prefix: Option<&Path>) -> Self {
        Self {
            prefix: prefix.unwrap_or_else(|| Path::new("/")).to_owned(),
        }
    }

    /// Whether the tool was pointed at a tree other than `/`.
    ///
    /// Anything that describes *this* running system -- the name service, the
    /// running kernel's idea of who exists -- says nothing about a prefixed
    /// tree, so a caller that consults such a source must not when this is
    /// true. See `uid_alloc::Scope`.
    #[must_use]
    pub fn is_prefixed(&self) -> bool {
        self.prefix != Path::new("/")
    }

    /// Resolve a path relative to the prefix.
    ///
    /// Strips a leading `/` from `relative` and joins it onto the prefix. This
    /// is a plain path computation and cannot fail: a `..` component is joined
    /// like any other. Callers that accept a path from the command line (a
    /// home directory, a skeleton directory) validate it before it gets here;
    /// the prefix itself is trusted because only root may set it.
    #[must_use]
    pub fn resolve(&self, relative: &str) -> PathBuf {
        let stripped = relative.strip_prefix('/').unwrap_or(relative);
        self.prefix.join(stripped)
    }

    /// Path to `/etc/passwd`.
    #[must_use]
    pub fn passwd_path(&self) -> PathBuf {
        self.resolve("/etc/passwd")
    }

    /// Path to `/etc/shadow`.
    #[must_use]
    pub fn shadow_path(&self) -> PathBuf {
        self.resolve("/etc/shadow")
    }

    /// Path to `/etc/group`.
    #[must_use]
    pub fn group_path(&self) -> PathBuf {
        self.resolve("/etc/group")
    }

    /// Path to `/etc/gshadow`.
    #[must_use]
    pub fn gshadow_path(&self) -> PathBuf {
        self.resolve("/etc/gshadow")
    }

    /// Path to `/etc/login.defs`.
    #[must_use]
    pub fn login_defs_path(&self) -> PathBuf {
        self.resolve("/etc/login.defs")
    }

    /// Path to `/etc/subuid`.
    #[must_use]
    pub fn subuid_path(&self) -> PathBuf {
        self.resolve("/etc/subuid")
    }

    /// Path to `/etc/subgid`.
    #[must_use]
    pub fn subgid_path(&self) -> PathBuf {
        self.resolve("/etc/subgid")
    }

    /// Path to `/etc/skel`.
    #[must_use]
    pub fn skel_path(&self) -> PathBuf {
        self.resolve("/etc/skel")
    }

    /// Path to `/etc/default/useradd`.
    #[must_use]
    pub fn useradd_defaults_path(&self) -> PathBuf {
        self.resolve("/etc/default/useradd")
    }

    /// Path to `/etc/shells`.
    #[must_use]
    pub fn shells_path(&self) -> PathBuf {
        self.resolve("/etc/shells")
    }
}

impl Default for SysRoot {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_root() {
        let root = SysRoot::default();
        assert_eq!(root.shadow_path(), PathBuf::from("/etc/shadow"));
        assert_eq!(root.passwd_path(), PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn test_with_prefix() {
        let root = SysRoot::new(Some(Path::new("/tmp/test")));
        assert_eq!(root.shadow_path(), PathBuf::from("/tmp/test/etc/shadow"));
        assert_eq!(root.passwd_path(), PathBuf::from("/tmp/test/etc/passwd"));
        assert_eq!(
            root.login_defs_path(),
            PathBuf::from("/tmp/test/etc/login.defs")
        );
    }

    #[test]
    fn test_resolve_strips_leading_slash() {
        let root = SysRoot::new(Some(Path::new("/mnt")));
        assert_eq!(
            root.resolve("/etc/shadow"),
            PathBuf::from("/mnt/etc/shadow")
        );
        assert_eq!(root.resolve("etc/shadow"), PathBuf::from("/mnt/etc/shadow"));
    }

    // A `..` anywhere — in a relative prefix given on the command line or in
    // a home directory read from /etc/passwd — used to trip an
    // `unreachable!()`; setuid `passwd --prefix ../x` aborted. It is now an
    // ordinary path component.
    #[test]
    fn test_parent_dir_components_never_panic() {
        let root = SysRoot::new(Some(Path::new("../chroot")));
        assert_eq!(root.passwd_path(), PathBuf::from("../chroot/etc/passwd"));

        let root = SysRoot::new(Some(Path::new("/")));
        assert_eq!(
            root.resolve("/home/../srv/foo"),
            PathBuf::from("/home/../srv/foo")
        );
    }
}
