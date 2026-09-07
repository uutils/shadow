// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore fchown mkdir umask useradd newusers

//! Creating a user's home directory.
//!
//! Shared by `useradd(8)` and `newusers(8)`, which both have to do it and must
//! do it identically. The care this takes -- forcing the umask so the mode is
//! exact, and changing ownership through a descriptor rather than a path -- is
//! the reason it lives in one place: a second copy would be a second chance to
//! get it wrong, and the mistake would be silent.

use std::os::unix::fs::DirBuilderExt as _;
use std::path::Path;

use crate::error::ShadowError;

/// What [`create`] found when it tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The directory was created and the skeleton copied into it.
    Created,
    /// The directory was already there. Nothing was copied into it: the
    /// skeleton would overwrite files the existing occupant put there.
    AlreadyExisted,
}

/// The conventional mode for a directory that only holds other homes.
const BASE_DIR_MODE: u32 = 0o755;

/// Create `home_path` owned by `uid`:`gid` with `mode`, and copy `skel_path`
/// into it.
///
/// Missing ancestors are created too, so a home under a base directory that
/// does not exist yet works. They get the conventional 0755 and stay
/// root-owned; only the home itself takes `mode` and the caller's ownership.
///
/// Returns [`Outcome::AlreadyExisted`] rather than an error when the directory
/// is already there, leaving it untouched. Whether that deserves a warning is
/// the calling tool's decision, not this function's.
pub fn create(
    home_path: &Path,
    skel_path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<Outcome, ShadowError> {
    create_ancestors(home_path)?;

    // The kernel does not reset the umask across setuid, so a caller-controlled
    // umask may still be in effect here, and it can mask off requested
    // permission bits: with umask 0700 even mkdir(0700) leaves the directory at
    // 0000. Forcing it to zero makes the requested mode exact. A umask can only
    // ever make the result less permissive, never more, so this cannot widen
    // anything. Scoped to the mkdir alone -- fchown does not need it, and
    // copy_skel manages its own.
    let mkdir_result = {
        let _umask = crate::atomic::UmaskGuard::zero();
        std::fs::DirBuilder::new().mode(mode).create(home_path)
    };

    match mkdir_result {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(Outcome::AlreadyExisted);
        }
        Err(e) => {
            return Err(ShadowError::Other(
                format!("cannot create directory '{}': {e}", home_path.display()).into(),
            ));
        }
    }

    set_ownership(home_path, uid, gid)?;

    crate::skel::copy_skel(skel_path, home_path, uid, gid).map_err(|e| {
        ShadowError::Other(
            format!(
                "cannot copy skel '{}' to '{}': {e}",
                skel_path.display(),
                home_path.display()
            )
            .into(),
        )
    })?;

    Ok(Outcome::Created)
}

/// Create the directories above `home_path` if they are missing.
fn create_ancestors(home_path: &Path) -> Result<(), ShadowError> {
    let Some(parent) = home_path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || parent.exists() {
        return Ok(());
    }
    let _umask = crate::atomic::UmaskGuard::zero();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(BASE_DIR_MODE)
        .create(parent)
        .map_err(|e| {
            ShadowError::Other(
                format!("cannot create directory '{}': {e}", parent.display()).into(),
            )
        })
}

/// Hand the directory to its owner.
///
/// Through a descriptor opened `O_NOFOLLOW`, never by path: between the mkdir
/// and this call, anyone who can write the parent -- a home under `/tmp`, or a
/// shared base directory -- could swap the directory for a symlink and have us
/// hand them the target.
fn set_ownership(home_path: &Path, uid: u32, gid: u32) -> Result<(), ShadowError> {
    use rustix::fs::{Mode, OFlags};

    let dir = rustix::fs::open(
        home_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|e| {
        ShadowError::Other(format!("cannot open '{}': {e}", home_path.display()).into())
    })?;

    rustix::fs::fchown(
        &dir,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    )
    .map_err(|e| {
        ShadowError::Other(format!("cannot set ownership on '{}': {e}", home_path.display()).into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mode has to survive a hostile umask, which is the whole reason for
    /// the guard: a home at 0000 locks the user out of their own directory,
    /// and one too permissive exposes it.
    #[test]
    fn test_mode_is_exact_under_any_umask() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let skel = dir.path().join("skel");
        std::fs::create_dir(&skel).expect("skel");

        let home = dir.path().join("home/alice");
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();

        assert_eq!(
            create(&home, &skel, uid, gid, 0o700).expect("create"),
            Outcome::Created
        );
        let mode = std::fs::metadata(&home).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "requested mode was not applied exactly"
        );
    }

    /// A missing base directory is created, and gets 0755 rather than the
    /// home's private mode -- other users' homes have to live there too.
    #[test]
    fn test_missing_base_directory_is_created() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let skel = dir.path().join("skel");
        std::fs::create_dir(&skel).expect("skel");

        let home = dir.path().join("deeply/nested/home/alice");
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        create(&home, &skel, uid, gid, 0o700).expect("create");

        let base = dir.path().join("deeply/nested/home");
        assert!(base.is_dir());
        let mode = std::fs::metadata(&base).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, BASE_DIR_MODE);
    }

    /// An existing directory is reported, not overwritten: copying the
    /// skeleton over it would clobber whatever is already there.
    #[test]
    fn test_an_existing_directory_is_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let skel = dir.path().join("skel");
        std::fs::create_dir(&skel).expect("skel");
        std::fs::write(skel.join(".profile"), "from skel\n").expect("skel file");

        let home = dir.path().join("home/alice");
        std::fs::create_dir_all(&home).expect("home");
        std::fs::write(home.join("notes"), "mine\n").expect("existing file");

        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        assert_eq!(
            create(&home, &skel, uid, gid, 0o700).expect("create"),
            Outcome::AlreadyExisted
        );
        assert!(
            home.join("notes").exists(),
            "existing content was disturbed"
        );
        assert!(
            !home.join(".profile").exists(),
            "the skeleton must not be copied over an existing home"
        );
    }

    /// The skeleton reaches the new home.
    #[test]
    fn test_skel_is_copied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let skel = dir.path().join("skel");
        std::fs::create_dir(&skel).expect("skel");
        std::fs::write(skel.join(".bashrc"), "alias x=y\n").expect("skel file");

        let home = dir.path().join("home/alice");
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        create(&home, &skel, uid, gid, 0o700).expect("create");

        assert_eq!(
            std::fs::read_to_string(home.join(".bashrc")).expect("copied"),
            "alias x=y\n"
        );
    }
}
