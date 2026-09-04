// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore fsync

//! Atomic file replacement.
//!
//! Implements the write-tmp-then-rename pattern:
//! 1. Write to a temporary file in the same directory as the target
//! 2. `fsync` the temporary file
//! 3. `rename` the temporary file over the target (atomic on POSIX)
//!
//! The replacement inode carries the original's mode, owner, group and
//! `SELinux` label. That is not cosmetic: `/etc/shadow` is `root:shadow 0640`
//! on most distributions and is read by sgid-`shadow` helpers, and a setuid
//! tool runs with the *caller's* group, so a rewrite that merely created a
//! new file would hand the caller's group read access to every hash.

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::ShadowError;

/// RAII guard that saves and restores the process umask.
///
/// On creation, sets the umask to zero so that file mode bits passed to
/// `OpenOptions::mode()` (or `DirBuilder::mode()`) are applied exactly.
/// The original umask is restored when the guard is dropped, even on
/// error or panic paths.
///
/// # Thread safety
///
/// `umask(2)` is a process-wide operation. This guard is NOT safe to use
/// from multiple threads concurrently. All shadow-rs tools are
/// single-threaded, so this is not an issue in practice. The embedded
/// `PhantomData<Rc<()>>` makes the guard `!Send`, preventing accidental
/// movement across threads.
pub struct UmaskGuard(rustix::fs::Mode, std::marker::PhantomData<std::rc::Rc<()>>);

impl UmaskGuard {
    /// Set umask to zero and return a guard that restores the original.
    #[must_use = "the umask is restored when the guard is dropped; binding to `_` drops it immediately"]
    pub fn zero() -> Self {
        Self(
            rustix::process::umask(rustix::fs::Mode::empty()),
            std::marker::PhantomData,
        )
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        rustix::process::umask(self.0);
    }
}

/// Drop guard that auto-deletes a temporary file unless explicitly committed.
///
/// Ensures the tmp file is cleaned up on any error path, including panics.
struct TmpGuard {
    path: PathBuf,
    committed: bool,
}

impl TmpGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Atomically replace a file's contents.
///
/// Creates a temporary file in the same directory, writes content via the
/// provided closure (through a buffered writer), fsyncs, then renames over
/// the target. If any step fails, the temporary file is cleaned up and the
/// original is untouched. The new file keeps the original's mode, owner,
/// group and `SELinux` label; a target that does not exist yet is created
/// `0600` and owned by the process.
///
/// # Errors
///
/// Returns `ShadowError` if any I/O operation fails, if the ownership of the
/// original cannot be reproduced, or if the closure returns an error.
pub fn atomic_write<F>(target: &Path, f: F) -> Result<(), ShadowError>
where
    F: FnOnce(&mut dyn Write) -> Result<(), ShadowError>,
{
    // rename(2) over a symlink replaces the link, not the file behind it. An
    // /etc/passwd that is a symlink into a state directory (read-only root
    // filesystems) has to keep working, so operate on the final path. A
    // target that does not exist yet is simply a new file.
    let target = fs::canonicalize(target).unwrap_or_else(|_| target.to_owned());

    let dir = target.parent().ok_or_else(|| {
        ShadowError::Other(format!("no parent directory for {}", target.display()).into())
    })?;

    let tmp_path = tmp_path_for(&target);

    // Mode is applied at creation so there is no window where the file is
    // more readable than the original; owner, group and label are copied
    // from the original's descriptor below.
    let original = File::open(&target).ok();
    let (mode, owner) = match &original {
        Some(file) => {
            let meta = file
                .metadata()
                .map_err(|e| ShadowError::IoPath(e, target.clone()))?;
            (meta.mode() & 0o7777, Some((meta.uid(), meta.gid())))
        }
        None => (0o600, None),
    };

    let mut guard = TmpGuard::new(tmp_path.clone());

    // Save and reset umask to ensure mode parameter is applied exactly.
    // A caller could set a restrictive umask before invoking setuid passwd.
    // The guard restores the original umask on any exit path.
    let _umask = UmaskGuard::zero();

    let mut tmp_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp_path)
        .or_else(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                // Stale tmp file from a crashed run — remove and retry once.
                fs::remove_file(&tmp_path)
                    .map_err(|re| ShadowError::IoPath(re, tmp_path.clone()))?;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(mode)
                    .open(&tmp_path)
                    .map_err(|e2| ShadowError::IoPath(e2, tmp_path.clone()))
            } else {
                Err(ShadowError::IoPath(e, tmp_path.clone()))
            }
        })?;

    // Ownership is a hard requirement — a shadow file that changed group is
    // a security regression — so a failure here aborts the write. The label
    // copy is best effort: without SELinux the attribute simply is not there.
    if let Some((uid, gid)) = owner {
        rustix::fs::fchown(
            &tmp_file,
            Some(rustix::fs::Uid::from_raw(uid)),
            Some(rustix::fs::Gid::from_raw(gid)),
        )
        .map_err(|e| ShadowError::IoPath(io::Error::from(e), tmp_path.clone()))?;
    }
    if let Some(file) = &original {
        copy_selinux_label(file, &tmp_file);
    }

    // A plain File turns every `write!` fragment into its own write(2); a
    // passwd line is ~14 of them. Buffer, then flush before measuring.
    {
        let mut writer = io::BufWriter::new(&mut tmp_file);
        f(&mut writer)?;
        writer
            .flush()
            .map_err(|e| ShadowError::IoPath(e, tmp_path.clone()))?;
    }

    // Zero-length output guard: a zero-length shadow file locks out all users.
    // OpenBSD checks this in pw_mkdb before replacing the original.
    let written = tmp_file
        .metadata()
        .map_err(|e| ShadowError::IoPath(e, tmp_path.clone()))?
        .len();
    if written == 0 {
        return Err(ShadowError::Other(
            "refusing to write zero-length file".into(),
        ));
    }

    rustix::fs::fsync(&tmp_file)
        .map_err(|e| ShadowError::IoPath(io::Error::from(e), tmp_path.clone()))?;

    // Atomic rename.
    fs::rename(&tmp_path, &target).map_err(|e| ShadowError::IoPath(e, target.clone()))?;

    // The rename succeeded — prevent the guard from deleting the (now-gone) tmp file.
    guard.commit();

    // Fsync the parent directory to ensure the rename is durable.
    if let Ok(dir_fd) = File::open(dir) {
        let _ = rustix::fs::fsync(&dir_fd);
    }

    Ok(())
}

/// Copy the `SELinux` label of `from` onto `to`.
///
/// A new file gets the directory's default label, and the file-context rules
/// that would give `/etc/shadow` its `shadow_t` key on the final name, which
/// the temporary file does not have; `rename(2)` then keeps the wrong label.
/// Best effort: no `SELinux`, no xattr support or a refused write leave the
/// label alone.
fn copy_selinux_label(from: &File, to: &File) {
    let mut label = [0u8; 256];
    if let Ok(len) = rustix::fs::fgetxattr(from, c"security.selinux", &mut label) {
        let _ = rustix::fs::fsetxattr(
            to,
            c"security.selinux",
            &label[..len],
            rustix::fs::XattrFlags::empty(),
        );
    }
}

/// Atomic counter for unique temp file names across threads.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique temporary file path in the same directory as the target.
///
/// Uses PID + atomic counter to avoid collisions between threads.
fn tmp_path_for(target: &Path) -> PathBuf {
    let file_name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let pid = std::process::id();
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    target.with_file_name(format!(".{file_name}.shadow-rs.{pid}.{seq}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test_file");

        atomic_write(&target, |f| {
            writeln!(f, "hello")?;
            Ok(())
        })
        .unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "hello\n");
    }

    #[test]
    fn test_atomic_write_replaces_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test_file");
        fs::write(&target, "old content").unwrap();

        atomic_write(&target, |f| {
            write!(f, "new content")?;
            Ok(())
        })
        .unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "new content");
    }

    #[test]
    fn test_atomic_write_failure_preserves_original() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test_file");
        fs::write(&target, "original").unwrap();

        let result = atomic_write(&target, |_f| {
            Err(ShadowError::Other("intentional failure".into()))
        });

        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
    }

    // The whole point of the rewrite: /etc/shadow must still be root:shadow
    // 0640 afterwards. Only root can hand a file to another owner, so the
    // foreign uid/gid part of the check runs in the Docker images; elsewhere
    // the test still proves mode and (own) ownership survive.
    #[test]
    fn test_atomic_write_preserves_mode_owner_and_group() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("shadow");
        fs::write(&target, "root:*:0:0:99999:7:::\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        if rustix::process::geteuid().is_root() {
            std::os::unix::fs::chown(&target, Some(12345), Some(54321)).unwrap();
        }
        let before = fs::metadata(&target).unwrap();

        atomic_write(&target, |f| {
            writeln!(f, "root:*:0:0:99999:7:::")?;
            Ok(())
        })
        .unwrap();

        let after = fs::metadata(&target).unwrap();
        assert_eq!(after.mode() & 0o7777, 0o640);
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
    }

    // rename(2) over a symlink would replace the link itself; the file it
    // points to must be the one that changes.
    #[test]
    fn test_atomic_write_follows_symlinked_target() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let link = dir.path().join("link");
        fs::write(&real, "old").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        atomic_write(&link, |f| {
            write!(f, "new")?;
            Ok(())
        })
        .unwrap();

        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&real).unwrap(), "new");
    }

    #[test]
    fn test_tmp_path_is_hidden() {
        let target = Path::new("/etc/passwd");
        let tmp = tmp_path_for(target);
        let name = tmp.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with('.'));
        assert!(name.contains("shadow-rs"));
        assert!(name.ends_with(".tmp"));
    }
}
