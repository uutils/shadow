// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore lockfile

//! File locking for `/etc/passwd`, `/etc/shadow`, etc.
//!
//! Two locks are taken together for the account files, so shadow-rs excludes
//! both other shadow-rs invocations and the rest of the system:
//!
//! * a `.lock` file (e.g. `/etc/passwd.lock`), created atomically with
//!   `O_CREAT | O_EXCL` via the classic link trick and carrying the holder's
//!   PID for stale detection. This is what shadow-utils uses.
//! * `/etc/.pwd.lock`, held with an `fcntl` open-file-description write lock —
//!   the lock `lckpwdf(3)` provides and that `vipw`, `pwconv`, `libuser`,
//!   `systemd-sysusers` and `pam_unix` all take. Without it a concurrent
//!   `passwd` run by `pam_unix` could silently overwrite our change.
//!
//! The `.pwd.lock` is process-wide and reference-counted per path, so the
//! nested locks a single tool takes (passwd, then group, then gshadow, …)
//! share one `fcntl` lock and release it when the last one goes away.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::ShadowError;

/// Default lock timeout (matches GNU shadow-utils `LOCK_TIMEOUT`).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Retry interval when waiting for a lock.
const RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Process-wide `/etc/.pwd.lock` holders, keyed by path so a `--prefix` run
/// (and the parallel test suite) keeps each tree's lock independent. The
/// `File` holds the `fcntl` lock; dropping it releases the lock, so the entry
/// is removed once its reference count reaches zero.
static PWD_LOCKS: LazyLock<Mutex<HashMap<PathBuf, (File, usize)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// A held file lock. The lock is released when this value is dropped.
pub struct FileLock {
    lock_path: PathBuf,
    released: bool,
    /// Set when this lock also holds a reference to the `/etc/.pwd.lock` for
    /// `pwd_lock_path`; the reference is dropped in `Drop`.
    pwd_lock_path: Option<PathBuf>,
}

impl FileLock {
    /// Acquire a lock for the given file using the default timeout.
    ///
    /// Creates `{file_path}.lock` atomically. If another process holds the lock,
    /// retries until the timeout expires. Stale locks (held by dead processes)
    /// are automatically cleaned up.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Lock` if the lock cannot be acquired within the timeout.
    pub fn acquire(file_path: &Path) -> Result<Self, ShadowError> {
        Self::acquire_with_timeout(file_path, DEFAULT_TIMEOUT)
    }

    /// Acquire a lock with a custom timeout.
    ///
    /// Uses the classic lock-via-link pattern to avoid TOCTOU races:
    /// 1. Write our PID to a unique temp file
    /// 2. Try to `hard_link` it to the lock path (atomic on POSIX)
    /// 3. If link fails (lock exists), check for staleness and retry
    ///
    /// Even if two processes both detect a stale lock and both remove it,
    /// only one will succeed at the subsequent `hard_link`, so mutual
    /// exclusion is never violated.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Lock` if the lock cannot be acquired within the timeout.
    pub fn acquire_with_timeout(file_path: &Path, timeout: Duration) -> Result<Self, ShadowError> {
        let lock_path = lock_path_for(file_path);
        let deadline = Instant::now() + timeout;
        let tmp_path = tmp_lock_path(&lock_path);

        // Write our PID to the temp file once, then try to link it in a loop.
        write_pid_file(&tmp_path)?;

        let result = Self::acquire_loop(&lock_path, &tmp_path, deadline);

        // Always clean up our temp file, regardless of success or failure.
        let _ = fs::remove_file(&tmp_path);

        let mut lock = result?;

        // For the account files, also take /etc/.pwd.lock so we exclude the
        // system's own account tools. If it cannot be taken, drop the .lock we
        // just got (via the early return running `lock`'s destructor).
        if let Some(pwd_path) = account_pwd_lock_path(file_path) {
            acquire_pwd_lock(&pwd_path, deadline)?;
            lock.pwd_lock_path = Some(pwd_path);
        }

        Ok(lock)
    }

    /// Inner acquisition loop. Separated so the caller can guarantee temp file cleanup.
    fn acquire_loop(
        lock_path: &Path,
        tmp_path: &Path,
        deadline: Instant,
    ) -> Result<Self, ShadowError> {
        loop {
            // Attempt to hard-link our temp file to the lock path. hard_link is
            // atomic: it either creates the destination or fails, so two
            // processes can never both succeed for the same lock_path.
            match fs::hard_link(tmp_path, lock_path) {
                Ok(()) => {
                    return Ok(Self {
                        lock_path: lock_path.to_owned(),
                        released: false,
                        pwd_lock_path: None,
                    });
                }
                // The lock is held — fall through to staleness / retry.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                // Anything else (e.g. a filesystem without hard links returning
                // EPERM) is not "held" — report it now instead of waiting out
                // the whole timeout on a lock that will never appear.
                Err(e) => {
                    return Err(ShadowError::Lock(
                        format!("cannot create lock {}: {e}", lock_path.display()).into(),
                    ));
                }
            }

            // Link failed because the lock file exists. If it is stale, try to
            // remove it and retry immediately; if the removal itself fails
            // (e.g. the file was made immutable), fall through to the bounded
            // wait rather than spinning on it.
            if is_stale_lock(lock_path) {
                match fs::remove_file(lock_path) {
                    Ok(()) => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => {}
                }
            }

            if Instant::now() >= deadline {
                return Err(ShadowError::Lock(
                    format!("cannot acquire lock {}: timed out", lock_path.display()).into(),
                ));
            }

            thread::sleep(RETRY_INTERVAL);
        }
    }

    /// Explicitly release the lock.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Lock` if the lock file cannot be removed. The
    /// `/etc/.pwd.lock` reference, if any, is still released via `Drop`.
    pub fn release(mut self) -> Result<(), ShadowError> {
        self.released = true;
        fs::remove_file(&self.lock_path).map_err(|e| {
            ShadowError::Lock(
                format!("cannot release lock {}: {e}", self.lock_path.display()).into(),
            )
        })
        // `self` is dropped here, releasing the /etc/.pwd.lock reference.
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if !self.released {
            let _ = fs::remove_file(&self.lock_path);
        }
        if let Some(pwd_path) = self.pwd_lock_path.take() {
            release_pwd_lock(&pwd_path);
        }
    }
}

/// The `/etc/.pwd.lock` path for an account file, or `None` for other files.
///
/// Only `passwd`, `shadow`, `group` and `gshadow` are guarded by the system
/// password lock; `subuid`/`subgid` and anything else keep just their `.lock`.
fn account_pwd_lock_path(file_path: &Path) -> Option<PathBuf> {
    match file_path.file_name()?.to_str()? {
        "passwd" | "shadow" | "group" | "gshadow" => Some(file_path.with_file_name(".pwd.lock")),
        _ => None,
    }
}

/// Take (or add a reference to) the `/etc/.pwd.lock` at `path`.
fn acquire_pwd_lock(path: &Path, deadline: Instant) -> Result<(), ShadowError> {
    use rustix::fs::FlockOperation;

    let mut locks = PWD_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if let Some((_, count)) = locks.get_mut(path) {
        *count += 1;
        return Ok(());
    }

    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|e| ShadowError::Lock(format!("cannot open {}: {e}", path.display()).into()))?;

    loop {
        match rustix::fs::fcntl_lock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                locks.insert(path.to_owned(), (file, 1));
                return Ok(());
            }
            // Held by another process (glibc uses EAGAIN/EACCES for F_SETLK).
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::ACCESS) => {
                if Instant::now() >= deadline {
                    return Err(ShadowError::Lock(
                        format!("cannot acquire {}: timed out", path.display()).into(),
                    ));
                }
                thread::sleep(RETRY_INTERVAL);
            }
            Err(e) => {
                return Err(ShadowError::Lock(
                    format!("cannot lock {}: {e}", path.display()).into(),
                ));
            }
        }
    }
}

/// Drop one reference to the `/etc/.pwd.lock` at `path`, releasing the
/// underlying `fcntl` lock when the last reference goes away.
fn release_pwd_lock(path: &Path) {
    let mut locks = PWD_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, count)) = locks.get_mut(path) {
        *count -= 1;
        if *count == 0 {
            // Dropping the File closes the fd, which releases the fcntl lock.
            locks.remove(path);
        }
    }
}

/// Compute the lock file path: append `.lock` to the file path.
fn lock_path_for(file_path: &Path) -> PathBuf {
    let mut lock = file_path.as_os_str().to_owned();
    lock.push(".lock");
    PathBuf::from(lock)
}

/// Compute a unique temp file path for the lock-via-link pattern.
///
/// Uses PID to avoid collisions between concurrent processes.
fn tmp_lock_path(lock_path: &Path) -> PathBuf {
    let pid = std::process::id();
    let mut tmp = lock_path.as_os_str().to_owned();
    tmp.push(format!(".{pid}.tmp"));
    PathBuf::from(tmp)
}

/// Write our PID to a temp file for later hard-linking.
///
/// Uses `O_CREAT | O_EXCL` (`create_new`) to prevent symlink attacks: if
/// an attacker plants a symlink at `tmp_path`, `open` will fail instead of
/// following it. If the file already exists from a previous crashed run,
/// we remove it first and retry once.
fn write_pid_file(tmp_path: &Path) -> Result<(), ShadowError> {
    let open_exclusive = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp_path)
    };

    let mut file = match open_exclusive() {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Stale temp file from a previous crashed run — remove and retry.
            let _ = fs::remove_file(tmp_path);
            open_exclusive().map_err(|e2| {
                ShadowError::Lock(format!("cannot create {}: {e2}", tmp_path.display()).into())
            })?
        }
        Err(e) => {
            return Err(ShadowError::Lock(
                format!("cannot create {}: {e}", tmp_path.display()).into(),
            ));
        }
    };

    let pid = rustix::process::getpid();
    write!(file, "{pid}").map_err(|e| {
        ShadowError::Lock(format!("cannot write {}: {e}", tmp_path.display()).into())
    })?;

    file.flush().map_err(|e| {
        ShadowError::Lock(format!("cannot flush {}: {e}", tmp_path.display()).into())
    })?;
    rustix::fs::fsync(&file).map_err(|e| {
        ShadowError::Lock(format!("cannot fsync {}: {e}", tmp_path.display()).into())
    })?;

    Ok(())
}

/// Check if an existing lock file is stale (held by a dead process).
fn is_stale_lock(lock_path: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(lock_path) else {
        return false;
    };

    let Ok(pid) = contents.trim().parse::<i32>() else {
        // Cannot parse PID — treat as stale.
        return true;
    };

    if pid <= 0 {
        return true;
    }

    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        return true;
    };

    // Signal 0 checks if the process exists without actually sending a signal.
    // Only ESRCH means "no such process". EPERM means the process exists but
    // we lack permission to signal it — that is a valid lock holder.
    matches!(
        rustix::process::test_kill_process(pid),
        Err(rustix::io::Errno::SRCH)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_path_for() {
        assert_eq!(
            lock_path_for(Path::new("/etc/shadow")),
            PathBuf::from("/etc/shadow.lock")
        );
    }

    #[test]
    fn test_acquire_and_release() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test_file");
        fs::write(&file, "data").unwrap();

        let lock = FileLock::acquire(&file).unwrap();
        assert!(lock.lock_path.exists());

        lock.release().unwrap();
        assert!(!dir.path().join("test_file.lock").exists());
    }

    #[test]
    fn test_drop_releases_lock() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test_file");
        fs::write(&file, "data").unwrap();

        {
            let _lock = FileLock::acquire(&file).unwrap();
            assert!(dir.path().join("test_file.lock").exists());
        }
        // Lock should be released by drop.
        assert!(!dir.path().join("test_file.lock").exists());
    }

    #[test]
    fn test_double_lock_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test_file");
        fs::write(&file, "data").unwrap();

        let _lock1 = FileLock::acquire(&file).unwrap();

        // Second lock should time out.
        let result = FileLock::acquire_with_timeout(&file, Duration::from_millis(200));
        assert!(result.is_err());
    }

    #[test]
    fn test_stale_lock_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test_file");
        fs::write(&file, "data").unwrap();

        // Create a lock file with a PID that doesn't exist.
        let lock_path = dir.path().join("test_file.lock");
        fs::write(&lock_path, "999999999").unwrap();

        // Should succeed because the stale lock is cleaned up.
        let lock = FileLock::acquire(&file).unwrap();
        lock.release().unwrap();
    }

    #[test]
    fn test_lock_file_has_cloexec() {
        use std::os::unix::io::AsFd;

        // Rust's stdlib sets O_CLOEXEC by default on Linux.
        // Verify the lock file FD won't leak to child processes.
        let dir = tempfile::tempdir().expect("tempdir creation failed");
        let file = dir.path().join("test_file");
        fs::write(&file, "data").expect("failed to write test file");

        let lock = FileLock::acquire(&file).expect("failed to acquire lock");

        let f = fs::File::open(&lock.lock_path).expect("failed to open lock file");
        let flags = rustix::io::fcntl_getfd(f.as_fd()).expect("fcntl F_GETFD failed");
        assert!(
            flags.contains(rustix::io::FdFlags::CLOEXEC),
            "FD should have CLOEXEC set"
        );

        lock.release().expect("failed to release lock");
    }

    #[test]
    fn test_account_pwd_lock_path() {
        assert_eq!(
            account_pwd_lock_path(Path::new("/etc/shadow")),
            Some(PathBuf::from("/etc/.pwd.lock"))
        );
        assert_eq!(
            account_pwd_lock_path(Path::new("/mnt/root/etc/group")),
            Some(PathBuf::from("/mnt/root/etc/.pwd.lock"))
        );
        // Files not covered by lckpwdf keep only their own .lock.
        assert_eq!(account_pwd_lock_path(Path::new("/etc/subuid")), None);
        assert_eq!(account_pwd_lock_path(Path::new("/etc/passwd.lock")), None);
    }

    // Locking an account file creates and holds /etc/.pwd.lock, the file
    // glibc's lckpwdf and pam_unix contend on. (The fcntl lock is a
    // traditional POSIX record lock, owned by the process, so its exclusion
    // of *other* processes cannot be observed from this one — that is covered
    // by the cross-process check in the PR; here we assert the mechanics.)
    #[test]
    fn test_account_lock_takes_pwd_lock() {
        let dir = tempfile::tempdir().unwrap();
        let shadow = dir.path().join("shadow");
        fs::write(&shadow, "root:*:0:0:99999:7:::\n").unwrap();
        let pwd_lock = dir.path().join(".pwd.lock");

        let lock = FileLock::acquire(&shadow).unwrap();
        assert!(pwd_lock.exists(), ".pwd.lock should be created");
        assert!(
            PWD_LOCKS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&pwd_lock),
            "the fcntl lock should be held while the FileLock lives"
        );

        lock.release().unwrap();
        assert!(
            !PWD_LOCKS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&pwd_lock),
            "the fcntl lock should be released"
        );
    }

    // Nested locks a single tool takes share one fcntl lock, released only
    // when the last one is dropped.
    #[test]
    fn test_pwd_lock_is_reference_counted() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["passwd", "group"] {
            fs::write(dir.path().join(name), "x\n").unwrap();
        }
        let pwd_lock = dir.path().join(".pwd.lock");

        let a = FileLock::acquire(&dir.path().join("passwd")).unwrap();
        let b = FileLock::acquire(&dir.path().join("group")).unwrap();
        assert_eq!(
            PWD_LOCKS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&pwd_lock)
                .map(|(_, n)| *n),
            Some(2)
        );

        drop(a);
        drop(b);
        assert!(
            !PWD_LOCKS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&pwd_lock),
            "the fcntl lock should be gone once the last reference drops"
        );
    }

    #[test]
    fn test_lock_file_contains_pid() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test_file");
        fs::write(&file, "data").unwrap();

        let lock = FileLock::acquire(&file).unwrap();
        let contents = fs::read_to_string(&lock.lock_path).unwrap();
        let pid: i32 = contents.trim().parse().unwrap();
        assert_eq!(pid, i32::try_from(std::process::id()).unwrap());

        lock.release().unwrap();
    }
}
