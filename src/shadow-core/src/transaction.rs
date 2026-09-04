// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! A record file held under its lock for the duration of a change.
//!
//! Every tool repeats the same five steps: take the lock, read under it,
//! change the entries, write atomically, release. Written out by hand at each
//! of the thirty-odd call sites, the order is easy to get wrong, and it was:
//! `pwck -s` sorted entries it had read *before* taking the lock, so a change
//! another process made in between was silently reverted.
//!
//! [`LockedFile`] makes the correct order the only one available. `open` locks
//! and then reads; `entries_mut` hands out the data; `commit` validates,
//! writes atomically and releases; dropping without committing releases
//! without writing. There is no way to read outside the lock or write after
//! releasing it, because neither is expressible.
//!
//! Signals are blocked for the lifetime of the value. A `SIGINT` between
//! acquiring the lock and finishing the write would otherwise leave a stale
//! lock file behind, which every later run has to wait out.

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::atomic;
use crate::error::ShadowError;
use crate::hardening::SignalBlocker;
use crate::lock::FileLock;
use crate::records::{self, Layout, Named};

/// A record type a [`LockedFile`] can read, change and write back.
///
/// The three halves of the format in one place: parsing, rendering, and the
/// check that a value cannot corrupt the record it is written into.
pub trait Record: FromStr<Err = ShadowError> + Display + Named {
    /// Reject a field value that would break the file format.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Validation` naming the offending field.
    fn validate_fields(&self) -> Result<(), ShadowError>;
}

/// A record file, locked, read, and waiting to be written back.
///
/// Dropping this without calling [`LockedFile::commit`] releases the lock and
/// leaves the file untouched, which is what every error path wants.
pub struct LockedFile<T> {
    path: PathBuf,
    /// Taken in `open`, released by `commit` or by `Drop`.
    lock: Option<FileLock>,
    entries: Vec<T>,
    layout: Layout,
    /// Restores the signal mask when the transaction ends, whichever way.
    _signals: SignalBlocker,
}

impl<T: Record> LockedFile<T> {
    /// Lock `path`, then read it.
    ///
    /// In that order: reading first and locking afterwards leaves a window in
    /// which another process can change the file, and the change is then lost
    /// when this one writes.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Lock` if the lock cannot be taken within the
    /// timeout, and `ShadowError::Parse` or `ShadowError::IoPath` if the file
    /// cannot be read.
    pub fn open(path: &Path) -> Result<Self, ShadowError> {
        let signals = SignalBlocker::block_critical()?;
        let lock = FileLock::acquire(path)?;
        // On any failure from here on, `lock` drops and the file is untouched.
        let (entries, layout) = records::read_with_layout::<T>(path)?;
        Ok(Self {
            path: path.to_owned(),
            lock: Some(lock),
            entries,
            layout,
            _signals: signals,
        })
    }

    /// Like [`LockedFile::open`], but a file that does not exist reads as
    /// empty instead of failing.
    ///
    /// For the tools that create a record file where there was none -- a
    /// `groupadd` into a fresh `--prefix` tree, for instance. `open` stays
    /// strict on purpose: for `passwd` and `chage` a missing `/etc/shadow` is
    /// its own error with its own exit code, and reading it as "no accounts"
    /// would report every login as unknown instead.
    ///
    /// The lock is still taken first, so two processes cannot both decide the
    /// file is absent and both create it.
    ///
    /// # Errors
    ///
    /// As [`LockedFile::open`], except that a missing file is not an error.
    pub fn open_or_empty(path: &Path) -> Result<Self, ShadowError> {
        let signals = SignalBlocker::block_critical()?;
        let lock = FileLock::acquire(path)?;
        let (entries, layout) = if path.exists() {
            records::read_with_layout::<T>(path)?
        } else {
            (Vec::new(), Layout::default())
        };
        Ok(Self {
            path: path.to_owned(),
            lock: Some(lock),
            entries,
            layout,
            _signals: signals,
        })
    }

    /// The entries as read, in file order.
    #[must_use]
    pub fn entries(&self) -> &[T] {
        &self.entries
    }

    /// The entries, to be changed before committing.
    pub fn entries_mut(&mut self) -> &mut Vec<T> {
        &mut self.entries
    }

    /// The entry with this name, if the file has one.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&T> {
        self.entries.iter().find(|e| e.name() == name)
    }

    /// The entry with this name, to be changed.
    pub fn find_mut(&mut self, name: &str) -> Option<&mut T> {
        self.entries.iter_mut().find(|e| e.name() == name)
    }

    /// The path this transaction is against.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Validate every entry, write the file atomically, and release the lock.
    ///
    /// The comments, blank lines and NIS compatibility lines the file carried
    /// are put back where they were, each still attached to the entry it
    /// preceded.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Validation` if an entry holds a value that would
    /// corrupt the record -- in which case nothing is written -- and
    /// `ShadowError::IoPath` if the write fails.
    pub fn commit(mut self) -> Result<(), ShadowError> {
        let entries = &self.entries;
        let layout = &self.layout;
        let result = atomic::atomic_write(&self.path, |mut file| {
            // `write_with_layout` takes `&mut W`, and `atomic_write` hands over
            // a `&mut dyn Write`; borrowing it again makes `W` the fat pointer,
            // which is sized, rather than the unsized `dyn Write`.
            records::write_with_layout(entries, layout, &mut file, |entry, w| {
                entry.validate_fields()?;
                writeln!(w, "{entry}")?;
                Ok(())
            })
        });

        // Release before returning either way: an error path that held the
        // lock until the process exited would block every concurrent tool for
        // as long as the caller took to report it.
        drop(self.lock.take());
        result
    }

    /// Like [`LockedFile::commit`], but remove the file when nothing is left
    /// in it.
    ///
    /// For `/etc/group`, `/etc/gshadow` and the subid files an absent file and
    /// an empty one mean the same thing, and the atomic writer refuses to
    /// produce a zero-length file: a truncated account file is a far more
    /// common failure than a deliberately empty one, so it is treated as a
    /// bug. Deleting the last group therefore has to unlink.
    ///
    /// Not for `/etc/passwd` or `/etc/shadow`, where an empty file is not a
    /// state anyone wants to reach by accident; those use `commit`.
    ///
    /// The file is only removed when it carried no comments or other preserved
    /// lines either. A file that is all comments still says something.
    ///
    /// # Errors
    ///
    /// As [`LockedFile::commit`], plus `ShadowError::IoPath` if the file
    /// cannot be removed.
    pub fn commit_or_remove(mut self) -> Result<(), ShadowError> {
        if !self.entries.is_empty() || !self.layout.is_empty() {
            return self.commit();
        }
        let result = std::fs::remove_file(&self.path).or_else(|e| {
            // Already gone is the state we wanted.
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(ShadowError::IoPath(e, self.path.clone()))
            }
        });
        drop(self.lock.take());
        result
    }

    /// Release the lock and discard the changes.
    ///
    /// The same as dropping the value; useful where the intent is worth
    /// stating.
    pub fn abandon(self) {
        drop(self);
    }
}

impl<T> Drop for LockedFile<T> {
    fn drop(&mut self) {
        // `commit` has already taken it; this covers every other exit.
        drop(self.lock.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passwd::PasswdEntry;

    fn temp_passwd(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("passwd");
        std::fs::write(&path, content).expect("write");
        (dir, path)
    }

    const TWO: &str = "alice:x:1000:1000::/home/alice:/bin/sh\n\
                       bob:x:1001:1001::/home/bob:/bin/sh\n";

    #[test]
    fn test_commit_writes_the_changes() {
        let (_d, path) = temp_passwd(TWO);
        let mut file = LockedFile::<PasswdEntry>::open(&path).expect("open");
        file.find_mut("alice").expect("alice").shell = "/bin/bash".into();
        file.commit().expect("commit");

        let content = std::fs::read_to_string(&path).expect("read");
        assert!(content.contains("alice:x:1000:1000::/home/alice:/bin/bash"));
        assert!(content.contains("bob:x:1001:1001::/home/bob:/bin/sh"));
    }

    /// Every error path wants this: the file is left exactly as it was.
    #[test]
    fn test_dropping_without_committing_changes_nothing() {
        let (_d, path) = temp_passwd(TWO);
        {
            let mut file = LockedFile::<PasswdEntry>::open(&path).expect("open");
            file.find_mut("alice").expect("alice").shell = "/bin/bash".into();
            // No commit.
        }
        assert_eq!(std::fs::read_to_string(&path).expect("read"), TWO);
    }

    /// And the lock is gone afterwards, so the next transaction can start.
    #[test]
    fn test_the_lock_is_released_either_way() {
        let (_d, path) = temp_passwd(TWO);
        drop(LockedFile::<PasswdEntry>::open(&path).expect("first open"));
        LockedFile::<PasswdEntry>::open(&path)
            .expect("a released lock must be takeable again")
            .commit()
            .expect("commit");
        LockedFile::<PasswdEntry>::open(&path).expect("still takeable after a commit");
    }

    /// A value that would corrupt the record stops the write; the file keeps
    /// its previous contents rather than half of them.
    #[test]
    fn test_an_invalid_entry_aborts_the_write() {
        let (_d, path) = temp_passwd(TWO);
        let mut file = LockedFile::<PasswdEntry>::open(&path).expect("open");
        file.find_mut("alice").expect("alice").gecos = "has:a:separator".into();
        assert!(file.commit().is_err(), "a colon in a field must be refused");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), TWO);
    }

    /// Comments and blank lines survive a change, still attached to the entry
    /// they preceded.
    #[test]
    fn test_layout_is_preserved() {
        let text = "# the first account\nalice:x:1000:1000::/home/alice:/bin/sh\n\n# and bob\nbob:x:1001:1001::/home/bob:/bin/sh\n";
        let (_d, path) = temp_passwd(text);
        let mut file = LockedFile::<PasswdEntry>::open(&path).expect("open");
        file.find_mut("bob").expect("bob").shell = "/bin/bash".into();
        file.commit().expect("commit");

        let content = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            content,
            "# the first account\nalice:x:1000:1000::/home/alice:/bin/sh\n\n# and bob\nbob:x:1001:1001::/home/bob:/bin/bash\n"
        );
    }

    #[test]
    fn test_entries_are_read_in_file_order() {
        let (_d, path) = temp_passwd(TWO);
        let file = LockedFile::<PasswdEntry>::open(&path).expect("open");
        let names: Vec<&str> = file.entries().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["alice", "bob"]);
        assert!(file.find("ghost").is_none());
    }

    #[test]
    fn test_adding_and_removing_entries() {
        let (_d, path) = temp_passwd(TWO);
        let mut file = LockedFile::<PasswdEntry>::open(&path).expect("open");
        file.entries_mut().retain(|e| e.name != "bob");
        file.entries_mut().push(PasswdEntry {
            name: "carol".into(),
            passwd: "x".into(),
            uid: 1002,
            gid: 1002,
            gecos: String::new(),
            home: "/home/carol".into(),
            shell: "/bin/sh".into(),
        });
        file.commit().expect("commit");

        let content = std::fs::read_to_string(&path).expect("read");
        assert!(content.contains("alice:"));
        assert!(!content.contains("bob:"));
        assert!(content.contains("carol:x:1002:1002::/home/carol:/bin/sh"));
    }

    /// A file that does not parse is an error at `open`, before anything is
    /// changed, rather than a silent loss of the lines that failed.
    #[test]
    fn test_a_malformed_file_fails_to_open() {
        let (_d, path) = temp_passwd("alice:x:1000:1000::/home/alice:/bin/sh\nnot-a-record\n");
        assert!(LockedFile::<PasswdEntry>::open(&path).is_err());
    }
}
