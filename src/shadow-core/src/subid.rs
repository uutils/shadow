// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore subuid subgid subid

//! Parser and writer for `/etc/subuid` and `/etc/subgid` (subordinate ID ranges).
//!
//! File format (man 5 subuid / man 5 subgid):
//! ```text
//! username:start:count
//! ```
//!
//! Each line grants the named user (or UID) a contiguous block of
//! subordinate UIDs (or GIDs) starting at `start` with `count` entries.
//! These ranges are used by `newuidmap` / `newgidmap` for user-namespace
//! ID mapping (rootless containers).

use std::fmt;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::str::FromStr;

use crate::error::ShadowError;
pub use crate::records::Layout;
use crate::validate::validate_field;

/// A single entry from `/etc/subuid` or `/etc/subgid`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubIdEntry {
    /// Login name (or numeric UID/GID as a string).
    pub name: String,
    /// First subordinate ID in the range.
    pub start: u64,
    /// Number of subordinate IDs allocated.
    pub count: u64,
}

impl fmt::Display for SubIdEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.name, self.start, self.count)
    }
}

impl SubIdEntry {
    /// Refuse an entry whose name would break the file format; see
    /// [`crate::passwd::PasswdEntry::validate_fields`].
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Validation` naming the character.
    pub fn validate_fields(&self) -> Result<(), ShadowError> {
        validate_field("owner name", &self.name)
    }
}

impl FromStr for SubIdEntry {
    type Err = ShadowError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let mut fields = line.splitn(4, ':');

        let name = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing subid name".into()))?;
        let start_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing subid start".into()))?;
        let count_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing subid count".into()))?;

        if fields.next().is_some() {
            return Err(ShadowError::Parse("too many fields in subid entry".into()));
        }

        let start = start_str.parse::<u64>().map_err(|e| {
            ShadowError::Parse(format!("invalid subid start '{start_str}': {e}").into())
        })?;
        let count = count_str.parse::<u64>().map_err(|e| {
            ShadowError::Parse(format!("invalid subid count '{count_str}': {e}").into())
        })?;

        Ok(Self {
            name: name.to_string(),
            start,
            count,
        })
    }
}

/// Read all entries from an `/etc/subuid` or `/etc/subgid`-formatted file.
///
/// Skips blank lines and lines starting with `#`.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or contains malformed entries.
pub fn read_subid_file(path: &Path) -> Result<Vec<SubIdEntry>, ShadowError> {
    let file = std::fs::File::open(path).map_err(|e| ShadowError::IoPath(e, path.to_owned()))?;
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        // Comments, blank lines and NIS compat lines are not entries. Use
        // read_*_with_layout when they must survive a rewrite.
        if crate::records::is_raw_line(&line) {
            continue;
        }
        entries.push(line.parse()?);
    }

    Ok(entries)
}

/// Write entries to an `/etc/subuid` or `/etc/subgid`-formatted file.
///
/// # Errors
///
/// Returns `ShadowError` on I/O write failure.
pub fn write_subid<W: Write>(entries: &[SubIdEntry], mut writer: W) -> Result<(), ShadowError> {
    for entry in entries {
        entry.validate_fields()?;
        writeln!(writer, "{entry}")?;
    }
    Ok(())
}

impl crate::records::Named for SubIdEntry {
    fn name(&self) -> &str {
        &self.name
    }
}

/// Read `/etc/subuid` keeping comments, blank lines and NIS compat lines.
///
/// Returns the entries plus the [`crate::records::Layout`] that
/// [`write_subid_with_layout`] needs to put those lines back.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or an entry is malformed.
pub fn read_subid_with_layout(
    path: &Path,
) -> Result<(Vec<SubIdEntry>, crate::records::Layout), ShadowError> {
    crate::records::read_with_layout(path)
}

/// Write entries back, restoring the lines [`read_subid_with_layout`] preserved.
///
/// # Errors
///
/// Returns `ShadowError` on a write failure or an entry that would corrupt the
/// record format.
pub fn write_subid_with_layout<W: Write>(
    entries: &[SubIdEntry],
    layout: &crate::records::Layout,
    mut writer: W,
) -> Result<(), ShadowError> {
    crate::records::write_with_layout(entries, layout, &mut writer, |entry, w| {
        entry.validate_fields()?;
        writeln!(w, "{entry}")?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_entry() {
        let entry: SubIdEntry = "alice:100000:65536".parse().unwrap();
        assert_eq!(entry.name, "alice");
        assert_eq!(entry.start, 100_000);
        assert_eq!(entry.count, 65536);
    }

    #[test]
    fn test_parse_numeric_name() {
        let entry: SubIdEntry = "1000:200000:65536".parse().unwrap();
        assert_eq!(entry.name, "1000");
        assert_eq!(entry.start, 200_000);
    }

    #[test]
    fn test_roundtrip() {
        let line = "bob:165536:65536";
        let entry: SubIdEntry = line.parse().unwrap();
        assert_eq!(entry.to_string(), line);
    }

    #[test]
    fn test_parse_too_few_fields() {
        assert!("alice:100000".parse::<SubIdEntry>().is_err());
    }

    #[test]
    fn test_parse_too_many_fields() {
        assert!("alice:100000:65536:extra".parse::<SubIdEntry>().is_err());
    }

    #[test]
    fn test_parse_invalid_start() {
        assert!("alice:abc:65536".parse::<SubIdEntry>().is_err());
    }

    #[test]
    fn test_parse_invalid_count() {
        assert!("alice:100000:xyz".parse::<SubIdEntry>().is_err());
    }

    #[test]
    fn test_parse_negative_start() {
        assert!("alice:-1:65536".parse::<SubIdEntry>().is_err());
    }

    #[test]
    fn test_write_read_roundtrip_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subuid");

        let entries = vec![
            SubIdEntry {
                name: "alice".into(),
                start: 100_000,
                count: 65536,
            },
            SubIdEntry {
                name: "bob".into(),
                start: 165_536,
                count: 65536,
            },
        ];

        let file = std::fs::File::create(&path).unwrap();
        write_subid(&entries, file).unwrap();

        let read_back = read_subid_file(&path).unwrap();
        assert_eq!(entries, read_back);
    }

    #[test]
    fn test_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subuid");
        std::fs::write(&path, "").unwrap();
        let entries = read_subid_file(&path).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_comments_and_blanks_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subuid");
        std::fs::write(&path, "# subordinate UIDs\n\nalice:100000:65536\n# end\n").unwrap();
        let entries = read_subid_file(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "alice");
    }

    #[test]
    fn test_large_values() {
        let line = "root:4294967296:4294967296";
        let entry: SubIdEntry = line.parse().unwrap();
        assert_eq!(entry.start, 4_294_967_296);
        assert_eq!(entry.count, 4_294_967_296);
        assert_eq!(entry.to_string(), line);
    }

    use proptest::prelude::*;

    fn arb_subid_entry() -> impl Strategy<Value = SubIdEntry> {
        ("[a-z_][a-z0-9_-]{0,31}", 0u64..1_000_000_000, 1u64..200_000)
            .prop_map(|(name, start, count)| SubIdEntry { name, start, count })
    }

    proptest! {
        #[test]
        fn test_subid_roundtrip(entry in arb_subid_entry()) {
            let line = entry.to_string();
            let parsed: SubIdEntry = line.parse().unwrap();
            prop_assert_eq!(parsed, entry);
        }
    }
}
