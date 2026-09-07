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
use std::io::Write;
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
    crate::records::read_entries(path)
}

/// Write entries to an `/etc/subuid` or `/etc/subgid`-formatted file.
///
/// # Errors
///
/// Returns `ShadowError` on I/O write failure.
pub fn write_subid<W: Write>(entries: &[SubIdEntry], writer: W) -> Result<(), ShadowError> {
    crate::records::write_entries(entries, writer)
}

impl crate::records::Named for SubIdEntry {
    fn name(&self) -> &str {
        &self.name
    }
}

impl crate::transaction::Record for SubIdEntry {
    fn validate_fields(&self) -> Result<(), ShadowError> {
        Self::validate_fields(self)
    }
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

// ---------------------------------------------------------------------------
// Ranges: what usermod -v/-V/-w/-W do to a user's entries
// ---------------------------------------------------------------------------

/// Parse `FIRST-LAST`, both inclusive, as usermod(8) spells a range.
///
/// Plain decimals only, `LAST` not below `FIRST`, and nothing above the
/// 32-bit ids the kernel maps. `None` for anything else, which the caller
/// reports as an invalid range.
#[must_use]
pub fn parse_range(spec: &str) -> Option<(u64, u64)> {
    let (first, last) = spec.split_once('-')?;
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u64>().ok())
            .flatten()
            .filter(|n| u32::try_from(*n).is_ok())
    };
    let (first, last) = (number(first)?, number(last)?);
    (last >= first).then_some((first, last))
}

/// Grant `[first, last]` to `name`.
///
/// A range already covered by one of the user's entries is left alone -- the
/// grant exists, and a second copy would only confuse whoever reads the file
/// -- otherwise a new entry is appended. No check is made against other
/// users' entries: the GNU tool makes none, and an administrator may
/// deliberately share a range.
pub fn add_range(entries: &mut Vec<SubIdEntry>, name: &str, first: u64, last: u64) {
    let covered = entries
        .iter()
        .any(|e| e.name == name && e.start <= first && last < e.start + e.count);
    if !covered {
        entries.push(SubIdEntry {
            name: name.to_string(),
            start: first,
            count: last - first + 1,
        });
    }
}

/// Revoke `[first, last]` from `name`.
///
/// An entry the range covers entirely disappears; one it overlaps is trimmed,
/// and one it cuts through the middle of is split in two, so the ids on
/// either side stay granted. A range the user never had is a no-op.
pub fn remove_range(entries: &mut Vec<SubIdEntry>, name: &str, first: u64, last: u64) {
    let mut kept = Vec::with_capacity(entries.len() + 1);
    for e in entries.drain(..) {
        if e.name != name || e.count == 0 {
            kept.push(e);
            continue;
        }
        let (start, end) = (e.start, e.start + e.count - 1);
        if last < start || first > end {
            kept.push(e);
            continue;
        }
        if start < first {
            kept.push(SubIdEntry {
                name: e.name.clone(),
                start,
                count: first - start,
            });
        }
        if end > last {
            kept.push(SubIdEntry {
                name: e.name.clone(),
                start: last + 1,
                count: end - last,
            });
        }
    }
    *entries = kept;
}

#[cfg(test)]
mod range_tests {
    use super::*;

    fn e(name: &str, start: u64, count: u64) -> SubIdEntry {
        SubIdEntry {
            name: name.to_string(),
            start,
            count,
        }
    }

    #[test]
    fn test_parse_range() {
        assert_eq!(parse_range("300000-300999"), Some((300_000, 300_999)));
        assert_eq!(parse_range("5-5"), Some((5, 5)));
        assert_eq!(parse_range("0-10"), Some((0, 10)));
        for bad in [
            "300999-300000",
            "a-b",
            "300000",
            "-5",
            "5-",
            "1-4294967296",
            " 1-2",
            "1-2-3",
        ] {
            assert_eq!(parse_range(bad), None, "{bad:?}");
        }
    }

    /// Adding appends, unless the user already holds the range.
    #[test]
    fn test_add_range() {
        let mut v = vec![e("alice", 100_000, 65_536)];
        add_range(&mut v, "alice", 300_000, 300_999);
        assert_eq!(v.len(), 2);
        assert_eq!((v[1].start, v[1].count), (300_000, 1000));
        add_range(&mut v, "alice", 300_000, 300_999);
        add_range(&mut v, "alice", 300_500, 300_600);
        assert_eq!(v.len(), 2, "covered ranges are not added again");
        add_range(&mut v, "bob", 300_000, 300_999);
        assert_eq!(v.len(), 3, "another user may hold the same ids");
    }

    /// Removing trims, splits or deletes, and ignores what was never there.
    #[test]
    fn test_remove_range() {
        let mut v = vec![e("alice", 300_000, 1000), e("bob", 300_000, 1000)];
        remove_range(&mut v, "alice", 300_000, 300_499);
        assert_eq!(
            v.iter()
                .filter(|x| x.name == "alice")
                .map(|x| (x.start, x.count))
                .collect::<Vec<_>>(),
            vec![(300_500, 500)]
        );
        assert!(
            v.iter().any(|x| x.name == "bob" && x.count == 1000),
            "bob is untouched"
        );

        remove_range(&mut v, "alice", 300_700, 300_799);
        let alice: Vec<_> = v
            .iter()
            .filter(|x| x.name == "alice")
            .map(|x| (x.start, x.count))
            .collect();
        assert_eq!(
            alice,
            vec![(300_500, 200), (300_800, 200)],
            "a cut in the middle splits"
        );

        remove_range(&mut v, "alice", 500_000, 500_010);
        assert_eq!(
            v.iter().filter(|x| x.name == "alice").count(),
            2,
            "a range never held is a no-op"
        );

        remove_range(&mut v, "alice", 300_000, 300_999);
        assert_eq!(
            v.iter().filter(|x| x.name == "alice").count(),
            0,
            "covered entries disappear"
        );
    }
}
