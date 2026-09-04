// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore gshadow

//! Parser and writer for `/etc/gshadow`.
//!
//! File format (man 5 gshadow):
//! ```text
//! groupname:password:admins:members
//! ```
//!
//! `admins` and `members` are comma-separated lists of usernames.

use std::fmt;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::str::FromStr;

use crate::error::ShadowError;
pub use crate::records::Layout;
use crate::validate::{validate_field, validate_list_item};

/// A single entry from `/etc/gshadow`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GshadowEntry {
    /// Group name (must match an `/etc/group` entry).
    pub name: String,
    /// Encrypted group password (or `!`/`*` for no group password).
    pub passwd: String,
    /// Comma-separated list of group administrators.
    pub admins: Vec<String>,
    /// Comma-separated list of group members.
    pub members: Vec<String>,
}

impl fmt::Display for GshadowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.name,
            self.passwd,
            self.admins.join(","),
            self.members.join(",")
        )
    }
}

impl GshadowEntry {
    /// Refuse an entry whose text fields would break the file format; see
    /// [`crate::passwd::PasswdEntry::validate_fields`]. Administrators and
    /// members must also be free of the `,` that separates them.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Validation` naming the field and character.
    pub fn validate_fields(&self) -> Result<(), ShadowError> {
        validate_field("group name", &self.name)?;
        validate_field("password hash", &self.passwd)?;
        self.admins
            .iter()
            .try_for_each(|a| validate_list_item("administrator name", a))?;
        self.members
            .iter()
            .try_for_each(|m| validate_list_item("member name", m))
    }
}

impl FromStr for GshadowEntry {
    type Err = ShadowError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let mut fields = line.splitn(5, ':');

        let name = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing gshadow group name".into()))?;
        let passwd = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing gshadow password".into()))?;
        let admins_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing gshadow admins".into()))?;
        let members_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing gshadow members".into()))?;

        if fields.next().is_some() {
            return Err(ShadowError::Parse(
                "too many fields in gshadow entry".into(),
            ));
        }

        let admins = if admins_str.is_empty() {
            Vec::new()
        } else {
            admins_str.split(',').map(ToString::to_string).collect()
        };

        let members = if members_str.is_empty() {
            Vec::new()
        } else {
            members_str.split(',').map(ToString::to_string).collect()
        };

        Ok(Self {
            name: name.to_string(),
            passwd: passwd.to_string(),
            admins,
            members,
        })
    }
}

/// Read all entries from an `/etc/gshadow`-formatted file.
///
/// Skips blank lines and lines starting with `#`.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or contains malformed entries.
pub fn read_gshadow_file(path: &Path) -> Result<Vec<GshadowEntry>, ShadowError> {
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

/// Write entries to an `/etc/gshadow`-formatted file.
///
/// # Errors
///
/// Returns `ShadowError` on I/O write failure.
pub fn write_gshadow<W: Write>(entries: &[GshadowEntry], mut writer: W) -> Result<(), ShadowError> {
    for entry in entries {
        entry.validate_fields()?;
        writeln!(writer, "{entry}")?;
    }
    Ok(())
}

impl crate::records::Named for GshadowEntry {
    fn name(&self) -> &str {
        &self.name
    }
}

/// Read `/etc/gshadow` keeping comments, blank lines and NIS compat lines.
///
/// Returns the entries plus the [`crate::records::Layout`] that
/// [`write_gshadow_with_layout`] needs to put those lines back.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or an entry is malformed.
pub fn read_gshadow_with_layout(
    path: &Path,
) -> Result<(Vec<GshadowEntry>, crate::records::Layout), ShadowError> {
    crate::records::read_with_layout(path)
}

/// Write entries back, restoring the lines [`read_gshadow_with_layout`] preserved.
///
/// # Errors
///
/// Returns `ShadowError` on a write failure or an entry that would corrupt the
/// record format.
pub fn write_gshadow_with_layout<W: Write>(
    entries: &[GshadowEntry],
    layout: &crate::records::Layout,
    mut writer: W,
) -> Result<(), ShadowError> {
    crate::records::write_with_layout(entries, layout, &mut writer, |entry, w| {
        entry.validate_fields()?;
        writeln!(w, "{entry}")?;
        Ok(())
    })
}

impl crate::transaction::Record for GshadowEntry {
    fn validate_fields(&self) -> Result<(), ShadowError> {
        Self::validate_fields(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_entry() {
        let entry: GshadowEntry = "root:*::".parse().unwrap();
        assert_eq!(entry.name, "root");
        assert_eq!(entry.passwd, "*");
        assert!(entry.admins.is_empty());
        assert!(entry.members.is_empty());
    }

    #[test]
    fn test_parse_with_admins_and_members() {
        let entry: GshadowEntry = "sudo:!:alice,bob:alice,bob,charlie".parse().unwrap();
        assert_eq!(entry.name, "sudo");
        assert_eq!(entry.passwd, "!");
        assert_eq!(entry.admins, vec!["alice", "bob"]);
        assert_eq!(entry.members, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn test_parse_admins_only() {
        let entry: GshadowEntry = "wheel:!:root:".parse().unwrap();
        assert_eq!(entry.admins, vec!["root"]);
        assert!(entry.members.is_empty());
    }

    #[test]
    fn test_parse_members_only() {
        let entry: GshadowEntry = "docker:!::deploy,ci".parse().unwrap();
        assert!(entry.admins.is_empty());
        assert_eq!(entry.members, vec!["deploy", "ci"]);
    }

    #[test]
    fn test_roundtrip() {
        let line = "sudo:!:alice,bob:alice,bob,charlie";
        let entry: GshadowEntry = line.parse().unwrap();
        assert_eq!(entry.to_string(), line);
    }

    #[test]
    fn test_roundtrip_empty_lists() {
        let line = "root:*::";
        let entry: GshadowEntry = line.parse().unwrap();
        assert_eq!(entry.to_string(), line);
    }

    #[test]
    fn test_parse_too_few_fields() {
        assert!("root:*:".parse::<GshadowEntry>().is_err());
    }

    #[test]
    fn test_parse_too_many_fields() {
        assert!("root:*:::extra".parse::<GshadowEntry>().is_err());
    }

    #[test]
    fn test_write_read_roundtrip_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gshadow");

        let entries = vec![
            GshadowEntry {
                name: "root".into(),
                passwd: "*".into(),
                admins: vec![],
                members: vec![],
            },
            GshadowEntry {
                name: "sudo".into(),
                passwd: "!".into(),
                admins: vec!["alice".into()],
                members: vec!["alice".into(), "bob".into()],
            },
        ];

        let file = std::fs::File::create(&path).unwrap();
        write_gshadow(&entries, file).unwrap();

        let read_back = read_gshadow_file(&path).unwrap();
        assert_eq!(entries, read_back);
    }

    #[test]
    fn test_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gshadow");
        std::fs::write(&path, "").unwrap();
        let entries = read_gshadow_file(&path).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_comments_and_blanks_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gshadow");
        std::fs::write(
            &path,
            "# comment\n\nroot:*::\n# another\nsudo:!:admin:alice\n",
        )
        .unwrap();
        let entries = read_gshadow_file(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "root");
        assert_eq!(entries[1].name, "sudo");
    }

    use proptest::prelude::*;

    fn arb_gshadow_entry() -> impl Strategy<Value = GshadowEntry> {
        (
            "[a-z_][a-z0-9_-]{0,31}",
            "(\\*|!|!!|\\$6\\$[a-z]{4})",
            proptest::collection::vec("[a-z_][a-z0-9_]{0,15}", 0..5),
            proptest::collection::vec("[a-z_][a-z0-9_]{0,15}", 0..5),
        )
            .prop_map(|(name, passwd, admins, members)| GshadowEntry {
                name,
                passwd,
                admins,
                members,
            })
    }

    proptest! {
        #[test]
        fn test_gshadow_roundtrip(entry in arb_gshadow_entry()) {
            let line = entry.to_string();
            let parsed: GshadowEntry = line.parse().unwrap();
            prop_assert_eq!(parsed, entry);
        }
    }
}
