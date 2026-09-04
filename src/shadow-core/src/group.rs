// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Parser and writer for `/etc/group`.
//!
//! File format (man 5 group):
//! ```text
//! groupname:password:GID:user_list
//! ```
//!
//! `user_list` is a comma-separated list of usernames.

use std::fmt;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::str::FromStr;

use crate::error::ShadowError;
use crate::validate::{validate_field, validate_list_item};

/// A single entry from `/etc/group`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupEntry {
    /// Group name.
    pub name: String,
    /// Encrypted password (usually `x` or empty).
    pub passwd: String,
    /// Numeric group ID.
    pub gid: u32,
    /// Comma-separated list of member usernames.
    pub members: Vec<String>,
}

impl fmt::Display for GroupEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.name,
            self.passwd,
            self.gid,
            self.members.join(",")
        )
    }
}

impl GroupEntry {
    /// Refuse an entry whose text fields would break the file format; see
    /// [`crate::passwd::PasswdEntry::validate_fields`]. Members must also be
    /// free of the `,` that separates them.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Validation` naming the field and character.
    pub fn validate_fields(&self) -> Result<(), ShadowError> {
        validate_field("group name", &self.name)?;
        validate_field("password field", &self.passwd)?;
        self.members
            .iter()
            .try_for_each(|m| validate_list_item("member name", m))
    }
}

impl FromStr for GroupEntry {
    type Err = ShadowError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let mut fields = line.splitn(5, ':');

        let name = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing group name".into()))?;
        let passwd = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing group password".into()))?;
        let gid_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing GID".into()))?;
        let members_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing members".into()))?;

        if fields.next().is_some() {
            return Err(ShadowError::Parse("too many fields in group entry".into()));
        }

        let gid = gid_str
            .parse::<u32>()
            .map_err(|e| ShadowError::Parse(format!("invalid GID '{gid_str}': {e}").into()))?;

        let members = if members_str.is_empty() {
            Vec::new()
        } else {
            members_str.split(',').map(ToString::to_string).collect()
        };

        Ok(Self {
            name: name.to_string(),
            passwd: passwd.to_string(),
            gid,
            members,
        })
    }
}

/// Read all entries from an `/etc/group`-formatted file.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or contains malformed entries.
pub fn read_group_file(path: &Path) -> Result<Vec<GroupEntry>, ShadowError> {
    let file = std::fs::File::open(path).map_err(|e| ShadowError::IoPath(e, path.to_owned()))?;
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        entries.push(line.parse()?);
    }

    Ok(entries)
}

/// Write entries to an `/etc/group`-formatted file.
///
/// # Errors
///
/// Returns `ShadowError` on I/O write failure.
pub fn write_group<W: Write>(entries: &[GroupEntry], mut writer: W) -> Result<(), ShadowError> {
    for entry in entries {
        entry.validate_fields()?;
        writeln!(writer, "{entry}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_entry() {
        let entry: GroupEntry = "root:x:0:".parse().unwrap();
        assert_eq!(entry.name, "root");
        assert_eq!(entry.passwd, "x");
        assert_eq!(entry.gid, 0);
        assert!(entry.members.is_empty());
    }

    #[test]
    fn test_parse_with_members() {
        let entry: GroupEntry = "sudo:x:27:alice,bob,charlie".parse().unwrap();
        assert_eq!(entry.name, "sudo");
        assert_eq!(entry.gid, 27);
        assert_eq!(entry.members, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn test_parse_single_member() {
        let entry: GroupEntry = "docker:x:999:deploy".parse().unwrap();
        assert_eq!(entry.members, vec!["deploy"]);
    }

    #[test]
    fn test_roundtrip() {
        let line = "sudo:x:27:alice,bob";
        let entry: GroupEntry = line.parse().unwrap();
        assert_eq!(entry.to_string(), line);
    }

    #[test]
    fn test_roundtrip_no_members() {
        let line = "root:x:0:";
        let entry: GroupEntry = line.parse().unwrap();
        assert_eq!(entry.to_string(), line);
    }

    #[test]
    fn test_parse_too_few_fields() {
        assert!("root:x:0".parse::<GroupEntry>().is_err());
    }

    #[test]
    fn test_parse_too_many_fields() {
        assert!("root:x:0::extra".parse::<GroupEntry>().is_err());
    }

    #[test]
    fn test_parse_invalid_gid() {
        assert!("root:x:abc:".parse::<GroupEntry>().is_err());
    }

    #[test]
    fn test_write_read_roundtrip_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("group");

        let entries = vec![
            GroupEntry {
                name: "root".into(),
                passwd: "x".into(),
                gid: 0,
                members: vec![],
            },
            GroupEntry {
                name: "sudo".into(),
                passwd: "x".into(),
                gid: 27,
                members: vec!["alice".into(), "bob".into()],
            },
        ];

        let file = std::fs::File::create(&path).unwrap();
        write_group(&entries, file).unwrap();

        let read_back = read_group_file(&path).unwrap();
        assert_eq!(entries, read_back);
    }

    #[test]
    fn test_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("group");
        std::fs::write(&path, "").unwrap();
        let entries = read_group_file(&path).unwrap();
        assert!(entries.is_empty());
    }

    use proptest::prelude::*;

    fn arb_group_entry() -> impl Strategy<Value = GroupEntry> {
        (
            "[a-z_][a-z0-9_-]{0,31}",
            "(x|\\*|!)",
            0u32..65535,
            proptest::collection::vec("[a-z_][a-z0-9_]{0,15}", 0..5),
        )
            .prop_map(|(name, passwd, gid, members)| GroupEntry {
                name,
                passwd,
                gid,
                members,
            })
    }

    proptest! {
        #[test]
        fn test_group_roundtrip(entry in arb_group_entry()) {
            let line = entry.to_string();
            let parsed: GroupEntry = line.parse().unwrap();
            prop_assert_eq!(parsed, entry);
        }
    }
}
