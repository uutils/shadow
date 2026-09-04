// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore gecos

//! Parser and writer for `/etc/passwd`.
//!
//! File format (man 5 passwd):
//! ```text
//! username:password:uid:gid:gecos:home:shell
//! ```
//!
//! Each field is colon-separated. The password field is typically `x`
//! (indicating the hash is in `/etc/shadow`).

use std::fmt;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::str::FromStr;

use crate::error::ShadowError;
pub use crate::records::Layout;
use crate::validate::validate_field;

/// A single entry from `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasswdEntry {
    /// Login name.
    pub name: String,
    /// Encrypted password (usually `x` — real hash in `/etc/shadow`).
    pub passwd: String,
    /// Numeric user ID.
    pub uid: u32,
    /// Numeric primary group ID.
    pub gid: u32,
    /// GECOS / comment field (real name, room, phone, etc.).
    pub gecos: String,
    /// Home directory.
    pub home: String,
    /// Login shell.
    pub shell: String,
}

impl fmt::Display for PasswdEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}:{}",
            self.name, self.passwd, self.uid, self.gid, self.gecos, self.home, self.shell
        )
    }
}

impl PasswdEntry {
    /// Refuse an entry whose text fields would break the file format.
    ///
    /// The writer calls this before emitting every line, so a `:` or a
    /// newline smuggled into a GECOS field can never add a field or a
    /// record to `/etc/passwd`; tools validate earlier to give a precise
    /// error, this is the last line of defence.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Validation` naming the field and character.
    pub fn validate_fields(&self) -> Result<(), ShadowError> {
        validate_field("login name", &self.name)?;
        validate_field("password field", &self.passwd)?;
        validate_field("GECOS field", &self.gecos)?;
        validate_field("home directory", &self.home)?;
        validate_field("login shell", &self.shell)
    }
}

impl FromStr for PasswdEntry {
    type Err = ShadowError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        // Use splitn(8) to detect extra fields without allocating a Vec.
        let mut fields = line.splitn(8, ':');

        let name = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing name".into()))?;
        let passwd = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing passwd".into()))?;
        let uid_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing uid".into()))?;
        let gid_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing gid".into()))?;
        let gecos = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing gecos".into()))?;
        let home = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing home".into()))?;
        let shell = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing shell".into()))?;

        if fields.next().is_some() {
            return Err(ShadowError::Parse("too many fields".into()));
        }

        let uid = uid_str
            .parse::<u32>()
            .map_err(|e| ShadowError::Parse(format!("invalid UID '{uid_str}': {e}").into()))?;
        let gid = gid_str
            .parse::<u32>()
            .map_err(|e| ShadowError::Parse(format!("invalid GID '{gid_str}': {e}").into()))?;

        Ok(Self {
            name: name.to_string(),
            passwd: passwd.to_string(),
            uid,
            gid,
            gecos: gecos.to_string(),
            home: home.to_string(),
            shell: shell.to_string(),
        })
    }
}

/// Read all entries from an `/etc/passwd`-formatted file.
///
/// Skips blank lines and lines starting with `#`.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or contains malformed entries.
pub fn read_passwd_file(path: &Path) -> Result<Vec<PasswdEntry>, ShadowError> {
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
        // Parse the original untrimmed line to preserve field whitespace.
        entries.push(line.parse()?);
    }

    Ok(entries)
}

/// Write entries to an `/etc/passwd`-formatted file.
///
/// This writes to the provided writer. For atomic file replacement,
/// use this with `atomic::AtomicFile`.
///
/// # Errors
///
/// Returns `ShadowError` on I/O write failure.
pub fn write_passwd<W: Write>(entries: &[PasswdEntry], mut writer: W) -> Result<(), ShadowError> {
    for entry in entries {
        entry.validate_fields()?;
        writeln!(writer, "{entry}")?;
    }
    Ok(())
}

impl crate::records::Named for PasswdEntry {
    fn name(&self) -> &str {
        &self.name
    }
}

/// Read `/etc/passwd` keeping comments, blank lines and NIS compat lines.
///
/// Returns the entries plus the [`crate::records::Layout`] that
/// [`write_passwd_with_layout`] needs to put those lines back.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or an entry is malformed.
pub fn read_passwd_with_layout(
    path: &Path,
) -> Result<(Vec<PasswdEntry>, crate::records::Layout), ShadowError> {
    crate::records::read_with_layout(path)
}

/// Write entries back, restoring the lines [`read_passwd_with_layout`] preserved.
///
/// # Errors
///
/// Returns `ShadowError` on a write failure or an entry that would corrupt the
/// record format.
pub fn write_passwd_with_layout<W: Write>(
    entries: &[PasswdEntry],
    layout: &crate::records::Layout,
    mut writer: W,
) -> Result<(), ShadowError> {
    crate::records::write_with_layout(entries, layout, &mut writer, |entry, w| {
        entry.validate_fields()?;
        writeln!(w, "{entry}")?;
        Ok(())
    })
}

impl crate::transaction::Record for PasswdEntry {
    fn validate_fields(&self) -> Result<(), ShadowError> {
        Self::validate_fields(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The writer is the last line of defence: whatever a tool forgot to
    // check, a field that would add a record or a field never reaches disk.
    #[test]
    fn test_write_refuses_field_separators_and_newlines() {
        let mut entry = PasswdEntry {
            name: "inj".into(),
            passwd: "x".into(),
            uid: 1000,
            gid: 1000,
            gecos: "x\nevil::0:0::/:/bin/sh".into(),
            home: "/home/inj".into(),
            shell: "/bin/sh".into(),
        };
        let mut out = Vec::new();
        assert!(write_passwd(std::slice::from_ref(&entry), &mut out).is_err());
        assert!(
            out.is_empty(),
            "nothing may be written for a rejected entry"
        );

        entry.gecos = "Jane Doe,,,".into();
        entry.shell = "/bin/sh:x".into();
        assert!(write_passwd(std::slice::from_ref(&entry), &mut out).is_err());

        entry.shell = "/bin/sh".into();
        write_passwd(std::slice::from_ref(&entry), &mut out).unwrap();
        assert_eq!(out, b"inj:x:1000:1000:Jane Doe,,,:/home/inj:/bin/sh\n");
    }

    #[test]
    fn test_parse_valid_entry() {
        let entry: PasswdEntry = "root:x:0:0:root:/root:/bin/bash".parse().unwrap();
        assert_eq!(entry.name, "root");
        assert_eq!(entry.passwd, "x");
        assert_eq!(entry.uid, 0);
        assert_eq!(entry.gid, 0);
        assert_eq!(entry.gecos, "root");
        assert_eq!(entry.home, "/root");
        assert_eq!(entry.shell, "/bin/bash");
    }

    #[test]
    fn test_parse_empty_gecos() {
        let entry: PasswdEntry = "nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin"
            .parse()
            .unwrap();
        assert_eq!(entry.name, "nobody");
        assert_eq!(entry.gecos, "");
    }

    #[test]
    fn test_parse_wrong_field_count() {
        let result = "root:x:0:0".parse::<PasswdEntry>();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_uid() {
        let result = "root:x:abc:0:root:/root:/bin/bash".parse::<PasswdEntry>();
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip() {
        let line = "testuser:x:1000:1000:Test User:/home/testuser:/bin/zsh";
        let entry: PasswdEntry = line.parse().unwrap();
        assert_eq!(entry.to_string(), line);
    }

    #[test]
    fn test_write_passwd() {
        let entries = vec![
            "root:x:0:0:root:/root:/bin/bash"
                .parse::<PasswdEntry>()
                .unwrap(),
            "nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin"
                .parse::<PasswdEntry>()
                .unwrap(),
        ];
        let mut buf = Vec::new();
        write_passwd(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(
            output,
            "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n"
        );
    }

    // -------------------------------------------------------------------
    // Issue #16: parser edge case tests
    // -------------------------------------------------------------------

    #[test]
    fn test_parse_too_few_fields() {
        let result = "root:x:0:0".parse::<PasswdEntry>();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_too_many_fields() {
        let result = "root:x:0:0:gecos:home:shell:extra".parse::<PasswdEntry>();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_line_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwd");
        std::fs::write(
            &path,
            "root:x:0:0:root:/root:/bin/bash\n\n\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n",
        )
        .unwrap();
        let entries = read_passwd_file(&path).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_comment_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwd");
        std::fs::write(
            &path,
            "# comment line\nroot:x:0:0:root:/root:/bin/bash\n# another comment\n",
        )
        .unwrap();
        let entries = read_passwd_file(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "root");
    }

    #[test]
    fn test_parse_uid_overflow() {
        let result = "root:x:99999999999:0:root:/root:/bin/bash".parse::<PasswdEntry>();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_negative_uid() {
        let result = "root:x:-1:0:root:/root:/bin/bash".parse::<PasswdEntry>();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_name() {
        // Parsing itself succeeds (field-count is correct), but yields an empty name.
        let entry: PasswdEntry = ":x:0:0:::".parse().unwrap();
        assert_eq!(entry.name, "");
    }

    #[test]
    fn test_parse_extra_colons_fails() {
        // 8+ colons means 9+ fields, which must fail.
        let result = "root:x:0:0:ge:cos:home:shell:extra".parse::<PasswdEntry>();
        assert!(result.is_err());
    }

    #[test]
    fn test_write_read_roundtrip_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwd");

        let entries = vec![
            PasswdEntry {
                name: "root".into(),
                passwd: "x".into(),
                uid: 0,
                gid: 0,
                gecos: "root".into(),
                home: "/root".into(),
                shell: "/bin/bash".into(),
            },
            PasswdEntry {
                name: "nobody".into(),
                passwd: "x".into(),
                uid: 65534,
                gid: 65534,
                gecos: String::new(),
                home: "/nonexistent".into(),
                shell: "/usr/sbin/nologin".into(),
            },
        ];

        let file = std::fs::File::create(&path).unwrap();
        write_passwd(&entries, file).unwrap();

        let read_back = read_passwd_file(&path).unwrap();
        assert_eq!(entries, read_back);
    }

    #[test]
    fn test_empty_file_returns_empty_vec() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwd");
        std::fs::write(&path, "").unwrap();
        let entries = read_passwd_file(&path).unwrap();
        assert!(entries.is_empty());
    }

    // -------------------------------------------------------------------
    // Issue #15: proptest round-trip tests
    // -------------------------------------------------------------------

    use proptest::prelude::*;

    fn arb_passwd_entry() -> impl Strategy<Value = PasswdEntry> {
        (
            "[a-z_][a-z0-9_-]{0,31}",               // name
            "(x|\\*|!|\\$6\\$[a-z]{4})",            // passwd
            0u32..65535,                            // uid
            0u32..65535,                            // gid
            "[A-Za-z0-9 ,.-]{0,50}",                // gecos
            "/[a-z/]{1,30}",                        // home
            "/(bin|usr/bin)/(bash|sh|zsh|nologin)", // shell
        )
            .prop_map(|(name, passwd, uid, gid, gecos, home, shell)| PasswdEntry {
                name,
                passwd,
                uid,
                gid,
                gecos,
                home,
                shell,
            })
    }

    proptest! {
        #[test]
        fn test_passwd_roundtrip(entry in arb_passwd_entry()) {
            let line = entry.to_string();
            let parsed: PasswdEntry = line.parse().unwrap();
            prop_assert_eq!(parsed, entry);
        }
    }
}
