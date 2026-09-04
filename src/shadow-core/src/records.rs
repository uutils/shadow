// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore nsswitch netgroup

//! Lossless reading and writing of the colon-separated account files.
//!
//! The parsers turn a file into a `Vec` of typed entries, which is what the
//! tools want to work with. Everything that is *not* an entry — comments,
//! blank lines, and the NIS compatibility lines `nsswitch.conf(5)` documents
//! for `compat` mode (`+user`, `+@netgroup`, `-user`, a bare `+::::::`) — used
//! to be dropped on read and therefore deleted the first time any tool
//! rewrote the file. Worse, the compat lines did not parse, so on a host using
//! `compat` every tool failed outright.
//!
//! [`read_with_layout`] returns the entries plus a [`Layout`] recording those
//! lines and where they sat; [`write_with_layout`] puts them back. Each raw
//! line is anchored to the **name of the entry it preceded**, not to a line
//! number, so it stays with that entry even when the file is reordered (a
//! comment above an account follows the account when `pwck -s` sorts) and
//! survives entries being added or removed elsewhere.

use std::fmt::Display;
use std::io::{BufRead, Write};
use std::path::Path;
use std::str::FromStr;

use crate::error::ShadowError;

/// An entry that can be identified by name — the anchor a raw line uses.
pub trait Named {
    /// The entry's name (login or group name).
    fn name(&self) -> &str;
}

/// Where a preserved raw line belongs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Anchor {
    /// Immediately before the entry with this name.
    Before(String),
    /// After every entry.
    End,
}

/// The non-entry lines of a record file, and where they belong.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    items: Vec<(Anchor, String)>,
}

impl Layout {
    /// Whether the file carried anything besides entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Whether a line is preserved verbatim rather than parsed.
///
/// Blank lines and `#` comments are obvious. A line whose first character is
/// `+` or `-` is an NIS compat entry: `nsswitch.conf(5)` documents them for
/// `compat` mode, they are not in the record format, and no username or group
/// name may start with either character. Readers that return only entries skip
/// these lines; [`read_with_layout`] keeps them.
#[must_use]
pub fn is_raw_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(['+', '-'])
}

/// Read a record file, skipping the lines that are not entries.
///
/// Comments, blank lines and NIS compatibility lines are dropped. Use
/// [`read_with_layout`] where they must survive a rewrite, which is any
/// path that writes the file back.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or an entry line is
/// malformed.
pub fn read_entries<T>(path: &Path) -> Result<Vec<T>, ShadowError>
where
    T: FromStr<Err = ShadowError>,
{
    let file = std::fs::File::open(path).map_err(|e| ShadowError::IoPath(e, path.to_owned()))?;
    let reader = std::io::BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if is_raw_line(&line) {
            continue;
        }
        // Parse the original untrimmed line to preserve field whitespace.
        entries.push(line.parse()?);
    }

    Ok(entries)
}

/// Write entries to a record file, validating each one first.
///
/// Nothing but the entries: any comments the file carried are lost, which is
/// why every path that rewrites an existing file goes through
/// [`write_with_layout`] or the transaction instead.
///
/// # Errors
///
/// Returns `ShadowError::Validation` for a value that would corrupt a record,
/// and `ShadowError::Io` on a write failure.
pub fn write_entries<T, W>(entries: &[T], mut writer: W) -> Result<(), ShadowError>
where
    T: Display + crate::transaction::Record,
    W: Write,
{
    for entry in entries {
        crate::transaction::Record::validate_fields(entry)?;
        writeln!(writer, "{entry}")?;
    }
    Ok(())
}

/// Read a record file, keeping the lines that are not entries.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or an entry line is
/// malformed.
pub fn read_with_layout<T>(path: &Path) -> Result<(Vec<T>, Layout), ShadowError>
where
    T: FromStr<Err = ShadowError> + Named,
{
    let file = std::fs::File::open(path).map_err(|e| ShadowError::IoPath(e, path.to_owned()))?;
    let reader = std::io::BufReader::new(file);

    let mut entries: Vec<T> = Vec::new();
    let mut layout = Layout::default();
    let mut pending: Vec<String> = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if is_raw_line(&line) {
            pending.push(line);
            continue;
        }
        // Parse the original untrimmed line to preserve field whitespace.
        let entry: T = line.parse()?;
        for raw in pending.drain(..) {
            layout
                .items
                .push((Anchor::Before(entry.name().to_owned()), raw));
        }
        entries.push(entry);
    }

    for raw in pending {
        layout.items.push((Anchor::End, raw));
    }

    Ok((entries, layout))
}

/// Write entries back, restoring the preserved lines around them.
///
/// A raw line whose anchor entry no longer exists is not dropped: it is
/// written after the entries, so removing an account never silently deletes
/// the comment that described it.
///
/// # Errors
///
/// Returns `ShadowError` on a write failure or if an entry holds a value that
/// would corrupt the record (checked by the caller's writer).
pub fn write_with_layout<T, W, F>(
    entries: &[T],
    layout: &Layout,
    writer: &mut W,
    mut write_entry: F,
) -> Result<(), ShadowError>
where
    T: Display + Named,
    W: Write,
    F: FnMut(&T, &mut W) -> Result<(), ShadowError>,
{
    let mut emitted = vec![false; layout.items.len()];

    for entry in entries {
        for (i, (anchor, raw)) in layout.items.iter().enumerate() {
            if !emitted[i] && *anchor == Anchor::Before(entry.name().to_owned()) {
                writeln!(writer, "{raw}")?;
                emitted[i] = true;
            }
        }
        write_entry(entry, writer)?;
    }

    // End-anchored lines, then anything whose entry disappeared.
    for (i, (anchor, raw)) in layout.items.iter().enumerate() {
        if !emitted[i] && *anchor == Anchor::End {
            writeln!(writer, "{raw}")?;
            emitted[i] = true;
        }
    }
    for (i, (_, raw)) in layout.items.iter().enumerate() {
        if !emitted[i] {
            writeln!(writer, "{raw}")?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Debug, PartialEq, Eq)]
    struct Row {
        name: String,
        value: String,
    }

    impl Named for Row {
        fn name(&self) -> &str {
            &self.name
        }
    }

    impl fmt::Display for Row {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}", self.name, self.value)
        }
    }

    impl FromStr for Row {
        type Err = ShadowError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let (name, value) = s
                .split_once(':')
                .ok_or_else(|| ShadowError::Parse("missing ':'".into()))?;
            Ok(Self {
                name: name.to_string(),
                value: value.to_string(),
            })
        }
    }

    fn render(entries: &[Row], layout: &Layout) -> String {
        let mut out = Vec::new();
        write_with_layout(entries, layout, &mut out, |e, w| {
            writeln!(w, "{e}")?;
            Ok(())
        })
        .expect("write");
        String::from_utf8(out).expect("utf-8")
    }

    fn read(text: &str) -> (Vec<Row>, Layout) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("file");
        std::fs::write(&path, text).expect("write");
        read_with_layout::<Row>(&path).expect("read")
    }

    #[test]
    fn test_round_trip_is_byte_identical() {
        let text = "# leading comment\n\nalice:1\n# about bob\nbob:2\n\n# trailer\n";
        let (entries, layout) = read(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(render(&entries, &layout), text);
    }

    #[test]
    fn test_nis_compat_lines_are_preserved_not_parsed() {
        // These do not parse as records; before, every tool failed on them.
        let text = "alice:1\n+@admins\n+::::::\n-guest\n";
        let (entries, layout) = read(text);
        assert_eq!(entries.len(), 1, "only alice is an entry");
        assert_eq!(render(&entries, &layout), text);
    }

    #[test]
    fn test_comment_follows_its_entry_when_reordered() {
        let text = "# about zoe\nzoe:26\n# about amy\namy:1\n";
        let (mut entries, layout) = read(text);
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(
            render(&entries, &layout),
            "# about amy\namy:1\n# about zoe\nzoe:26\n"
        );
    }

    #[test]
    fn test_removing_an_entry_keeps_its_comment() {
        let text = "# about bob\nbob:2\nalice:1\n";
        let (mut entries, layout) = read(text);
        entries.retain(|e| e.name != "bob");
        // The comment is kept rather than silently deleted, moved to the end.
        assert_eq!(render(&entries, &layout), "alice:1\n# about bob\n");
    }

    #[test]
    fn test_added_entry_appends_before_trailing_lines() {
        let text = "alice:1\n# trailer\n";
        let (mut entries, layout) = read(text);
        entries.push(Row {
            name: "bob".into(),
            value: "2".into(),
        });
        assert_eq!(render(&entries, &layout), "alice:1\nbob:2\n# trailer\n");
    }

    #[test]
    fn test_malformed_entry_still_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("file");
        std::fs::write(&path, "alice:1\nnot-a-record\n").expect("write");
        assert!(read_with_layout::<Row>(&path).is_err());
    }
}
