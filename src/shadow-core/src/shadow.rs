// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore lstchg

//! Parser and writer for `/etc/shadow`.
//!
//! File format (man 5 shadow):
//! ```text
//! username:password:lstchg:min:max:warn:inactive:expire:reserved
//! ```
//!
//! All date fields are in days since epoch (1970-01-01).

use std::fmt;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use crate::error::ShadowError;
pub use crate::records::Layout;
use crate::validate::validate_field;

/// A single entry from `/etc/shadow`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShadowEntry {
    /// Login name (must match an `/etc/passwd` entry).
    pub name: String,
    /// Encrypted password hash (or `!`/`*` for locked/no-login).
    pub passwd: String,
    /// Date of last password change (days since epoch), or empty.
    pub last_change: Option<i64>,
    /// Minimum days between password changes, or empty.
    pub min_age: Option<i64>,
    /// Maximum days a password is valid, or empty.
    pub max_age: Option<i64>,
    /// Days before expiry to warn user, or empty.
    pub warn_days: Option<i64>,
    /// Days after expiry until account is disabled, or empty.
    pub inactive_days: Option<i64>,
    /// Account expiration date (days since epoch), or empty.
    pub expire_date: Option<i64>,
    /// Reserved field (unused).
    pub reserved: String,
}

impl ShadowEntry {
    /// Whether the account password is locked.
    ///
    /// GNU shadow-utils considers a password locked if it:
    /// - starts with `!` (explicitly locked via `passwd -l`)
    /// - equals `*` (system account, no valid password)
    /// - equals `!!` (never had a password set)
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.passwd.starts_with('!') || self.passwd == "*"
    }

    /// Whether the account has no password (empty password field).
    #[must_use]
    pub fn has_no_password(&self) -> bool {
        self.passwd.is_empty()
    }

    /// Lock the password by prepending `!`.
    ///
    /// Idempotent, as `passwd -l` is: locking an already-locked account
    /// leaves one marker, not a second. Prepending unconditionally meant two
    /// locks needed two unlocks, and since `passwd -u` refuses to unlock an
    /// account that would stay locked, an account locked twice could not be
    /// unlocked with the tool at all. Verified against GNU shadow 4.17, where
    /// three locks leave a single `!` that one unlock removes.
    pub fn lock(&mut self) {
        if !self.passwd.starts_with('!') {
            self.passwd.insert(0, '!');
        }
    }

    /// Unlock the password by removing the leading `!`.
    ///
    /// Returns `false` if the password is not locked, would become empty
    /// after unlocking, or is the system account marker `*` (which
    /// cannot be unlocked — use `delete_password` + rehash instead).
    ///
    /// Note: `is_locked()` returns `true` for `*`, but `unlock()` returns
    /// `false` because removing one character from `*` yields an empty
    /// password, which GNU passwd refuses.
    pub fn unlock(&mut self) -> bool {
        if !self.is_locked() {
            return false;
        }
        let after = &self.passwd[1..];
        if after.is_empty() || after == "!" {
            // Would result in empty or still-locked password.
            return false;
        }
        self.passwd = after.to_string();
        true
    }

    /// Delete the password (set to empty string, making the account passwordless).
    pub fn delete_password(&mut self) {
        self.passwd = String::new();
    }

    /// Expire the password (set `last_change` to 0, forcing change at next login).
    pub fn expire(&mut self) {
        self.last_change = Some(0);
    }

    /// Password status character for `passwd -S` output.
    #[must_use]
    pub fn status_char(&self) -> &'static str {
        if self.is_locked() {
            "L"
        } else if self.has_no_password() {
            "NP"
        } else {
            "P"
        }
    }
}

/// Current date as days since Unix epoch, for `last_change` updates.
///
/// # Errors
///
/// Returns `ShadowError` if the system clock is before the Unix epoch.
pub fn days_since_epoch() -> Result<i64, ShadowError> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ShadowError::Other("system clock is before Unix epoch".into()))?;
    let secs = i64::try_from(secs.as_secs()).unwrap_or(i64::MAX);
    Ok(secs / 86400)
}

/// Parse an optional numeric field — empty string becomes `None`.
fn parse_optional_field(field: &str) -> Result<Option<i64>, ShadowError> {
    if field.is_empty() {
        Ok(None)
    } else {
        field
            .parse::<i64>()
            .map(Some)
            .map_err(|e| ShadowError::Parse(format!("invalid numeric field '{field}': {e}").into()))
    }
}

/// Format an optional numeric field — `None` becomes empty string.
fn fmt_optional(val: Option<i64>) -> String {
    match val {
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

impl fmt::Display for ShadowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.name,
            self.passwd,
            fmt_optional(self.last_change),
            fmt_optional(self.min_age),
            fmt_optional(self.max_age),
            fmt_optional(self.warn_days),
            fmt_optional(self.inactive_days),
            fmt_optional(self.expire_date),
            self.reserved,
        )
    }
}

impl ShadowEntry {
    /// Refuse an entry whose text fields would break the file format; see
    /// [`crate::passwd::PasswdEntry::validate_fields`].
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Validation` naming the field and character.
    pub fn validate_fields(&self) -> Result<(), ShadowError> {
        validate_field("login name", &self.name)?;
        validate_field("password hash", &self.passwd)?;
        validate_field("reserved field", &self.reserved)
    }
}

impl FromStr for ShadowEntry {
    type Err = ShadowError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        // Use splitn(10) to detect extra fields without allocating a Vec.
        let mut fields = line.splitn(10, ':');

        let name = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing name".into()))?;
        let passwd = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing passwd".into()))?;
        let last_change_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing last_change".into()))?;
        let min_age_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing min_age".into()))?;
        let max_age_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing max_age".into()))?;
        let warn_days_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing warn_days".into()))?;
        let inactive_days_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing inactive_days".into()))?;
        let expire_date_str = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing expire_date".into()))?;
        let reserved = fields
            .next()
            .ok_or_else(|| ShadowError::Parse("missing reserved".into()))?;

        if fields.next().is_some() {
            return Err(ShadowError::Parse("too many fields".into()));
        }

        Ok(Self {
            name: name.to_string(),
            passwd: passwd.to_string(),
            last_change: parse_optional_field(last_change_str)?,
            min_age: parse_optional_field(min_age_str)?,
            max_age: parse_optional_field(max_age_str)?,
            warn_days: parse_optional_field(warn_days_str)?,
            inactive_days: parse_optional_field(inactive_days_str)?,
            expire_date: parse_optional_field(expire_date_str)?,
            reserved: reserved.to_string(),
        })
    }
}

/// Read all entries from an `/etc/shadow`-formatted file.
///
/// # Errors
///
/// Returns `ShadowError` if the file cannot be opened or contains malformed entries.
pub fn read_shadow_file(path: &Path) -> Result<Vec<ShadowEntry>, ShadowError> {
    crate::records::read_entries(path)
}

/// Write entries to an `/etc/shadow`-formatted file.
///
/// # Errors
///
/// Returns `ShadowError` on I/O write failure.
pub fn write_shadow<W: Write>(entries: &[ShadowEntry], writer: W) -> Result<(), ShadowError> {
    crate::records::write_entries(entries, writer)
}

impl crate::records::Named for ShadowEntry {
    fn name(&self) -> &str {
        &self.name
    }
}

impl crate::transaction::Record for ShadowEntry {
    fn validate_fields(&self) -> Result<(), ShadowError> {
        Self::validate_fields(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_entry() {
        let entry: ShadowEntry = "root:$6$hash:19000:0:99999:7:::".parse().unwrap();
        assert_eq!(entry.name, "root");
        assert_eq!(entry.passwd, "$6$hash");
        assert_eq!(entry.last_change, Some(19000));
        assert_eq!(entry.min_age, Some(0));
        assert_eq!(entry.max_age, Some(99999));
        assert_eq!(entry.warn_days, Some(7));
        assert_eq!(entry.inactive_days, None);
        assert_eq!(entry.expire_date, None);
        assert_eq!(entry.reserved, "");
    }

    #[test]
    fn test_parse_locked_account() {
        let entry: ShadowEntry = "locked:!:19000::::::".parse().unwrap();
        assert_eq!(entry.passwd, "!");
        assert_eq!(entry.min_age, None);
    }

    #[test]
    fn test_roundtrip() {
        let line = "testuser:$6$rounds=5000$salt$hash:19500:0:99999:7:30::";
        let entry: ShadowEntry = line.parse().unwrap();
        assert_eq!(entry.to_string(), line);
    }

    #[test]
    fn test_all_empty_optional_fields() {
        let entry: ShadowEntry = "svc:*:::::::".parse().unwrap();
        assert_eq!(entry.last_change, None);
        assert_eq!(entry.min_age, None);
        assert_eq!(entry.max_age, None);
        assert_eq!(entry.warn_days, None);
        assert_eq!(entry.inactive_days, None);
        assert_eq!(entry.expire_date, None);
    }

    // -------------------------------------------------------------------
    // ShadowEntry helper method tests
    // -------------------------------------------------------------------

    #[test]
    fn test_is_locked_with_bang() {
        let entry = ShadowEntry {
            name: "u".into(),
            passwd: "!$6$hash".into(),
            ..Default::default()
        };
        assert!(entry.is_locked());
    }

    #[test]
    fn test_is_locked_without_bang() {
        let entry = ShadowEntry {
            name: "u".into(),
            passwd: "$6$hash".into(),
            ..Default::default()
        };
        assert!(!entry.is_locked());
    }

    #[test]
    fn test_has_no_password_empty() {
        let entry = ShadowEntry {
            name: "u".into(),
            ..Default::default()
        };
        assert!(entry.has_no_password());
    }

    #[test]
    fn test_has_no_password_with_hash() {
        let entry = ShadowEntry {
            name: "u".into(),
            passwd: "$6$hash".into(),
            ..Default::default()
        };
        assert!(!entry.has_no_password());
    }

    #[test]
    fn test_lock_adds_bang() {
        let mut entry = ShadowEntry {
            name: "u".into(),
            passwd: "$6$hash".into(),
            ..Default::default()
        };
        entry.lock();
        assert_eq!(entry.passwd, "!$6$hash");
    }

    /// Locking is idempotent, as `passwd -l` is. Adding a second marker meant
    /// two locks needed two unlocks, and `passwd -u` refuses to unlock an
    /// account that would stay locked, so a twice-locked account could not be
    /// unlocked with the tool at all. Verified against GNU shadow 4.17: three
    /// locks leave one `!`, and one unlock removes it.
    #[test]
    fn test_locking_twice_leaves_one_marker() {
        let mut entry = ShadowEntry {
            name: "u".into(),
            passwd: "$6$hash".into(),
            ..Default::default()
        };
        for _ in 0..3 {
            entry.lock();
        }
        assert_eq!(entry.passwd, "!$6$hash");
        assert!(entry.unlock(), "one unlock must undo any number of locks");
        assert_eq!(entry.passwd, "$6$hash");
    }

    #[test]
    fn test_unlock_removes_bang() {
        let mut entry = ShadowEntry {
            name: "u".into(),
            passwd: "!$6$hash".into(),
            ..Default::default()
        };
        assert!(entry.unlock());
        assert_eq!(entry.passwd, "$6$hash");
    }

    #[test]
    fn test_unlock_not_locked_returns_false() {
        let mut entry = ShadowEntry {
            name: "u".into(),
            passwd: "$6$hash".into(),
            ..Default::default()
        };
        assert!(!entry.unlock());
        assert_eq!(entry.passwd, "$6$hash", "should be unchanged");
    }

    #[test]
    fn test_unlock_only_bang_returns_false() {
        // "!" alone cannot be unlocked — would result in empty password.
        let mut entry = ShadowEntry {
            name: "u".into(),
            passwd: "!".into(),
            ..Default::default()
        };
        assert!(!entry.unlock());
        assert_eq!(entry.passwd, "!", "should be unchanged");
    }

    #[test]
    fn test_unlock_double_bang_returns_false() {
        // "!!" — removing one '!' leaves "!" which is still invalid.
        let mut entry = ShadowEntry {
            name: "u".into(),
            passwd: "!!".into(),
            ..Default::default()
        };
        assert!(!entry.unlock());
        assert_eq!(entry.passwd, "!!", "should be unchanged");
    }

    #[test]
    fn test_delete_password_clears() {
        let mut entry = ShadowEntry {
            name: "u".into(),
            passwd: "$6$hash".into(),
            ..Default::default()
        };
        entry.delete_password();
        assert_eq!(entry.passwd, "");
    }

    #[test]
    fn test_expire_sets_zero() {
        let mut entry = ShadowEntry {
            name: "u".into(),
            passwd: "$6$hash".into(),
            last_change: Some(19500),
            ..Default::default()
        };
        entry.expire();
        assert_eq!(entry.last_change, Some(0));
    }

    #[test]
    fn test_status_char_locked() {
        let entry = ShadowEntry {
            name: "u".into(),
            passwd: "!$6$hash".into(),
            ..Default::default()
        };
        assert_eq!(entry.status_char(), "L");
    }

    #[test]
    fn test_status_char_no_password() {
        let entry = ShadowEntry {
            name: "u".into(),
            ..Default::default()
        };
        assert_eq!(entry.status_char(), "NP");
    }

    #[test]
    fn test_status_char_usable() {
        let entry = ShadowEntry {
            name: "u".into(),
            passwd: "$6$hash".into(),
            ..Default::default()
        };
        assert_eq!(entry.status_char(), "P");
    }

    // -------------------------------------------------------------------
    // Issue #16: parser edge case tests
    // -------------------------------------------------------------------

    #[test]
    fn test_parse_too_few_fields() {
        let result = "root:$6$hash:19000:0:99999:7::".parse::<ShadowEntry>();
        assert!(result.is_err(), "8 fields should be rejected (need 9)");
    }

    #[test]
    fn test_parse_too_many_fields() {
        let result = "root:$6$hash:19000:0:99999:7:::extra:field".parse::<ShadowEntry>();
        assert!(result.is_err(), "10+ fields should be rejected (need 9)");
    }

    #[test]
    fn test_parse_negative_last_change() {
        // Negative last_change is valid — it means "never changed" in some implementations.
        let entry: ShadowEntry = "user:$6$hash:-1:0:99999:7:::".parse().unwrap();
        assert_eq!(entry.last_change, Some(-1));
    }

    #[test]
    fn test_parse_max_i64_value() {
        let max_str = i64::MAX.to_string();
        let line = format!("user:$6$hash:{max_str}:0:99999:7:::");
        let entry: ShadowEntry = line.parse().unwrap();
        assert_eq!(entry.last_change, Some(i64::MAX));
    }

    #[test]
    fn test_parse_empty_reserved_field() {
        let entry: ShadowEntry = "user:$6$hash:19000:0:99999:7:::".parse().unwrap();
        assert_eq!(entry.reserved, "");
    }

    #[test]
    fn test_write_read_roundtrip_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shadow");

        let entries = vec![
            ShadowEntry {
                name: "root".into(),
                passwd: "$6$hash".into(),
                last_change: Some(19000),
                min_age: Some(0),
                max_age: Some(99999),
                warn_days: Some(7),
                inactive_days: None,
                expire_date: None,
                reserved: String::new(),
            },
            ShadowEntry {
                name: "svc".into(),
                passwd: "*".into(),
                last_change: None,
                min_age: None,
                max_age: None,
                warn_days: None,
                inactive_days: None,
                expire_date: None,
                reserved: String::new(),
            },
        ];

        let file = std::fs::File::create(&path).unwrap();
        write_shadow(&entries, file).unwrap();

        let read_back = read_shadow_file(&path).unwrap();
        assert_eq!(entries, read_back);
    }

    #[test]
    fn test_empty_file_returns_empty_vec() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shadow");
        std::fs::write(&path, "").unwrap();
        let entries = read_shadow_file(&path).unwrap();
        assert!(entries.is_empty());
    }

    // -------------------------------------------------------------------
    // Issue #15: proptest round-trip tests
    // -------------------------------------------------------------------

    use proptest::prelude::*;

    fn arb_optional_i64() -> impl Strategy<Value = Option<i64>> {
        prop_oneof![Just(None), (0i64..100_000).prop_map(Some),]
    }

    fn arb_shadow_entry() -> impl Strategy<Value = ShadowEntry> {
        (
            "[a-z_][a-z0-9_-]{0,31}",     // name
            "(\\*|!|!!|\\$6\\$[a-z]{4})", // passwd
            arb_optional_i64(),           // last_change
            arb_optional_i64(),           // min_age
            arb_optional_i64(),           // max_age
            arb_optional_i64(),           // warn_days
            arb_optional_i64(),           // inactive_days
            arb_optional_i64(),           // expire_date
        )
            .prop_map(
                |(
                    name,
                    passwd,
                    last_change,
                    min_age,
                    max_age,
                    warn_days,
                    inactive_days,
                    expire_date,
                )| {
                    ShadowEntry {
                        name,
                        passwd,
                        last_change,
                        min_age,
                        max_age,
                        warn_days,
                        inactive_days,
                        expire_date,
                        reserved: String::new(),
                    }
                },
            )
    }

    proptest! {
        #[test]
        fn test_shadow_roundtrip(entry in arb_shadow_entry()) {
            let line = entry.to_string();
            let parsed: ShadowEntry = line.parse().unwrap();
            prop_assert_eq!(parsed, entry);
        }
    }
}
