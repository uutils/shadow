// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore login_defs

//! Parser for `/etc/login.defs` configuration file.
//!
//! File format: `KEY VALUE` pairs, one per line. Lines starting with `#`
//! are comments. Blank lines are ignored. Keys are case-sensitive.

use std::collections::HashMap;
use std::io::BufRead;
use std::path::Path;

use crate::error::ShadowError;

/// Parsed `/etc/login.defs` configuration.
#[derive(Debug, Clone)]
pub struct LoginDefs {
    entries: HashMap<String, String>,
}

impl LoginDefs {
    /// Load and parse `/etc/login.defs` from the given path.
    ///
    /// If the file does not exist, returns an empty `LoginDefs` (this is
    /// intentional — missing `login.defs` is not an error, defaults apply).
    ///
    /// # Errors
    ///
    /// Returns `ShadowError` on I/O errors other than file-not-found.
    pub fn load(path: &Path) -> Result<Self, ShadowError> {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    entries: HashMap::new(),
                });
            }
            Err(e) => return Err(ShadowError::IoPath(e, path.to_owned())),
        };

        let reader = std::io::BufReader::new(file);
        let mut entries = HashMap::new();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Split on first whitespace: KEY VALUE
            if let Some((key, value)) = trimmed.split_once(|c: char| c.is_whitespace()) {
                entries.insert(key.to_string(), value.trim().to_string());
            }
        }

        Ok(Self { entries })
    }

    /// Get a string value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    /// Get a numeric value by key.
    #[must_use]
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.entries.get(key).and_then(|v| v.parse().ok())
    }

    /// Insert or replace a configuration value for later `get` / `get_i64` calls.
    ///
    /// Used when a tool accepts runtime overrides of login.defs defaults
    /// (for example `useradd -K KEY=VALUE`).
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.insert(key.into(), value.into());
    }

    /// Apply several `KEY=VALUE` overrides; later entries win on duplicate keys.
    pub fn apply_overrides<'a, I>(&mut self, overrides: I)
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        for (key, value) in overrides {
            self.set(key, value);
        }
    }
}

/// Split a `-K KEY=VALUE` argument into its key and value.
///
/// Shared by every tool that accepts login.defs overrides so they agree on
/// what is malformed: a missing `=` or an empty key is rejected, an empty
/// value is allowed (it unsets the key for this run).
///
/// # Errors
///
/// Returns [`ShadowError::Validation`] for a malformed pair.
pub fn parse_override(kv: &str) -> Result<(&str, &str), ShadowError> {
    match kv.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key, value)),
        _ => Err(ShadowError::Validation(
            format!("invalid key=value pair: '{kv}'").into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn write_login_defs(dir: &Path, content: &str) -> PathBuf {
        let path = dir.join("login.defs");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_parse_override_accepts_key_value() {
        assert_eq!(parse_override("GID_MIN=9100").unwrap(), ("GID_MIN", "9100"));
        // An empty value is a legitimate way to unset a key for the run.
        assert_eq!(parse_override("SKEL=").unwrap(), ("SKEL", ""));
        // Only the first '=' separates; the value may contain more.
        assert_eq!(parse_override("A=b=c").unwrap(), ("A", "b=c"));
    }

    #[test]
    fn test_parse_override_rejects_malformed() {
        assert!(parse_override("GID_MIN").is_err(), "missing '='");
        assert!(parse_override("=9100").is_err(), "empty key");
        assert!(parse_override("").is_err(), "empty argument");
    }

    #[test]
    fn test_parse_basic() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_login_defs(
            dir.path(),
            "PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\n",
        );
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(defs.get_i64("PASS_MAX_DAYS"), Some(99999));
        assert_eq!(defs.get_i64("PASS_MIN_DAYS"), Some(0));
        assert_eq!(defs.get_i64("PASS_WARN_AGE"), Some(7));
    }

    #[test]
    fn test_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_login_defs(
            dir.path(),
            "# This is a comment\n\nPASS_MAX_DAYS 99999\n# Another comment\n",
        );
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(defs.get_i64("PASS_MAX_DAYS"), Some(99999));
        assert_eq!(defs.get("# This is a comment"), None);
    }

    #[test]
    fn test_string_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_login_defs(
            dir.path(),
            "ENCRYPT_METHOD SHA512\nENV_PATH /bin:/usr/bin\n",
        );
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(defs.get("ENCRYPT_METHOD"), Some("SHA512"));
        assert_eq!(defs.get("ENV_PATH"), Some("/bin:/usr/bin"));
    }

    #[test]
    fn test_missing_file_returns_empty() {
        let defs = LoginDefs::load(Path::new("/nonexistent/login.defs")).unwrap();
        assert_eq!(defs.get("PASS_MAX_DAYS"), None);
    }

    #[test]
    fn test_get_i64_invalid_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_login_defs(dir.path(), "ENCRYPT_METHOD SHA512\n");
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(defs.get_i64("ENCRYPT_METHOD"), None);
    }

    #[test]
    fn test_set_overrides_existing_and_inserts_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_login_defs(dir.path(), "UID_MIN 1000\n");
        let mut defs = LoginDefs::load(&path).unwrap();
        assert_eq!(defs.get_i64("UID_MIN"), Some(1000));

        defs.set("UID_MIN", "9100");
        defs.set("PASS_MAX_DAYS", "-1");
        assert_eq!(defs.get_i64("UID_MIN"), Some(9100));
        assert_eq!(defs.get("PASS_MAX_DAYS"), Some("-1"));
    }

    #[test]
    fn test_apply_overrides() {
        let mut defs = LoginDefs::load(Path::new("/nonexistent")).unwrap();
        defs.apply_overrides([
            ("UID_MIN", "2000"),
            ("UID_MAX", "2000"),
            ("UID_MIN", "3000"),
        ]);
        // Later duplicate wins.
        assert_eq!(defs.get("UID_MIN"), Some("3000"));
        assert_eq!(defs.get("UID_MAX"), Some("2000"));
    }

    // -------------------------------------------------------------------
    // Issue #16: parser edge case tests
    // -------------------------------------------------------------------

    #[test]
    fn test_parse_tabs_and_spaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_login_defs(dir.path(), "PASS_MAX_DAYS\t \t 99999\n");
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(defs.get_i64("PASS_MAX_DAYS"), Some(99999));
    }

    #[test]
    fn test_parse_trailing_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_login_defs(dir.path(), "PASS_MAX_DAYS  99999  \n");
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(defs.get_i64("PASS_MAX_DAYS"), Some(99999));
    }

    #[test]
    fn test_parse_duplicate_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_login_defs(dir.path(), "PASS_MAX_DAYS 10000\nPASS_MAX_DAYS 99999\n");
        let defs = LoginDefs::load(&path).unwrap();
        // Last value wins (HashMap insert overwrites).
        assert_eq!(defs.get_i64("PASS_MAX_DAYS"), Some(99999));
    }

    #[test]
    fn test_parse_key_only_no_value() {
        // A line with only a key and no whitespace-separated value should be
        // silently skipped (split_once returns None).
        let dir = tempfile::tempdir().unwrap();
        let path = write_login_defs(dir.path(), "LONELY_KEY\nPASS_MAX_DAYS 99999\n");
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(defs.get("LONELY_KEY"), None);
        assert_eq!(defs.get_i64("PASS_MAX_DAYS"), Some(99999));
    }

    #[test]
    fn test_parse_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_login_defs(dir.path(), "");
        let defs = LoginDefs::load(&path).unwrap();
        assert_eq!(defs.get("PASS_MAX_DAYS"), None);
    }

    // -------------------------------------------------------------------
    // Issue #15: proptest round-trip tests
    // -------------------------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_login_defs_roundtrip(
            key in "[A-Z_]{1,20}",
            value in "[A-Za-z0-9/_:-]{1,40}",
        ) {
            let dir = tempfile::tempdir().unwrap();
            let line = format!("{key} {value}\n");
            let path = write_login_defs(dir.path(), &line);
            let defs = LoginDefs::load(&path).unwrap();
            prop_assert_eq!(defs.get(&key), Some(value.as_str()));
        }
    }
}
