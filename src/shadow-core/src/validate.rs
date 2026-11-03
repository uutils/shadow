// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Username and groupname validation rules.
//!
//! Based on POSIX Portable Filename Character Set plus Linux extensions.
//! See: POSIX 3.437 (User Name), man 8 useradd.

use crate::error::ShadowError;

/// Longest user name: upstream's `useradd`, `usermod -l` and `newusers` take
/// 255 characters, and `pwck` passes as many.
pub const MAX_USER_NAME_LEN: usize = 255;

/// Longest group name: upstream's `groupadd`, `groupmod -n`, `newusers` and
/// `grpck` stop at 32 characters.
pub const MAX_GROUP_NAME_LEN: usize = 32;

/// Whether a name already in an account file passes the checks of `pwck` and
/// `grpck`, which take `max_len`: a user name may run to 255, a group name to 32.
///
/// The rule is what Ubuntu 26.04's `pwck` and `grpck` were seen to do: ASCII
/// letters, digits, `_`, `.` and `-`, with one `$` at the end, and not `.`,
/// `..`, or something that reads as a number in base 10, 8 or 16 (`123`,
/// `0o7`, `0xABC`), which would be taken for an ID. A leading digit is fine:
/// `1abc` is a name, `123` is a UID.
#[must_use]
pub fn is_valid_account_name(name: &str, max_len: usize) -> bool {
    let body = name.strip_suffix('$').unwrap_or(name);
    let reads_as_number = |text: &str, radix: u32| text.chars().all(|c| c.is_digit(radix));
    let is_number = reads_as_number(name, 10)
        || name
            .strip_prefix("0x")
            .is_some_and(|hex| reads_as_number(hex, 16))
        || name
            .strip_prefix("0o")
            .is_some_and(|oct| reads_as_number(oct, 8));

    !body.is_empty()
        && name.len() <= max_len
        && !is_number
        && name != "."
        && name != ".."
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Whether a new or renamed account may take `name`: the rule of
/// [`is_valid_account_name`], and not starting with `-`, which every tool
/// downstream would read as an option. Ubuntu 26.04's `useradd`, `usermod -l`,
/// `groupadd`, `groupmod -n` and `newusers` were seen to refuse a leading `-`
/// that `pwck` and `grpck` let pass in a file.
fn is_valid_new_name(name: &str, max_len: usize) -> bool {
    !name.starts_with('-') && is_valid_account_name(name, max_len)
}

/// Whether `useradd`, `usermod -l` and `newusers` may give a user this name,
/// without `--badname`.
///
/// Upper case, a leading digit or dot, a trailing dot and a Samba machine
/// account's trailing `$` are all accepted, as upstream does; lower case is
/// the recommendation, not a rule.
#[must_use]
pub fn is_valid_user_name(name: &str) -> bool {
    is_valid_new_name(name, MAX_USER_NAME_LEN)
}

/// Whether `groupadd`, `groupmod -n` and `newusers` may give a group this
/// name: the user name rule, at most 32 characters.
#[must_use]
pub fn is_valid_group_name(name: &str) -> bool {
    is_valid_new_name(name, MAX_GROUP_NAME_LEN)
}

/// Reject a value that would corrupt a colon-separated account file.
///
/// Fields are written verbatim, so a `:` adds a field, a newline adds a
/// record — `useradd -c $'x\nevil::0:0::/:/bin/sh'` created a passwordless
/// UID 0 account — and any other control character corrupts the output of
/// every program that reads the file. `what` names the field in the error.
///
/// # Errors
///
/// Returns `ShadowError::Validation` naming the offending character.
pub fn validate_field(what: &str, value: &str) -> Result<(), ShadowError> {
    if let Some(bad) = value.chars().find(|c| *c == ':' || c.is_control()) {
        return Err(ShadowError::Validation(
            format!("invalid {what}: must not contain {}", describe_char(bad)).into(),
        ));
    }
    Ok(())
}

/// [`validate_field`] for one item of a comma-separated list (group members
/// and administrators), which additionally must not contain the separator.
///
/// # Errors
///
/// Returns `ShadowError::Validation` naming the offending character.
pub fn validate_list_item(what: &str, value: &str) -> Result<(), ShadowError> {
    validate_field(what, value)?;
    if value.contains(',') {
        return Err(ShadowError::Validation(
            format!("invalid {what}: must not contain ','").into(),
        ));
    }
    Ok(())
}

fn describe_char(c: char) -> String {
    match c {
        ':' => "':'".to_string(),
        '\n' => "a newline".to_string(),
        '\r' => "a carriage return".to_string(),
        '\0' => "a NUL byte".to_string(),
        c => format!("control character U+{:04X}", u32::from(c)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What Ubuntu 26.04's `useradd`, `usermod -l` and `newusers` were seen
    /// to accept and refuse.
    #[test]
    fn test_user_names_follow_the_probe() {
        for name in [
            "root", "_apt", "user123", "Alice", "MACHINE$", "0abc", "1e5", "1-1", "_abc", ".abc",
            "a.", "...", "a$", "1$", "123$", ".$", "0xg", "0X1", "0b1", "1.5", "0x1$", "a-",
            "a..b", "0abc.",
        ] {
            assert!(is_valid_user_name(name), "{name} should be accepted");
        }
        for name in [
            "", "123", "0", "00", "0x", "0x1a", "0o7", "-abc", "-x", "-", ".", "..", "$", "a$b",
            "a$$", "ma$chine", "a@b", "a+b", "a b", "a:b", "é", "café", "\0user",
        ] {
            assert!(!is_valid_user_name(name), "{name:?} should be refused");
        }
        assert!(is_valid_user_name(&"a".repeat(255)));
        assert!(!is_valid_user_name(&"a".repeat(256)));
    }

    /// Groups follow the user rule but stop at 32 characters, `$` included.
    #[test]
    fn test_group_names_follow_the_probe() {
        assert!(is_valid_group_name("0abc"));
        assert!(!is_valid_group_name("123"));
        assert!(!is_valid_group_name("-x"));
        assert!(is_valid_group_name(&"a".repeat(32)));
        assert!(!is_valid_group_name(&"a".repeat(33)));
        assert!(is_valid_group_name(&format!("{}$", "a".repeat(31))));
        assert!(!is_valid_group_name(&format!("{}$", "a".repeat(32))));
    }

    // -------------------------------------------------------------------
    // Field validation
    // -------------------------------------------------------------------

    #[test]
    fn test_validate_field_accepts_ordinary_values() {
        assert!(validate_field("GECOS", "Jane Doe,Room 1,555-1234,,").is_ok());
        assert!(validate_field("home", "/home/jane doe").is_ok());
        assert!(validate_field("password", "$6$salt$hash").is_ok());
        assert!(validate_field("GECOS", "").is_ok());
        assert!(validate_field("GECOS", "Zoë Müller").is_ok());
    }

    #[test]
    fn test_validate_field_rejects_separators_and_control_chars() {
        let err = validate_field("comment", "a:b").unwrap_err().to_string();
        assert_eq!(err, "invalid comment: must not contain ':'");
        assert!(validate_field("comment", "x\nevil::0:0::/:/bin/sh").is_err());
        assert!(validate_field("comment", "x\r").is_err());
        assert!(validate_field("comment", "x\0").is_err());
        assert!(validate_field("comment", "x\u{1b}[31m").is_err());
        assert!(validate_field("comment", "x\ty").is_err());
    }

    #[test]
    fn test_validate_list_item_rejects_comma() {
        assert!(validate_list_item("member", "alice").is_ok());
        assert!(validate_list_item("member", "alice,bob").is_err());
        assert!(validate_list_item("member", "ali:ce").is_err());
    }

    #[test]
    fn test_is_valid_account_name_follows_the_probe() {
        for name in [
            "Upper", "a.b", "1abc", "a$", "1$", ".$", "-x", ".a", "a.", "...", "_", "1e5", "1.5",
            "1-1", "0X1", "0xg", "0b1", "a..b",
        ] {
            assert!(is_valid_account_name(name, 255), "{name} should pass");
        }
        for name in [
            "", "a@b", "a b", "a,b", "é", "123", "0", "00", "0x", "0x1", "0xABC", "0o7", ".", "..",
            "$", "a$b", "$a", "a$$", "a+b",
        ] {
            assert!(!is_valid_account_name(name, 255), "{name} should not pass");
        }
        assert!(is_valid_account_name(&"a".repeat(255), 255));
        assert!(!is_valid_account_name(&"a".repeat(256), 255));
        assert!(is_valid_account_name(&"a".repeat(32), 32));
        assert!(!is_valid_account_name(&"a".repeat(33), 32));
    }
}
