// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Username and groupname validation rules.
//!
//! Based on POSIX Portable Filename Character Set plus Linux extensions.
//! See: POSIX 3.437 (User Name), man 8 useradd.

use crate::error::ShadowError;

/// Maximum username length on Linux.
const MAX_USERNAME_LEN: usize = 32;

/// Whether a name already in an account file passes the checks of `pwck` and
/// `grpck`, which take `max_len`: a user name may run to 255, a group name to 32.
///
/// This is wider than [`validate_username`], which judges a new account: `1abc`
/// or 40 letters may be on a system already, and calling them bad would fail the
/// whole check there. The rule is what Ubuntu 26.04's `pwck` and `grpck` were
/// seen to do: ASCII letters, digits, `_`, `.` and `-`, with one `$` at the end,
/// and not `.`, `..`, or something that reads as a number in base 10, 8 or 16
/// (`123`, `0o7`, `0xABC`).
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

/// Validate a username or group name.
///
/// Rules, from the CAVEATS of useradd(8) and groupadd(8):
/// - must not be empty, and at most 32 characters
/// - first character is a letter or underscore
/// - the rest are letters, digits, underscores, hyphens or periods
/// - a single trailing `$` is allowed, which is how Samba names machine
///   accounts (`MACHINE$`)
/// - must not end with a period, and must not consist only of periods
///
/// Upper case is accepted: `useradd Alice` succeeds on GNU shadow-utils
/// (verified), and rejecting it made us refuse accounts that already exist on
/// real systems. Lower case remains the recommendation, not a rule.
///
/// # Errors
///
/// Returns `ShadowError::Validation` if the name violates any rule.
pub fn validate_username(name: &str) -> Result<(), ShadowError> {
    if name.len() > MAX_USERNAME_LEN {
        return Err(ShadowError::Validation(
            format!("username '{name}' exceeds maximum length of {MAX_USERNAME_LEN} characters")
                .into(),
        ));
    }

    // A single trailing '$' is part of the name but not of the character set.
    let body = name.strip_suffix('$').unwrap_or(name);

    let mut chars = body.chars();
    // Reject empty names by requiring a first character here.
    let Some(first) = chars.next() else {
        return Err(ShadowError::Validation("username must not be empty".into()));
    };

    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(ShadowError::Validation(
            format!("username '{name}' must start with a letter or underscore").into(),
        ));
    }

    for ch in chars {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' && ch != '.' {
            return Err(ShadowError::Validation(
                format!("username '{name}' contains invalid character '{ch}'").into(),
            ));
        }
    }

    if body.ends_with('.') {
        return Err(ShadowError::Validation(
            format!("username '{name}' must not end with a period").into(),
        ));
    }

    if body.chars().all(|c| c == '.') {
        return Err(ShadowError::Validation(
            format!("username '{name}' must not consist only of periods").into(),
        ));
    }

    Ok(())
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

    #[test]
    fn test_valid_usernames() {
        assert!(validate_username("root").is_ok());
        assert!(validate_username("_apt").is_ok());
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("test-user").is_ok());
        assert!(validate_username("test.user").is_ok());
        assert!(validate_username("a").is_ok());
    }

    #[test]
    fn test_empty_username() {
        assert!(validate_username("").is_err());
    }

    #[test]
    fn test_too_long() {
        let long_name = "a".repeat(33);
        assert!(validate_username(&long_name).is_err());
        let max_name = "a".repeat(32);
        assert!(validate_username(&max_name).is_ok());
    }

    #[test]
    fn test_invalid_first_char() {
        assert!(validate_username("1user").is_err());
        assert!(validate_username("-user").is_err());
        assert!(validate_username(".user").is_err());
    }

    #[test]
    fn test_invalid_chars() {
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user:name").is_err());
    }

    #[test]
    fn test_trailing_period() {
        assert!(validate_username("user.").is_err());
    }

    // -------------------------------------------------------------------
    // Issue #16: additional edge case tests
    // -------------------------------------------------------------------

    #[test]
    fn test_unicode_username_rejected() {
        assert!(validate_username("café").is_err());
    }

    #[test]
    fn test_null_byte_rejected() {
        assert!(validate_username("\0user").is_err());
    }

    #[test]
    fn test_max_length_32_ok() {
        let name = "a".repeat(32);
        assert!(validate_username(&name).is_ok());
    }

    #[test]
    fn test_length_33_rejected() {
        let name = "a".repeat(33);
        assert!(validate_username(&name).is_err());
    }

    #[test]
    fn test_only_dots_rejected() {
        assert!(validate_username("..").is_err());
        assert!(validate_username("...").is_err());
    }

    #[test]
    fn test_hyphen_start_rejected() {
        assert!(validate_username("-user").is_err());
    }

    // GNU shadow-utils accepts these (verified against useradd(8)); refusing
    // them made us reject accounts that exist on real systems.
    #[test]
    fn test_uppercase_and_machine_accounts_accepted() {
        assert!(validate_username("Alice").is_ok());
        assert!(validate_username("DevOps").is_ok());
        assert!(validate_username("MACHINE$").is_ok());
        // The '$' is only meaningful as the last character.
        assert!(validate_username("ma$chine").is_err());
        assert!(validate_username("$").is_err());
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
