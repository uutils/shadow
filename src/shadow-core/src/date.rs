// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Calendar arithmetic for the account-expiry and aging fields.
//!
//! `/etc/shadow` stores those fields as days since the Unix epoch, while the
//! tools accept the `YYYY-MM-DD` form their man pages document. Both live
//! here so `useradd`, `usermod` and `chage` agree on what a date is.

use crate::error::ShadowError;

/// Days since the Unix epoch (1970-01-01) for a Gregorian date.
///
/// Algorithm from <https://howardhinnant.github.io/date_algorithms.html>.
#[must_use]
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };

    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Whether `year` is a leap year in the Gregorian calendar.
#[must_use]
pub fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Number of days in a 1-indexed `month` of `year`; 0 for an invalid month.
#[must_use]
pub fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Parse an account-expiry argument into days since the epoch.
///
/// Accepts the `YYYY-MM-DD` form the man pages document, an empty string or
/// `-1` meaning "no expiry" (`None`), and a bare non-negative integer already
/// expressed in days since the epoch. Impossible dates (month 13, 31 April,
/// 29 February in a common year) are rejected rather than normalised.
///
/// # Errors
///
/// Returns `ShadowError::Validation` describing the malformed value.
pub fn parse_expire_date(s: &str) -> Result<Option<i64>, ShadowError> {
    if s.is_empty() || s == "-1" {
        return Ok(None);
    }

    // A bare integer is already days since the epoch.
    if !s.contains('-') {
        return s.parse::<i64>().map(Some).map_err(|_| {
            ShadowError::Validation(
                format!("invalid date '{s}' (expected YYYY-MM-DD or days since epoch)").into(),
            )
        });
    }

    let invalid =
        || ShadowError::Validation(format!("invalid date '{s}' (expected YYYY-MM-DD)").into());

    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return Err(invalid());
    }
    let year: i64 = parts[0].parse().map_err(|_| invalid())?;
    let month: i64 = parts[1].parse().map_err(|_| invalid())?;
    let day: i64 = parts[2].parse().map_err(|_| invalid())?;

    if !(1..=12).contains(&month) || year < 1970 {
        return Err(ShadowError::Validation(
            format!("invalid date '{s}' (expected YYYY-MM-DD with valid ranges)").into(),
        ));
    }

    let max_day = days_in_month(year, month);
    if !(1..=max_day).contains(&day) {
        return Err(ShadowError::Validation(
            format!("invalid date '{s}' (day {day} out of range for month {month})").into(),
        ));
    }

    Ok(Some(days_from_civil(year, month, day)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_days_from_civil_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(days_from_civil(2024, 2, 29), 19782);
    }

    #[test]
    fn test_leap_years_and_month_lengths() {
        assert!(is_leap_year(2000) && is_leap_year(2024));
        assert!(!is_leap_year(1900) && !is_leap_year(2023));
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2023, 2), 28);
        assert_eq!(days_in_month(2023, 4), 30);
        assert_eq!(days_in_month(2023, 13), 0);
    }

    #[test]
    fn test_parse_expire_date_forms() {
        assert_eq!(parse_expire_date("").unwrap(), None);
        assert_eq!(parse_expire_date("-1").unwrap(), None);
        assert_eq!(parse_expire_date("2024-02-29").unwrap(), Some(19782));
        // A bare integer is already days since the epoch.
        assert_eq!(parse_expire_date("19782").unwrap(), Some(19782));
    }

    #[test]
    fn test_parse_expire_date_rejects_impossible_dates() {
        for bad in [
            "2023-02-29",
            "2024-13-01",
            "2024-04-31",
            "2024-00-10",
            "1969-01-01",
            "2024-02",
            "not-a-date",
            "2024-ab-01",
        ] {
            assert!(
                parse_expire_date(bad).is_err(),
                "'{bad}' should be rejected"
            );
        }
    }
}
