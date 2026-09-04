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

/// The range of day counts this module will turn back into a calendar date.
///
/// The aging fields are read from a file anyone with write access to
/// `/etc/shadow` can put anything in, and they are summed (`lastchg + max +
/// inactive`) before being displayed. Bounding the input keeps every such sum
/// inside `i64` and keeps the output a date a human can read: the limits are
/// 0001-01-01 and 9999-12-31.
const MIN_DAYS: i64 = -719_162;
const MAX_DAYS: i64 = 2_932_896;

/// The civil date `(year, month, day)` for `days` since the Unix epoch.
///
/// `None` for a value outside the representable range, which is how a corrupt
/// or absurd field arrives here. The inverse of [`days_from_civil`].
#[must_use]
pub fn civil_from_days(days: i64) -> Option<(i64, i64, i64)> {
    if !(MIN_DAYS..=MAX_DAYS).contains(&days) {
        return None;
    }

    // Shift the epoch to 0000-03-01 so leap days fall at the end of the era.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };

    Some((if m <= 2 { y + 1 } else { y }, m, d))
}

/// Format `days` since the epoch the way `chage -l` prints a date, for example
/// `Jan 01, 2026`.
///
/// `None` for a value that is not a representable date; every caller displays
/// `never` in that case, which is also what GNU `chage` shows for a field it
/// cannot make sense of.
#[must_use]
pub fn format_human(days: i64) -> Option<String> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (year, month, day) = civil_from_days(days)?;
    let name = MONTHS.get(usize::try_from(month - 1).ok()?)?;
    Some(format!("{name} {day:02}, {year}"))
}

/// Format the sum of `days` as a date, or `None` if any term overflows or the
/// total is not a representable date.
///
/// `chage -l` adds `lastchg + max` and `lastchg + max + inactive`, each read
/// from the file. Plain `+` would wrap in release builds and panic in debug
/// ones, so the addition is checked here once for every caller.
#[must_use]
pub fn format_human_sum(days: &[i64]) -> Option<String> {
    let mut total: i64 = 0;
    for d in days {
        total = total.checked_add(*d)?;
    }
    format_human(total)
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
    fn test_civil_from_days_round_trips() {
        for (y, m, d) in [
            (1970, 1, 1),
            (1970, 1, 2),
            (2000, 2, 29),
            (2024, 2, 29),
            (2026, 1, 1),
            (2053, 5, 18),
            (1, 1, 1),
            (9999, 12, 31),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(
                civil_from_days(days),
                Some((y, m, d)),
                "round trip failed for {y}-{m}-{d}"
            );
        }
    }

    /// The aging fields come from a file, so the arithmetic must survive
    /// anything that can be written into one rather than wrapping or panicking.
    #[test]
    fn test_out_of_range_days_have_no_date() {
        assert_eq!(civil_from_days(i64::MAX), None);
        assert_eq!(civil_from_days(i64::MIN), None);
        assert_eq!(civil_from_days(MAX_DAYS + 1), None);
        assert_eq!(civil_from_days(MIN_DAYS - 1), None);
        assert_eq!(format_human(i64::MAX), None);
    }

    #[test]
    fn test_format_human_matches_the_chage_form() {
        assert_eq!(
            format_human(days_from_civil(2026, 1, 1)).as_deref(),
            Some("Jan 01, 2026")
        );
        assert_eq!(format_human(0).as_deref(), Some("Jan 01, 1970"));
    }

    /// `lastchg + max + inactive` is three file-supplied values added together.
    #[test]
    fn test_format_human_sum_is_checked() {
        let base = days_from_civil(2026, 1, 1);
        assert_eq!(
            format_human_sum(&[base, 9999]).as_deref(),
            Some("May 18, 2053")
        );
        assert_eq!(format_human_sum(&[i64::MAX, 1]), None);
        assert_eq!(format_human_sum(&[i64::MAX, i64::MAX]), None);
        assert_eq!(format_human_sum(&[i64::MIN, -1]), None);
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
