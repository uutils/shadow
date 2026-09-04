// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chage warndays maxdays mindays expiredate lastday

//! Integration tests for the `chage` utility.
//!
//! These run the real binary against a `--prefix` tree and assert on what it
//! writes and prints. They used to set a field through `shadow-core` and read
//! it back, which tested the parser twice and `chage` not at all; the tool had
//! no `--prefix` then, and `--root` performs a real `chroot(2)` that an
//! in-process test cannot use.

use crate::common::{Output, run, tool};

/// A prefix tree holding `etc/shadow`, and `etc/passwd` for the tools that
/// look an account up before touching its aging fields.
fn prefix(shadow: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");
    std::fs::write(etc.join("shadow"), shadow).expect("failed to write shadow file");
    std::fs::write(
        etc.join("passwd"),
        "testuser:x:4000:4000::/home/testuser:/bin/sh\n",
    )
    .expect("failed to write passwd file");
    dir
}

/// The account's shadow line, without its trailing newline.
fn shadow_line(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/shadow"))
        .expect("failed to read shadow file")
        .trim_end()
        .to_string()
}

/// Run `chage --prefix <dir> <args...>`.
fn chage(dir: &tempfile::TempDir, args: &[&str]) -> Output {
    let mut cmd = tool("chage");
    cmd.arg("--prefix").arg(dir.path()).args(args);
    crate::common::run_cmd(&mut cmd)
}

/// The value column of one `chage -l` line, counting from 1.
///
/// `chage -l` on an account other than the caller's needs root, whatever
/// `--prefix` says: the identity check runs before any file is opened. Every
/// test using this is guarded accordingly.
fn field(dir: &tempfile::TempDir, line: usize) -> String {
    let out = chage(dir, &["-l", "testuser"]);
    out.assert_code(0);
    let Some((_, value)) = out
        .stdout
        .lines()
        .nth(line - 1)
        .and_then(|l| l.rsplit_once(": "))
    else {
        panic!("no line {line} in:\n{}", out.stdout)
    };
    value.to_string()
}

// ---------------------------------------------------------------------------
// Argument handling
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    run("chage", &["--help"])
        .assert_code(0)
        .assert_stdout_contains("--lastday");
}

#[test]
fn test_missing_login_exits_two() {
    run("chage", &["-l"])
        .assert_code(2)
        .assert_stderr_contains("<login>");
}

/// `-l` prints; it does not also change things.
#[test]
fn test_list_conflicts_with_every_field_option() {
    for (flag, value) in [
        ("-m", "5"),
        ("-M", "90"),
        ("-d", "0"),
        ("-W", "7"),
        ("-I", "3"),
    ] {
        run("chage", &["-l", flag, value, "testuser"])
            .assert_code(2)
            .assert_stderr_contains("cannot be used with");
    }
}

/// A day count is either non-negative or -1, which clears the field. Anything
/// else is not a policy a reader can act on.
#[test]
fn test_negative_aging_values_are_rejected() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix("testuser:$6$hash:19500:0:99999:7:::\n");
    let before = shadow_line(&dir);
    for flag in ["-m", "-M", "-W", "-I"] {
        chage(&dir, &[flag, "-5", "testuser"]).assert_code(2);
    }
    chage(&dir, &["-d", "-5", "testuser"]).assert_code(2);
    assert_eq!(before, shadow_line(&dir), "a refused value was written");
}

/// An unknown login is an ordinary failure. chage(1) reserves 15 for "can't
/// find the shadow password file", and GNU exits 1 here.
#[test]
fn test_unknown_login_exits_one() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix("testuser:$6$hash:19500:0:99999:7:::\n");
    chage(&dir, &["-l", "ghost"]).assert_code(1);
    chage(&dir, &["-M", "10", "ghost"]).assert_code(1);
}

// ---------------------------------------------------------------------------
// Writing the aging fields
// ---------------------------------------------------------------------------

#[test]
fn test_each_field_option_writes_its_own_field() {
    if crate::common::skip_unless_root() {
        return;
    }
    // Every case starts from the same line, so the assertion pins the whole
    // record: a flag that also disturbed a neighbouring field would show.
    let start = "testuser:$6$hash:19500:0:99999:7:::\n";
    for (args, expected) in [
        (vec!["-m", "10"], "testuser:$6$hash:19500:10:99999:7:::"),
        (vec!["-M", "180"], "testuser:$6$hash:19500:0:180:7:::"),
        (vec!["-W", "14"], "testuser:$6$hash:19500:0:99999:14:::"),
        (vec!["-I", "30"], "testuser:$6$hash:19500:0:99999:7:30::"),
        (vec!["-d", "0"], "testuser:$6$hash:0:0:99999:7:::"),
        (
            vec!["-E", "2024-10-04"],
            "testuser:$6$hash:19500:0:99999:7::20000:",
        ),
        (
            vec!["-E", "20000"],
            "testuser:$6$hash:19500:0:99999:7::20000:",
        ),
    ] {
        let dir = prefix(start);
        chage(&dir, &[args.clone(), vec!["testuser"]].concat()).assert_code(0);
        assert_eq!(shadow_line(&dir), expected, "after chage {args:?}");
    }
}

/// -1 clears a field rather than storing a negative number.
#[test]
fn test_minus_one_clears_a_field() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix("testuser:$6$hash:19500:5:180:14:30:20000:\n");
    chage(
        &dir,
        &[
            "-m", "-1", "-M", "-1", "-W", "-1", "-I", "-1", "-E", "-1", "testuser",
        ],
    )
    .assert_code(0);
    assert_eq!(shadow_line(&dir), "testuser:$6$hash:19500::::::");
}

/// A date that does not exist is refused, not rolled over into the next month.
#[test]
fn test_impossible_dates_are_rejected() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix("testuser:$6$hash:19500:0:99999:7:::\n");
    let before = shadow_line(&dir);
    for date in ["2025-02-29", "2025-04-31", "2025-13-01", "not-a-date"] {
        chage(&dir, &["-E", date, "testuser"]).assert_code(2);
    }
    assert_eq!(before, shadow_line(&dir));
}

// ---------------------------------------------------------------------------
// The -l output
//
// The expected text is GNU shadow 4.17's. Scripts parse these lines, so the
// wording and the thresholds are part of the contract.
// ---------------------------------------------------------------------------

#[test]
fn test_list_prints_the_gnu_labels() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix("testuser:$6$hash:19500:0:99999:7:::\n");
    let out = chage(&dir, &["-l", "testuser"]);
    out.assert_code(0);
    for label in [
        "Last password change",
        "Password expires",
        "Password inactive",
        "Account expires",
        "Minimum number of days between password change",
        "Maximum number of days between password change",
        "Number of days of warning before password expires",
    ] {
        out.assert_stdout_contains(label);
    }
}

/// A last change of 0 is `passwd -e`'s "must change at next login" marker, not
/// a date, and it makes the two dates derived from it meaningless as well.
#[test]
fn test_last_change_zero_reports_must_be_changed() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix("testuser:$6$hash:0:0:90:7:30:0:\n");
    assert_eq!(field(&dir, 1), "password must be changed");
    assert_eq!(field(&dir, 2), "password must be changed");
    assert_eq!(field(&dir, 3), "password must be changed");
    // The account expiry is a separate field and keeps its own date.
    assert_eq!(field(&dir, 4), "Jan 01, 1970");
}

/// Expiry is disabled at a maximum age of 10000 days, not 99999.
#[test]
fn test_never_threshold_is_ten_thousand_days() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix("testuser:$6$hash:20454:0:9999:7:::\n");
    assert_eq!(field(&dir, 2), "May 18, 2053");

    let dir = prefix("testuser:$6$hash:20454:0:10000:7:::\n");
    assert_eq!(field(&dir, 2), "never");
}

#[test]
fn test_unset_fields_report_never_and_minus_one() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix("testuser:$6$hash:::::::\n");
    assert_eq!(field(&dir, 1), "never");
    assert_eq!(field(&dir, 2), "never");
    assert_eq!(field(&dir, 3), "never");
    assert_eq!(field(&dir, 4), "never");
    assert_eq!(field(&dir, 5), "-1");
    assert_eq!(field(&dir, 6), "-1");
    assert_eq!(field(&dir, 7), "-1");
}

/// Anyone who can write /etc/shadow can put a value in it that overflows the
/// `lastchg + max + inactive` sums. That must read as `never` rather than wrap
/// into a plausible-looking date.
#[test]
fn test_absurd_field_values_report_never() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix("testuser:$6$hash:9223372036854775807:0:90:7:9223372036854775807::\n");
    assert_eq!(field(&dir, 1), "never");
    assert_eq!(field(&dir, 2), "never");
    assert_eq!(field(&dir, 3), "never");
}

/// The two derived dates are sums of three separate fields.
#[test]
fn test_derived_dates_are_the_sums_of_their_fields() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix("testuser:$6$hash:20454:0:90:7:30::\n");
    assert_eq!(field(&dir, 1), "Jan 01, 2026");
    assert_eq!(field(&dir, 2), "Apr 01, 2026");
    assert_eq!(field(&dir, 3), "May 01, 2026");
}
