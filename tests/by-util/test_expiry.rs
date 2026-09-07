// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore setgid

//! Integration tests for `expiry`.
//!
//! `expiry` judges the *caller's* shadow line, so the tests run as root and
//! write root's line into a prefix tree in each state. Under `--prefix` the
//! tool reports and never changes anything, which is what lets a required
//! change be asserted here without a password prompt; the prompt itself is
//! exercised in the e2e suite, on a real user, on a terminal.

use crate::common::{run, skip_unless_root};

fn prefix(shadow_line: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("etc");
    std::fs::write(etc.join("shadow"), format!("{shadow_line}\n")).expect("shadow");
    dir
}

fn expiry(dir: &tempfile::TempDir, args: &[&str]) -> crate::common::Output {
    let p = dir.path().to_str().expect("utf8").to_string();
    let mut all = vec!["--prefix", p.as_str()];
    all.extend_from_slice(args);
    run("expiry", &all)
}

fn today() -> i64 {
    shadow_core::shadow::days_since_epoch().expect("clock")
}

#[test]
fn test_help_and_usage() {
    run("expiry", &["--help"])
        .assert_code(0)
        .assert_stdout_contains("Usage:");
    // Nothing asked, nothing done: usage, exit 2, as the GNU tool.
    run("expiry", &[]).assert_code(2);
}

#[test]
fn test_healthy_is_silent() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(&format!("root:$6$x$y:{}:0:99999:7:::", today() - 10));
    let out = expiry(&dir, &["-c"]);
    out.assert_code(0);
    assert!(out.stdout.is_empty(), "{:?}", out.stdout);
}

#[test]
fn test_warning_before_expiry() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(&format!("root:$6$x$y:{}:0:30:7:::", today() - 27));
    expiry(&dir, &["-c"])
        .assert_code(0)
        .assert_stdout_contains("Your password will expire in 3 days.");
}

#[test]
fn test_expired_password_requires_a_change() {
    if skip_unless_root() {
        return;
    }
    for line in [
        "root:$6$x$y:0:0:99999:7:::".to_string(),
        format!("root:$6$x$y:{}:0:30:7:::", today() - 60),
    ] {
        let dir = prefix(&line);
        expiry(&dir, &["-c"]).assert_code(1).assert_stdout_contains(
            "You are required to change your password immediately (password expired).",
        );
        expiry(&dir, &["-f"]).assert_code(1);
    }
}

#[test]
fn test_expired_account_is_turned_away() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(&format!(
        "root:$6$x$y:{}:0:99999:7::{}:",
        today() - 10,
        today() - 1
    ));
    expiry(&dir, &["-c"]).assert_code(1).assert_stdout_contains(
        "Your account has expired; please contact your system administrator.",
    );
}

/// A locked password is a policy of its own.
#[test]
fn test_locked_is_silent() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix("root:!$6$x$y:0:0:1:7:::");
    let out = expiry(&dir, &["-c"]);
    out.assert_code(0);
    assert!(out.stdout.is_empty());
}

/// No shadow line for the caller: no policy to enforce.
#[test]
fn test_no_line_is_silent() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix("someoneelse:$6$x$y:0:0:1:7:::");
    expiry(&dir, &["-c"]).assert_code(0);
}
