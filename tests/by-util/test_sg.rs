// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore newgrp

//! Integration tests for the `sg` utility.
//!
//! `sg` execs the command it was given, so a successful run never returns.
//! In-process tests therefore only exercise the paths that fail before the
//! exec; everything that has to observe a *successful* switch runs the real
//! binary as a child, which is also the only way to see the exit status the
//! command left behind.

use std::ffi::OsString;

use crate::common::{run, skip_unless_root};

/// Run `uumain` in-process, returning the exit code.
///
/// Only ever called with input that fails before the exec: a successful `sg`
/// would replace this test binary with a shell.
fn run_in_process(args: &[&str]) -> i32 {
    let os_args: Vec<OsString> = args.iter().map(|s| (*s).into()).collect();
    sg::uumain(os_args.into_iter())
}

// ---------------------------------------------------------------------------
// Non-root tests
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    assert_eq!(run_in_process(&["sg", "--help"]), 0, "--help should exit 0");
}

/// GNU's wording, which scripts match on.
#[test]
fn test_unknown_group_is_refused() {
    run("sg", &["nonexistent_group_99999", "-c", "true"])
        .assert_code(1)
        .assert_stderr_contains("no such group");
}

// ---------------------------------------------------------------------------
// Root tests — a real group switch
// ---------------------------------------------------------------------------

/// Create a group to switch into, ignoring the error if a previous run left
/// it behind.
fn ensure_group(name: &str) {
    let _ = run("groupadd", &[name]);
}

#[test]
fn test_runs_the_command_in_the_target_group() {
    if skip_unless_root() {
        return;
    }
    ensure_group("sgtest");

    run("sg", &["sgtest", "-c", "id -gn"])
        .assert_code(0)
        .assert_stdout_contains("sgtest");
}

/// `-c` is optional: `sg staff 'id -gn'` is the same request as
/// `sg staff -c 'id -gn'`, and the GNU tool accepts both.
#[test]
fn test_dash_c_is_optional() {
    if skip_unless_root() {
        return;
    }
    ensure_group("sgtest2");

    run("sg", &["sgtest2", "id -gn"])
        .assert_code(0)
        .assert_stdout_contains("sgtest2");
}

/// The reason `sg` execs instead of forking and waiting: whatever the command
/// exits with is what the caller sees. A wrapper that returned 0 here, or that
/// collapsed every failure to 1, would break any script testing `sg`'s status.
#[test]
fn test_the_commands_exit_status_reaches_the_caller() {
    if skip_unless_root() {
        return;
    }
    ensure_group("sgtest3");

    run("sg", &["sgtest3", "-c", "exit 7"]).assert_code(7);
    run("sg", &["sgtest3", "-c", "false"]).assert_code(1);
    // A command the shell cannot run is 127 by convention, and that too has to
    // survive the trip.
    run("sg", &["sgtest3", "-c", "/nonexistent/command"]).assert_code(127);
}

/// The switch changes the primary group and keeps the caller's identity: `sg`
/// is not `su`.
#[test]
fn test_the_uid_is_unchanged() {
    if skip_unless_root() {
        return;
    }
    ensure_group("sgtest4");

    run("sg", &["sgtest4", "-c", "id -u"])
        .assert_code(0)
        .assert_stdout_contains("0");
}

/// Supplementary groups are reinitialized from the caller's own membership
/// rather than dropped, so the target group is added to what the caller had.
#[test]
fn test_supplementary_groups_are_kept() {
    if skip_unless_root() {
        return;
    }
    ensure_group("sgtest5");

    let out = run("sg", &["sgtest5", "-c", "id -Gn"]);
    out.assert_code(0).assert_stdout_contains("root");
}

/// `sg` and `newgrp` are one implementation on a GNU system, where `sg` is a
/// symlink. Both must reach the same code here too.
#[test]
fn test_sg_and_newgrp_agree_on_an_unknown_group() {
    let sg = run("sg", &["nonexistent_group_99999", "-c", "true"]);
    let newgrp = run("newgrp", &["nonexistent_group_99999"]);
    assert_eq!(
        sg.code, newgrp.code,
        "sg and newgrp disagree on an unknown group"
    );
    assert_eq!(
        sg.stderr.trim_start_matches("sg:"),
        newgrp.stderr.trim_start_matches("newgrp:"),
        "sg and newgrp report an unknown group differently"
    );
}
