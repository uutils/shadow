// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Tests for the multicall binary itself: which applets it carries and how it
//! dispatches to them.
//!
//! One table in `src/bin/shadow-rs.rs` drives both `--list` and dispatch, so a
//! tool that is compiled in but missing from the table, or listed but not
//! reachable, is a single-line mistake with no other symptom. Nothing checked
//! for it.

use std::process::Command;

use crate::common::{run, run_cmd};

/// Every applet this build is expected to carry, in `--list` order.
const TOOLS: [&str; 14] = [
    "chage", "chfn", "chpasswd", "chsh", "groupadd", "groupdel", "groupmod", "grpck", "newgrp",
    "passwd", "pwck", "useradd", "userdel", "usermod",
];

/// The binary with no applet argument.
fn multicall(args: &[&str]) -> crate::common::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shadow-rs"));
    cmd.env_clear().env("PATH", "/usr/bin:/bin").args(args);
    run_cmd(&mut cmd)
}

#[test]
fn test_list_names_every_tool_in_order() {
    let out = multicall(&["--list"]);
    out.assert_code(0);
    let listed: Vec<String> = out
        .stdout
        .lines()
        .skip(1) // "Available utilities:"
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(listed, TOOLS, "--list does not match the expected applets");
}

/// Listed is not the same as reachable: dispatch is what a symlink uses.
#[test]
fn test_every_listed_tool_dispatches() {
    for tool in TOOLS {
        run(tool, &["--help"])
            .assert_code(0)
            .assert_stdout_contains("Usage:");
    }
}

/// The same table, reached the other way: `shadow-rs <tool> --help` and the
/// symlink form must produce the same help text.
#[test]
fn test_help_is_identical_through_both_entry_points() {
    for tool in TOOLS {
        let via_argument = run(tool, &["--help"]);
        via_argument.assert_code(0);

        let link = tempfile::tempdir().expect("tempdir");
        let path = link.path().join(tool);
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_shadow-rs"), &path).expect("symlink");

        let mut cmd = Command::new(&path);
        cmd.env_clear().env("PATH", "/usr/bin:/bin").arg("--help");
        let via_symlink = run_cmd(&mut cmd);
        via_symlink.assert_code(0);

        via_symlink.assert_stdout_is(&via_argument.stdout);
    }
}

#[test]
fn test_unknown_applet_is_refused() {
    multicall(&["no-such-tool"])
        .assert_code(1)
        .assert_stderr_contains("no-such-tool");
}

#[test]
fn test_version_is_reported() {
    multicall(&["--version"])
        .assert_code(0)
        .assert_stdout_contains(env!("CARGO_PKG_VERSION"));
}
