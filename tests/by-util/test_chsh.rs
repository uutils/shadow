// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Integration tests for the `chsh` utility.
//!
//! Root-only tests exercise real operations via synthetic files.
//! Non-root tests exercise clap parsing and error paths.

use std::ffi::OsString;

/// Run `uumain` with the given args, returning the exit code.
fn run(args: &[&str]) -> i32 {
    let os_args: Vec<OsString> = args.iter().map(|s| (*s).into()).collect();
    chsh::uumain(os_args.into_iter())
}

// ---------------------------------------------------------------------------
// Non-root tests
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["chsh", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_one() {
    let code = run(&["chsh", "--bogus"]);
    assert_eq!(code, 1, "unknown flag should exit 1");
}

/// Without `-s`, chsh prompts for the new shell, so it must not be given a
/// target it can never change. An unknown login fails before any prompt: for a
/// non-root caller because it is not their own account, for root because the
/// account has no record to show a current value from.
#[test]
fn test_unknown_user_exits_error_without_prompting() {
    let code = run(&["chsh", "no-such-user-9f3a1c"]);
    assert_eq!(code, 1, "unknown login should exit 1");
}

// ---------------------------------------------------------------------------
// Root-only tests
// ---------------------------------------------------------------------------

#[test]
fn test_list_shells() {
    if crate::common::skip_unless_root() {
        return;
    }
    // -l should list shells and exit 0 (assuming /etc/shells exists on the system)
    let code = run(&["chsh", "-l"]);
    // Exit 0 even if /etc/shells is empty — the tool prints a warning but succeeds
    assert_eq!(code, 0, "--list-shells should exit 0");
}

#[test]
fn test_invalid_shell_path() {
    if crate::common::skip_unless_root() {
        return;
    }
    // Relative path should be rejected
    let code = run(&["chsh", "-s", "bin/bash"]);
    assert_eq!(code, 1, "relative shell path should exit 1");
}
