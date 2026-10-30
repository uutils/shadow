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

#[test]
fn test_chsh_success_prints_nothing() {
    if crate::common::skip_unless_root() {
        return;
    }
    // Upstream chsh prints nothing when the change succeeds.
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");
    std::fs::write(
        etc.join("passwd"),
        "root:x:0:0:root:/root:/bin/bash\ntestuser:x:1000:1000:Old Name,,,:/home/testuser:/bin/sh\n",
    )
    .expect("failed to write passwd");
    std::fs::write(etc.join("shells"), "/bin/sh\n/bin/bash\n").expect("failed to write shells");
    // The new shell must exist under the root.
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).expect("failed to create bin dir");
    std::fs::write(bin.join("bash"), "").expect("failed to write shell");
    std::fs::set_permissions(
        bin.join("bash"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("failed to make shell executable");

    let mut cmd = crate::common::tool("chsh");
    cmd.arg("-R")
        .arg(dir.path())
        .args(["-s", "/bin/bash", "testuser"]);
    let out = crate::common::run_cmd(&mut cmd);
    out.assert_code(0);
    assert_eq!(out.stdout, "");
    assert_eq!(out.stderr, "");
    let passwd = std::fs::read_to_string(etc.join("passwd")).expect("failed to read passwd");
    assert!(
        passwd.contains(":/home/testuser:/bin/bash"),
        "passwd not updated:\n{passwd}"
    );
}
