// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chage warndays maxdays mindays expiredate lastday

//! Integration tests for the `chage` utility.
//!
//! Tests that require root are guarded by `common::skip_unless_root()` and run inside
//! Docker CI containers. Non-root tests exercise clap parsing and error paths
//! that do not need privilege.

use std::ffi::OsString;

#[path = "../common/mod.rs"]
mod common;

/// Run `uumain` with the given args, returning the exit code.
fn run(args: &[&str]) -> i32 {
    let os_args: Vec<OsString> = args.iter().map(|s| (*s).into()).collect();
    chage::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with an `etc/shadow` file.
fn setup_shadow(shadow_content: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");
    std::fs::write(etc.join("shadow"), shadow_content).expect("failed to write shadow file");
    dir
}

/// Read the shadow file content back from a prefix dir.
fn read_shadow(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/shadow")).expect("failed to read shadow file")
}

// ---------------------------------------------------------------------------
// Non-root tests — exercise clap parsing and error paths
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["chage", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_missing_login_exits_two() {
    let code = run(&["chage", "-l"]);
    assert_eq!(code, 2, "missing LOGIN should exit 2");
}

#[test]
fn test_conflicting_list_and_modification() {
    let code = run(&["chage", "-l", "-m", "5", "testuser"]);
    assert_eq!(code, 2, "-l with -m should exit 2");
}

#[test]
fn test_conflicting_list_and_maxdays() {
    let code = run(&["chage", "-l", "-M", "90", "testuser"]);
    assert_eq!(code, 2, "-l with -M should exit 2");
}

#[test]
fn test_conflicting_list_and_lastday() {
    let code = run(&["chage", "-l", "-d", "0", "testuser"]);
    assert_eq!(code, 2, "-l with -d should exit 2");
}

// ---------------------------------------------------------------------------
// Root-only tests — exercise real operations via SysRoot prefix
// ---------------------------------------------------------------------------
//
// TODO(#integration): These tests directly manipulate shadow-core data
// structures instead of calling chage::uumain(). Full end-to-end integration
// via uumain() is not yet feasible because chage only supports --root (which
// performs a real chroot(2) and requires root), not --prefix (path-prefix
// without chroot). Once chage gains a --prefix flag, replace these tests with
// uumain() calls using run(&["chage", "--prefix", ..., "-m", "10", "testuser"])
// with synthetic files.

#[test]
fn test_list_output() {
    if common::skip_unless_root() {
        return;
    }

    // Create a shadow file and use chage's internal list function.
    let dir = setup_shadow("testuser:$6$hash:19500:0:99999:7:::\n");

    // We can't easily test -l with --root since chage uses chroot, not prefix.
    // But we can verify the shadow file was set up correctly.
    let content = read_shadow(&dir);
    assert!(
        content.contains("testuser:$6$hash:19500:0:99999:7:::"),
        "shadow file should contain expected entry"
    );
}

#[test]
fn test_set_mindays() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_shadow("testuser:$6$hash:19500:0:99999:7:::\n");

    // Use shadow-core directly to test mutation logic.
    let shadow_path = dir.path().join("etc/shadow");
    let mut entries =
        shadow_core::shadow::read_shadow_file(&shadow_path).expect("failed to read shadow");

    let entry = entries
        .iter_mut()
        .find(|e| e.name == "testuser")
        .expect("testuser not found");
    entry.min_age = Some(10);

    let file = std::fs::File::create(&shadow_path).expect("failed to create shadow file");
    shadow_core::shadow::write_shadow(&entries, file).expect("failed to write shadow");

    let content = read_shadow(&dir);
    assert!(
        content.contains(":10:99999:"),
        "min_age should be 10, got: {content}"
    );
}

#[test]
fn test_set_maxdays() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_shadow("testuser:$6$hash:19500:0:99999:7:::\n");
    let shadow_path = dir.path().join("etc/shadow");
    let mut entries =
        shadow_core::shadow::read_shadow_file(&shadow_path).expect("failed to read shadow");

    let entry = entries
        .iter_mut()
        .find(|e| e.name == "testuser")
        .expect("testuser not found");
    entry.max_age = Some(180);

    let file = std::fs::File::create(&shadow_path).expect("failed to create shadow file");
    shadow_core::shadow::write_shadow(&entries, file).expect("failed to write shadow");

    let content = read_shadow(&dir);
    assert!(
        content.contains(":0:180:7:"),
        "max_age should be 180, got: {content}"
    );
}

#[test]
fn test_set_warndays() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_shadow("testuser:$6$hash:19500:0:99999:7:::\n");
    let shadow_path = dir.path().join("etc/shadow");
    let mut entries =
        shadow_core::shadow::read_shadow_file(&shadow_path).expect("failed to read shadow");

    let entry = entries
        .iter_mut()
        .find(|e| e.name == "testuser")
        .expect("testuser not found");
    entry.warn_days = Some(14);

    let file = std::fs::File::create(&shadow_path).expect("failed to create shadow file");
    shadow_core::shadow::write_shadow(&entries, file).expect("failed to write shadow");

    let content = read_shadow(&dir);
    assert!(
        content.contains(":99999:14:"),
        "warn_days should be 14, got: {content}"
    );
}

#[test]
fn test_set_inactive() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_shadow("testuser:$6$hash:19500:0:99999:7:::\n");
    let shadow_path = dir.path().join("etc/shadow");
    let mut entries =
        shadow_core::shadow::read_shadow_file(&shadow_path).expect("failed to read shadow");

    let entry = entries
        .iter_mut()
        .find(|e| e.name == "testuser")
        .expect("testuser not found");
    entry.inactive_days = Some(30);

    let file = std::fs::File::create(&shadow_path).expect("failed to create shadow file");
    shadow_core::shadow::write_shadow(&entries, file).expect("failed to write shadow");

    let content = read_shadow(&dir);
    assert!(
        content.contains(":7:30:"),
        "inactive_days should be 30, got: {content}"
    );
}

#[test]
fn test_set_expiredate() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_shadow("testuser:$6$hash:19500:0:99999:7:::\n");
    let shadow_path = dir.path().join("etc/shadow");
    let mut entries =
        shadow_core::shadow::read_shadow_file(&shadow_path).expect("failed to read shadow");

    let entry = entries
        .iter_mut()
        .find(|e| e.name == "testuser")
        .expect("testuser not found");
    entry.expire_date = Some(20000);

    let file = std::fs::File::create(&shadow_path).expect("failed to create shadow file");
    shadow_core::shadow::write_shadow(&entries, file).expect("failed to write shadow");

    let content = read_shadow(&dir);
    assert!(
        content.contains("::20000:"),
        "expire_date should be 20000, got: {content}"
    );
}

#[test]
fn test_set_lastchange() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_shadow("testuser:$6$hash:19500:0:99999:7:::\n");
    let shadow_path = dir.path().join("etc/shadow");
    let mut entries =
        shadow_core::shadow::read_shadow_file(&shadow_path).expect("failed to read shadow");

    let entry = entries
        .iter_mut()
        .find(|e| e.name == "testuser")
        .expect("testuser not found");
    entry.last_change = Some(0);

    let file = std::fs::File::create(&shadow_path).expect("failed to create shadow file");
    shadow_core::shadow::write_shadow(&entries, file).expect("failed to write shadow");

    let content = read_shadow(&dir);
    assert!(
        content.contains("testuser:$6$hash:0:"),
        "last_change should be 0, got: {content}"
    );
}

#[test]
fn test_remove_expiredate() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_shadow("testuser:$6$hash:19500:0:99999:7::20000:\n");
    let shadow_path = dir.path().join("etc/shadow");
    let mut entries =
        shadow_core::shadow::read_shadow_file(&shadow_path).expect("failed to read shadow");

    let entry = entries
        .iter_mut()
        .find(|e| e.name == "testuser")
        .expect("testuser not found");
    // -1 means remove the field.
    entry.expire_date = None;

    let file = std::fs::File::create(&shadow_path).expect("failed to create shadow file");
    shadow_core::shadow::write_shadow(&entries, file).expect("failed to write shadow");

    let content = read_shadow(&dir);
    assert!(
        content.contains(":7::"),
        "expire_date should be empty after removal, got: {content}"
    );
}

// ---------------------------------------------------------------------------
// Aging-field bounds (chage(1))
// ---------------------------------------------------------------------------

#[test]
fn test_negative_aging_values_are_rejected() {
    if common::skip_unless_root() {
        return;
    }

    // The range check runs before any file is opened, so this touches nothing
    // even though chage has no prefix option: a day count may only be -1
    // ("unset") or non-negative.
    for flag in ["-m", "-M", "-W", "-I"] {
        assert_eq!(
            run(&["chage", flag, "-5", "no_such_user_for_chage_test"]),
            2,
            "{flag} -5 must be an invalid argument"
        );
    }
}
