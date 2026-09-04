// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore groupadd gshadow nscd sysroot

//! Integration tests for the `groupadd` utility.
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
    groupadd::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with `etc/group`, `etc/gshadow`, and
/// `etc/login.defs`.
fn setup_prefix(group_content: &str, login_defs_content: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");
    std::fs::write(etc.join("group"), group_content).expect("failed to write group file");
    std::fs::write(etc.join("gshadow"), "").expect("failed to write gshadow file");
    std::fs::write(etc.join("login.defs"), login_defs_content)
        .expect("failed to write login.defs file");
    dir
}

/// Read the group file content back from a prefix dir.
fn read_group(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/group")).expect("failed to read group file")
}

/// Run `uumain` with a `--prefix` dir prepended to the args.
fn run_with_prefix(dir: &tempfile::TempDir, extra_args: &[&str]) -> i32 {
    let prefix_str = dir.path().to_str().expect("non-UTF-8 temp path");
    let mut args = vec!["groupadd", "-P", prefix_str];
    args.extend_from_slice(extra_args);
    run(&args)
}

// ---------------------------------------------------------------------------
// Non-root tests -- exercise clap parsing and error paths
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["groupadd", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_error() {
    let code = run(&["groupadd", "--bogus", "somegroup"]);
    assert_eq!(code, 2, "unknown flag should exit 2");
}

#[test]
fn test_missing_group_name_exits_error() {
    let code = run(&["groupadd"]);
    assert_eq!(code, 2, "missing GROUP should exit 2");
}

// ---------------------------------------------------------------------------
// Root-only tests -- exercise real operations via --prefix
// ---------------------------------------------------------------------------

#[test]
fn test_create_group_basic() {
    if common::skip_unless_root() {
        return;
    }

    let login_defs = "GID_MIN 1000\nGID_MAX 60000\n";
    let dir = setup_prefix("root:x:0:\n", login_defs);

    let code = run_with_prefix(&dir, &["newgroup"]);
    assert_eq!(code, 0, "creating a basic group should succeed");

    let content = read_group(&dir);
    assert!(
        content.contains("newgroup:x:"),
        "newgroup should appear in /etc/group, got: {content}"
    );
    // The original root entry should be preserved.
    assert!(
        content.contains("root:x:0:"),
        "root entry should be preserved, got: {content}"
    );
}

#[test]
fn test_create_group_with_gid() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix("root:x:0:\n", "");

    let code = run_with_prefix(&dir, &["-g", "5000", "devgrp"]);
    assert_eq!(code, 0, "creating group with explicit GID should succeed");

    let content = read_group(&dir);
    assert!(
        content.contains("devgrp:x:5000:"),
        "devgrp should have GID 5000, got: {content}"
    );
}

#[test]
fn test_create_group_system() {
    if common::skip_unless_root() {
        return;
    }

    let login_defs = "SYS_GID_MIN 100\nSYS_GID_MAX 999\nGID_MIN 1000\nGID_MAX 60000\n";
    let dir = setup_prefix("root:x:0:\n", login_defs);

    let code = run_with_prefix(&dir, &["-r", "sysgrp"]);
    assert_eq!(code, 0, "creating system group should succeed");

    let content = read_group(&dir);
    assert!(
        content.contains("sysgrp:x:"),
        "sysgrp should appear in /etc/group, got: {content}"
    );

    // Extract the GID and verify it is in the system range (< 1000).
    let gid_str = content
        .lines()
        .find(|l| l.starts_with("sysgrp:"))
        .expect("sysgrp line should exist")
        .split(':')
        .nth(2)
        .expect("GID field should exist");
    let gid: u32 = gid_str.parse().expect("GID should be numeric");
    assert!(gid < 1000, "system group GID should be < 1000, got: {gid}");
}

#[test]
fn test_create_group_non_unique() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix("root:x:0:\n", "");

    // -o allows non-unique GID; -g 0 duplicates root's GID.
    let code = run_with_prefix(&dir, &["-o", "-g", "0", "dupgrp"]);
    assert_eq!(code, 0, "creating group with non-unique GID should succeed");

    let content = read_group(&dir);
    assert!(
        content.contains("dupgrp:x:0:"),
        "dupgrp should have GID 0, got: {content}"
    );
}

#[test]
fn test_duplicate_group_fails() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix("mygrp:x:1000:\n", "");

    let code = run_with_prefix(&dir, &["mygrp"]);
    assert_eq!(
        code, 9,
        "adding existing group should exit 9 (GROUP_IN_USE)"
    );
}

#[test]
fn test_duplicate_gid_fails() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix("existing:x:5000:\n", "");

    // Without -o, a duplicate GID should fail.
    let code = run_with_prefix(&dir, &["-g", "5000", "newgrp"]);
    assert_eq!(code, 4, "duplicate GID should exit 4 (GID_IN_USE)");
}

#[test]
fn test_force_on_existing_succeeds() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix("mygrp:x:1000:\n", "");

    // -f should exit successfully even if the group already exists.
    let code = run_with_prefix(&dir, &["-f", "mygrp"]);
    assert_eq!(code, 0, "-f on existing group should exit 0");
}

#[test]
fn test_other_entries_preserved() {
    if common::skip_unless_root() {
        return;
    }

    let login_defs = "GID_MIN 1000\nGID_MAX 60000\n";
    let dir = setup_prefix("root:x:0:\nadm:x:4:syslog\nstaff:x:50:\n", login_defs);

    let code = run_with_prefix(&dir, &["freshgrp"]);
    assert_eq!(code, 0);

    let content = read_group(&dir);
    assert!(
        content.contains("root:x:0:"),
        "root should be preserved, got: {content}"
    );
    assert!(
        content.contains("adm:x:4:syslog"),
        "adm should be preserved, got: {content}"
    );
    assert!(
        content.contains("staff:x:50:"),
        "staff should be preserved, got: {content}"
    );
    assert!(
        content.contains("freshgrp:x:"),
        "freshgrp should be added, got: {content}"
    );
}

#[test]
fn test_key_override_wins_over_login_defs() {
    if common::skip_unless_root() {
        return;
    }
    // login.defs says 5000-5999; -K must take precedence for this run.
    let dir = setup_prefix("root:x:0:\n", "GID_MIN 5000\nGID_MAX 5999\n");
    let code = run_with_prefix(
        &dir,
        &["-K", "GID_MIN=9100", "-K", "GID_MAX=9100", "keygrp"],
    );
    assert_eq!(code, 0, "groupadd -K should exit 0");
    assert!(
        read_group(&dir).contains("keygrp:x:9100:"),
        "GID should come from -K, got: {}",
        read_group(&dir)
    );
}

#[test]
fn test_key_sys_range_override_for_system_group() {
    if common::skip_unless_root() {
        return;
    }
    let dir = setup_prefix("root:x:0:\n", "SYS_GID_MIN 100\nSYS_GID_MAX 999\n");
    let code = run_with_prefix(
        &dir,
        &[
            "-r",
            "-K",
            "SYS_GID_MIN=250",
            "-K",
            "SYS_GID_MAX=250",
            "syskeygrp",
        ],
    );
    assert_eq!(code, 0, "groupadd -r -K should exit 0");
    assert!(
        read_group(&dir).contains("syskeygrp:x:250:"),
        "got: {}",
        read_group(&dir)
    );
}

#[test]
fn test_key_missing_equals_exits_bad_argument() {
    if common::skip_unless_root() {
        return;
    }
    let dir = setup_prefix("root:x:0:\n", "");
    let code = run_with_prefix(&dir, &["-K", "GID_MIN", "badkeygrp"]);
    assert_eq!(code, 3, "malformed KEY=VALUE should exit 3 (bad argument)");
    assert!(
        !read_group(&dir).contains("badkeygrp"),
        "nothing must be written"
    );
}

#[test]
fn test_users_flag_sets_members() {
    if common::skip_unless_root() {
        return;
    }

    // groupadd(8) -U: the new group starts with these members.
    let dir = setup_prefix("root:x:0:\n", "GID_MIN 1000\nGID_MAX 60000\n");
    let prefix = dir.path().to_str().unwrap();
    assert_eq!(
        run(&["groupadd", "-P", prefix, "-U", "alice,bob", "devs"]),
        0
    );
    let group = read_group(&dir);
    assert!(
        group.contains("devs:x:") && group.contains(":alice,bob"),
        "members should be set, got: {group}"
    );
}
