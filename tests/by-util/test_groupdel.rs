// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore groupdel gshadow testgrp testuser nogrp

//! Integration tests for the `groupdel` utility.
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
    groupdel::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with `etc/group`, `etc/gshadow`, and `etc/passwd`.
fn setup_root(
    group_content: &str,
    gshadow_content: &str,
    passwd_content: &str,
) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");
    std::fs::write(etc.join("group"), group_content).expect("failed to write group file");
    std::fs::write(etc.join("gshadow"), gshadow_content).expect("failed to write gshadow file");
    std::fs::write(etc.join("passwd"), passwd_content).expect("failed to write passwd file");
    dir
}

/// Read the group file content back from a prefix dir.
fn read_group(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/group")).expect("failed to read group file")
}

/// Read the gshadow file content back from a prefix dir.
fn read_gshadow(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/gshadow")).expect("failed to read gshadow file")
}

// ---------------------------------------------------------------------------
// Non-root tests — exercise clap parsing and error paths
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["groupdel", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_error() {
    let code = run(&["groupdel", "--nonexistent-flag"]);
    assert_eq!(code, 2, "unknown flag should exit 2");
}

#[test]
fn test_missing_group_name_exits_error() {
    let code = run(&["groupdel"]);
    assert_eq!(code, 2, "missing group name should exit 2");
}

// ---------------------------------------------------------------------------
// Root-only tests — exercise real operations via -P (prefix) flag
// ---------------------------------------------------------------------------

#[test]
fn test_delete_group_basic() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "root:x:0:\ntestgrp:x:1000:\nother:x:1001:\n",
        "root:!::\ntestgrp:!::\nother:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupdel", "-P", prefix, "testgrp"]);
    assert_eq!(code, 0, "deleting an existing group should exit 0");

    let content = read_group(&dir);
    assert!(
        !content.contains("testgrp"),
        "testgrp should be removed from group file"
    );
}

#[test]
fn test_delete_nonexistent_group_fails() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "root:x:0:\nother:x:1001:\n",
        "root:!::\nother:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupdel", "-P", prefix, "nogrp"]);
    assert_eq!(
        code, 6,
        "deleting a nonexistent group should exit 6 (GROUP_NOT_FOUND)"
    );
}

#[test]
fn test_delete_group_preserves_others() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "root:x:0:\nalpha:x:1000:\nbeta:x:1001:\ngamma:x:1002:\n",
        "root:!::\nalpha:!::\nbeta:!::\ngamma:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupdel", "-P", prefix, "beta"]);
    assert_eq!(code, 0);

    let content = read_group(&dir);
    assert!(!content.contains("beta"), "beta should be removed");
    assert!(
        content.contains("root:x:0:"),
        "root group should be preserved"
    );
    assert!(
        content.contains("alpha:x:1000:"),
        "alpha group should be preserved"
    );
    assert!(
        content.contains("gamma:x:1002:"),
        "gamma group should be preserved"
    );
}

#[test]
fn test_delete_primary_group_fails() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "testgrp:x:1000:\n",
        "testgrp:!::\n",
        "testuser:x:1000:1000:Test User:/home/testuser:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupdel", "-P", prefix, "testgrp"]);
    assert_eq!(
        code, 8,
        "deleting a primary group should exit 8 (PRIMARY_GROUP)"
    );

    // Group should still exist since deletion was refused.
    let content = read_group(&dir);
    assert!(
        content.contains("testgrp:x:1000:"),
        "testgrp should still exist after failed deletion"
    );
}

#[test]
fn test_delete_group_removes_gshadow() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "root:x:0:\ntestgrp:x:1000:\nother:x:1001:\n",
        "root:!::\ntestgrp:!::\nother:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupdel", "-P", prefix, "testgrp"]);
    assert_eq!(code, 0);

    let gs_content = read_gshadow(&dir);
    assert!(
        !gs_content.contains("testgrp"),
        "testgrp should be removed from gshadow file"
    );
    assert!(
        gs_content.contains("root:"),
        "root gshadow entry should be preserved"
    );
    assert!(
        gs_content.contains("other:"),
        "other gshadow entry should be preserved"
    );
}

#[test]
fn test_delete_with_root_flag() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "root:x:0:\ntarget:x:2000:\n",
        "root:!::\ntarget:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let root_path = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupdel", "-R", root_path, "target"]);
    assert_eq!(code, 0, "-R flag should work the same as -P");

    let content = read_group(&dir);
    assert!(
        !content.contains("target"),
        "target should be removed using -R flag"
    );
}

#[test]
fn test_delete_group_with_members() {
    if common::skip_unless_root() {
        return;
    }

    // Group has supplementary members but is not anyone's primary group.
    let dir = setup_root(
        "root:x:0:\ndevteam:x:1500:alice,bob\n",
        "root:!::\ndevteam:!::alice,bob\n",
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\nbob:x:1001:1001:Bob:/home/bob:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupdel", "-P", prefix, "devteam"]);
    assert_eq!(
        code, 0,
        "deleting a group with supplementary members should succeed"
    );

    let content = read_group(&dir);
    assert!(!content.contains("devteam"), "devteam should be removed");
}

#[test]
fn test_force_and_sole_gshadow_entry() {
    if common::skip_unless_root() {
        return;
    }

    // groupdel(8) -f: succeed even when the group does not exist.
    let dir = setup_root(
        "only:x:1000:\n",
        "only:!::\n",
        "root:x:0:0:root:/root:/bin/sh\n",
    );
    let prefix = dir.path().to_str().unwrap();
    assert_eq!(run(&["groupdel", "-P", prefix, "-f", "ghost"]), 0);

    // The sole gshadow entry used to be left behind: the write was skipped
    // whenever the result was empty.
    assert_eq!(run(&["groupdel", "-P", prefix, "only"]), 0);
    let gshadow = dir.path().join("etc/gshadow");
    assert!(
        !gshadow.exists() || !std::fs::read_to_string(&gshadow).unwrap().contains("only:"),
        "the deleted group must not remain in gshadow"
    );
}
