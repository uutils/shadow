// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore groupmod gshadow testgrp newgrp oldgrp nogroup

//! Integration tests for the `groupmod` utility.
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
    groupmod::uumain(os_args.into_iter())
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

/// Read the passwd file content back from a prefix dir.
fn read_passwd(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/passwd")).expect("failed to read passwd file")
}

// ---------------------------------------------------------------------------
// Non-root tests — exercise clap parsing and error paths
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["groupmod", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_error() {
    let code = run(&["groupmod", "--nonexistent-flag"]);
    assert_eq!(code, 2, "unknown flag should exit 2");
}

#[test]
fn test_missing_group_name_exits_error() {
    let code = run(&["groupmod"]);
    assert_eq!(code, 2, "missing group name should exit 2");
}

// ---------------------------------------------------------------------------
// Root-only tests — exercise real operations via -P (prefix) flag
// ---------------------------------------------------------------------------

#[test]
fn test_change_gid() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "testgrp:x:1000:\n",
        "testgrp:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupmod", "-g", "9999", "-P", prefix, "testgrp"]);
    assert_eq!(code, 0, "changing GID should exit 0");

    let content = read_group(&dir);
    assert!(
        content.contains("testgrp:x:9999:"),
        "GID should be changed to 9999, got: {content}"
    );
}

// groupmod(8): changing a group's GID re-homes the users whose primary group
// it is, so they are not left pointing at a GID that no longer names a group.
#[test]
fn test_change_gid_updates_primary_group_members_in_passwd() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "devs:x:1000:\n",
        "devs:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n\
         alice:x:1500:1000:Alice:/home/alice:/bin/bash\n\
         bob:x:1600:1000:Bob:/home/bob:/bin/bash\n\
         carol:x:1700:1700:Carol:/home/carol:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupmod", "-g", "2000", "-P", prefix, "devs"]);
    assert_eq!(code, 0, "changing GID should exit 0");

    assert!(read_group(&dir).contains("devs:x:2000:"));
    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("alice:x:1500:2000:") && passwd.contains("bob:x:1600:2000:"),
        "primary-group members should follow the GID, got: {passwd}"
    );
    assert!(
        passwd.contains("carol:x:1700:1700:"),
        "unrelated users must be untouched, got: {passwd}"
    );
}

#[test]
fn test_gid_minus_one_sentinel_is_rejected() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "g:x:1000:\n",
        "g:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );
    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupmod", "-g", "4294967295", "-P", prefix, "g"]);
    assert_eq!(code, 3, "(gid_t)-1 must be a bad argument");
    assert!(read_group(&dir).contains("g:x:1000:"), "group unchanged");
}

#[test]
fn test_change_name() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "oldgrp:x:1000:\n",
        "oldgrp:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupmod", "-n", "newname", "-P", prefix, "oldgrp"]);
    assert_eq!(code, 0, "renaming group should exit 0");

    let content = read_group(&dir);
    assert!(
        content.contains("newname:x:1000:"),
        "group should be renamed to newname, got: {content}"
    );
    assert!(
        !content.contains("oldgrp"),
        "old group name should not remain"
    );
}

#[test]
fn test_non_unique_gid() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "root:x:0:\ntestgrp:x:1000:\n",
        "root:!::\ntestgrp:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");

    // Without -o, setting GID to 0 (already used by root) should fail.
    let code = run(&["groupmod", "-g", "0", "-P", prefix, "testgrp"]);
    assert_eq!(
        code, 4,
        "duplicate GID without -o should exit 4 (GID_IN_USE)"
    );

    // With -o, it should succeed.
    let code = run(&["groupmod", "-o", "-g", "0", "-P", prefix, "testgrp"]);
    assert_eq!(code, 0, "duplicate GID with -o should exit 0");

    let content = read_group(&dir);
    assert!(
        content.contains("testgrp:x:0:"),
        "GID should be changed to 0 with -o, got: {content}"
    );
}

#[test]
fn test_nonexistent_group_fails() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "root:x:0:\n",
        "root:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupmod", "-g", "5000", "-P", prefix, "nogroup"]);
    assert_eq!(
        code, 6,
        "modifying a nonexistent group should exit 6 (GROUP_NOT_FOUND)"
    );
}

#[test]
fn test_rename_preserves_members() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "devteam:x:1500:alice,bob\n",
        "devteam:!::alice,bob\n",
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\nbob:x:1001:1001:Bob:/home/bob:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupmod", "-n", "engineering", "-P", prefix, "devteam"]);
    assert_eq!(code, 0, "renaming group with members should exit 0");

    let content = read_group(&dir);
    assert!(
        content.contains("engineering:x:1500:alice,bob"),
        "members should be preserved after rename, got: {content}"
    );
    assert!(
        !content.contains("devteam"),
        "old group name should not remain"
    );
}

#[test]
fn test_rename_updates_gshadow() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "mygrp:x:2000:user1\n",
        "mygrp:!::user1\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupmod", "-n", "renamed", "-P", prefix, "mygrp"]);
    assert_eq!(code, 0, "renaming should update gshadow");

    let gs_content = read_gshadow(&dir);
    assert!(
        gs_content.contains("renamed:"),
        "gshadow should reflect the new name, got: {gs_content}"
    );
    assert!(
        !gs_content.contains("mygrp"),
        "old name should not remain in gshadow"
    );
}

#[test]
fn test_name_collision_fails() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "grp1:x:1000:\ngrp2:x:2000:\n",
        "grp1:!::\ngrp2:!::\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&["groupmod", "-n", "grp2", "-P", prefix, "grp1"]);
    assert_eq!(
        code, 9,
        "renaming to an existing group name should exit 9 (NAME_IN_USE)"
    );
}

#[test]
fn test_change_gid_and_name_together() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "oldgrp:x:1000:member1\n",
        "oldgrp:!::member1\n",
        "root:x:0:0:root:/root:/bin/bash\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    let code = run(&[
        "groupmod", "-g", "7777", "-n", "freshgrp", "-P", prefix, "oldgrp",
    ]);
    assert_eq!(code, 0, "changing both GID and name should exit 0");

    let content = read_group(&dir);
    assert!(
        content.contains("freshgrp:x:7777:member1"),
        "both GID and name should be updated, got: {content}"
    );
    assert!(
        !content.contains("oldgrp"),
        "old group name should not remain"
    );
}
