// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore groupmod gshadow testgrp newgrp oldgrp nogroup

//! Integration tests for the `groupmod` utility.
//!
//! Tests that require root are guarded by `crate::common::skip_unless_root()` and run inside
//! Docker CI containers. Non-root tests exercise clap parsing and error paths
//! that do not need privilege.

use std::ffi::OsString;

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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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

// groupmod(8) -U sets the members in gshadow too; only group was updated.
#[test]
fn test_users_update_gshadow() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "mygrp:x:2000:user1\n",
        "mygrp:!::user1\n",
        "user2:x:1002:1002::/h:/bin/sh\nuser3:x:1003:1003::/h:/bin/sh\n",
    );

    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    assert_eq!(run(&["groupmod", "-U", "user2", "-P", prefix, "mygrp"]), 0);
    assert_eq!(read_group(&dir), "mygrp:x:2000:user2\n");
    assert_eq!(read_gshadow(&dir), "mygrp:!::user2\n");

    assert_eq!(
        run(&["groupmod", "-a", "-U", "user3", "-P", prefix, "mygrp"]),
        0
    );
    assert_eq!(read_group(&dir), "mygrp:x:2000:user2,user3\n");
    assert_eq!(read_gshadow(&dir), "mygrp:!::user2,user3\n");
}

#[test]
fn test_name_collision_fails() {
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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

// Probed on Ubuntu 26.04's groupmod: every name in -U has to be a user, and an
// empty name is not one, wherever in the list it stands. Nothing changes.
#[test]
fn test_users_refuses_a_bad_name_and_changes_nothing() {
    if crate::common::skip_unless_root() {
        return;
    }

    for bad in [
        "ghost",
        "alice,ghost",
        "",
        ",",
        "alice,",
        ",alice",
        "alice,,bob",
        " alice",
    ] {
        for extra in [&[][..], &["-a"][..]] {
            let dir = setup_root(
                "mygrp:x:2000:bob\n",
                "mygrp:!::bob\n",
                "alice:x:1000:1000::/h:/bin/sh\nbob:x:1001:1001::/h:/bin/sh\n",
            );
            let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
            let mut args = vec!["groupmod", "-U", bad, "-P", prefix, "mygrp"];
            args.extend_from_slice(extra);
            assert_eq!(run(&args), 10, "-U {bad:?} {extra:?} should exit 10");
            assert_eq!(
                read_group(&dir),
                "mygrp:x:2000:bob\n",
                "-U {bad:?} {extra:?}"
            );
            assert_eq!(read_gshadow(&dir), "mygrp:!::bob\n", "-U {bad:?} {extra:?}");
        }
    }
}

// A prefixed run manages the files under the prefix: a user of this system
// that is not in them does not count, which root in every container shows.
#[test]
fn test_users_under_a_prefix_looks_only_at_the_prefix() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "mygrp:x:2000:\n",
        "mygrp:!::\n",
        "onlyhere:x:1000:1000::/h:/bin/sh\n",
    );
    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    assert_eq!(run(&["groupmod", "-U", "root", "-P", prefix, "mygrp"]), 10);
    assert_eq!(read_group(&dir), "mygrp:x:2000:\n");
    assert_eq!(
        run(&["groupmod", "-U", "onlyhere", "-P", prefix, "mygrp"]),
        0
    );
    assert_eq!(read_group(&dir), "mygrp:x:2000:onlyhere\n");
}

// The group has to exist first, and -g and -n are refused before the names are
// looked at: the code says which of them was wrong.
#[test]
fn test_users_is_checked_after_the_group_the_gid_and_the_name() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "mygrp:x:2000:\nother:x:2001:\n",
        "mygrp:!::\nother:!::\n",
        "alice:x:1000:1000::/h:/bin/sh\n",
    );
    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    assert_eq!(
        run(&["groupmod", "-U", "ghost", "-P", prefix, "nogroup"]),
        6
    );
    assert_eq!(
        run(&[
            "groupmod", "-U", "ghost", "-g", "2001", "-P", prefix, "mygrp"
        ]),
        4
    );
    assert_eq!(
        run(&[
            "groupmod", "-U", "ghost", "-n", "other", "-P", prefix, "mygrp"
        ]),
        9
    );
}

#[test]
fn test_users_listed_twice_is_written_once() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "mygrp:x:2000:\n",
        "mygrp:!::\n",
        "alice:x:1000:1000::/h:/bin/sh\n",
    );
    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    assert_eq!(
        run(&["groupmod", "-U", "alice,alice", "-P", prefix, "mygrp"]),
        0
    );
    assert_eq!(read_group(&dir), "mygrp:x:2000:alice\n");
    assert_eq!(read_gshadow(&dir), "mygrp:!::alice\n");
}

// Ubuntu 26.04's groupmod takes -a on its own, and with -n, and does nothing
// with it: exit 0, the member list as it was.
#[test]
fn test_append_without_users_is_accepted_and_does_nothing() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "mygrp:x:2000:bob\n",
        "mygrp:!::bob\n",
        "bob:x:1001:1001::/h:/bin/sh\n",
    );
    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    assert_eq!(run(&["groupmod", "-a", "-P", prefix, "mygrp"]), 0);
    assert_eq!(read_group(&dir), "mygrp:x:2000:bob\n");
    assert_eq!(run(&["groupmod", "-a", "-P", prefix, "nogroup"]), 6);
    assert_eq!(
        run(&["groupmod", "-a", "-n", "renamed", "-P", prefix, "mygrp"]),
        0
    );
    assert_eq!(read_group(&dir), "renamed:x:2000:bob\n");
}

// A password that would break the file format is refused with the code of a
// failed write, 10, as Ubuntu 26.04's groupmod does, and nothing is written.
#[test]
fn test_password_with_a_colon_exits_10() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root("mygrp:x:2000:\n", "mygrp:!::\n", "");
    let prefix = dir.path().to_str().expect("temp dir path is valid UTF-8");
    assert_eq!(run(&["groupmod", "-p", "a:b", "-P", prefix, "mygrp"]), 10);
    assert_eq!(read_gshadow(&dir), "mygrp:!::\n");
}
