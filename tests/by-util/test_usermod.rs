// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore usermod gecos gshadow

//! Integration tests for the `usermod` utility.
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
    usermod::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with `etc/passwd`, `etc/shadow`, `etc/group`,
/// `etc/gshadow`, and `etc/login.defs`.
fn setup_prefix(
    passwd_content: &str,
    shadow_content: &str,
    group_content: &str,
) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");
    std::fs::write(etc.join("passwd"), passwd_content).expect("failed to write passwd file");
    std::fs::write(etc.join("shadow"), shadow_content).expect("failed to write shadow file");
    std::fs::write(etc.join("group"), group_content).expect("failed to write group file");
    std::fs::write(etc.join("gshadow"), "").expect("failed to write gshadow file");
    std::fs::write(etc.join("login.defs"), "").expect("failed to write login.defs file");
    dir
}

/// Read the passwd file content back from a prefix dir.
fn read_passwd(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/passwd")).expect("failed to read passwd file")
}

/// Read the shadow file content back from a prefix dir.
fn read_shadow(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/shadow")).expect("failed to read shadow file")
}

/// Read the group file content back from a prefix dir.
fn read_group(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/group")).expect("failed to read group file")
}

/// Run `uumain` with a `--prefix` dir prepended to the args.
fn run_with_prefix(dir: &tempfile::TempDir, extra_args: &[&str]) -> i32 {
    let prefix_str = dir.path().to_str().expect("non-UTF-8 temp path");
    let mut args = vec!["usermod", "-P", prefix_str];
    args.extend_from_slice(extra_args);
    run(&args)
}

// ---------------------------------------------------------------------------
// Non-root tests -- exercise clap parsing and error paths
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["usermod", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_error() {
    let code = run(&["usermod", "--bogus", "someuser"]);
    assert_eq!(code, 2, "unknown flag should exit 2");
}

#[test]
fn test_missing_login_exits_error() {
    let code = run(&["usermod"]);
    assert_eq!(code, 2, "missing LOGIN should exit 2");
}

#[test]
fn test_lock_unlock_conflict() {
    // -L and -U conflict; clap reports ArgumentConflict which maps to exit 2.
    let code = run(&["usermod", "-L", "-U", "someuser"]);
    assert_eq!(code, 2, "conflicting -L -U flags should exit 2");
}

// ---------------------------------------------------------------------------
// Root-only tests -- exercise real operations via --prefix
// ---------------------------------------------------------------------------

#[test]
fn test_change_shell() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test User:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let code = run_with_prefix(&dir, &["-s", "/bin/zsh", "testuser"]);
    assert_eq!(code, 0, "changing shell should succeed");

    let content = read_passwd(&dir);
    assert!(
        content.contains(":/bin/zsh"),
        "shell should be /bin/zsh, got: {content}"
    );
    // Verify the rest of the entry is intact.
    assert!(
        content.contains("testuser:x:1000:1000:Test User:/home/testuser:/bin/zsh"),
        "full passwd entry should be correct, got: {content}"
    );
}

#[test]
fn test_change_comment() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Old Name:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let code = run_with_prefix(&dir, &["-c", "New Name", "testuser"]);
    assert_eq!(code, 0, "changing GECOS comment should succeed");

    let content = read_passwd(&dir);
    assert!(
        content.contains(":New Name:"),
        "GECOS should be 'New Name', got: {content}"
    );
}

// A value that would add a field or a record is refused with exit 3 before
// the file is locked, so the entry is left exactly as it was.
#[test]
fn test_fields_with_colon_or_newline_are_rejected_before_write() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Old Name:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );
    let original = read_passwd(&dir);

    assert_eq!(run_with_prefix(&dir, &["-c", "a:b", "testuser"]), 3);
    assert_eq!(run_with_prefix(&dir, &["-s", "/bin/sh\nx", "testuser"]), 3);
    assert_eq!(run_with_prefix(&dir, &["-d", "/home/x\r", "testuser"]), 3);
    assert_eq!(run_with_prefix(&dir, &["-p", "$6$a:b", "testuser"]), 3);

    assert_eq!(read_passwd(&dir), original);
    assert!(read_shadow(&dir).contains("testuser:$6$hash:"));
}

#[test]
fn test_change_home() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let code = run_with_prefix(&dir, &["-d", "/new/home", "testuser"]);
    assert_eq!(code, 0, "changing home directory should succeed");

    let content = read_passwd(&dir);
    assert!(
        content.contains(":/new/home:"),
        "home should be /new/home, got: {content}"
    );
}

#[test]
fn test_change_uid() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let code = run_with_prefix(&dir, &["-u", "9999", "testuser"]);
    assert_eq!(code, 0, "changing UID should succeed");

    let content = read_passwd(&dir);
    assert!(
        content.contains("testuser:x:9999:"),
        "UID should be 9999, got: {content}"
    );
}

#[test]
fn test_add_to_groups() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\ngroup1:x:2001:\ngroup2:x:2002:\n",
    );

    let code = run_with_prefix(&dir, &["-G", "group1,group2", "testuser"]);
    assert_eq!(code, 0, "adding to supplementary groups should succeed");

    let content = read_group(&dir);
    assert!(
        content.contains("group1:x:2001:testuser"),
        "testuser should be in group1, got: {content}"
    );
    assert!(
        content.contains("group2:x:2002:testuser"),
        "testuser should be in group2, got: {content}"
    );
}

#[test]
fn test_lock_user() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let code = run_with_prefix(&dir, &["-L", "testuser"]);
    assert_eq!(code, 0, "locking user should succeed");

    let content = read_shadow(&dir);
    assert!(
        content.contains("testuser:!$6$hash:"),
        "after lock, expected '!' prefix on password, got: {content}"
    );
}

#[test]
fn test_unlock_user() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:!$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let code = run_with_prefix(&dir, &["-U", "testuser"]);
    assert_eq!(code, 0, "unlocking user should succeed");

    let content = read_shadow(&dir);
    assert!(
        content.contains("testuser:$6$hash:"),
        "after unlock, expected no '!' prefix, got: {content}"
    );
}

#[test]
fn test_nonexistent_user_fails() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let code = run_with_prefix(&dir, &["-s", "/bin/zsh", "nosuchuser"]);
    assert_eq!(code, 6, "modifying nonexistent user should exit 6");
}

#[test]
fn test_multiple_modifications_combined() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Old Name:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let code = run_with_prefix(
        &dir,
        &[
            "-c",
            "New Name",
            "-s",
            "/bin/zsh",
            "-d",
            "/new/home",
            "testuser",
        ],
    );
    assert_eq!(code, 0, "combined modifications should succeed");

    let content = read_passwd(&dir);
    assert!(
        content.contains(":New Name:"),
        "GECOS should be updated, got: {content}"
    );
    assert!(
        content.contains(":/bin/zsh"),
        "shell should be updated, got: {content}"
    );
    assert!(
        content.contains(":/new/home:"),
        "home should be updated, got: {content}"
    );
}

#[test]
fn test_other_users_unchanged() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n\
         bob:x:1002:1002:Bob:/home/bob:/bin/bash\n\
         charlie:x:1003:1003:Charlie:/home/charlie:/bin/bash\n",
        "alice:$6$ahash:19500:0:99999:7:::\n\
         bob:$6$bhash:19500:0:99999:7:::\n\
         charlie:$6$chash:19500:0:99999:7:::\n",
        "alice:x:1001:\nbob:x:1002:\ncharlie:x:1003:\n",
    );

    let code = run_with_prefix(&dir, &["-c", "Robert", "bob"]);
    assert_eq!(code, 0);

    let content = read_passwd(&dir);
    assert!(
        content.contains("alice:x:1001:1001:Alice:/home/alice:/bin/bash"),
        "alice should be unchanged, got: {content}"
    );
    assert!(
        content.contains("charlie:x:1003:1003:Charlie:/home/charlie:/bin/bash"),
        "charlie should be unchanged, got: {content}"
    );
    assert!(
        content.contains(":Robert:"),
        "bob's GECOS should be updated, got: {content}"
    );
}

#[test]
fn test_uid_collision_fails() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n\
         bob:x:1002:1002:Bob:/home/bob:/bin/bash\n",
        "alice:$6$ahash:19500:0:99999:7:::\n\
         bob:$6$bhash:19500:0:99999:7:::\n",
        "alice:x:1001:\nbob:x:1002:\n",
    );

    // Try to set bob's UID to alice's UID -- should fail.
    let code = run_with_prefix(&dir, &["-u", "1001", "bob"]);
    assert_eq!(code, 4, "UID collision should exit 4");
}

#[test]
fn test_set_password() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:*:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let hash = "$6$rounds=5000$saltsalt$hashvalue";
    let code = run_with_prefix(&dir, &["-p", hash, "testuser"]);
    assert_eq!(code, 0, "setting password should succeed");

    let content = read_shadow(&dir);
    assert!(
        content.contains(&format!("testuser:{hash}:")),
        "shadow should contain the new hash, got: {content}"
    );
    // last_change should be updated (not 19500 anymore)
    assert!(
        !content.contains(":19500:"),
        "last_change should be updated from 19500, got: {content}"
    );
}

#[test]
fn test_set_password_long_flag() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:!:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let hash = "$6$newsalt$newhash";
    let code = run_with_prefix(&dir, &["--password", hash, "testuser"]);
    assert_eq!(code, 0, "--password long flag should succeed");

    let content = read_shadow(&dir);
    assert!(
        content.contains(&format!("testuser:{hash}:")),
        "shadow should contain the new hash, got: {content}"
    );
}

#[test]
fn test_set_password_preserves_other_fields() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$old:19500:1:90:14:30:20000:\n",
        "testuser:x:1000:\n",
    );

    let hash = "$6$new$newhash";
    let code = run_with_prefix(&dir, &["-p", hash, "testuser"]);
    assert_eq!(code, 0);

    let content = read_shadow(&dir);
    // min_age=1, max_age=90, warn=14, inactive=30, expire=20000 should be preserved
    let line = content
        .lines()
        .find(|l| l.starts_with("testuser:"))
        .unwrap();
    let fields: Vec<&str> = line.split(':').collect();
    assert_eq!(fields[0], "testuser");
    assert_eq!(fields[1], hash);
    // fields[2] = last_change (updated, not 19500)
    assert_ne!(fields[2], "19500", "last_change should be updated");
    assert_eq!(fields[3], "1", "min_age should be preserved");
    assert_eq!(fields[4], "90", "max_age should be preserved");
    assert_eq!(fields[5], "14", "warn_days should be preserved");
    assert_eq!(fields[6], "30", "inactive_days should be preserved");
    assert_eq!(fields[7], "20000", "expire_date should be preserved");
    assert_eq!(fields.len(), 9, "shadow entry should have exactly 9 fields");
    assert_eq!(fields[8], "", "reserved field should be empty");
}

// ---------------------------------------------------------------------------
// usermod(8): rename collisions and date formats
// ---------------------------------------------------------------------------

#[test]
fn test_rename_to_existing_login_is_rejected() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "root:x:0:0:root:/root:/bin/bash\n\
         alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        "root:*:19500:0:99999:7:::\nalice:$6$h:19500:0:99999:7:::\n",
        "alice:x:1000:\n",
    );

    let code = run_with_prefix(&dir, &["-l", "root", "alice"]);
    assert_eq!(code, 9, "renaming onto an existing login must exit 9");

    let passwd = read_passwd(&dir);
    assert_eq!(
        passwd.matches("root:x:0:").count(),
        1,
        "there must still be exactly one root entry, got: {passwd}"
    );
    assert!(passwd.contains("alice:x:1000:"), "alice must be unchanged");
}

#[test]
fn test_expiredate_accepts_iso_date() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        "alice:$6$h:19500:0:99999:7:::\n",
        "alice:x:1000:\n",
    );

    // 2024-02-29 is 19782 days after the epoch.
    let code = run_with_prefix(&dir, &["-e", "2024-02-29", "alice"]);
    assert_eq!(code, 0, "YYYY-MM-DD must be accepted");
    assert!(
        read_shadow(&dir).contains(":19782:"),
        "expiry should be stored as days since epoch, got: {}",
        read_shadow(&dir)
    );
}

#[test]
fn test_bad_expiredate_changes_nothing() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        "alice:$6$h:19500:0:99999:7:::\n",
        "alice:x:1000:\n",
    );
    let before = read_passwd(&dir);

    let code = run_with_prefix(&dir, &["-c", "New Name", "-e", "2023-02-29", "alice"]);
    assert_eq!(code, 3, "an impossible date is a bad argument");
    assert_eq!(
        read_passwd(&dir),
        before,
        "no field may be committed when a later argument is invalid"
    );
}
