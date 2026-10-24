// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore usermod gecos gshadow

//! Integration tests for the `usermod` utility.
//!
//! Tests that require root are guarded by `crate::common::skip_unless_root()` and run inside
//! Docker CI containers. Non-root tests exercise clap parsing and error paths
//! that do not need privilege.

use std::ffi::OsString;

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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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

/// Owner and group of `path`, without following a symlink.
fn owner_of(path: &std::path::Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(path).expect("stat failed");
    (meta.uid(), meta.gid())
}

/// A prefix with testuser (1000:1000) and group dev (2000). The home holds a
/// file of testuser's, a root-owned file in the old group, a file in another
/// group, and a symlink in the old group to a file outside the home.
fn setup_home_with_files() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\ndev:x:2000:\n",
    );
    let home = dir.path().join("home/testuser");
    std::fs::create_dir_all(home.join("sub")).expect("failed to create home");
    for (path, uid, gid) in [
        (home.join("mine"), 1000, 1000),
        (home.join("root-owned"), 0, 1000),
        (home.join("other-group"), 1000, 0),
        (dir.path().join("outside"), 1000, 1000),
    ] {
        std::fs::write(&path, "").expect("failed to write file");
        std::os::unix::fs::chown(&path, Some(uid), Some(gid)).expect("chown failed");
    }
    std::os::unix::fs::symlink(dir.path().join("outside"), home.join("link"))
        .expect("failed to create symlink");
    std::os::unix::fs::lchown(home.join("link"), Some(1000), Some(1000)).expect("chown failed");
    std::os::unix::fs::chown(&home, Some(1000), Some(1000)).expect("chown failed");
    std::os::unix::fs::chown(home.join("sub"), Some(1000), Some(1000)).expect("chown failed");
    (dir, home)
}

#[test]
fn test_change_gid_regroups_home_files() {
    if crate::common::skip_unless_root() {
        return;
    }

    let (dir, home) = setup_home_with_files();
    let code = run_with_prefix(&dir, &["-g", "dev", "testuser"]);
    assert_eq!(code, 0, "changing the primary group should succeed");

    for (name, expected) in [
        ("", (1000, 2000)),
        ("sub", (1000, 2000)),
        ("mine", (1000, 2000)),
        ("root-owned", (0, 2000)),
        ("other-group", (1000, 0)),
        ("link", (1000, 2000)),
    ] {
        assert_eq!(owner_of(&home.join(name)), expected, "home entry '{name}'");
    }
    assert_eq!(
        owner_of(&dir.path().join("outside")),
        (1000, 1000),
        "the symlink target outside the home should be left alone"
    );
}

#[test]
fn test_change_uid_and_gid_rechowns_home_files() {
    if crate::common::skip_unless_root() {
        return;
    }

    let (dir, home) = setup_home_with_files();
    let code = run_with_prefix(&dir, &["-u", "1500", "-g", "dev", "testuser"]);
    assert_eq!(code, 0, "changing the UID and primary group should succeed");

    for (name, expected) in [
        ("", (1500, 2000)),
        ("sub", (1500, 2000)),
        ("mine", (1500, 2000)),
        ("root-owned", (0, 2000)),
        ("other-group", (1500, 0)),
        ("link", (1500, 2000)),
    ] {
        assert_eq!(owner_of(&home.join(name)), expected, "home entry '{name}'");
    }
    assert_eq!(
        owner_of(&dir.path().join("outside")),
        (1000, 1000),
        "the symlink target outside the home should be left alone"
    );
}

#[test]
fn test_home_not_owned_by_user_is_left_alone() {
    if crate::common::skip_unless_root() {
        return;
    }

    for args in [["-g", "dev"], ["-u", "1500"]] {
        for symlinked in [false, true] {
            let dir = setup_prefix(
                "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
                "testuser:$6$hash:19500:0:99999:7:::\n",
                "testuser:x:1000:\ndev:x:2000:\n",
            );
            let home = dir.path().join("home/testuser");
            // A symlinked home points at a real directory the user owns.
            let real = if symlinked {
                dir.path().join("real-home")
            } else {
                home.clone()
            };
            std::fs::create_dir_all(&real).expect("failed to create home");
            std::fs::write(real.join("mine"), "").expect("failed to write file");
            std::os::unix::fs::chown(real.join("mine"), Some(1000), Some(1000))
                .expect("chown failed");
            let real_owner = if symlinked { 1000 } else { 0 };
            std::os::unix::fs::chown(&real, Some(real_owner), Some(1000)).expect("chown failed");
            if symlinked {
                std::fs::create_dir_all(home.parent().expect("home has a parent"))
                    .expect("failed to create /home");
                std::os::unix::fs::symlink(&real, &home).expect("failed to create symlink");
            }

            let code = run_with_prefix(&dir, &[args[0], args[1], "testuser"]);
            // GNU exits 12 for a symlinked home: #351.
            if !symlinked {
                assert_eq!(code, 0, "{args:?} should succeed");
            }
            assert_eq!(
                owner_of(&real),
                (real_owner, 1000),
                "{args:?}, symlinked {symlinked}: home should be left alone"
            );
            assert_eq!(
                owner_of(&real.join("mine")),
                (1000, 1000),
                "{args:?}, symlinked {symlinked}: files under it should be left alone"
            );
        }
    }
}

#[test]
fn test_add_to_groups() {
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
    if crate::common::skip_unless_root() {
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
fn test_negative_one_blanks_inactive_and_expiredate() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        "alice:$6$h:19500:0:99999:7:30:19782:\n",
        "alice:x:1000:\n",
    );

    let code = run_with_prefix(&dir, &["-e", "-1", "-f", "-1", "alice"]);
    assert_eq!(code, 0, "-1 must be accepted for -e and -f");
    assert_eq!(
        read_shadow(&dir),
        "alice:$6$h:19500:0:99999:7:::\n",
        "-1 must blank the inactive and expire fields"
    );
}

#[test]
fn test_bad_expiredate_changes_nothing() {
    if crate::common::skip_unless_root() {
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

#[test]
fn test_primary_group_by_name_and_existence() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "alice:x:1000:1000:Alice:/home/alice:/bin/sh\n",
        "alice:$6$h:19500:0:99999:7:::\n",
        "alice:x:1000:\nstaff:x:2000:\n",
    );

    // usermod(8): -g takes a name or a GID, and the group must exist.
    assert_eq!(run_with_prefix(&dir, &["-g", "staff", "alice"]), 0);
    assert!(read_passwd(&dir).contains("alice:x:1000:2000:"));

    assert_eq!(
        run_with_prefix(&dir, &["-g", "12345", "alice"]),
        6,
        "a GID naming no group is exit 6"
    );
    assert_eq!(run_with_prefix(&dir, &["-g", "nosuch", "alice"]), 6);
    assert!(
        read_passwd(&dir).contains("alice:x:1000:2000:"),
        "a failed -g changes nothing"
    );
}

#[test]
fn test_empty_group_list_clears_memberships() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "alice:x:1000:1000:Alice:/home/alice:/bin/sh\n",
        "alice:$6$h:19500:0:99999:7:::\n",
        "alice:x:1000:\nwheel:x:2000:alice\ndocker:x:2001:alice\n",
    );

    // usermod(8): an empty -G list removes every supplementary membership.
    assert_eq!(run_with_prefix(&dir, &["-G", "", "alice"]), 0);
    let group = read_group(&dir);
    assert!(
        group.contains("wheel:x:2000:\n") && group.contains("docker:x:2001:\n"),
        "memberships should be cleared, got: {group}"
    );
}

#[test]
fn test_rename_with_groups_uses_the_new_login() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "alice:x:1000:1000:Alice:/home/alice:/bin/sh\n",
        "alice:$6$h:19500:0:99999:7:::\n",
        "alice:x:1000:\nwheel:x:2000:\n",
    );
    std::fs::write(dir.path().join("etc/gshadow"), "wheel:!::\n").unwrap();

    assert_eq!(
        run_with_prefix(&dir, &["-l", "bob", "-G", "wheel", "alice"]),
        0
    );
    let group = read_group(&dir);
    assert!(
        group.contains("wheel:x:2000:bob"),
        "the new login must be the member, got: {group}"
    );
    let gshadow = std::fs::read_to_string(dir.path().join("etc/gshadow")).unwrap();
    assert!(
        gshadow.contains("wheel:!::bob"),
        "gshadow must follow the group file, got: {gshadow}"
    );
}
