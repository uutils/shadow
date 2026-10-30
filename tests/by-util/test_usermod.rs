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

#[test]
fn test_reserved_uid_fails() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let code = run_with_prefix(&dir, &["-u", "4294967295", "testuser"]);
    assert_eq!(code, 3, "(uid_t)-1 must be a bad argument");
    assert!(
        read_passwd(&dir).contains("testuser:x:1000:"),
        "UID unchanged"
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
            // Upstream: a home that is the user's through a symlink is not walked,
            // and that is exit 12, with /etc/passwd written all the same.
            assert_eq!(
                code,
                if symlinked { 12 } else { 0 },
                "{args:?}, symlinked {symlinked}"
            );
            let passwd = read_passwd(&dir);
            let expected = if args[0] == "-u" {
                "testuser:x:1500:1000:"
            } else {
                "testuser:x:1000:2000:"
            };
            assert!(
                passwd.contains(expected),
                "{args:?}, symlinked {symlinked}: {passwd}"
            );
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
fn test_move_home_requires_home() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );
    assert_eq!(run_with_prefix(&dir, &["-m", "testuser"]), 2);
}

#[test]
fn test_move_home() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );
    let old = dir.path().join("home/testuser");
    std::fs::create_dir_all(old.join("sub")).expect("failed to create home");
    std::fs::write(old.join("sub/f"), "data").expect("failed to write file");

    let code = run_with_prefix(&dir, &["-d", "/home/moved", "-m", "testuser"]);
    assert_eq!(code, 0, "moving the home directory should succeed");

    assert!(!old.exists(), "old home should be gone");
    let moved = dir.path().join("home/moved/sub/f");
    assert_eq!(std::fs::read_to_string(moved).expect("moved file"), "data");
    assert!(read_passwd(&dir).contains(":/home/moved:"));
}

#[test]
fn test_move_home_onto_existing_directory_fails() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );
    std::fs::create_dir_all(dir.path().join("home/testuser")).expect("failed to create home");
    std::fs::create_dir_all(dir.path().join("home/taken")).expect("failed to create dir");

    let code = run_with_prefix(&dir, &["-d", "/home/taken", "-m", "testuser"]);
    assert_eq!(code, 12, "a move onto an existing directory should exit 12");
    assert!(
        dir.path().join("home/testuser").is_dir(),
        "old home should stay"
    );
}

/// One account with the home `/home/testuser` in its prefix, not created yet.
fn setup_move_prefix() -> tempfile::TempDir {
    setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\nnewgrp:x:2000:\n",
    )
}

#[test]
fn test_move_home_reowns_the_moved_home() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_move_prefix();
    let old = dir.path().join("home/testuser");
    std::fs::create_dir_all(old.join("sub")).expect("failed to create home");
    std::fs::write(old.join("sub/mine"), "x").expect("failed to write file");
    std::fs::write(old.join("theirs"), "x").expect("failed to write file");
    for p in [&old, &old.join("sub"), &old.join("sub/mine")] {
        std::os::unix::fs::lchown(p, Some(1000), Some(1000)).expect("chown");
    }
    std::os::unix::fs::lchown(old.join("theirs"), Some(3333), Some(3333)).expect("chown");

    let code = run_with_prefix(
        &dir,
        &[
            "-d",
            "/home/moved",
            "-m",
            "-u",
            "1500",
            "-g",
            "newgrp",
            "testuser",
        ],
    );
    assert_eq!(code, 0);

    let new = dir.path().join("home/moved");
    assert_eq!(owner_of(&new), (1500, 2000));
    assert_eq!(owner_of(&new.join("sub")), (1500, 2000));
    assert_eq!(owner_of(&new.join("sub/mine")), (1500, 2000));
    assert_eq!(owner_of(&new.join("theirs")), (3333, 3333));
    assert!(!old.exists(), "old home should be gone");
}

#[test]
fn test_move_home_same_value_reowns_in_place() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_move_prefix();
    let home = dir.path().join("home/testuser");
    std::fs::create_dir_all(&home).expect("failed to create home");
    std::os::unix::fs::lchown(&home, Some(1000), Some(1000)).expect("chown");

    let code = run_with_prefix(
        &dir,
        &["-d", "/home/testuser", "-m", "-u", "1500", "testuser"],
    );
    assert_eq!(code, 0);
    assert_eq!(owner_of(&home).0, 1500, "nothing to move, still re-owned");
}

#[test]
fn test_move_home_same_value_with_slash_counts_as_taken() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_move_prefix();
    let home = dir.path().join("home/testuser");
    std::fs::create_dir_all(&home).expect("failed to create home");

    // Ubuntu's usermod compares the spelling given, then finds the path taken.
    let code = run_with_prefix(&dir, &["-d", "/home/testuser/", "-m", "testuser"]);
    assert_eq!(code, 12);
    assert!(read_passwd(&dir).contains(":/home/testuser:"));
    assert!(home.is_dir());
}

#[test]
fn test_move_home_new_slash_is_dropped() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_move_prefix();
    std::fs::create_dir_all(dir.path().join("home/testuser")).expect("failed to create home");

    let code = run_with_prefix(&dir, &["-d", "/home/moved/", "-m", "testuser"]);
    assert_eq!(code, 0);
    assert!(read_passwd(&dir).contains(":/home/moved:"));
    assert!(dir.path().join("home/moved").is_dir());
}

#[test]
fn test_move_home_relative_is_refused() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_move_prefix();
    let home = dir.path().join("home/testuser");
    std::fs::create_dir_all(&home).expect("failed to create home");

    assert_eq!(run_with_prefix(&dir, &["-d", "rel", "-m", "testuser"]), 3);
    assert!(read_passwd(&dir).contains(":/home/testuser:"));
    assert!(home.is_dir());
}

#[test]
fn test_move_home_taken_target_is_not_reowned() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_move_prefix();
    let old = dir.path().join("home/testuser");
    let taken = dir.path().join("home/taken");
    for d in [&old, &taken] {
        std::fs::create_dir_all(d).expect("failed to create dir");
        std::os::unix::fs::lchown(d, Some(1000), Some(1000)).expect("chown");
    }

    let code = run_with_prefix(&dir, &["-d", "/home/taken", "-m", "-u", "1500", "testuser"]);
    assert_eq!(code, 12);
    let passwd = read_passwd(&dir);
    assert!(passwd.contains("testuser:x:1500:"), "account is written");
    assert!(passwd.contains(":/home/taken:"), "account is written");
    assert_eq!(owner_of(&old).0, 1000, "not moved, so not re-owned");
    assert_eq!(owner_of(&taken).0, 1000, "not moved, so not re-owned");
}

#[test]
fn test_move_home_taken_target_wins_over_missing_home() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_move_prefix();
    std::fs::create_dir_all(dir.path().join("home/taken")).expect("failed to create dir");

    assert_eq!(
        run_with_prefix(&dir, &["-d", "/home/taken", "-m", "testuser"]),
        12
    );
}

#[test]
fn test_move_home_failed_rename_is_not_reowned() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_move_prefix();
    let old = dir.path().join("home/testuser");
    std::fs::create_dir_all(&old).expect("failed to create home");
    std::os::unix::fs::lchown(&old, Some(1000), Some(1000)).expect("chown");

    let code = run_with_prefix(
        &dir,
        &["-d", "/home/no/such/moved", "-m", "-u", "1500", "testuser"],
    );
    assert_eq!(code, 12);
    assert!(read_passwd(&dir).contains(":/home/no/such/moved:"));
    assert_eq!(owner_of(&old).0, 1000);
}

#[test]
fn test_move_home_missing_home_warns_and_succeeds() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_move_prefix();
    std::fs::create_dir_all(dir.path().join("home")).expect("failed to create dir");

    let code = run_with_prefix(&dir, &["-d", "/home/moved", "-m", "-u", "1500", "testuser"]);
    assert_eq!(code, 0);
    assert!(read_passwd(&dir).contains(":/home/moved:"));
    assert!(!dir.path().join("home/moved").exists());
}

#[test]
fn test_move_home_empty_home_field_is_not_the_prefix_root() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test::/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );

    let code = run_with_prefix(&dir, &["-d", "/moved", "-m", "testuser"]);
    assert_eq!(code, 0);
    assert!(dir.path().join("etc/passwd").exists(), "prefix untouched");
    assert!(!dir.path().join("moved").exists());
}

#[test]
fn test_move_home_that_is_a_file_fails() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_move_prefix();
    std::fs::create_dir_all(dir.path().join("home")).expect("failed to create dir");
    let old = dir.path().join("home/testuser");
    std::fs::write(&old, "x").expect("failed to write file");

    assert_eq!(
        run_with_prefix(&dir, &["-d", "/home/moved", "-m", "testuser"]),
        12
    );
    assert!(old.is_file(), "left where it is");
    assert!(!dir.path().join("home/moved").exists());
}

#[test]
fn test_move_home_symlink_moves_the_link_and_fails() {
    if crate::common::skip_unless_root() {
        return;
    }

    // Probed on Ubuntu 26.04: the link is renamed, nothing behind it changes,
    // and the exit status is 12, whoever owns what it points to.
    for (owner, args) in [
        (1000, &["-d", "/home/moved", "-m", "testuser"][..]),
        (
            1000,
            &["-d", "/home/moved", "-m", "-u", "1500", "testuser"][..],
        ),
        (3333, &["-d", "/home/moved", "-m", "testuser"][..]),
    ] {
        let dir = setup_move_prefix();
        let real = dir.path().join("home/real");
        std::fs::create_dir_all(&real).expect("failed to create dir");
        std::fs::write(real.join("f"), "x").expect("failed to write file");
        for p in [&real, &real.join("f")] {
            std::os::unix::fs::lchown(p, Some(owner), Some(owner)).expect("chown");
        }
        std::os::unix::fs::symlink("real", dir.path().join("home/testuser")).expect("symlink");

        assert_eq!(run_with_prefix(&dir, args), 12, "{args:?} owner {owner}");
        assert_eq!(
            std::fs::read_link(dir.path().join("home/moved")).expect("the link moved"),
            std::path::Path::new("real")
        );
        assert_eq!(owner_of(&real).0, owner, "the target is not touched");
        assert_eq!(
            owner_of(&real.join("f")).0,
            owner,
            "the target is not touched"
        );
    }
}

#[test]
fn test_move_home_dangling_symlink_warns_and_succeeds() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_move_prefix();
    std::fs::create_dir_all(dir.path().join("home")).expect("failed to create dir");
    let old = dir.path().join("home/testuser");
    std::os::unix::fs::symlink("/nonexistent", &old).expect("symlink");

    assert_eq!(
        run_with_prefix(&dir, &["-d", "/home/moved", "-m", "testuser"]),
        0
    );
    assert!(std::fs::read_link(&old).is_ok(), "left where it is");
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
fn test_remove_from_groups() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\ngroup1:x:2001:testuser\ngroup2:x:2002:other,testuser\ngroup3:x:2003:testuser\n",
    );

    let code = run_with_prefix(&dir, &["-r", "-G", "group1,group2", "testuser"]);
    assert_eq!(code, 0, "removing from supplementary groups should succeed");
    assert_eq!(
        read_group(&dir),
        "testuser:x:1000:\ngroup1:x:2001:\ngroup2:x:2002:other\ngroup3:x:2003:testuser\n"
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

/// The user owns the home and can swap entries while root walks it. Here a
/// thread keeps exchanging subdirectories with symlinks to a directory
/// outside the home, atomically, for the whole run. A walk that checks an
/// entry by path and then opens it by path can be steered through the link
/// and re-own the file outside; the walk must never touch it.
#[test]
fn test_rechown_never_follows_an_entry_swapped_mid_walk() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const PAIRS: usize = 32;

    if crate::common::skip_unless_root() {
        return;
    }

    for round in 0..40 {
        let dir = setup_prefix(
            "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
            "testuser:$6$hash:19500:0:99999:7:::\n",
            "testuser:x:1000:\n",
        );
        let home = dir.path().join("home/testuser");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).expect("failed to create outside dir");
        std::fs::write(outside.join("victim"), "").expect("failed to write victim");
        std::os::unix::fs::chown(outside.join("victim"), Some(1000), Some(1000))
            .expect("chown failed");
        std::fs::create_dir_all(&home).expect("failed to create home");
        for i in 0..PAIRS {
            let sub = home.join(format!("d{i}"));
            std::fs::create_dir(&sub).expect("failed to create subdir");
            std::fs::write(sub.join("f"), "").expect("failed to write file");
            std::os::unix::fs::symlink(&outside, home.join(format!("l{i}")))
                .expect("failed to create symlink");
        }
        // Entries the swapper does not touch, to see the walk really walked.
        std::fs::create_dir(home.join("keep")).expect("failed to create subdir");
        std::fs::write(home.join("keep/f"), "").expect("failed to write file");
        std::fs::write(home.join("plain"), "").expect("failed to write file");
        // chown -R by hand: everything in the home is the user's.
        for entry in std::fs::read_dir(&home).expect("read home") {
            let path = entry.expect("entry").path();
            std::os::unix::fs::lchown(&path, Some(1000), Some(1000)).expect("chown failed");
            if path.is_dir() && !path.is_symlink() {
                std::os::unix::fs::chown(path.join("f"), Some(1000), Some(1000))
                    .expect("chown failed");
            }
        }
        std::os::unix::fs::chown(&home, Some(1000), Some(1000)).expect("chown failed");

        let stop = Arc::new(AtomicBool::new(false));
        let swapper = {
            let stop = Arc::clone(&stop);
            let home = home.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    for i in 0..PAIRS {
                        let _ = rustix::fs::renameat_with(
                            rustix::fs::CWD,
                            home.join(format!("d{i}")),
                            rustix::fs::CWD,
                            home.join(format!("l{i}")),
                            rustix::fs::RenameFlags::EXCHANGE,
                        );
                    }
                }
            })
        };
        let code = run_with_prefix(&dir, &["-u", "1500", "testuser"]);
        stop.store(true, Ordering::Relaxed);
        swapper.join().expect("swapper thread panicked");

        assert_eq!(code, 0, "round {round}: changing the UID should succeed");
        assert_eq!(
            owner_of(&outside.join("victim")),
            (1000, 1000),
            "round {round}: a file outside the home was re-owned through a swapped symlink"
        );
        assert_eq!(
            owner_of(&outside),
            (0, 0),
            "round {round}: outside dir re-owned"
        );
        // Never following anything is easy for a walk that does nothing.
        for path in [
            home.clone(),
            home.join("keep"),
            home.join("keep/f"),
            home.join("plain"),
        ] {
            assert_eq!(
                owner_of(&path),
                (1500, 1000),
                "round {round}: {} not re-owned",
                path.display()
            );
        }
    }
}

/// Upstream decides whether the home is the user's through a symlink. A home the
/// user owns that cannot be walked without following a link, or that is not
/// a directory, is exit 12; a home that is not the user's, missing, or a
/// dangling link, is left alone with exit 0.
#[test]
fn test_rechown_home_that_cannot_be_walked() {
    if crate::common::skip_unless_root() {
        return;
    }

    // (setup, expected exit code)
    let cases: [(&str, i32); 4] = [
        ("regular file owned by the user", 12),
        ("symlink to a root-owned directory", 0),
        ("dangling symlink", 0),
        ("missing", 0),
    ];
    for (case, expected) in cases {
        let dir = setup_prefix(
            "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
            "testuser:$6$hash:19500:0:99999:7:::\n",
            "testuser:x:1000:\n",
        );
        let home = dir.path().join("home/testuser");
        std::fs::create_dir_all(dir.path().join("home")).expect("failed to create /home");
        match case {
            "regular file owned by the user" => {
                std::fs::write(&home, "").expect("failed to write file");
                std::os::unix::fs::chown(&home, Some(1000), Some(1000)).expect("chown failed");
            }
            "symlink to a root-owned directory" => {
                let real = dir.path().join("real");
                std::fs::create_dir(&real).expect("failed to create dir");
                std::os::unix::fs::symlink(&real, &home).expect("failed to create symlink");
            }
            "dangling symlink" => {
                std::os::unix::fs::symlink(dir.path().join("nowhere"), &home)
                    .expect("failed to create symlink");
            }
            _ => {}
        }
        let code = run_with_prefix(&dir, &["-u", "1500", "testuser"]);
        assert_eq!(code, expected, "home is a {case}");
        assert!(
            read_passwd(&dir).contains("testuser:x:1500:"),
            "home is a {case}: /etc/passwd should be updated"
        );
    }
}

/// Listens on `/dev/log` for the life of a test, and removes it afterwards.
///
/// Sending to a full datagram socket blocks, and every test in this process
/// that logs sends to this one while it exists, this test's own `usermod`
/// included. So a thread keeps it drained the whole time.
struct SyslogListener {
    lines: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl SyslogListener {
    const PATH: &'static str = "/dev/log";

    /// `None` where a real syslog daemon already owns the socket: taking it
    /// over would lose that daemon's log, and its messages cannot be read here.
    fn bind() -> Option<Self> {
        use std::sync::atomic::Ordering;

        if std::fs::symlink_metadata(Self::PATH).is_ok() {
            return None;
        }
        let socket = std::os::unix::net::UnixDatagram::bind(Self::PATH).expect("bind /dev/log");
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .expect("set timeout");
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let lines = std::sync::Arc::clone(&lines);
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(n) = socket.recv(&mut buf) {
                        lines
                            .lock()
                            .expect("lines lock")
                            .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                    }
                }
            })
        };
        Some(Self {
            lines,
            stop,
            reader: Some(reader),
        })
    }

    /// The first line about `login`. Tests run in parallel in this process and
    /// log too, so lines about other accounts are expected here.
    fn line_about(&self, login: &str) -> String {
        let needle = format!("acct=\"{login}\"");
        for _ in 0..1000 {
            let lines = self.lines.lock().expect("lines lock");
            if let Some(line) = lines.iter().find(|line| line.contains(&needle)) {
                return line.clone();
            }
            drop(lines);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("no syslog line about {login}");
    }
}

impl Drop for SyslogListener {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let _ = std::fs::remove_file(Self::PATH);
    }
}

/// The account files are written either way, but a home that could not be
/// re-owned means the change did not complete, and exit 12 says so: the audit
/// trail must not record the same run as a success.
#[test]
fn test_audit_records_a_failed_home_rechown_as_failed() {
    if crate::common::skip_unless_root() {
        return;
    }
    let Some(listener) = SyslogListener::bind() else {
        return;
    };

    let setup = |login: &str| {
        let dir = setup_prefix(
            &format!("{login}:x:1000:1000:Test:/home/{login}:/bin/bash\n"),
            &format!("{login}:$6$hash:19500:0:99999:7:::\n"),
            &format!("{login}:x:1000:\n"),
        );
        std::fs::create_dir_all(dir.path().join("home")).expect("failed to create /home");
        dir
    };

    // A symlinked home is the user's and is not walked: exit 12.
    let dir = setup("auditfail");
    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("failed to create dir");
    std::os::unix::fs::chown(&real, Some(1000), Some(1000)).expect("chown failed");
    std::os::unix::fs::symlink(&real, dir.path().join("home/auditfail"))
        .expect("failed to create symlink");
    assert_eq!(run_with_prefix(&dir, &["-u", "1500", "auditfail"]), 12);
    let line = listener.line_about("auditfail");
    assert!(line.contains("res=failed"), "{line}");

    // The same change on a home that can be walked.
    let dir = setup("auditok");
    let home = dir.path().join("home/auditok");
    std::fs::create_dir(&home).expect("failed to create home");
    std::os::unix::fs::chown(&home, Some(1000), Some(1000)).expect("chown failed");
    assert_eq!(run_with_prefix(&dir, &["-u", "1500", "auditok"]), 0);
    let line = listener.line_about("auditok");
    assert!(line.contains("res=success"), "{line}");
}

/// `O_NOFOLLOW` only looks at the last component, and with a trailing slash
/// that component is empty: the kernel resolves a symlink before it. A home
/// spelled with one must not reach the walk through a link that the same home
/// spelled without one is refused for.
#[test]
fn test_rechown_trailing_slash_on_a_symlinked_home() {
    if crate::common::skip_unless_root() {
        return;
    }

    for spelling in ["testuser", "testuser/", "testuser//", "testuser/."] {
        let dir = setup_prefix(
            &format!("testuser:x:1000:1000:Test:/home/{spelling}:/bin/bash\n"),
            "testuser:$6$hash:19500:0:99999:7:::\n",
            "testuser:x:1000:\n",
        );
        let real = dir.path().join("real");
        std::fs::create_dir(&real).expect("failed to create dir");
        std::fs::write(real.join("file"), "").expect("failed to write file");
        std::os::unix::fs::chown(real.join("file"), Some(1000), Some(1000)).expect("chown failed");
        std::os::unix::fs::chown(&real, Some(1000), Some(1000)).expect("chown failed");
        std::fs::create_dir_all(dir.path().join("home")).expect("failed to create /home");
        std::os::unix::fs::symlink(&real, dir.path().join("home/testuser"))
            .expect("failed to create symlink");

        let code = run_with_prefix(&dir, &["-u", "1500", "testuser"]);
        assert_eq!(code, 12, "home spelled {spelling}");
        assert_eq!(owner_of(&real), (1000, 1000), "home spelled {spelling}");
        assert_eq!(
            owner_of(&real.join("file")),
            (1000, 1000),
            "home spelled {spelling}"
        );
        assert!(
            read_passwd(&dir).contains("testuser:x:1500:"),
            "home spelled {spelling}: /etc/passwd should be updated"
        );
    }

    // The real directory reached with a trailing slash is walked as usual.
    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser/:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );
    let home = dir.path().join("home/testuser");
    std::fs::create_dir_all(&home).expect("failed to create home");
    std::fs::write(home.join("file"), "").expect("failed to write file");
    std::os::unix::fs::chown(home.join("file"), Some(1000), Some(1000)).expect("chown failed");
    std::os::unix::fs::chown(&home, Some(1000), Some(1000)).expect("chown failed");
    assert_eq!(run_with_prefix(&dir, &["-u", "1500", "testuser"]), 0);
    assert_eq!(owner_of(&home), (1500, 1000));
    assert_eq!(owner_of(&home.join("file")), (1500, 1000));
}

/// Run `usermod` on a thread of its own with `dropped` removed from the
/// effective capabilities, which are per thread. Root otherwise gets past every
/// permission check, and the failures a walk has to survive cannot be made.
fn run_without_capabilities(
    dir: &tempfile::TempDir,
    args: &[&str],
    dropped: rustix::thread::CapabilitySet,
) -> i32 {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut caps = rustix::thread::capabilities(None).expect("capget failed");
                caps.effective.remove(dropped);
                rustix::thread::set_capabilities(None, caps).expect("capset failed");
                run_with_prefix(dir, args)
            })
            .join()
            .expect("usermod thread panicked")
    })
}

/// A home holding a directory root cannot open once it has no way around the
/// mode: `blocked` is mode 000, with `inner` in it, next to `plain` and
/// `open/f`.
fn home_with_a_blocked_directory(dir: &tempfile::TempDir) -> std::path::PathBuf {
    use std::os::unix::fs::{PermissionsExt, chown};

    let home = dir.path().join("home/testuser");
    let blocked = home.join("blocked");
    std::fs::create_dir_all(&blocked).expect("failed to create blocked");
    std::fs::create_dir(home.join("open")).expect("failed to create open");
    for file in [
        blocked.join("inner"),
        home.join("plain"),
        home.join("open/f"),
    ] {
        std::fs::write(&file, "").expect("failed to write file");
        chown(&file, Some(1000), Some(1000)).expect("chown failed");
    }
    for path in [&blocked, &home.join("open"), &home] {
        chown(path, Some(1000), Some(1000)).expect("chown failed");
    }
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000))
        .expect("chmod failed");
    home
}

/// A directory the walk cannot open cannot be walked, but it can still be
/// re-owned through the descriptor that found it, which needs no permission
/// on the directory and follows nothing.
#[test]
fn test_rechown_reowns_a_directory_it_cannot_open() {
    use rustix::thread::CapabilitySet;

    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );
    let home = home_with_a_blocked_directory(&dir);

    let code = run_without_capabilities(
        &dir,
        &["-u", "1500", "testuser"],
        CapabilitySet::DAC_OVERRIDE | CapabilitySet::DAC_READ_SEARCH,
    );

    assert_eq!(code, 12, "a directory was not walked, and that must show");
    assert!(read_passwd(&dir).contains("testuser:x:1500:"));
    assert_eq!(owner_of(&home.join("blocked")), (1500, 1000));
    assert_eq!(
        owner_of(&home.join("blocked/inner")),
        (1000, 1000),
        "the walk could not have reached this"
    );
    assert_eq!(owner_of(&home), (1500, 1000));
    assert_eq!(owner_of(&home.join("plain")), (1500, 1000));
    assert_eq!(owner_of(&home.join("open")), (1500, 1000));
    assert_eq!(owner_of(&home.join("open/f")), (1500, 1000));
}

/// A change that fails is reported, but does not stop the walk. Without
/// `CAP_CHOWN` root can still move a file it owns to a group it is in, and
/// nothing else: the home and `theirs` fail, whatever order the walk finds
/// them in, while `ours` and `ours-dir/f` change.
#[test]
fn test_rechown_keeps_walking_after_a_chown_fails() {
    use rustix::thread::CapabilitySet;
    use std::os::unix::fs::chown;

    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "root:x:0:\ntestuser:x:1000:\n",
    );
    let home = dir.path().join("home/testuser");
    std::fs::create_dir_all(home.join("ours-dir")).expect("failed to create dirs");
    for (path, uid) in [
        ("ours", 0),
        ("ours-dir/f", 0),
        ("theirs", 1000),
        ("ours-dir/theirs", 1000),
    ] {
        std::fs::write(home.join(path), "").expect("failed to write file");
        chown(home.join(path), Some(uid), Some(1000)).expect("chown failed");
    }
    chown(home.join("ours-dir"), Some(0), Some(1000)).expect("chown failed");
    chown(&home, Some(1000), Some(1000)).expect("chown failed");

    let code = run_without_capabilities(&dir, &["-g", "0", "testuser"], CapabilitySet::CHOWN);

    assert_eq!(code, 12);
    assert!(read_passwd(&dir).contains("testuser:x:1000:0:"));
    assert_eq!(owner_of(&home), (1000, 1000));
    assert_eq!(owner_of(&home.join("theirs")), (1000, 1000));
    assert_eq!(owner_of(&home.join("ours-dir/theirs")), (1000, 1000));
    assert_eq!(owner_of(&home.join("ours")), (0, 0));
    assert_eq!(owner_of(&home.join("ours-dir")), (0, 0));
    assert_eq!(owner_of(&home.join("ours-dir/f")), (0, 0));
}

/// Running out of descriptors on a deep tree must not look like success. A
/// parent stays open while siblings of the next level wait, so depth is what
/// uses them up; the real binary runs under a low limit, as the limit is per
/// process. `d` is created first and the siblings are named per level, so the
/// order `d` is reached in differs through the tree on every filesystem.
#[test]
fn test_rechown_at_the_descriptor_limit_exits_12() {
    use std::os::unix::fs::{MetadataExt, chown};

    const DEPTH: usize = 200;

    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );
    let home = dir.path().join("home/testuser");
    let mut level = home.clone();
    std::fs::create_dir_all(&level).expect("failed to create home");
    chown(&level, Some(1000), Some(1000)).expect("chown failed");
    for i in 0..DEPTH {
        let next = level.join("d");
        std::fs::create_dir(&next).expect("failed to create chain");
        chown(&next, Some(1000), Some(1000)).expect("chown failed");
        for sibling in ["a", "b", "c"] {
            let sibling = level.join(format!("{sibling}{i}"));
            std::fs::create_dir(&sibling).expect("failed to create sibling");
            chown(&sibling, Some(1000), Some(1000)).expect("chown failed");
            std::fs::write(sibling.join("f"), "").expect("failed to write file");
            chown(sibling.join("f"), Some(1000), Some(1000)).expect("chown failed");
        }
        level = next;
    }
    std::fs::write(level.join("bottom"), "").expect("failed to write file");
    chown(level.join("bottom"), Some(1000), Some(1000)).expect("chown failed");

    let out = crate::common::run_cmd(
        std::process::Command::new("sh")
            .args(["-c", "ulimit -n 20; exec \"$0\" \"$@\""])
            .arg(env!("CARGO_BIN_EXE_shadow-rs"))
            .args(["usermod", "-P"])
            .arg(dir.path())
            .args(["-u", "1500", "testuser"]),
    );
    out.assert_code(12)
        .assert_stderr_contains("Failed to change ownership of the home directory");
    assert!(read_passwd(&dir).contains("testuser:x:1500:"));

    // What the limit did not stop was still done: the shallow part is all
    // re-owned, and the deep part really was out of reach.
    assert_eq!(owner_of(&home), (1500, 1000));
    assert_eq!(owner_of(&home.join("a0/f")), (1500, 1000));
    assert_eq!(owner_of(&home.join("b0/f")), (1500, 1000));
    assert_eq!(owner_of(&home.join("c0/f")), (1500, 1000));
    assert_eq!(
        std::fs::symlink_metadata(level.join("bottom"))
            .expect("stat failed")
            .uid(),
        1000,
        "exit 12 with nothing left behind would be wrong"
    );
}

/// The user may delete their own files while root walks the home. What was
/// deleted needs no new owner, so that is not a failure.
#[test]
fn test_rechown_entries_deleted_mid_walk_are_not_a_failure() {
    use std::os::unix::fs::chown;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const DIRS: usize = 64;
    const FILES: usize = 16;

    if crate::common::skip_unless_root() {
        return;
    }

    for round in 0..20 {
        let dir = setup_prefix(
            "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
            "testuser:$6$hash:19500:0:99999:7:::\n",
            "testuser:x:1000:\n",
        );
        let home = dir.path().join("home/testuser");
        std::fs::create_dir_all(&home).expect("failed to create home");
        chown(&home, Some(1000), Some(1000)).expect("chown failed");
        for d in 0..DIRS {
            let sub = home.join(format!("d{d}"));
            std::fs::create_dir(&sub).expect("failed to create dir");
            chown(&sub, Some(1000), Some(1000)).expect("chown failed");
            for f in 0..FILES {
                let file = sub.join(format!("f{f}"));
                std::fs::write(&file, "").expect("failed to write file");
                chown(&file, Some(1000), Some(1000)).expect("chown failed");
            }
        }

        let stop = Arc::new(AtomicBool::new(false));
        let deleter = {
            let stop = Arc::clone(&stop);
            let home = home.clone();
            std::thread::spawn(move || {
                let mut d = 0;
                while !stop.load(Ordering::Relaxed) && d < DIRS {
                    let _ = std::fs::remove_dir_all(home.join(format!("d{d}")));
                    d += 1;
                }
            })
        };
        let code = run_with_prefix(&dir, &["-u", "1500", "testuser"]);
        stop.store(true, Ordering::Relaxed);
        deleter.join().expect("deleter thread panicked");

        assert_eq!(code, 0, "round {round}");
        assert_eq!(owner_of(&home), (1500, 1000), "round {round}");
    }
}

/// A hard link in the home to a file of someone else is that person's file,
/// whatever group it is in. Both names are the same inode, so regrouping it
/// here regroups it where its owner keeps it. The user's own hard links, in the
/// home or out of it, are the user's files and change as any other does.
#[test]
fn test_rechown_leaves_the_group_of_someone_elses_hard_link() {
    use std::os::unix::fs::chown;

    if crate::common::skip_unless_root() {
        return;
    }

    // (args, what the user's own link becomes, what the other link stays at)
    let cases: [(&[&str], (u32, u32)); 3] = [
        (&["-g", "dev"], (1000, 2000)),
        (&["-u", "1500", "-g", "dev"], (1500, 2000)),
        (&["-u", "1500"], (1500, 1000)),
    ];
    for (args, own_expected) in cases {
        let dir = setup_prefix(
            "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
            "testuser:$6$hash:19500:0:99999:7:::\n",
            "testuser:x:1000:\ndev:x:2000:\n",
        );
        let home = dir.path().join("home/testuser");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&home).expect("failed to create home");
        std::fs::create_dir_all(&outside).expect("failed to create outside");
        chown(&home, Some(1000), Some(1000)).expect("chown failed");

        // Someone else's file, in the user's old group, linked into the home.
        std::fs::write(outside.join("theirs"), "").expect("failed to write file");
        chown(outside.join("theirs"), Some(1100), Some(1000)).expect("chown failed");
        std::fs::hard_link(outside.join("theirs"), home.join("theirs")).expect("link failed");
        // The user's own file, with a second name.
        std::fs::write(outside.join("mine"), "").expect("failed to write file");
        chown(outside.join("mine"), Some(1000), Some(1000)).expect("chown failed");
        std::fs::hard_link(outside.join("mine"), home.join("mine")).expect("link failed");
        // Someone else's file with one name is still regrouped: it was moved
        // into the home, and this is the only place it is reachable from.
        std::fs::write(home.join("given"), "").expect("failed to write file");
        chown(home.join("given"), Some(1100), Some(1000)).expect("chown failed");

        assert_eq!(
            run_with_prefix(&dir, &[args, &["testuser"]].concat()),
            0,
            "{args:?}"
        );

        assert_eq!(owner_of(&home.join("theirs")), (1100, 1000), "{args:?}");
        assert_eq!(owner_of(&outside.join("theirs")), (1100, 1000), "{args:?}");
        assert_eq!(owner_of(&home.join("mine")), own_expected, "{args:?}");
        let given = if args.contains(&"-g") {
            (1100, 2000)
        } else {
            (1100, 1000)
        };
        assert_eq!(owner_of(&home.join("given")), given, "{args:?}");
    }
}

/// `-d` with `-u` or `-g` re-owns the home the account ends up with, whether
/// that is the same value or an existing directory of the user's elsewhere.
/// Without `-m` nothing moves, so a previous home stays as it is: it may well
/// not be the user's to give away any more.
#[test]
fn test_rechown_follows_the_home_given_with_d() {
    use std::os::unix::fs::chown;

    if crate::common::skip_unless_root() {
        return;
    }

    let cases: [(&[&str], (u32, u32)); 3] = [
        (&["-u", "1500"], (1500, 1000)),
        (&["-g", "dev"], (1000, 2000)),
        (&["-u", "1500", "-g", "dev"], (1500, 2000)),
    ];
    for (id_args, changed) in cases {
        let setup = || {
            let dir = setup_prefix(
                "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
                "testuser:$6$hash:19500:0:99999:7:::\n",
                "testuser:x:1000:\ndev:x:2000:\n",
            );
            for name in ["testuser", "other"] {
                let home = dir.path().join("home").join(name);
                std::fs::create_dir_all(home.join("sub")).expect("failed to create dirs");
                std::fs::write(home.join("sub/f"), "").expect("failed to write file");
                for path in [home.join("sub/f"), home.join("sub"), home] {
                    chown(path, Some(1000), Some(1000)).expect("chown failed");
                }
            }
            dir
        };
        let check = |dir: &tempfile::TempDir, name: &str, expected: (u32, u32), case: &str| {
            let home = dir.path().join("home").join(name);
            for path in [home.clone(), home.join("sub"), home.join("sub/f")] {
                assert_eq!(owner_of(&path), expected, "{case} {id_args:?}: {name}");
            }
        };

        // The same value: as if -d had not been given.
        let dir = setup();
        let args = [&["-d", "/home/testuser"], id_args, &["testuser"]].concat();
        assert_eq!(run_with_prefix(&dir, &args), 0, "same value {id_args:?}");
        check(&dir, "testuser", changed, "same value");
        check(&dir, "other", (1000, 1000), "same value");

        // An existing directory of the user's: that one changes, not the old.
        let dir = setup();
        let args = [&["-d", "/home/other"], id_args, &["testuser"]].concat();
        assert_eq!(run_with_prefix(&dir, &args), 0, "existing {id_args:?}");
        check(&dir, "other", changed, "existing");
        check(&dir, "testuser", (1000, 1000), "existing");
        assert!(read_passwd(&dir).contains(":/home/other:"));

        // A directory that is not there: nothing to do, nothing else touched.
        let dir = setup();
        let args = [&["-d", "/home/absent"], id_args, &["testuser"]].concat();
        assert_eq!(run_with_prefix(&dir, &args), 0, "absent {id_args:?}");
        check(&dir, "testuser", (1000, 1000), "absent");
        check(&dir, "other", (1000, 1000), "absent");
    }
}

/// The checks on the home apply to the new one as they do to the current one:
/// not the user's is left alone, and a symlink is exit 12 and not walked.
#[test]
fn test_rechown_new_home_that_cannot_be_walked() {
    use std::os::unix::fs::{chown, symlink};

    if crate::common::skip_unless_root() {
        return;
    }

    let setup = || {
        let dir = setup_prefix(
            "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
            "testuser:$6$hash:19500:0:99999:7:::\n",
            "testuser:x:1000:\n",
        );
        std::fs::create_dir_all(dir.path().join("home")).expect("failed to create /home");
        dir
    };

    // Someone else's directory, with a file of the user's in it.
    let dir = setup();
    let other = dir.path().join("home/other");
    std::fs::create_dir(&other).expect("failed to create dir");
    std::fs::write(other.join("f"), "").expect("failed to write file");
    chown(other.join("f"), Some(1000), Some(1000)).expect("chown failed");
    chown(&other, Some(1100), Some(100)).expect("chown failed");
    let code = run_with_prefix(&dir, &["-d", "/home/other", "-u", "1500", "testuser"]);
    assert_eq!(code, 0);
    assert_eq!(owner_of(&other), (1100, 100));
    assert_eq!(owner_of(&other.join("f")), (1000, 1000));

    // A symlink to a directory of the user's.
    let dir = setup();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("failed to create dir");
    chown(&real, Some(1000), Some(1000)).expect("chown failed");
    symlink(&real, dir.path().join("home/other")).expect("failed to create symlink");
    let code = run_with_prefix(&dir, &["-d", "/home/other", "-u", "1500", "testuser"]);
    assert_eq!(code, 12);
    assert_eq!(owner_of(&real), (1000, 1000));
    assert!(read_passwd(&dir).contains("testuser:x:1500:1000:Test:/home/other:"));
}

/// usermod(8) exit 3. A relative path would be resolved against wherever root
/// happens to be running this, and now that the new home is re-owned, that
/// directory is what would change hands.
#[test]
fn test_relative_home_is_refused() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\n",
    );
    let before = read_passwd(&dir);
    let code = run_with_prefix(&dir, &["-d", "rel/path", "-u", "1500", "testuser"]);
    assert_eq!(code, 3);
    assert_eq!(read_passwd(&dir), before, "nothing should be written");
}

/// One trailing slash is dropped from the value `-d` gives, and only one, as
/// the packaged usermod does. The root directory stays.
#[test]
fn test_home_given_with_a_trailing_slash_is_stored_without() {
    if crate::common::skip_unless_root() {
        return;
    }

    for (given, stored) in [
        ("/new/home/", "/new/home"),
        ("/new/home//", "/new/home/"),
        ("/new/home", "/new/home"),
        ("/", "/"),
        ("//", "/"),
    ] {
        let dir = setup_prefix(
            "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
            "testuser:$6$hash:19500:0:99999:7:::\n",
            "testuser:x:1000:\n",
        );
        assert_eq!(run_with_prefix(&dir, &["-d", given, "testuser"]), 0);
        let passwd = read_passwd(&dir);
        assert!(
            passwd.contains(&format!(":{stored}:/bin/bash")),
            "-d {given}: {passwd}"
        );
    }
}

/// One account, unlocked, in no supplementary group, with its files at hand.
fn setup_one_user() -> tempfile::TempDir {
    setup_prefix(
        "testuser:x:1000:1000:Test:/home/testuser:/bin/bash\n",
        "testuser:$6$hash:19500:0:99999:7:::\n",
        "testuser:x:1000:\nwheel:x:10:\n",
    )
}

/// Assert that a command exits `code` and leaves passwd and shadow alone.
fn assert_refused(dir: &tempfile::TempDir, args: &[&str], code: i32) {
    let (passwd, shadow) = (read_passwd(dir), read_shadow(dir));
    assert_eq!(run_with_prefix(dir, args), code, "{args:?}");
    assert_eq!(read_passwd(dir), passwd, "{args:?}");
    assert_eq!(read_shadow(dir), shadow, "{args:?}");
}

// Ubuntu 26.04's usermod with a login and nothing else: "no options", exit 2,
// unless the login does not exist. These two look at the real /etc, since -P
// is an option, and change nothing there.
#[test]
fn test_no_option_at_all_exits_2() {
    if crate::common::skip_unless_root() {
        return;
    }
    assert_eq!(run(&["usermod", "root"]), 2);
    assert_eq!(run(&["usermod", "no_such_user_9f3a"]), 6);
}

// -P and -R count as options to it: exit 0, "no changes".
#[test]
fn test_only_a_prefix_exits_0() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_one_user();
    assert_refused(&dir, &["testuser"], 0);
}

// Probed on Ubuntu 26.04: -a, -r and -m need their partner, -r excludes -a and
// -L, -U and -p exclude each other, all exit 2 and nothing written. Debian 13
// gives the same.
#[test]
fn test_flags_that_need_each_other_exit_2() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_one_user();
    for args in [
        &["-a", "testuser"][..],
        &["-a", "-c", "new", "testuser"][..],
        &["-a", "-l", "renamed", "testuser"][..],
        &["-r", "testuser"][..],
        &["-m", "testuser"][..],
        &["-a", "-r", "-G", "wheel", "testuser"][..],
        &["-L", "-U", "testuser"][..],
        &["-L", "-p", "x", "testuser"][..],
        &["-U", "-p", "x", "testuser"][..],
    ] {
        assert_refused(&dir, args, 2);
    }
}

// The login is looked up first, so the code says it is the name that is wrong.
#[test]
fn test_missing_user_comes_before_the_flag_checks() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_one_user();
    for args in [
        &["-a", "ghost"][..],
        &["-r", "ghost"][..],
        &["-m", "ghost"][..],
        &["-L", "-U", "ghost"][..],
        &["-p", "a:b", "ghost"][..],
    ] {
        assert_refused(&dir, args, 6);
    }
}

// A value the option cannot parse is exit 3, before the login is looked at.
#[test]
fn test_value_that_does_not_parse_exits_3() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_one_user();
    assert_refused(&dir, &["-u", "abc", "ghost"], 3);
    assert_refused(&dir, &["-f", "abc", "testuser"], 3);
    assert_refused(&dir, &["-c", "a:b", "-a", "testuser"], 3);
}

// Ubuntu 26.04's usermod -U on a field that would come out empty warns, exits 0
// and leaves it locked. Everything else on the command line still happens.
#[test]
fn test_unlock_to_an_empty_field_warns_and_exits_0() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_one_user();
    std::fs::write(
        dir.path().join("etc/shadow"),
        "testuser:!:19500:0:99999:7:::\n",
    )
    .expect("failed to write shadow file");

    assert_eq!(run_with_prefix(&dir, &["-U", "-c", "new", "testuser"]), 0);
    assert!(read_shadow(&dir).contains("testuser:!:"), "still locked");
    assert!(read_passwd(&dir).contains(":new:"), "-c still applied");
}

// One '!' goes per -U; a field with none is left as it is, without complaint.
#[test]
fn test_unlock_matches_upstream_on_every_field() {
    if crate::common::skip_unless_root() {
        return;
    }
    for (before, after) in [
        ("$6$h", "$6$h"),
        ("!$6$h", "$6$h"),
        ("!!$6$h", "!$6$h"),
        ("!!", "!"),
        ("!", "!"),
        ("", ""),
        ("*", "*"),
        ("!*", "*"),
    ] {
        let dir = setup_one_user();
        std::fs::write(
            dir.path().join("etc/shadow"),
            format!("testuser:{before}:19500:0:99999:7:::\n"),
        )
        .expect("failed to write shadow file");
        assert_eq!(run_with_prefix(&dir, &["-U", "testuser"]), 0, "{before:?}");
        assert!(
            read_shadow(&dir).starts_with(&format!("testuser:{after}:")),
            "{before:?} should give {after:?}, got {}",
            read_shadow(&dir)
        );
    }
}

// Ubuntu 26.04's usermod -p with a character that would break the file exits 1.
// It has already written passwd by then, so -l or -c stay applied and the account
// is half renamed. Here nothing is written, which usermod(8) records.
#[test]
fn test_password_that_breaks_the_file_exits_1_and_writes_nothing() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_one_user();
    for args in [
        &["-p", "a:b", "testuser"][..],
        &["-p", ":", "testuser"][..],
        &["-p", "a\nb", "testuser"][..],
        &["-c", "new", "-p", "a:b", "testuser"][..],
        &["-l", "renamed", "-p", "a:b", "testuser"][..],
    ] {
        assert_refused(&dir, args, 1);
    }
}

fn setup_two_users() -> tempfile::TempDir {
    setup_prefix(
        "a:x:1000:1000::/h:/bin/sh\nb:x:1001:1000::/h:/bin/sh\n",
        "a:x:1:0:99999:7:::\nb:x:1:0:99999:7:::\n",
        "a:x:1000:\n",
    )
}

#[test]
fn test_non_unique_needs_uid() {
    if crate::common::skip_unless_root() {
        return;
    }
    assert_eq!(run_with_prefix(&setup_two_users(), &["-o", "b"]), 2);
}

#[test]
fn test_non_unique_allows_a_uid_in_use() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_two_users();
    assert_eq!(run_with_prefix(&dir, &["-u", "1000", "b"]), 4);
    assert_eq!(run_with_prefix(&dir, &["-o", "-u", "1000", "b"]), 0);
    assert!(read_passwd(&dir).contains("b:x:1000:"));
}

#[test]
fn test_badname_allows_a_bad_name_only_with_it() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_two_users();
    assert_eq!(run_with_prefix(&dir, &["-l", "a@b", "b"]), 3);
    assert_eq!(run_with_prefix(&dir, &["-b", "-l", "a:b", "b"]), 3);
    assert_eq!(run_with_prefix(&dir, &["-b", "-l", "a@b", "b"]), 0);
    assert!(read_passwd(&dir).contains("a@b:x:1001:"));
}

#[test]
fn test_selinux_user_needs_a_selinux_kernel() {
    if crate::common::skip_unless_root() || shadow_core::selinux::kernel_enabled() {
        return;
    }
    assert_eq!(run(&["usermod", "-Z", "user_u", "no_such_user_9f3a"]), 3);
}

#[test]
fn test_selinux_range_needs_selinux_user() {
    assert_eq!(run(&["usermod", "--selinux-range", "s0", "root"]), 2);
}
