// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore userdel gshadow

//! Integration tests for the `userdel` utility.
//!
//! Tests that require root are guarded by `crate::common::skip_unless_root()` and run inside
//! Docker CI containers. Non-root tests exercise clap parsing and error paths
//! that do not need privilege.

use std::ffi::OsString;

/// Run `uumain` with the given args, returning the exit code.
fn run(args: &[&str]) -> i32 {
    let os_args: Vec<OsString> = args.iter().map(|s| (*s).into()).collect();
    userdel::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with pre-populated files for userdel tests:
/// - etc/passwd with root + testuser
/// - etc/shadow with root + testuser
/// - etc/group with root group + a group containing testuser as member
fn setup_root_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");

    std::fs::write(
        etc.join("passwd"),
        "\
root:x:0:0:root:/root:/bin/bash\n\
testuser:x:1000:1000:Test User:/home/testuser:/bin/bash\n\
otheruser:x:1001:1001:Other User:/home/otheruser:/bin/bash\n",
    )
    .expect("failed to write passwd file");

    std::fs::write(
        etc.join("shadow"),
        "\
root:$6$roothash:19500:0:99999:7:::\n\
testuser:$6$testhash:19500:0:99999:7:::\n\
otheruser:$6$otherhash:19500:0:99999:7:::\n",
    )
    .expect("failed to write shadow file");

    std::fs::write(
        etc.join("group"),
        "\
root:x:0:\n\
testgroup:x:1000:testuser\n\
othergroup:x:1001:otheruser\n\
shared:x:1002:testuser,otheruser\n",
    )
    .expect("failed to write group file");

    dir
}

/// Run `uumain` with a `--root` dir prepended to the args.
fn run_with_root(dir: &tempfile::TempDir, extra_args: &[&str]) -> i32 {
    let root_str = dir.path().to_str().expect("non-UTF-8 temp path");
    let mut args = vec!["userdel", "-P", root_str];
    args.extend_from_slice(extra_args);
    run(&args)
}

/// Read the passwd file content back from a root dir.
fn read_passwd(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/passwd")).expect("failed to read passwd file")
}

/// Read the shadow file content back from a root dir.
fn read_shadow(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/shadow")).expect("failed to read shadow file")
}

/// Read the group file content back from a root dir.
fn read_group(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/group")).expect("failed to read group file")
}

// ---------------------------------------------------------------------------
// Non-root tests -- exercise clap parsing and error paths
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["userdel", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_error() {
    let code = run(&["userdel", "--bogus"]);
    assert_eq!(code, 2, "unknown flag should exit 2");
}

#[test]
fn test_missing_login_exits_error() {
    let code = run(&["userdel"]);
    assert_eq!(code, 2, "missing LOGIN should exit 2");
}

// ---------------------------------------------------------------------------
// Root-only tests -- exercise real operations via --root
// ---------------------------------------------------------------------------

#[test]
fn test_delete_user_basic() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["testuser"]);
    assert_eq!(code, 0, "userdel testuser should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        !passwd.contains("testuser:"),
        "passwd should not contain testuser after deletion, got: {passwd}"
    );

    let shadow = read_shadow(&dir);
    assert!(
        !shadow.contains("testuser:"),
        "shadow should not contain testuser after deletion, got: {shadow}"
    );
}

#[test]
fn test_delete_user_remove_home() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();

    // Create the home directory that userdel -r should remove, owned by the
    // user as useradd would leave it (userdel -r without -f only removes a
    // home the user owns).
    let home_path = dir.path().join("home/testuser");
    std::fs::create_dir_all(&home_path).expect("failed to create home dir");
    std::fs::write(home_path.join("somefile.txt"), "content")
        .expect("failed to write file in home");
    std::os::unix::fs::chown(&home_path, Some(1000), Some(1000)).expect("chown home to user");

    // Update passwd to point home to the temp dir path.
    let passwd_path = dir.path().join("etc/passwd");
    let home_str = "/home/testuser";
    let passwd_content = format!(
        "\
root:x:0:0:root:/root:/bin/bash\n\
testuser:x:1000:1000:Test User:{home_str}:/bin/bash\n\
otheruser:x:1001:1001:Other User:/home/otheruser:/bin/bash\n"
    );
    std::fs::write(&passwd_path, &passwd_content).expect("failed to rewrite passwd");

    let code = run_with_root(&dir, &["-r", "testuser"]);
    assert_eq!(code, 0, "userdel -r testuser should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        !passwd.contains("testuser:"),
        "passwd should not contain testuser, got: {passwd}"
    );

    // The home directory should be removed.
    assert!(
        !home_path.exists(),
        "home directory should have been removed at {}",
        home_path.display()
    );
}

#[test]
fn test_delete_nonexistent_user_fails() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["nouser"]);
    assert_ne!(code, 0, "deleting nonexistent user should fail");
}

#[test]
fn test_delete_user_preserves_others() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["testuser"]);
    assert_eq!(code, 0, "userdel testuser should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("root:x:0:0:root:/root:/bin/bash"),
        "root entry should be preserved, got: {passwd}"
    );
    assert!(
        passwd.contains("otheruser:x:1001:1001:Other User:/home/otheruser:/bin/bash"),
        "otheruser entry should be preserved, got: {passwd}"
    );
    assert!(
        !passwd.contains("testuser:"),
        "testuser should be removed, got: {passwd}"
    );

    let shadow = read_shadow(&dir);
    assert!(
        shadow.contains("root:"),
        "root shadow entry should be preserved, got: {shadow}"
    );
    assert!(
        shadow.contains("otheruser:"),
        "otheruser shadow entry should be preserved, got: {shadow}"
    );
}

#[test]
fn test_delete_user_removes_group_membership() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["testuser"]);
    assert_eq!(code, 0, "userdel testuser should exit 0");

    let group = read_group(&dir);
    // testuser should be removed from all group membership lists.
    assert!(
        !group.contains("testuser"),
        "testuser should be removed from group membership lists, got: {group}"
    );

    // otheruser should still be a member of shared group.
    assert!(
        group.contains("otheruser"),
        "otheruser should remain in group membership lists, got: {group}"
    );
}

#[test]
fn test_delete_user_shadow_entry_removed() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["testuser"]);
    assert_eq!(code, 0, "userdel should exit 0");

    let shadow = read_shadow(&dir);
    assert!(
        !shadow.contains("testuser:"),
        "shadow entry should be removed, got: {shadow}"
    );
    assert!(
        shadow.contains("otheruser:$6$otherhash:"),
        "otheruser shadow entry should be intact, got: {shadow}"
    );
}

#[test]
fn test_delete_user_force_flag_accepted() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    // -f is accepted without error (force removal even if user is logged in).
    let code = run_with_root(&dir, &["-f", "testuser"]);
    assert_eq!(code, 0, "userdel -f should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        !passwd.contains("testuser:"),
        "testuser should be deleted with -f, got: {passwd}"
    );
}

#[test]
fn test_delete_multiple_users_sequentially() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();

    let code = run_with_root(&dir, &["testuser"]);
    assert_eq!(code, 0, "first userdel should succeed");

    let code = run_with_root(&dir, &["otheruser"]);
    assert_eq!(code, 0, "second userdel should succeed");

    let passwd = read_passwd(&dir);
    assert!(
        !passwd.contains("testuser:"),
        "testuser should be gone, got: {passwd}"
    );
    assert!(
        !passwd.contains("otheruser:"),
        "otheruser should be gone, got: {passwd}"
    );
    assert!(
        passwd.contains("root:"),
        "root should remain, got: {passwd}"
    );
}

// ---------------------------------------------------------------------------
// Safety and cleanup (userdel(8))
// ---------------------------------------------------------------------------

/// A tree where `priv` has a private group of the same name and a home.
fn setup_private_group_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("etc");
    std::fs::write(
        etc.join("passwd"),
        "root:x:0:0:root:/root:/bin/bash\n\
         priv:x:1000:1000:Priv:/home/priv:/bin/bash\n",
    )
    .unwrap();
    std::fs::write(
        etc.join("shadow"),
        "root:*:19500:0:99999:7:::\npriv:$6$h:19500:0:99999:7:::\n",
    )
    .unwrap();
    std::fs::write(etc.join("group"), "root:x:0:\npriv:x:1000:\n").unwrap();
    std::fs::write(etc.join("gshadow"), "root:*::\npriv:!::\n").unwrap();
    std::fs::write(etc.join("subuid"), "priv:100000:65536\nkeep:200000:65536\n").unwrap();
    std::fs::write(etc.join("subgid"), "priv:100000:65536\n").unwrap();
    dir
}

#[test]
fn test_missing_user_exits_6() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_root_dir();
    assert_eq!(run_with_root(&dir, &["ghost"]), 6, "missing user is exit 6");
    // Ubuntu 26.04's userdel: -f does not change that.
    for args in [
        &["-f", "ghost"][..],
        &["--force", "ghost"][..],
        &["-r", "-f", "ghost"][..],
    ] {
        assert_eq!(run_with_root(&dir, args), 6, "{args:?}");
    }
}

// Ubuntu 26.04's userdel -f leaves what a name not in passwd left behind alone:
// its shadow row, its group memberships, its subordinate ids.
#[test]
fn test_force_on_a_missing_user_touches_nothing() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_private_group_dir();
    let etc = dir.path().join("etc");
    std::fs::write(
        etc.join("shadow"),
        "priv:!:19000:0:99999:7:::\ngone:!:19000:0:99999:7:::\n",
    )
    .unwrap();
    std::fs::write(
        etc.join("group"),
        "root:x:0:gone\npriv:x:1000:\ngone:x:1001:\n",
    )
    .unwrap();
    std::fs::write(etc.join("gshadow"), "root:*::gone\npriv:!::\ngone:!::\n").unwrap();
    std::fs::write(etc.join("subuid"), "gone:100000:65536\n").unwrap();
    let read = |name: &str| std::fs::read_to_string(etc.join(name)).unwrap();
    let before = ["shadow", "group", "gshadow", "subuid"].map(read);

    assert_eq!(run_with_root(&dir, &["-f", "gone"]), 6);

    assert_eq!(["shadow", "group", "gshadow", "subuid"].map(read), before);
}

#[test]
fn test_private_group_is_removed() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_private_group_dir();
    assert_eq!(run_with_root(&dir, &["priv"]), 0);
    let group = read_group(&dir);
    assert!(
        !group.contains("priv:x:1000:"),
        "private group gone: {group}"
    );
    assert!(group.contains("root:x:0:"), "other groups kept");
    // subuid rows for priv gone, others kept; subgid emptied → file unlinked.
    let subuid = std::fs::read_to_string(dir.path().join("etc/subuid")).unwrap();
    assert!(
        !subuid.contains("priv:") && subuid.contains("keep:"),
        "subuid: {subuid}"
    );
    assert!(
        !dir.path().join("etc/subgid").exists(),
        "emptied subgid is unlinked"
    );
}

#[test]
fn test_private_group_kept_when_it_has_other_members() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_private_group_dir();
    // Add another member to priv's group.
    std::fs::write(
        dir.path().join("etc/group"),
        "root:x:0:\npriv:x:1000:someone\n",
    )
    .unwrap();
    assert_eq!(run_with_root(&dir, &["priv"]), 0);
    let group = read_group(&dir);
    assert!(
        group.contains("priv:x:1000:someone"),
        "kept with member: {group}"
    );
}

#[test]
fn test_remove_home_refuses_foreign_owner_without_force() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = setup_private_group_dir();
    let home = dir.path().join("home/priv");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("f"), "x").unwrap();
    // Home owned by someone else (uid 4242), not priv (1000).
    std::os::unix::fs::chown(&home, Some(4242), None).unwrap();

    assert_eq!(
        run_with_root(&dir, &["-r", "priv"]),
        12,
        "a home not owned by the user must not be removed"
    );
    assert!(home.exists(), "home must still exist after refusal");

    // But the account itself is still removed (userdel proceeds, home refused
    // is a separate exit). Re-create priv to test -f removes the home.
    std::fs::write(
        dir.path().join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\npriv:x:1000:1000:Priv:/home/priv:/bin/bash\n",
    )
    .unwrap();
    assert_eq!(
        run_with_root(&dir, &["-r", "-f", "priv"]),
        0,
        "-f forces removal"
    );
    assert!(!home.exists(), "-f removes the foreign-owned home");
}

#[test]
fn test_remove_home_refuses_shared_home_without_force() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).unwrap();
    // Two accounts share /home/shared.
    std::fs::write(
        etc.join("passwd"),
        "a:x:1000:1000:A:/home/shared:/bin/sh\nb:x:1001:1001:B:/home/shared:/bin/sh\n",
    )
    .unwrap();
    std::fs::write(etc.join("group"), "a:x:1000:\nb:x:1001:\n").unwrap();
    let home = dir.path().join("home/shared");
    std::fs::create_dir_all(&home).unwrap();
    std::os::unix::fs::chown(&home, Some(1000), None).unwrap();

    assert_eq!(
        run_with_root(&dir, &["-r", "a"]),
        12,
        "a home shared with another account must not be removed"
    );
    assert!(home.exists(), "shared home must survive");
}

#[test]
fn test_selinux_user_needs_a_selinux_kernel() {
    if crate::common::skip_unless_root() || shadow_core::selinux::kernel_enabled() {
        return;
    }
    let dir = setup_private_group_dir();
    assert_eq!(run_with_root(&dir, &["-Z", "priv"]), 3);
    assert!(
        std::fs::read_to_string(dir.path().join("etc/passwd"))
            .unwrap()
            .contains("priv:")
    );
}

// Probed on Ubuntu 26.04: a prefix with no /etc/passwd, or none at all, has no
// users, exit 6 with "user 'u383' does not exist", with -r and -f too. A prefix
// that is a file is still exit 1.
#[test]
fn test_prefix_without_a_passwd_file_exits_6() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let missing = dir.path().join("nonexistent");
    let missing = missing.to_str().expect("non-UTF-8 temp path");
    let empty = dir.path().to_str().expect("non-UTF-8 temp path");
    for args in [
        &["-P", missing, "u383"][..],
        &["-r", "-P", missing, "u383"][..],
        &["-f", "-P", missing, "u383"][..],
        &["-P", empty, "u383"][..],
    ] {
        crate::common::run("userdel", args)
            .assert_code(6)
            .assert_stderr_contains("user 'u383' does not exist");
    }

    let file = dir.path().join("a-file");
    std::fs::write(&file, "").expect("failed to write file");
    let file = file.to_str().expect("non-UTF-8 temp path");
    assert_eq!(run(&["userdel", "-P", file, "u383"]), 1);
}

// The user's private group was the last entry in gshadow: removing it left
// nothing to write, and the zero-length guard failed the lot, exit 10, with the
// account gone from passwd and its row still in gshadow. groupdel removes the
// file in that case, and so does userdel now.
#[test]
fn test_last_private_group_in_gshadow_goes_with_the_file() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");
    for (file, content) in [
        (
            "passwd",
            "root:x:0:0::/root:/bin/sh\nu1:x:1000:1000::/home/u1:/bin/sh\n",
        ),
        ("shadow", "u1:!:20000:0:99999:7:::\n"),
        ("group", "root:x:0:\nu1:x:1000:\n"),
        ("gshadow", "u1:!::\n"),
        ("login.defs", ""),
    ] {
        std::fs::write(etc.join(file), content).expect("failed to write file");
    }
    let prefix = dir.path().to_str().expect("non-UTF-8 temp path");
    crate::common::run("userdel", &["-P", prefix, "u1"]).assert_code(0);
    assert_eq!(
        std::fs::read_to_string(etc.join("group")).expect("read group"),
        "root:x:0:\n"
    );
    assert!(!etc.join("gshadow").exists());
}

/// The messages of a run, without the program name each line starts with.
fn messages(out: &crate::common::Output) -> Vec<String> {
    out.stderr
        .lines()
        .map(|l| l.split_once(": ").map_or(l, |(_, rest)| rest).to_string())
        .collect()
}

/// `userdel -r` says so when the mail spool or the home is not there, mail
/// spool first, on standard error and with exit 0, as Ubuntu 26.04's does.
#[test]
fn test_remove_reports_a_missing_mail_spool_and_home() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let root = dir.path();
    let prefix = root.to_str().expect("non-UTF-8 temp path");
    let out = crate::common::run("userdel", &["-P", prefix, "-r", "testuser"]);
    out.assert_code(0);
    assert!(out.stdout.is_empty(), "stdout: {:?}", out.stdout);
    assert_eq!(
        messages(&out),
        [
            format!(
                "testuser mail spool ({}) not found",
                root.join("var/mail/testuser").display()
            ),
            format!(
                "testuser home directory ({}) not found",
                root.join("home/testuser").display()
            ),
        ]
    );
    assert!(!read_passwd(&dir).contains("testuser:"));
}

/// Only the home is missing: the spool goes without a word.
#[test]
fn test_remove_reports_a_missing_home() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let root = dir.path();
    let prefix = root.to_str().expect("non-UTF-8 temp path");
    let spool = root.join("var/mail/testuser");
    std::fs::create_dir_all(root.join("var/mail")).expect("mail dir");
    std::fs::write(&spool, "").expect("spool");
    std::os::unix::fs::chown(&spool, Some(1000), Some(1000)).expect("chown spool");
    let out = crate::common::run("userdel", &["-P", prefix, "-r", "testuser"]);
    out.assert_code(0);
    assert_eq!(
        messages(&out),
        [format!(
            "testuser home directory ({}) not found",
            root.join("home/testuser").display()
        )]
    );
    assert!(!spool.exists(), "the mail spool should have been removed");
}

/// Only the spool is missing: the home goes without a word.
#[test]
fn test_remove_reports_a_missing_mail_spool() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let root = dir.path();
    let prefix = root.to_str().expect("non-UTF-8 temp path");
    let home = root.join("home/testuser");
    std::fs::create_dir_all(&home).expect("home");
    std::os::unix::fs::chown(&home, Some(1000), Some(1000)).expect("chown home");
    let out = crate::common::run("userdel", &["-P", prefix, "-r", "testuser"]);
    out.assert_code(0);
    assert_eq!(
        messages(&out),
        [format!(
            "testuser mail spool ({}) not found",
            root.join("var/mail/testuser").display()
        )]
    );
    assert!(!home.exists(), "the home should have been removed");
}

/// An empty home field is reported as an empty path, as upstream does.
#[test]
fn test_remove_reports_an_empty_home_field() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let passwd = read_passwd(&dir).replace("/home/testuser", "");
    std::fs::write(dir.path().join("etc/passwd"), passwd).expect("rewrite passwd");
    let prefix = dir.path().to_str().expect("non-UTF-8 temp path");
    let out = crate::common::run("userdel", &["-P", prefix, "-r", "testuser"]);
    out.assert_code(0);
    assert_eq!(
        messages(&out)[1..],
        ["testuser home directory () not found".to_string()]
    );
}

/// A mail spool that is a dangling symlink counts as missing and is left in
/// place, as Ubuntu 26.04's `userdel -r` does.
#[test]
fn test_remove_leaves_a_dangling_mail_spool_link() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let root = dir.path();
    let prefix = root.to_str().expect("non-UTF-8 temp path");
    let home = root.join("home/testuser");
    std::fs::create_dir_all(&home).expect("home");
    std::os::unix::fs::chown(&home, Some(1000), Some(1000)).expect("chown home");
    let spool = root.join("var/mail/testuser");
    std::fs::create_dir_all(root.join("var/mail")).expect("mail dir");
    std::os::unix::fs::symlink(root.join("nowhere"), &spool).expect("spool link");
    let out = crate::common::run("userdel", &["-P", prefix, "-r", "testuser"]);
    out.assert_code(0);
    assert_eq!(
        messages(&out),
        [format!(
            "testuser mail spool ({}) not found",
            spool.display()
        )]
    );
    let meta = std::fs::symlink_metadata(&spool).expect("the link should be left in place");
    assert!(meta.file_type().is_symlink());
    assert!(!home.exists(), "the home should have been removed");
    assert!(!read_passwd(&dir).contains("testuser:"));
}

/// A home that is a dangling symlink counts as missing and is left in place,
/// as Ubuntu 26.04's `userdel -r` does.
#[test]
fn test_remove_leaves_a_dangling_home_link() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let root = dir.path();
    let prefix = root.to_str().expect("non-UTF-8 temp path");
    let home = root.join("home/testuser");
    std::fs::create_dir_all(root.join("home")).expect("home parent");
    std::os::unix::fs::symlink(root.join("nowhere"), &home).expect("home link");
    let out = crate::common::run("userdel", &["-P", prefix, "-r", "testuser"]);
    out.assert_code(0);
    assert_eq!(
        messages(&out),
        [
            format!(
                "testuser mail spool ({}) not found",
                root.join("var/mail/testuser").display()
            ),
            format!("testuser home directory ({}) not found", home.display()),
        ]
    );
    let meta = std::fs::symlink_metadata(&home).expect("the link should be left in place");
    assert!(meta.file_type().is_symlink());
    assert!(!read_passwd(&dir).contains("testuser:"));
}
