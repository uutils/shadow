// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore pwck nologin gecos

//! Integration tests for the `pwck` utility.
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
    pwck::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with `etc/passwd`, `etc/shadow`, `etc/group`,
/// and `etc/shells` files, plus the required home directory.
fn setup_root(
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
    std::fs::write(etc.join("shells"), "/bin/bash\n/bin/sh\n").expect("failed to write shells");
    dir
}

// ---------------------------------------------------------------------------
// Non-root tests -- exercise clap parsing and error paths
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["pwck", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_error() {
    let code = run(&["pwck", "--bogus"]);
    assert!(code != 0, "unknown flag should exit non-zero");
}

#[test]
fn test_read_only_mode() {
    // -r with a nonexistent file still exits 3 (cant open), but -r is accepted.
    let code = run(&["pwck", "-r", "/nonexistent/passwd"]);
    assert_eq!(
        code, 3,
        "-r with nonexistent file should exit 3 (cant open)"
    );
}

// ---------------------------------------------------------------------------
// Root-only tests -- exercise full checks via -R/--root with temp dirs
// ---------------------------------------------------------------------------

#[test]
fn test_valid_files_exits_zero() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "root:x:0:0:root:/root:/bin/bash\n",
        "root:$6$hash:19000:0:99999:7:::\n",
        "root:x:0:\n",
    );
    // Create the home directory that pwck checks for.
    std::fs::create_dir_all(dir.path().join("root")).expect("failed to create root home");

    let passwd_path = dir.path().join("etc/passwd");
    let shadow_path = dir.path().join("etc/shadow");

    let code = run(&[
        "pwck",
        "-r",
        "-R",
        dir.path().to_str().expect("non-utf8 path"),
        passwd_path.to_str().expect("non-utf8 path"),
        shadow_path.to_str().expect("non-utf8 path"),
    ]);
    assert_eq!(code, 0, "consistent passwd+shadow should return 0");
}

#[test]
fn test_missing_shadow_entry() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
        // Shadow only has root, not alice.
        "root:$6$hash:19000:0:99999:7:::\n",
        "root:x:0:\nusers:x:1000:\n",
    );
    std::fs::create_dir_all(dir.path().join("root")).expect("mkdir root");
    std::fs::create_dir_all(dir.path().join("home/alice")).expect("mkdir alice home");

    let passwd_path = dir.path().join("etc/passwd");
    let shadow_path = dir.path().join("etc/shadow");

    let code = run(&[
        "pwck",
        "-r",
        "-R",
        dir.path().to_str().expect("non-utf8 path"),
        passwd_path.to_str().expect("non-utf8 path"),
        shadow_path.to_str().expect("non-utf8 path"),
    ]);
    assert_eq!(
        code, 2,
        "user in passwd but not shadow should be detected (exit 2)"
    );
}

#[test]
fn test_extra_shadow_entry() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "root:x:0:0:root:/root:/bin/bash\n",
        // Shadow has root + ghost (no matching passwd entry).
        "root:$6$hash:19000:0:99999:7:::\nghost:$6$hash:19000:0:99999:7:::\n",
        "root:x:0:\n",
    );
    std::fs::create_dir_all(dir.path().join("root")).expect("mkdir root");

    let passwd_path = dir.path().join("etc/passwd");
    let shadow_path = dir.path().join("etc/shadow");

    let code = run(&[
        "pwck",
        "-r",
        "-R",
        dir.path().to_str().expect("non-utf8 path"),
        passwd_path.to_str().expect("non-utf8 path"),
        shadow_path.to_str().expect("non-utf8 path"),
    ]);
    assert_eq!(
        code, 2,
        "entry in shadow but not passwd should be detected (exit 2)"
    );
}

#[test]
fn test_invalid_uid() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        // UID field is "abc" -- not a valid number.
        "baduser:x:abc:0:bad:/home/bad:/bin/bash\n",
        "",
        "root:x:0:\n",
    );

    let passwd_path = dir.path().join("etc/passwd");
    let shadow_path = dir.path().join("etc/shadow");

    let code = run(&[
        "pwck",
        "-r",
        "-R",
        dir.path().to_str().expect("non-utf8 path"),
        passwd_path.to_str().expect("non-utf8 path"),
        shadow_path.to_str().expect("non-utf8 path"),
    ]);
    assert_eq!(
        code, 2,
        "non-numeric UID should be detected as invalid (exit 2)"
    );
}

#[test]
fn test_invalid_gid() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        // GID field is "xyz" -- not a valid number.
        "baduser:x:1000:xyz:bad:/home/bad:/bin/bash\n",
        "",
        "root:x:0:\n",
    );

    let passwd_path = dir.path().join("etc/passwd");
    let shadow_path = dir.path().join("etc/shadow");

    let code = run(&[
        "pwck",
        "-r",
        "-R",
        dir.path().to_str().expect("non-utf8 path"),
        passwd_path.to_str().expect("non-utf8 path"),
        shadow_path.to_str().expect("non-utf8 path"),
    ]);
    assert_eq!(
        code, 2,
        "non-numeric GID should be detected as invalid (exit 2)"
    );
}

#[test]
fn test_duplicate_username() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "alice:x:1000:1000::/home/alice:/bin/bash\nalice:x:1001:1000::/home/alice2:/bin/bash\n",
        "alice:$6$hash:19000:0:99999:7:::\n",
        "users:x:1000:\n",
    );
    std::fs::create_dir_all(dir.path().join("home/alice")).expect("mkdir alice home");
    std::fs::create_dir_all(dir.path().join("home/alice2")).expect("mkdir alice2 home");

    let passwd_path = dir.path().join("etc/passwd");
    let shadow_path = dir.path().join("etc/shadow");

    let code = run(&[
        "pwck",
        "-r",
        "-R",
        dir.path().to_str().expect("non-utf8 path"),
        passwd_path.to_str().expect("non-utf8 path"),
        shadow_path.to_str().expect("non-utf8 path"),
    ]);
    assert_eq!(code, 2, "duplicate username should be detected (exit 2)");
}

#[test]
fn test_duplicate_uid() {
    if common::skip_unless_root() {
        return;
    }

    // Duplicate UIDs are detected by pwck. Two different users with same UID.
    let dir = setup_root(
        "alice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n",
        "alice:$6$hash:19000:0:99999:7:::\nbob:$6$hash:19000:0:99999:7:::\n",
        "users:x:1000:\n",
    );
    std::fs::create_dir_all(dir.path().join("home/alice")).expect("mkdir alice home");
    std::fs::create_dir_all(dir.path().join("home/bob")).expect("mkdir bob home");

    let passwd_path = dir.path().join("etc/passwd");
    let shadow_path = dir.path().join("etc/shadow");

    // Duplicate UIDs produce warnings (not errors) in pwck -- verify it does
    // not crash and completes. Exit code 0 is acceptable since duplicate UIDs
    // are only a warning in most pwck implementations.
    let code = run(&[
        "pwck",
        "-r",
        "-R",
        dir.path().to_str().expect("non-utf8 path"),
        passwd_path.to_str().expect("non-utf8 path"),
        shadow_path.to_str().expect("non-utf8 path"),
    ]);
    // Duplicate UIDs are a warning, not an error -- exit 0 is valid.
    assert!(
        code == 0 || code == 2,
        "duplicate UID should either warn (exit 0) or error (exit 2), got {code}"
    );
}

#[test]
fn test_empty_username() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        // Empty username: line starts with ":"
        ":x:1000:1000::/home/empty:/bin/bash\n",
        "",
        "users:x:1000:\n",
    );

    let passwd_path = dir.path().join("etc/passwd");
    let shadow_path = dir.path().join("etc/shadow");

    let code = run(&[
        "pwck",
        "-r",
        "-R",
        dir.path().to_str().expect("non-utf8 path"),
        passwd_path.to_str().expect("non-utf8 path"),
        shadow_path.to_str().expect("non-utf8 path"),
    ]);
    assert_eq!(
        code, 2,
        "empty username should be detected as invalid (exit 2)"
    );
}

#[test]
fn test_missing_home_dir() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        "alice:x:1000:1000::/home/nonexistent:/bin/bash\n",
        "alice:$6$hash:19000:0:99999:7:::\n",
        "users:x:1000:\n",
    );
    // Deliberately do NOT create /home/nonexistent.

    let passwd_path = dir.path().join("etc/passwd");
    let shadow_path = dir.path().join("etc/shadow");

    let code = run(&[
        "pwck",
        "-r",
        "-R",
        dir.path().to_str().expect("non-utf8 path"),
        passwd_path.to_str().expect("non-utf8 path"),
        shadow_path.to_str().expect("non-utf8 path"),
    ]);
    assert_eq!(
        code, 2,
        "missing home directory should be detected (exit 2)"
    );
}

#[test]
fn test_malformed_passwd_line() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_root(
        // Only 4 fields instead of 7.
        "root:x:0:0\n",
        "",
        "root:x:0:\n",
    );

    let passwd_path = dir.path().join("etc/passwd");
    let shadow_path = dir.path().join("etc/shadow");

    let code = run(&[
        "pwck",
        "-r",
        "-R",
        dir.path().to_str().expect("non-utf8 path"),
        passwd_path.to_str().expect("non-utf8 path"),
        shadow_path.to_str().expect("non-utf8 path"),
    ]);
    assert_eq!(code, 2, "malformed passwd line should be detected (exit 2)");
}

#[test]
fn test_nonexistent_passwd_exits_cant_open() {
    let code = run(&["pwck", "-r", "/nonexistent/passwd"]);
    assert_eq!(
        code, 3,
        "nonexistent passwd file should return exit code 3 (cant open)"
    );
}

// ---------------------------------------------------------------------------
// -s must not rewrite the files when there are errors (data-loss guard)
// ---------------------------------------------------------------------------

fn read_etc(dir: &tempfile::TempDir, name: &str) -> String {
    std::fs::read_to_string(dir.path().join("etc").join(name)).expect("read etc file")
}

#[test]
fn test_sort_with_parse_error_does_not_write() {
    // A malformed line plus a comment and out-of-order entries: `-s` would
    // reorder and, on the old code, drop the comment and the unparsable line.
    let dir = setup_root(
        "# keep this comment\n\
         z:x:1000:1000::/home/z:/bin/sh\n\
         broken:x:notanumber:0::/:/bin/sh\n\
         a:x:500:500::/home/a:/bin/sh\n",
        "z:!:19500::::::\na:!:19500::::::\n",
        "z:x:1000:\na:x:500:\n",
    );
    let prefix = dir.path().to_str().unwrap();
    let before = read_etc(&dir, "passwd");

    let code = run(&["pwck", "-s", "-R", prefix]);
    assert_eq!(code, 2, "a parse error must make pwck exit 2");
    assert_eq!(
        read_etc(&dir, "passwd"),
        before,
        "the file must be left untouched when there are errors"
    );
}

#[test]
fn test_read_only_and_sort_conflict() {
    let dir = setup_root(
        "root:x:0:0::/root:/bin/sh\n",
        "root:!:19500::::::\n",
        "root:x:0:\n",
    );
    let prefix = dir.path().to_str().unwrap();
    let code = run(&["pwck", "-r", "-s", "-R", prefix]);
    assert_ne!(code, 0, "-r and -s cannot be combined");
}
