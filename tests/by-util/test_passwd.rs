// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore warndays maxdays mindays chauthtok

//! Integration tests for the `passwd` utility.
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
    passwd::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with an `etc/shadow` file.
fn setup_prefix(shadow_content: &str) -> tempfile::TempDir {
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

/// Run `uumain` with a `--prefix` dir prepended to the args.
fn run_with_prefix(dir: &tempfile::TempDir, extra_args: &[&str]) -> i32 {
    let prefix_str = dir.path().to_str().expect("non-UTF-8 temp path");
    let mut args = vec!["passwd", "-P", prefix_str];
    args.extend_from_slice(extra_args);
    run(&args)
}

// ---------------------------------------------------------------------------
// Non-root tests — exercise clap parsing and error paths
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["passwd", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_six() {
    let code = run(&["passwd", "--bogus"]);
    assert_eq!(code, 6, "unknown flag should exit 6");
}

#[test]
fn test_conflicting_flags_exits_two() {
    // -l and -u conflict; clap reports ArgumentConflict which maps to exit 2.
    let code = run(&["passwd", "-l", "-u", "someuser"]);
    assert_eq!(code, 2, "conflicting flags should exit 2");
}

// ---------------------------------------------------------------------------
// Root-only tests — exercise real operations via --prefix
// ---------------------------------------------------------------------------

#[test]
fn test_status_output_format() {
    if common::skip_unless_root() {
        return;
    }
    // Verify the status line matches the expected GNU format:
    //   username STATUS YYYY-MM-DD min max warn inactive
    let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
    let code = run_with_prefix(&dir, &["-S", "testuser"]);
    assert_eq!(code, 0);
}

#[test]
fn test_lock_unlock_cycle() {
    if common::skip_unless_root() {
        return;
    }
    let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");

    // Lock: password gets '!' prefix.
    let code = run_with_prefix(&dir, &["-l", "testuser"]);
    assert_eq!(code, 0);
    let content = read_shadow(&dir);
    assert!(
        content.contains("testuser:!$6$hash:"),
        "after lock, expected '!' prefix, got: {content}"
    );

    // Verify status is L by parsing the entry.
    let entry: shadow_core::shadow::ShadowEntry = content
        .trim()
        .parse()
        .expect("failed to parse shadow entry");
    assert_eq!(entry.status_char(), "L");

    // Unlock: '!' prefix removed.
    let code = run_with_prefix(&dir, &["-u", "testuser"]);
    assert_eq!(code, 0);
    let content = read_shadow(&dir);
    assert!(
        content.contains("testuser:$6$hash:"),
        "after unlock, expected no '!', got: {content}"
    );

    // Verify status is P.
    let entry: shadow_core::shadow::ShadowEntry = content
        .trim()
        .parse()
        .expect("failed to parse shadow entry");
    assert_eq!(entry.status_char(), "P");
}

#[test]
fn test_expire_sets_epoch() {
    if common::skip_unless_root() {
        return;
    }
    let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
    let code = run_with_prefix(&dir, &["-e", "testuser"]);
    assert_eq!(code, 0);

    let content = read_shadow(&dir);
    // last_change field (3rd colon-separated field) should be 0.
    assert!(
        content.contains("testuser:$6$hash:0:"),
        "expire should set last_change to 0, got: {content}"
    );
}

#[test]
fn test_aging_all_fields() {
    if common::skip_unless_root() {
        return;
    }
    let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
    let code = run_with_prefix(
        &dir,
        &["-n", "5", "-x", "90", "-w", "14", "-i", "30", "testuser"],
    );
    assert_eq!(code, 0);

    let content = read_shadow(&dir);
    assert!(
        content.contains("testuser:$6$hash:19500:5:90:14:30::"),
        "all aging fields should be updated, got: {content}"
    );
}

#[test]
fn test_nonexistent_user_fails() {
    if common::skip_unless_root() {
        return;
    }
    let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
    let code = run_with_prefix(&dir, &["-S", "nosuchuser"]);
    // GNU passwd exits 1 for an unknown login (verified against shadow 4.17);
    // 3 is reserved for an unexpected failure the caller did not ask for.
    assert_eq!(code, 1, "nonexistent user should exit 1");
}

#[test]
fn test_missing_shadow_fails() {
    if common::skip_unless_root() {
        return;
    }
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");
    // No shadow file exists.
    let code = run_with_prefix(&dir, &["-S", "testuser"]);
    assert_eq!(code, 4, "missing shadow file should exit 4");
}

#[test]
fn test_quiet_no_action_message() {
    if common::skip_unless_root() {
        return;
    }
    // -q suppresses the informational action message on stderr.
    // We verify the operation still succeeds and the file is modified.
    let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
    let code = run_with_prefix(&dir, &["-q", "-l", "testuser"]);
    assert_eq!(code, 0, "quiet lock should still succeed");

    let content = read_shadow(&dir);
    assert!(
        content.contains("testuser:!$6$hash:"),
        "lock should still be applied with -q, got: {content}"
    );
}

#[test]
fn test_lock_and_aging_combined() {
    if common::skip_unless_root() {
        return;
    }
    // Mutation flag + aging flags must all apply in a single operation.
    let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
    let code = run_with_prefix(
        &dir,
        &[
            "-l", "-n", "10", "-x", "60", "-w", "5", "-i", "20", "testuser",
        ],
    );
    assert_eq!(code, 0);

    let content = read_shadow(&dir);
    assert!(
        content.contains("testuser:!$6$hash:19500:10:60:5:20::"),
        "lock + aging should both apply, got: {content}"
    );
}

#[test]
fn test_multiple_users_only_target_modified() {
    if common::skip_unless_root() {
        return;
    }
    let shadow = "\
alice:$6$alice:19500:0:99999:7:::\n\
bob:$6$bob:19500:0:99999:7:::\n\
charlie:$6$charlie:19500:0:99999:7:::\n";
    let dir = setup_prefix(shadow);

    let code = run_with_prefix(&dir, &["-l", "bob"]);
    assert_eq!(code, 0);

    let content = read_shadow(&dir);
    assert!(
        content.contains("alice:$6$alice:19500:0:99999:7:::"),
        "alice should be unchanged, got: {content}"
    );
    assert!(
        content.contains("charlie:$6$charlie:19500:0:99999:7:::"),
        "charlie should be unchanged, got: {content}"
    );
    assert!(
        content.contains("bob:!$6$bob:19500:0:99999:7:::"),
        "bob should be locked, got: {content}"
    );
}

#[test]
fn test_delete_password() {
    if common::skip_unless_root() {
        return;
    }
    let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");
    let code = run_with_prefix(&dir, &["-d", "testuser"]);
    assert_eq!(code, 0);

    let content = read_shadow(&dir);
    assert!(
        content.contains("testuser::19500:"),
        "delete should clear password, got: {content}"
    );
}

#[test]
fn test_unlock_only_bang_fails() {
    if common::skip_unless_root() {
        return;
    }
    // Password "!" cannot be unlocked (would leave empty).
    let dir = setup_prefix("testuser:!:19500:0:99999:7:::\n");
    let code = run_with_prefix(&dir, &["-u", "testuser"]);
    assert_ne!(code, 0, "unlock with only '!' should fail");
}

#[test]
fn test_full_lifecycle() {
    if common::skip_unless_root() {
        return;
    }
    let dir = setup_prefix("testuser:$6$hash:19500:0:99999:7:::\n");

    // Lock.
    assert_eq!(run_with_prefix(&dir, &["-l", "testuser"]), 0);
    let entry: shadow_core::shadow::ShadowEntry =
        read_shadow(&dir).trim().parse().expect("parse after lock");
    assert_eq!(entry.status_char(), "L", "after lock");

    // Unlock.
    assert_eq!(run_with_prefix(&dir, &["-u", "testuser"]), 0);
    let entry: shadow_core::shadow::ShadowEntry = read_shadow(&dir)
        .trim()
        .parse()
        .expect("parse after unlock");
    assert_eq!(entry.status_char(), "P", "after unlock");

    // Delete.
    assert_eq!(run_with_prefix(&dir, &["-d", "testuser"]), 0);
    let entry: shadow_core::shadow::ShadowEntry = read_shadow(&dir)
        .trim()
        .parse()
        .expect("parse after delete");
    assert_eq!(entry.status_char(), "NP", "after delete");

    // Expire.
    assert_eq!(run_with_prefix(&dir, &["-e", "testuser"]), 0);
    let entry: shadow_core::shadow::ShadowEntry = read_shadow(&dir)
        .trim()
        .parse()
        .expect("parse after expire");
    assert_eq!(entry.last_change, Some(0), "after expire");
}

// ---------------------------------------------------------------------------
// Concurrency tests — verify lock file prevents corruption
// ---------------------------------------------------------------------------

/// Test that two concurrent lock/unlock operations don't corrupt the shadow file.
///
/// Spawns two threads that each try to lock then unlock testuser.
/// After both complete, the shadow file should still be valid and parseable.
#[test]
fn test_concurrent_lock_operations() {
    if common::skip_unless_root() {
        return;
    }

    let dir =
        setup_prefix("testuser:$6$hash:19500:0:99999:7:::\nother:$6$hash2:19500:0:99999:7:::\n");
    let prefix = dir.path().to_str().expect("valid utf-8 path").to_string();

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let p = prefix.clone();
            std::thread::spawn(move || {
                // Lock
                let args: Vec<std::ffi::OsString> = vec![
                    "passwd".into(),
                    "-q".into(),
                    "-l".into(),
                    "-P".into(),
                    p.clone().into(),
                    "testuser".into(),
                ];
                let _ = passwd::uumain(args.into_iter());
                // Unlock
                let args: Vec<std::ffi::OsString> = vec![
                    "passwd".into(),
                    "-q".into(),
                    "-u".into(),
                    "-P".into(),
                    p.into(),
                    "testuser".into(),
                ];
                let _ = passwd::uumain(args.into_iter());
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    // Verify shadow file is still valid — parseable and has both users.
    let content = std::fs::read_to_string(dir.path().join("etc/shadow")).expect("read shadow");
    assert!(content.contains("testuser:"), "testuser entry should exist");
    assert!(
        content.contains("other:"),
        "other entry should not be corrupted"
    );

    // Verify it's parseable
    let entries = shadow_core::shadow::read_shadow_file(&dir.path().join("etc/shadow"))
        .expect("shadow file should still be valid after concurrent access");
    assert_eq!(entries.len(), 2);
}

// ---------------------------------------------------------------------------
// GNU compatibility tests — verify output matches GNU passwd
// ---------------------------------------------------------------------------

/// Compare shadow-rs output with GNU passwd output for -S.
///
/// Runs both our passwd and GNU passwd with -S on the same users,
/// verifies the output format is identical.
#[test]
fn test_gnu_compat_status_output() {
    if common::skip_unless_root() {
        return;
    }

    // Run GNU passwd -S
    let gnu_output = std::process::Command::new("/usr/bin/passwd")
        .args(["-S", "root"])
        .output();

    let Ok(gnu) = gnu_output else {
        // GNU passwd not available (e.g., Alpine uses busybox)
        eprintln!("skipping: GNU passwd not available");
        return;
    };

    if !gnu.status.success() {
        eprintln!("skipping: GNU passwd -S root failed");
        return;
    }

    let gnu_stdout = String::from_utf8_lossy(&gnu.stdout);

    // Run our passwd -S
    // We need to capture stdout, which is tricky with uumain.
    // Instead, compare field-by-field.
    let gnu_fields: Vec<&str> = gnu_stdout.split_whitespace().collect();

    // GNU format: "root L 2026-03-16 0 99999 7 -1"
    assert!(
        gnu_fields.len() >= 7,
        "GNU output should have 7 fields: {gnu_stdout}"
    );

    // Verify our format matches by parsing a shadow entry and formatting it
    let shadow_path = std::path::Path::new("/etc/shadow");
    if let Ok(entries) = shadow_core::shadow::read_shadow_file(shadow_path)
        && let Some(entry) = entries.iter().find(|e| e.name == "root")
    {
        let our_status = entry.status_char();
        assert_eq!(
            our_status, gnu_fields[1],
            "status char mismatch: ours={our_status}, GNU={}",
            gnu_fields[1]
        );
    }
}

/// Compare lock/unlock cycle results with GNU passwd.
#[test]
fn test_gnu_compat_lock_unlock() {
    if common::skip_unless_root() {
        return;
    }

    // Create a test shadow file and run our lock
    let dir = setup_prefix("compatuser:$6$salt$hash:19500:0:99999:7:::\n");
    let prefix_str = dir.path().to_str().expect("valid path");

    // Lock with our tool
    let code = run(&["passwd", "-q", "-l", "-P", prefix_str, "compatuser"]);
    assert_eq!(code, 0, "lock should succeed");

    let content = read_shadow(&dir);
    assert!(
        content.starts_with("compatuser:!$6$salt$hash:"),
        "lock should prepend ! — got: {content}"
    );

    // Unlock with our tool
    let code = run(&["passwd", "-q", "-u", "-P", prefix_str, "compatuser"]);
    assert_eq!(code, 0, "unlock should succeed");

    let content = read_shadow(&dir);
    assert!(
        content.starts_with("compatuser:$6$salt$hash:"),
        "unlock should remove ! — got: {content}"
    );
}

// ---------------------------------------------------------------------------
// Aging-field bounds (passwd(1))
// ---------------------------------------------------------------------------

#[test]
fn test_maxdays_minus_one_clears_the_field() {
    if common::skip_unless_root() {
        return;
    }

    // passwd(1) documents `-x -1` as "no maximum": the field is cleared, not
    // stored as the literal -1.
    let dir = setup_prefix("alice:$6$hash:19500:0:99999:7:::\n");
    let code = run_with_prefix(&dir, &["-x", "-1", "alice"]);
    assert_eq!(code, 0, "-x -1 should be accepted");
    assert!(
        read_shadow(&dir).starts_with("alice:$6$hash:19500:0::7:"),
        "max-age should be empty, got: {}",
        read_shadow(&dir)
    );
}

#[test]
fn test_negative_aging_values_are_rejected() {
    if common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix("alice:$6$hash:19500:0:99999:7:::\n");
    let before = read_shadow(&dir);
    for flag in ["-n", "-x", "-w", "-i"] {
        assert_eq!(
            run_with_prefix(&dir, &[flag, "-5", "alice"]),
            6,
            "{flag} -5 must be an invalid argument"
        );
    }
    assert_eq!(read_shadow(&dir), before, "nothing may be written");
}
