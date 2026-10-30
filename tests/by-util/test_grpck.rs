// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore grpck gshadow

//! Integration tests for the `grpck` utility.
//!
//! Tests that require root are guarded by `crate::common::skip_unless_root()` and run inside
//! Docker CI containers. Non-root tests exercise clap parsing and error paths
//! that do not need privilege.

use std::ffi::OsString;

/// Run `uumain` with the given args, returning the exit code.
fn run(args: &[&str]) -> i32 {
    let os_args: Vec<OsString> = args.iter().map(|s| (*s).into()).collect();
    grpck::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with group and gshadow files at known paths.
/// Returns (`TempDir`, `group_path_string`, `gshadow_path_string`).
fn setup_files(group_content: &str, gshadow_content: &str) -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let group_path = dir.path().join("group");
    let gshadow_path = dir.path().join("gshadow");
    std::fs::write(&group_path, group_content).expect("failed to write group file");
    std::fs::write(&gshadow_path, gshadow_content).expect("failed to write gshadow file");
    let gp = group_path.to_str().expect("non-utf8 path").to_owned();
    let gsp = gshadow_path.to_str().expect("non-utf8 path").to_owned();
    (dir, gp, gsp)
}

// ---------------------------------------------------------------------------
// Non-root tests -- exercise clap parsing and error paths
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["grpck", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_error() {
    let code = run(&["grpck", "--bogus"]);
    assert!(code != 0, "unknown flag should exit non-zero");
}

#[test]
fn test_read_only_mode() {
    // -r with a nonexistent file still exits 3 (cant open), but -r is accepted.
    let code = run(&["grpck", "-r", "/nonexistent/group"]);
    assert_eq!(
        code, 3,
        "-r with nonexistent file should exit 3 (cant open)"
    );
}

// ---------------------------------------------------------------------------
// Root-only tests -- exercise full checks via positional file arguments
// ---------------------------------------------------------------------------

#[test]
fn test_valid_files_exits_zero() {
    if crate::common::skip_unless_root() {
        return;
    }

    let (_dir, gp, gsp) = setup_files("root:x:0:\nusers:x:1000:\n", "root:!::\nusers:!::\n");

    let code = run(&["grpck", "-r", &gp, &gsp]);
    assert_eq!(code, 0, "consistent group+gshadow should return 0");
}

#[test]
fn test_missing_gshadow_entry() {
    if crate::common::skip_unless_root() {
        return;
    }

    let (_dir, gp, gsp) = setup_files(
        "root:x:0:\nusers:x:1000:\n",
        // gshadow only has root, not users.
        "root:!::\n",
    );

    let code = run(&["grpck", "-r", &gp, &gsp]);
    assert_eq!(
        code, 2,
        "group without gshadow entry should be detected (exit 2)"
    );
}

#[test]
fn test_extra_gshadow_entry() {
    if crate::common::skip_unless_root() {
        return;
    }

    let (_dir, gp, gsp) = setup_files(
        "root:x:0:\n",
        // gshadow has root + orphan (no matching group entry).
        "root:!::\norphan:!::\n",
    );

    let code = run(&["grpck", "-r", &gp, &gsp]);
    assert_eq!(
        code, 2,
        "gshadow without matching group entry should be detected (exit 2)"
    );
}

#[test]
fn test_invalid_gid() {
    if crate::common::skip_unless_root() {
        return;
    }

    let (_dir, gp, gsp) = setup_files(
        // GID field is "abc" -- not a valid number.
        "badgroup:x:abc:\n",
        "",
    );

    let code = run(&["grpck", "-r", &gp, &gsp]);
    assert_eq!(
        code, 2,
        "non-numeric GID should be detected as invalid (exit 2)"
    );
}

#[test]
fn test_duplicate_group_name() {
    if crate::common::skip_unless_root() {
        return;
    }

    let (_dir, gp, gsp) = setup_files("users:x:1000:\nusers:x:1001:\n", "users:!::\n");

    let code = run(&["grpck", "-r", &gp, &gsp]);
    assert_eq!(code, 2, "duplicate group name should be detected (exit 2)");
}

#[test]
fn test_empty_group_name() {
    if crate::common::skip_unless_root() {
        return;
    }

    let (_dir, gp, gsp) = setup_files(
        // Empty group name: line starts with ":"
        ":x:1000:\n",
        "",
    );

    let code = run(&["grpck", "-r", &gp, &gsp]);
    assert_eq!(
        code, 2,
        "empty group name should be detected as invalid (exit 2)"
    );
}

#[test]
fn test_malformed_group_line() {
    if crate::common::skip_unless_root() {
        return;
    }

    let (_dir, gp, gsp) = setup_files(
        // Only 2 fields instead of 4.
        "badentry:x\n",
        "",
    );

    let code = run(&["grpck", "-r", &gp, &gsp]);
    assert_eq!(code, 2, "malformed group line should be detected (exit 2)");
}

#[test]
fn test_nonexistent_group_exits_cant_open() {
    let code = run(&["grpck", "-r", "/nonexistent/group"]);
    assert_eq!(
        code, 3,
        "nonexistent group file should return exit code 3 (cant open)"
    );
}

#[test]
fn test_valid_group_without_gshadow_file() {
    if crate::common::skip_unless_root() {
        return;
    }

    // When gshadow file does not exist, grpck should succeed if group is valid.
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let group_path = dir.path().join("group");
    let gshadow_path = dir.path().join("gshadow_nonexistent");
    std::fs::write(&group_path, "root:x:0:\nusers:x:1000:\n").expect("write group");

    let code = run(&[
        "grpck",
        "-r",
        group_path.to_str().expect("non-utf8 path"),
        gshadow_path.to_str().expect("non-utf8 path"),
    ]);
    assert_eq!(code, 0, "valid group without gshadow file should return 0");
}

// ---------------------------------------------------------------------------
// -s must not rewrite the files when there are errors (data-loss guard)
// ---------------------------------------------------------------------------

#[test]
fn test_sort_with_parse_error_does_not_write() {
    let (dir, gp, gsp) = setup_files(
        "# keep this comment\n\
         z:x:1000:\n\
         broken:x:notanumber:\n\
         a:x:500:\n",
        "z:!::\na:!::\n",
    );
    let before = std::fs::read_to_string(&gp).unwrap();

    let code = run(&["grpck", "-s", &gp, &gsp]);
    assert_eq!(code, 2, "a parse error must make grpck exit 2");
    assert_eq!(
        std::fs::read_to_string(&gp).unwrap(),
        before,
        "the file must be left untouched when there are errors"
    );
    let _ = dir;
}

#[test]
fn test_read_only_and_sort_conflict() {
    let (dir, gp, gsp) = setup_files("root:x:0:\n", "root:!::\n");
    let code = run(&["grpck", "-r", "-s", &gp, &gsp]);
    assert_ne!(code, 0, "-r and -s cannot be combined");
    let _ = dir;
}

#[test]
fn test_quiet_still_reports_errors_and_bad_gshadow() {
    // grpck(8) -q: "Report errors only" — it suppresses warnings, not errors.
    let (dir, gp, gsp) = setup_files("bad:x:notanumber:\n", "bad:!::\n");
    let _ = &dir;
    assert_eq!(
        run(&["grpck", "-r", "-q", &gp, &gsp]),
        2,
        "a malformed entry is an error even with -q"
    );
}

#[test]
fn test_malformed_gshadow_is_reported() {
    // A gshadow that cannot be parsed used to read as "nothing to check".
    let (dir, gp, gsp) = setup_files("good:x:1000:\n", "this is not a gshadow line\n");
    let _ = &dir;
    assert_eq!(run(&["grpck", "-r", &gp, &gsp]), 2);
}

/// Run grpck as a child, so its streams can be read. `root` is a member and an
/// admin who exists anywhere; `ghost` is one who does not.
fn grpck_files(group: &str, gshadow: &str, extra: &[&str]) -> crate::common::Output {
    let (_dir, gp, gsp) = setup_files(group, gshadow);
    let mut cmd = crate::common::tool("grpck");
    cmd.arg("-r").args(extra).arg(&gp).arg(&gsp);
    crate::common::run_cmd(&mut cmd)
}

/// A report, the way Ubuntu 26.04's grpck ends one, with -q or without.
fn assert_reported(group: &str, gshadow: &str, needle: &str) {
    for extra in [&[][..], &["-q"]] {
        let out = grpck_files(group, gshadow, extra);
        out.assert_code(2).assert_stdout_contains(needle);
        assert!(out.stdout.ends_with("grpck: no changes\n"), "{out:?}");
        assert_eq!(out.stderr, "", "{out:?}");
    }
}

#[test]
fn test_clean_files_print_nothing() {
    let out = grpck_files("root:x:0:root\n", "root:!::root\n", &[]);
    assert_eq!(
        (out.code, out.stdout.as_str(), out.stderr.as_str()),
        (0, "", "")
    );
}

#[test]
fn test_problems_go_to_stdout_and_end_with_no_changes() {
    assert_reported("a:x:1:\na:x:2:\n", "a:!::\n", "duplicate group entry");
    assert_reported("a:x:1:\n", "", "no matching gshadow entry");
    assert_reported("", "a:!::\n", "no matching group entry");
    assert_reported("bad\n", "", "invalid group file entry");
    assert_reported("a:x:1:\n", "not a gshadow line\n", "cannot read");
}

// Probed on Ubuntu 26.04: exit 2 on all of these, and the wording of the first
// three is theirs, without the offer to delete.
#[test]
fn test_members_and_admins_have_to_be_users_in_both_files() {
    assert_reported("a:x:1:ghost\n", "a:!::ghost\n", "group a: no user ghost\n");
    assert_reported(
        "a:x:1:\n",
        "a:!::ghost\n",
        "shadow group a: no user ghost\n",
    );
    assert_reported(
        "a:x:1:\n",
        "a:!:ghost:\n",
        "shadow group a: no administrative user ghost\n",
    );
}

#[test]
fn test_duplicate_gshadow_entry() {
    assert_reported("a:x:1:\n", "a:!::\na:!::\n", "duplicate shadow group entry");
}

#[test]
fn test_group_password_field_not_x() {
    for field in ["abc", ""] {
        assert_reported(
            &format!("a:{field}:1:\n"),
            "a:!::\n",
            "group a has an entry in",
        );
    }
}

// Membership that differs between the two files is said, but not a failure, on
// Ubuntu 26.04: exit 0, with -q as well, and no "no changes".
#[test]
fn test_members_that_differ_are_reported_with_exit_0() {
    for extra in [&[][..], &["-q"]] {
        let out = grpck_files("a:x:1:root\n", "a:!::\n", extra);
        assert_eq!((out.code, out.stderr.as_str()), (0, ""));
        assert!(
            out.stdout
                .starts_with("'root' is a member of the 'a' group in ")
                && out.stdout.contains(" but not in "),
            "{out:?}"
        );

        let out = grpck_files("a:x:1:\n", "a:!::root\n", extra);
        assert_eq!((out.code, out.stderr.as_str()), (0, ""));
        assert!(out.stdout.contains("'root' is a member"), "{out:?}");
    }
}

// The names Ubuntu 26.04's grpck takes and refuses. Unlike a user name, a group
// name stops at 32 characters.
#[test]
fn test_group_names_upstream_accepts_and_refuses() {
    let long_32 = "a".repeat(32);
    let long_33 = "a".repeat(33);
    for name in [
        "Upper", "a.b", "1abc", "a$", ".a", "a.", "_", "1e5", &long_32,
    ] {
        let out = grpck_files(&format!("{name}:x:1:\n"), &format!("{name}:!::\n"), &[]);
        assert_eq!(out.code, 0, "{name}: {out:?}");
    }
    for name in [
        "a@b", "a b", "a,b", "é", "123", "0", "0x1", ".", "..", "$", "a$b", &long_33,
    ] {
        assert_reported(
            &format!("{name}:x:1:\n"),
            &format!("{name}:!::\n"),
            "invalid group name",
        );
    }
}

#[test]
fn test_silence_warnings_hides_only_members_that_differ() {
    for flag in ["-S", "--silence-warnings"] {
        let out = grpck_files("a:x:1:root\n", "a:!::\n", &[flag]);
        assert_eq!((out.code, out.stdout.as_str()), (0, ""), "{flag}");
        grpck_files("a:x:1:ghost\n", "a:!::ghost\n", &[flag])
            .assert_code(2)
            .assert_stdout_contains("group a: no user ghost");
    }
}
