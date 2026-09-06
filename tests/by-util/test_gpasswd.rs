// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore gpasswd gshadow

//! Integration tests for the `gpasswd` utility.
//!
//! Tests that require root are guarded by `crate::common::skip_unless_root()` and run
//! inside Docker CI containers. Non-root tests exercise clap parsing and error
//! paths that do not need privilege.

use std::ffi::OsString;

/// Run `uumain` with the given args, returning the exit code.
fn run(args: &[&str]) -> i32 {
    let os_args: Vec<OsString> = args.iter().map(|s| (*s).into()).collect();
    gpasswd::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with `etc/group`, `etc/gshadow`, and `etc/passwd`.
fn setup_prefix() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");

    std::fs::write(etc.join("group"), "root:x:0:\ndevs:x:1000:bob\n")
        .expect("failed to write group file");
    std::fs::write(etc.join("gshadow"), "root:!::\ndevs:!::bob\n")
        .expect("failed to write gshadow file");
    std::fs::write(
        etc.join("passwd"),
        "root:x:0:0:root:/root:/bin/bash\n\
bob:x:1000:1000::/home/bob:/bin/bash\n\
alice:x:1001:1001::/home/alice:/bin/bash\n",
    )
    .expect("failed to write passwd file");

    dir
}

fn setup_prefix_without_gshadow() -> tempfile::TempDir {
    let dir = setup_prefix();
    std::fs::remove_file(dir.path().join("etc/gshadow")).expect("remove gshadow");
    dir
}

/// Run `uumain` with a `--prefix` dir prepended to the args.
fn run_with_prefix(dir: &tempfile::TempDir, extra_args: &[&str]) -> i32 {
    let prefix_str = dir.path().to_str().expect("non-UTF-8 temp path");
    let mut args = vec!["gpasswd", "-P", prefix_str];
    args.extend_from_slice(extra_args);
    run(&args)
}

fn read_group(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/group")).expect("failed to read group file")
}

fn read_gshadow(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/gshadow")).expect("failed to read gshadow file")
}

fn named_line(content: &str, name: &str) -> String {
    let prefix = format!("{name}:");
    content
        .lines()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("missing {name} entry in:\n{content}"))
        .to_owned()
}

fn colon_fields(line: &str) -> Vec<&str> {
    line.split(':').collect()
}

// ---------------------------------------------------------------------------
// Non-root tests -- clap parsing and error paths
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let code = run(&["gpasswd", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_missing_group_exits_error() {
    let code = run(&["gpasswd"]);
    assert_eq!(code, 2, "missing GROUP should exit 2");
}

#[test]
fn test_unknown_flag_exits_error() {
    let code = run(&["gpasswd", "--bogus", "devs"]);
    assert_eq!(code, 2, "unknown flag should exit 2");
}

#[test]
fn test_relative_root_exits_error() {
    let code = run(&["gpasswd", "-Q", "tmp", "-r", "devs"]);
    assert_eq!(code, 3, "relative --root should exit 3");
}

#[test]
fn test_add_and_restrict_exits_error() {
    let code = run(&["gpasswd", "-a", "alice", "-R", "devs"]);
    assert_eq!(code, 2, "exclusive options should exit 2");
}

#[test]
fn test_add_and_admins_combination_fails() {
    let code = run(&["gpasswd", "-a", "alice", "-A", "alice", "devs"]);
    assert_eq!(code, 2, "-a and -A cannot be combined");
}

// ---------------------------------------------------------------------------
// Root-only tests -- real operations via --prefix
// ---------------------------------------------------------------------------

#[test]
fn test_add_user() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    let code = run_with_prefix(&dir, &["-a", "alice", "devs"]);
    assert_eq!(code, 0, "gpasswd -a should exit 0");

    let group = named_line(&read_group(&dir), "devs");
    let members = colon_fields(&group)[3];
    assert!(
        members.split(',').any(|m| m == "alice"),
        "alice should appear in /etc/group, got: {group}"
    );
    assert!(
        members.split(',').any(|m| m == "bob"),
        "bob should remain in /etc/group, got: {group}"
    );

    let gshadow = named_line(&read_gshadow(&dir), "devs");
    let gs_members = colon_fields(&gshadow)[3];
    assert!(
        gs_members.split(',').any(|m| m == "alice"),
        "alice should appear in /etc/gshadow, got: {gshadow}"
    );
}

#[test]
fn test_add_user_idempotent() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    assert_eq!(run_with_prefix(&dir, &["-a", "alice", "devs"]), 0);
    assert_eq!(
        run_with_prefix(&dir, &["-a", "alice", "devs"]),
        0,
        "adding an existing member should still exit 0"
    );

    let group = named_line(&read_group(&dir), "devs");
    let count = colon_fields(&group)[3]
        .split(',')
        .filter(|m| *m == "alice")
        .count();
    assert_eq!(count, 1, "alice should appear only once, got: {group}");
}

#[test]
fn test_delete_non_member_fails() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    let code = run_with_prefix(&dir, &["-d", "alice", "devs"]);
    assert_eq!(code, 3, "deleting a non-member should exit 3");
    let group = named_line(&read_group(&dir), "devs");
    assert!(
        colon_fields(&group)[3].split(',').any(|m| m == "bob"),
        "bob should remain, got: {group}"
    );
}

#[test]
fn test_delete_user() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    let code = run_with_prefix(&dir, &["-d", "bob", "devs"]);
    assert_eq!(code, 0, "gpasswd -d should exit 0");

    let group = named_line(&read_group(&dir), "devs");
    let members = colon_fields(&group)[3];
    assert!(
        !members.split(',').any(|m| m == "bob"),
        "bob should be removed from /etc/group, got: {group}"
    );
}

#[test]
fn test_delete_does_not_remove_admin() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    std::fs::write(
        dir.path().join("etc/gshadow"),
        "root:!::\ndevs:!:alice:alice,bob\n",
    )
    .expect("write gshadow");
    std::fs::write(
        dir.path().join("etc/group"),
        "root:x:0:\ndevs:x:1000:alice,bob\n",
    )
    .expect("write group");

    assert_eq!(run_with_prefix(&dir, &["-d", "alice", "devs"]), 0);

    let gshadow = named_line(&read_gshadow(&dir), "devs");
    let fields = colon_fields(&gshadow);
    assert!(
        fields[2].split(',').any(|a| a == "alice"),
        "alice should remain an admin, got: {gshadow}"
    );
    assert!(
        !fields[3].split(',').any(|m| m == "alice"),
        "alice should be removed from members, got: {gshadow}"
    );
}

#[test]
fn test_set_members() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    let code = run_with_prefix(&dir, &["-M", "alice,bob", "devs"]);
    assert_eq!(code, 0, "gpasswd -M should exit 0");

    let group = named_line(&read_group(&dir), "devs");
    let members = colon_fields(&group)[3];
    assert!(
        members.split(',').any(|m| m == "alice") && members.split(',').any(|m| m == "bob"),
        "both members should be present, got: {group}"
    );

    let gshadow = named_line(&read_gshadow(&dir), "devs");
    let gs_members = colon_fields(&gshadow)[3];
    assert!(
        gs_members.split(',').any(|m| m == "alice") && gs_members.split(',').any(|m| m == "bob"),
        "both members should be in gshadow, got: {gshadow}"
    );
}

#[test]
fn test_clear_members() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    let code = run_with_prefix(&dir, &["-M", "", "devs"]);
    assert_eq!(code, 0, "gpasswd -M '' should exit 0");

    let group = named_line(&read_group(&dir), "devs");
    assert_eq!(
        colon_fields(&group)[3],
        "",
        "members should be empty, got: {group}"
    );
}

#[test]
fn test_set_administrators() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    let code = run_with_prefix(&dir, &["-A", "alice", "devs"]);
    assert_eq!(code, 0, "gpasswd -A should exit 0");

    let gshadow = named_line(&read_gshadow(&dir), "devs");
    let fields = colon_fields(&gshadow);
    assert!(
        fields.len() >= 3 && fields[2].split(',').any(|a| a == "alice"),
        "alice should be an admin, got: {gshadow}"
    );

    let group = named_line(&read_group(&dir), "devs");
    assert_eq!(
        colon_fields(&group)[3],
        "bob",
        "-A must not change group members, got: {group}"
    );
}

#[test]
fn test_set_admins_and_members_together() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    let code = run_with_prefix(&dir, &["-A", "alice", "-M", "alice,bob", "devs"]);
    assert_eq!(code, 0, "gpasswd -A -M should exit 0");

    let gshadow = named_line(&read_gshadow(&dir), "devs");
    let fields = colon_fields(&gshadow);
    assert!(
        fields[2].split(',').any(|a| a == "alice"),
        "alice should be an admin, got: {gshadow}"
    );
    assert!(
        fields[3].split(',').any(|m| m == "alice") && fields[3].split(',').any(|m| m == "bob"),
        "both members should be set, got: {gshadow}"
    );
}

#[test]
fn test_administrators_without_gshadow_fails() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix_without_gshadow();
    let code = run_with_prefix(&dir, &["-A", "alice", "devs"]);
    assert_eq!(code, 17, "-A without gshadow should exit 17");
}

#[test]
fn test_remove_password() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    std::fs::write(
        dir.path().join("etc/gshadow"),
        "root:!::\ndevs:$6$salt$hash::bob\n",
    )
    .expect("write gshadow");

    let code = run_with_prefix(&dir, &["-r", "devs"]);
    assert_eq!(code, 0, "gpasswd -r should exit 0");

    let gshadow = named_line(&read_gshadow(&dir), "devs");
    let fields = colon_fields(&gshadow);
    assert_eq!(
        fields[1], "",
        "password field should be empty, got: {gshadow}"
    );
}

#[test]
fn test_restrict() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    let code = run_with_prefix(&dir, &["-R", "devs"]);
    assert_eq!(code, 0, "gpasswd -R should exit 0");

    let gshadow = named_line(&read_gshadow(&dir), "devs");
    let fields = colon_fields(&gshadow);
    assert_eq!(fields[1], "!", "password should be !, got: {gshadow}");
}

#[test]
fn test_restrict_without_gshadow() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix_without_gshadow();
    let code = run_with_prefix(&dir, &["-R", "devs"]);
    assert_eq!(code, 0, "gpasswd -R without gshadow should exit 0");

    let group = named_line(&read_group(&dir), "devs");
    assert_eq!(
        colon_fields(&group)[1],
        "!",
        "group password should be !, got: {group}"
    );
}

#[test]
fn test_remove_password_without_gshadow() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix_without_gshadow();
    std::fs::write(
        dir.path().join("etc/group"),
        "root:x:0:\ndevs:hash:1000:bob\n",
    )
    .expect("write group");

    let code = run_with_prefix(&dir, &["-r", "devs"]);
    assert_eq!(code, 0, "gpasswd -r without gshadow should exit 0");

    let group = named_line(&read_group(&dir), "devs");
    assert_eq!(
        colon_fields(&group)[1],
        "",
        "group password should be empty, got: {group}"
    );
}

#[test]
fn test_creates_gshadow_entry() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    std::fs::write(dir.path().join("etc/gshadow"), "root:!::\n").expect("write gshadow");

    assert_eq!(run_with_prefix(&dir, &["-a", "alice", "devs"]), 0);

    let gshadow = named_line(&read_gshadow(&dir), "devs");
    let fields = colon_fields(&gshadow);
    assert_eq!(
        fields[1], "x",
        "new gshadow password should copy /etc/group, got: {gshadow}"
    );
    assert!(
        fields[3].split(',').any(|m| m == "alice"),
        "created gshadow line should list alice, got: {gshadow}"
    );
}

#[test]
fn test_nonexistent_group_fails() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    let code = run_with_prefix(&dir, &["-a", "alice", "missing"]);
    assert_eq!(code, 3, "missing group should exit 3");
}

#[test]
fn test_nonexistent_user_fails() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    let code = run_with_prefix(&dir, &["-a", "nobody", "devs"]);
    assert_eq!(code, 3, "missing user should exit 3 (BAD_ARGUMENT)");
}

#[test]
fn test_preserves_other_entries() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_prefix();
    assert_eq!(run_with_prefix(&dir, &["-a", "alice", "devs"]), 0);

    let group = read_group(&dir);
    assert!(
        group.contains("root:x:0:"),
        "root entry should be preserved, got: {group}"
    );
}
