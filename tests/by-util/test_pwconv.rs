// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore pwconv pwunconv grpconv grpunconv gshadow

//! Integration tests for `pwconv`, `pwunconv`, `grpconv` and `grpunconv`.
//!
//! Each tool moves fields between two files and may create or remove one of
//! them, so the tests run the real binary against a prefix tree and read both
//! files back, along with the mode and owner of anything created.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use crate::common::{run_cmd, skip_unless_root, tool};

/// A prefix tree. `shadowed` decides whether the shadow files exist.
fn prefix(shadowed: bool) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("etc");
    std::fs::write(
        etc.join("login.defs"),
        "PASS_MIN_DAYS 7\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 14\n",
    )
    .expect("login.defs");
    std::fs::write(
        etc.join("group"),
        "root:x:0:\nshadow:x:42:\nteam:x:5000:alice\n",
    )
    .expect("group");
    if shadowed {
        std::fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n",
        )
        .expect("passwd");
        std::fs::write(
            etc.join("shadow"),
            "root:!:19000:0:99999:7:::\nalice:$6$a$hash:19000:0:99999:7:::\n",
        )
        .expect("shadow");
        std::fs::write(
            etc.join("gshadow"),
            "root:!::\nshadow:!::\nteam:$6$t$hash::alice\n",
        )
        .expect("gshadow");
    } else {
        std::fs::write(
            etc.join("passwd"),
            "root:!:0:0:root:/root:/bin/sh\nalice:$6$a$hash:1000:1000::/home/alice:/bin/sh\n",
        )
        .expect("passwd");
        std::fs::write(
            etc.join("group"),
            "root:x:0:\nshadow:x:42:\nteam:$6$t$hash:5000:alice\n",
        )
        .expect("group");
    }
    dir
}

fn run(which: &str, dir: &tempfile::TempDir, args: &[&str]) -> crate::common::Output {
    let mut cmd = tool(which);
    cmd.arg("--prefix").arg(dir.path()).args(args);
    run_cmd(&mut cmd)
}

fn read(dir: &tempfile::TempDir, name: &str) -> String {
    std::fs::read_to_string(dir.path().join("etc").join(name))
        .unwrap_or_else(|e| panic!("cannot read {name}: {e}"))
}

fn exists(dir: &tempfile::TempDir, name: &str) -> bool {
    dir.path().join("etc").join(name).exists()
}

fn fields(dir: &tempfile::TempDir, file: &str, name: &str) -> Vec<String> {
    read(dir, file)
        .lines()
        .find(|l| l.starts_with(&format!("{name}:")))
        .unwrap_or_else(|| panic!("no {file} entry for {name}"))
        .split(':')
        .map(str::to_string)
        .collect()
}

fn today() -> i64 {
    shadow_core::shadow::days_since_epoch().expect("clock")
}

// ---------------------------------------------------------------------------
// pwconv
// ---------------------------------------------------------------------------

/// The core job: hashes leave the world-readable file, a new shadow file is
/// created with the right mode and owner, and new lines are dated today with
/// the aging login.defs asks for.
#[test]
fn test_pwconv_creates_shadow_from_passwd() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(false);
    run("pwconv", &dir, &[]).assert_code(0);

    assert_eq!(fields(&dir, "passwd", "alice")[1], "x");
    assert_eq!(fields(&dir, "passwd", "root")[1], "x");

    let alice = fields(&dir, "shadow", "alice");
    assert_eq!(alice[1], "$6$a$hash");
    assert_eq!(alice[2], today().to_string(), "a new line is dated today");
    assert_eq!(alice[3], "7");
    assert_eq!(alice[4], "90");
    assert_eq!(alice[5], "14");
    assert_eq!(fields(&dir, "shadow", "root")[1], "!");

    let meta = std::fs::metadata(dir.path().join("etc/shadow")).expect("stat");
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o640,
        "a new shadow file is 0640"
    );
    assert_eq!(
        meta.gid(),
        42,
        "owned by the tree's shadow group, not the host's"
    );
    assert_eq!(meta.uid(), 0);
}

/// A consistent system is left byte-for-byte alone.
#[test]
fn test_pwconv_is_idempotent() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(true);
    let (passwd, shadow) = (read(&dir, "passwd"), read(&dir, "shadow"));
    run("pwconv", &dir, &[]).assert_code(0);
    assert_eq!(read(&dir, "passwd"), passwd);
    assert_eq!(read(&dir, "shadow"), shadow);
}

/// A hash in passwd beside an existing shadow line is the newer one: it
/// replaces the shadow hash and the change is dated; the aging is kept.
#[test]
fn test_pwconv_hash_in_passwd_wins_over_shadow() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(true);
    let passwd = read(&dir, "passwd").replace("alice:x:", "alice:$6$new$hash:");
    std::fs::write(dir.path().join("etc/passwd"), passwd).expect("write");

    run("pwconv", &dir, &[]).assert_code(0);
    let alice = fields(&dir, "shadow", "alice");
    assert_eq!(alice[1], "$6$new$hash");
    assert_eq!(alice[2], today().to_string());
    assert_eq!(alice[4], "99999", "the existing aging must be kept");
    assert_eq!(fields(&dir, "passwd", "alice")[1], "x");
}

/// A shadow line for an account no longer in passwd is dropped, and a passwd
/// line with `x` but no shadow line gets one carrying that `x` -- an honest
/// record that the hash is gone.
#[test]
fn test_pwconv_reconciles_orphans_both_ways() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(true);
    let shadow = read(&dir, "shadow") + "ghost:$6$g$g:19000:0:99999:7:::\n";
    std::fs::write(dir.path().join("etc/shadow"), shadow).expect("write");
    let passwd = read(&dir, "passwd") + "dave:x:1001:1001::/home/dave:/bin/sh\n";
    std::fs::write(dir.path().join("etc/passwd"), passwd).expect("write");

    run("pwconv", &dir, &[]).assert_code(0);
    assert!(
        !read(&dir, "shadow").contains("ghost:"),
        "the orphan shadow line stayed"
    );
    assert_eq!(fields(&dir, "shadow", "dave")[1], "x");
}

/// Comments survive: the files are rewritten through the layout-preserving
/// writer, not regenerated.
#[test]
fn test_pwconv_keeps_comments() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(false);
    let passwd = "# local accounts\n".to_string() + &read(&dir, "passwd");
    std::fs::write(dir.path().join("etc/passwd"), passwd).expect("write");
    run("pwconv", &dir, &[]).assert_code(0);
    assert!(read(&dir, "passwd").starts_with("# local accounts\n"));
}

// ---------------------------------------------------------------------------
// pwunconv
// ---------------------------------------------------------------------------

#[test]
fn test_pwunconv_merges_hashes_back_and_removes_shadow() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(true);
    run("pwunconv", &dir, &[]).assert_code(0);
    assert_eq!(fields(&dir, "passwd", "alice")[1], "$6$a$hash");
    assert_eq!(fields(&dir, "passwd", "root")[1], "!");
    assert!(!exists(&dir, "shadow"), "the shadow file must be removed");
}

/// An account with no shadow line keeps whatever passwd holds, and a system
/// with no shadow file is already in the requested state.
#[test]
fn test_pwunconv_without_a_shadow_line_or_file() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(true);
    let passwd = read(&dir, "passwd") + "bob:x:1001:1001::/home/bob:/bin/sh\n";
    std::fs::write(dir.path().join("etc/passwd"), passwd).expect("write");
    run("pwunconv", &dir, &[]).assert_code(0);
    assert_eq!(fields(&dir, "passwd", "bob")[1], "x");

    let before = read(&dir, "passwd");
    run("pwunconv", &dir, &[]).assert_code(0);
    assert_eq!(read(&dir, "passwd"), before);
}

/// A round trip is the identity on the hashes.
#[test]
fn test_pwconv_pwunconv_round_trip() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(true);
    let shadow_hash = fields(&dir, "shadow", "alice")[1].clone();
    run("pwunconv", &dir, &[]).assert_code(0);
    run("pwconv", &dir, &[]).assert_code(0);
    assert_eq!(fields(&dir, "shadow", "alice")[1], shadow_hash);
    assert_eq!(fields(&dir, "passwd", "alice")[1], "x");
}

// ---------------------------------------------------------------------------
// grpconv / grpunconv
// ---------------------------------------------------------------------------

#[test]
fn test_grpconv_creates_gshadow_with_members() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(false);
    run("grpconv", &dir, &[]).assert_code(0);
    assert_eq!(fields(&dir, "group", "team")[1], "x");
    let team = fields(&dir, "gshadow", "team");
    assert_eq!(team[1], "$6$t$hash");
    assert_eq!(team[2], "", "no administrators are invented");
    assert_eq!(team[3], "alice", "the members come from /etc/group");

    let meta = std::fs::metadata(dir.path().join("etc/gshadow")).expect("stat");
    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
    assert_eq!(meta.gid(), 42);
}

#[test]
fn test_grpunconv_merges_back_and_removes_gshadow() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(true);
    run("grpunconv", &dir, &[]).assert_code(0);
    assert_eq!(fields(&dir, "group", "team")[1], "$6$t$hash");
    assert!(!exists(&dir, "gshadow"));
}

#[test]
fn test_grpconv_drops_orphan_gshadow_lines() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(true);
    let gshadow = read(&dir, "gshadow") + "orphan:!::\n";
    std::fs::write(dir.path().join("etc/gshadow"), gshadow).expect("write");
    run("grpconv", &dir, &[]).assert_code(0);
    assert!(!read(&dir, "gshadow").contains("orphan:"));
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// None of the four takes an operand: that is a usage error, exit 2.
#[test]
fn test_operands_are_a_usage_error() {
    let dir = prefix(true);
    for which in ["pwconv", "pwunconv", "grpconv", "grpunconv"] {
        run(which, &dir, &["extra"]).assert_code(2);
    }
}

#[test]
fn test_help_exits_zero() {
    let dir = prefix(true);
    for which in ["pwconv", "pwunconv", "grpconv", "grpunconv"] {
        run(which, &dir, &["--help"])
            .assert_code(0)
            .assert_stdout_contains("Usage:");
    }
}
