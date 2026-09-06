// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore newusers gshadow gecos

//! Integration tests for the `newusers` utility.
//!
//! `newusers` writes three files and a directory from one input line, so the
//! tests run the real binary against a prefix tree and read all four back.
//! Checking only `/etc/passwd` would miss the half of the job that makes the
//! account usable.

use std::io::Write as _;
use std::process::Stdio;

use crate::common::{Output, skip_unless_root, tool};

/// A prefix tree with the account files and a skeleton directory.
fn prefix() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("etc");
    std::fs::write(etc.join("passwd"), "root:x:0:0:root:/root:/bin/sh\n").expect("passwd");
    std::fs::write(etc.join("shadow"), "root:!:19000:0:99999:7:::\n").expect("shadow");
    std::fs::write(etc.join("group"), "root:x:0:\nstaff:x:2000:\n").expect("group");
    std::fs::write(
        etc.join("login.defs"),
        "UID_MIN 1000\nGID_MIN 1000\nENCRYPT_METHOD SHA512\n",
    )
    .expect("login.defs");
    let skel = etc.join("skel");
    std::fs::create_dir_all(&skel).expect("skel");
    std::fs::write(skel.join(".profile"), "# from skel\n").expect("skel file");
    dir
}

fn read(dir: &tempfile::TempDir, name: &str) -> String {
    std::fs::read_to_string(dir.path().join("etc").join(name))
        .unwrap_or_else(|e| panic!("cannot read {name}: {e}"))
}

/// One record from a colon-separated file, split into fields.
fn record(dir: &tempfile::TempDir, file: &str, name: &str) -> Vec<String> {
    read(dir, file)
        .lines()
        .find(|l| l.starts_with(&format!("{name}:")))
        .unwrap_or_else(|| panic!("no {file} entry for {name}"))
        .split(':')
        .map(str::to_string)
        .collect()
}

fn has_entry(dir: &tempfile::TempDir, file: &str, name: &str) -> bool {
    read(dir, file)
        .lines()
        .any(|l| l.starts_with(&format!("{name}:")))
}

/// Run `newusers --prefix <dir> <args...>` with `input` on stdin.
fn newusers(dir: &tempfile::TempDir, args: &[&str], input: &str) -> Output {
    let mut cmd = tool("newusers");
    cmd.arg("--prefix")
        .arg(dir.path())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("cannot spawn newusers");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("cannot write to newusers");
    let out = child.wait_with_output().expect("newusers did not finish");
    Output {
        code: out.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

// ---------------------------------------------------------------------------
// Creating accounts
// ---------------------------------------------------------------------------

/// One line has to produce a complete, usable account: the passwd record, a
/// hashed shadow record, a group, and a home directory carrying the skeleton.
#[test]
fn test_one_line_creates_a_whole_account() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    newusers(
        &dir,
        &[],
        "alice:secret:3000:3000:Alice A:/home/alice:/bin/bash\n",
    )
    .assert_code(0);

    let passwd = record(&dir, "passwd", "alice");
    assert_eq!(passwd[1], "x", "the hash must not be in /etc/passwd");
    assert_eq!(passwd[2], "3000");
    assert_eq!(passwd[3], "3000");
    assert_eq!(passwd[4], "Alice A");
    assert_eq!(passwd[5], "/home/alice");
    assert_eq!(passwd[6], "/bin/bash");

    let shadow = record(&dir, "shadow", "alice");
    assert!(
        shadow[1].starts_with("$6$"),
        "shadow should hold a SHA-512 hash, got {:?}",
        shadow[1]
    );
    assert!(!shadow[2].is_empty(), "the last-change day must be set");

    assert!(has_entry(&dir, "group", "alice"), "no group was created");

    let home = dir.path().join("home/alice");
    assert!(home.is_dir(), "the home directory was not created");
    assert!(
        home.join(".profile").exists(),
        "the skeleton was not copied in"
    );
}

/// Empty ID fields ask for an allocation, and it has to respect login.defs.
#[test]
fn test_empty_ids_are_allocated() {
    if skip_unless_root() {
        return;
    }
    // The home field is left empty: no directory, but real IDs.
    let dir = prefix();
    newusers(&dir, &[], "alice:secret:::::\n").assert_code(0);
    let passwd = record(&dir, "passwd", "alice");
    let uid: u32 = passwd[2].parse().expect("uid");
    assert!(uid >= 1000, "allocated uid {uid} is below UID_MIN");
    assert!(has_entry(&dir, "group", "alice"), "no group was created");
    assert!(
        !dir.path().join("home").exists(),
        "an empty home field must not create a directory"
    );
}

/// A numeric group that does not exist yet is created, so the account is never
/// left pointing at a group that is not there.
#[test]
fn test_a_numeric_gid_creates_the_missing_group() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    newusers(&dir, &[], "alice:secret:3000:7777:::\n").assert_code(0);
    assert_eq!(record(&dir, "passwd", "alice")[3], "7777");
    assert_eq!(
        record(&dir, "group", "alice")[2],
        "7777",
        "a group carrying the user's name should have been created"
    );
}

/// A group named in the field is used as it stands.
#[test]
fn test_a_named_group_is_used() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    newusers(&dir, &[], "alice:secret:3000:staff:::\n").assert_code(0);
    assert_eq!(record(&dir, "passwd", "alice")[3], "2000");
}

/// GNU quietly falls back to the user's own ID here and creates no group,
/// leaving the account pointing at a GID that does not exist. Naming a group
/// that is not there is a mistake worth reporting.
#[test]
fn test_an_unknown_group_name_is_refused() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let before = read(&dir, "passwd");
    newusers(&dir, &[], "alice:secret:3000:nosuchgroup:::\n")
        .assert_code(1)
        .assert_stderr_contains("does not exist");
    assert_eq!(read(&dir, "passwd"), before, "nothing may have changed");
}

// ---------------------------------------------------------------------------
// Updating accounts
// ---------------------------------------------------------------------------

/// An account that is already there is updated rather than refused.
#[test]
fn test_an_existing_account_is_updated() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    newusers(
        &dir,
        &[],
        "alice:secret:3000:3000:First:/home/alice:/bin/sh\n",
    )
    .assert_code(0);
    let first_hash = record(&dir, "shadow", "alice")[1].clone();

    newusers(
        &dir,
        &[],
        "alice:other:3000:3000:Second:/home/alice:/bin/bash\n",
    )
    .assert_code(0);

    let passwd = record(&dir, "passwd", "alice");
    assert_eq!(passwd[4], "Second");
    assert_eq!(passwd[6], "/bin/bash");
    assert_ne!(
        record(&dir, "shadow", "alice")[1],
        first_hash,
        "the password should have been changed"
    );
    assert_eq!(
        read(&dir, "passwd")
            .lines()
            .filter(|l| l.starts_with("alice:"))
            .count(),
        1,
        "the account must not be duplicated"
    );
}

/// An empty ID field on an existing account keeps the ID it has: reallocating
/// would orphan every file the account owns.
#[test]
fn test_an_empty_uid_keeps_the_existing_one() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    newusers(&dir, &[], "alice:secret:3000:3000:::\n").assert_code(0);
    newusers(&dir, &[], "alice:secret::3000:Changed::\n").assert_code(0);
    assert_eq!(record(&dir, "passwd", "alice")[2], "3000");
}

// ---------------------------------------------------------------------------
// All or nothing
// ---------------------------------------------------------------------------

/// The property that makes this safe to feed a generated file: one bad line
/// and the system is exactly as it was, including for the good lines above it.
#[test]
fn test_a_bad_line_changes_nothing() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let passwd_before = read(&dir, "passwd");
    let shadow_before = read(&dir, "shadow");

    newusers(&dir, &[], "alice:secret:3000:3000:::\nbadline\n")
        .assert_code(1)
        .assert_stderr_contains("line 2: invalid line");

    assert_eq!(read(&dir, "passwd"), passwd_before);
    assert_eq!(read(&dir, "shadow"), shadow_before);
    assert!(
        !dir.path().join("home").exists(),
        "no home may be created for a batch that failed"
    );
}

/// Six fields and eight are both wrong: a line that lost one to a stray colon
/// would otherwise describe a different account than intended.
#[test]
fn test_wrong_field_count_is_refused() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    for bad in [
        "alice:secret:3000:3000:x:/home/alice\n",
        "alice:secret:3000:3000:x:/home/alice:/bin/sh:extra\n",
        "\n",
    ] {
        newusers(&dir, &[], bad)
            .assert_code(1)
            .assert_stderr_contains("invalid line");
    }
    assert!(!has_entry(&dir, "passwd", "alice"));
}

/// An empty password would be hashed into something a bare Enter matches.
/// GNU hands it to PAM, which refuses it *after* creating the account.
#[test]
fn test_an_empty_password_is_refused_before_anything_is_written() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    newusers(&dir, &[], "alice::3000:3000:::\n")
        .assert_code(1)
        .assert_stderr_contains("no password supplied");
    assert!(
        !has_entry(&dir, "passwd", "alice"),
        "the account must not exist after the refusal"
    );
}

/// A field carrying a newline would add a record; `useradd -c` once created a
/// passwordless UID 0 account that way.
#[test]
fn test_a_field_that_would_add_a_record_is_refused() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    newusers(
        &dir,
        &[],
        "alice:secret:3000:3000:x\nevil::0:0::/:/bin/sh:/home/alice:/bin/sh\n",
    )
    .assert_code(1);
    assert!(!has_entry(&dir, "passwd", "evil"), "a record was injected");
}

// ---------------------------------------------------------------------------
// Input and flags
// ---------------------------------------------------------------------------

/// Empty input succeeds having done nothing.
#[test]
fn test_empty_input_succeeds() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let before = read(&dir, "passwd");
    newusers(&dir, &[], "").assert_code(0);
    assert_eq!(read(&dir, "passwd"), before);
}

/// Several accounts in one batch all land.
#[test]
fn test_a_whole_batch_applies() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    newusers(
        &dir,
        &[],
        "alice:one:3000:3000:::\nbob:two:3001:3001:::\ncarol:three:3002:3002:::\n",
    )
    .assert_code(0);
    for name in ["alice", "bob", "carol"] {
        assert!(has_entry(&dir, "passwd", name), "{name} is missing");
        assert!(has_entry(&dir, "shadow", name), "{name} has no hash");
    }
}

/// `--badname` allows a name the portability rules refuse but which cannot
/// corrupt the file -- the domain-qualified form a directory join produces.
#[test]
fn test_badname_allows_a_domain_qualified_name() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    newusers(&dir, &[], "alice@corp:secret:3000:3000:::\n").assert_code(1);
    newusers(&dir, &["--badname"], "alice@corp:secret:3000:3000:::\n").assert_code(0);
    assert!(has_entry(&dir, "passwd", "alice@corp"));
}

/// `-r` allocates from the system range.
#[test]
fn test_system_accounts_come_from_the_system_range() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    newusers(&dir, &["-r"], "svc:secret:::::\n").assert_code(0);
    let uid: u32 = record(&dir, "passwd", "svc")[2].parse().expect("uid");
    assert!(
        uid < 1000,
        "a system account should be below UID_MIN, got {uid}"
    );
}

#[test]
fn test_help_exits_zero() {
    let dir = prefix();
    newusers(&dir, &["--help"], "")
        .assert_code(0)
        .assert_stdout_contains("Usage:");
}
