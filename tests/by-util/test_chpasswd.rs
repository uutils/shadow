// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chpasswd yescrypt

//! Integration tests for the `chpasswd` utility.
//!
//! These feed the real binary on stdin and assert on what it writes. They used
//! to edit the shadow file through `shadow-core` and read it back, which
//! tested the parser twice and `chpasswd` not at all; the tool had no
//! `--prefix` then, and `--root` performs a real `chroot(2)` an in-process
//! test cannot use.

use std::io::Write as _;
use std::process::Stdio;

use crate::common::{Output, run, tool};

/// A prefix tree with a shadow file and a login.defs naming a hashing scheme.
fn prefix(shadow: &str, encrypt_method: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");
    std::fs::write(etc.join("shadow"), shadow).expect("failed to write shadow file");
    if let Some(method) = encrypt_method {
        std::fs::write(etc.join("login.defs"), format!("ENCRYPT_METHOD {method}\n"))
            .expect("failed to write login.defs");
    }
    dir
}

fn read_shadow(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("etc/shadow")).expect("failed to read shadow file")
}

/// Run `chpasswd --prefix <dir> <args...>` with `input` on stdin.
fn chpasswd(dir: &tempfile::TempDir, args: &[&str], input: &str) -> Output {
    let mut cmd = tool("chpasswd");
    cmd.arg("--prefix")
        .arg(dir.path())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("cannot spawn chpasswd");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("cannot write to chpasswd");
    let out = child.wait_with_output().expect("chpasswd did not finish");
    Output {
        code: out.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The hash field of one account.
fn hash_of(dir: &tempfile::TempDir, user: &str) -> String {
    read_shadow(dir)
        .lines()
        .find(|l| l.starts_with(&format!("{user}:")))
        .and_then(|l| l.split(':').nth(1))
        .unwrap_or_else(|| panic!("no entry for {user}"))
        .to_string()
}

const TWO_USERS: &str = "alice:$6$oldhash:19500:0:99999:7:::\nbob:$6$oldhash:19500:0:99999:7:::\n";

// ---------------------------------------------------------------------------
// Argument handling
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    run("chpasswd", &["--help"])
        .assert_code(0)
        .assert_stdout_contains("--crypt-method");
}

#[test]
fn test_invalid_crypt_method_is_a_usage_error() {
    run("chpasswd", &["-c", "BOGUS"])
        .assert_code(2)
        .assert_stderr_contains("BOGUS");
}

/// chpasswd(8) documents both of these as errors; they used to be accepted and
/// silently do nothing.
#[test]
fn test_forbidden_flag_pairs_are_usage_errors() {
    run("chpasswd", &["-s", "5000"]).assert_code(2);
    run("chpasswd", &["-e", "-c", "SHA512"]).assert_code(2);
    run("chpasswd", &["-e", "-m"]).assert_code(2);
}

// ---------------------------------------------------------------------------
// Applying a batch
// ---------------------------------------------------------------------------

#[test]
fn test_pre_hashed_batch_is_written_verbatim() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix(TWO_USERS, None);
    chpasswd(
        &dir,
        &["-e"],
        "alice:$6$newhash_alice\nbob:$6$newhash_bob\n",
    )
    .assert_code(0);
    assert_eq!(hash_of(&dir, "alice"), "$6$newhash_alice");
    assert_eq!(hash_of(&dir, "bob"), "$6$newhash_bob");
}

/// The line is not trimmed: trailing whitespace is part of the password, and
/// storing the hash of a different string than the caller supplied would lock
/// them out of the account they had just set.
#[test]
fn test_input_is_not_trimmed() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix(TWO_USERS, None);
    chpasswd(&dir, &["-e"], "alice:$6$hash_with_trailing_space \n").assert_code(0);
    assert_eq!(hash_of(&dir, "alice"), "$6$hash_with_trailing_space ");
}

/// Only the *first* colon separates, so a plaintext password may contain one
/// without any escaping.
#[test]
fn test_a_plaintext_password_may_contain_a_colon() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix(TWO_USERS, Some("SHA512"));
    chpasswd(&dir, &[], "alice:pass:with:colons\n").assert_code(0);
    let hash = hash_of(&dir, "alice");
    assert!(hash.starts_with("$6$"), "unexpected hash: {hash}");
    // The hash itself never carries a separator; that is what makes the
    // password's colons safe to store.
    assert!(!hash.contains("pass"), "the password was stored in clear");
}

/// A colon in a *pre-hashed* field is refused: it is written to the record
/// as-is, and one there would shift every following field on the next read.
#[test]
fn test_a_colon_in_a_pre_hashed_field_is_refused() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix(TWO_USERS, None);
    let before = read_shadow(&dir);
    chpasswd(&dir, &["-e"], "alice:$6$has:a:separator\n")
        .assert_code(1)
        .assert_stderr_contains("must not contain");
    assert_eq!(before, read_shadow(&dir));
}

/// Hashing an empty string produces a valid hash, and the account would then
/// accept a bare ENTER. Locking is what `passwd -l` is for.
#[test]
fn test_empty_plaintext_password_is_refused() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix(TWO_USERS, None);
    let before = read_shadow(&dir);
    chpasswd(&dir, &[], "alice:\n").assert_code(1);
    assert_eq!(before, read_shadow(&dir), "the file was modified anyway");
}

/// An unknown login anywhere in a batch leaves the file untouched, rather than
/// applying the part of the list that came before it.
#[test]
fn test_an_unknown_login_aborts_the_whole_batch() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix(TWO_USERS, None);
    let before = read_shadow(&dir);
    chpasswd(
        &dir,
        &["-e"],
        "alice:$6$applied\nghost:$6$nobody\nbob:$6$applied\n",
    )
    .assert_code(1);
    assert_eq!(before, read_shadow(&dir), "half the batch was applied");
}

#[test]
fn test_malformed_input_is_refused() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix(TWO_USERS, None);
    let before = read_shadow(&dir);
    for input in ["no-colon-here\n", ":$6$nameless\n", ""] {
        chpasswd(&dir, &["-e"], input).assert_code(1);
    }
    assert_eq!(before, read_shadow(&dir));
}

// ---------------------------------------------------------------------------
// Choosing the hashing scheme
// ---------------------------------------------------------------------------

/// The default comes from `ENCRYPT_METHOD`, which is how a distribution picks a
/// scheme for the whole system.
#[test]
fn test_default_scheme_follows_login_defs() {
    if crate::common::skip_unless_root() {
        return;
    }
    for (method, prefix_marker) in [("SHA512", "$6$"), ("SHA256", "$5$")] {
        let dir = prefix(TWO_USERS, Some(method));
        chpasswd(&dir, &[], "alice:a long passphrase\n").assert_code(0);
        let hash = hash_of(&dir, "alice");
        assert!(
            hash.starts_with(prefix_marker),
            "ENCRYPT_METHOD {method} produced {hash}"
        );
    }
}

/// An explicit -c wins over the configured default.
#[test]
fn test_crypt_method_option_overrides_the_default() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix(TWO_USERS, Some("SHA512"));
    chpasswd(&dir, &["-c", "SHA256"], "alice:a long passphrase\n").assert_code(0);
    assert!(hash_of(&dir, "alice").starts_with("$5$"));
}

/// A configuration this build will not write falls back rather than refusing
/// to set a password at all.
#[test]
fn test_unusable_encrypt_method_falls_back_to_sha512() {
    if crate::common::skip_unless_root() {
        return;
    }
    for method in ["MD5", "DES", "NOT_A_METHOD"] {
        let dir = prefix(TWO_USERS, Some(method));
        chpasswd(&dir, &[], "alice:a long passphrase\n").assert_code(0);
        let hash = hash_of(&dir, "alice");
        assert!(
            hash.starts_with("$6$"),
            "ENCRYPT_METHOD {method} produced {hash}"
        );
    }
}

/// The same passphrase must not produce the same hash twice: the salt is
/// random, and an equal hash would mean it is not.
#[test]
fn test_hashes_are_salted() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix(TWO_USERS, Some("SHA512"));
    chpasswd(&dir, &[], "alice:same passphrase\nbob:same passphrase\n").assert_code(0);
    assert_ne!(
        hash_of(&dir, "alice"),
        hash_of(&dir, "bob"),
        "two accounts with one passphrase got the same hash"
    );
}

/// Only the accounts named are touched; the rest of the file, and the other
/// fields of the accounts that are, stay as they were.
#[test]
fn test_other_fields_and_accounts_are_left_alone() {
    if crate::common::skip_unless_root() {
        return;
    }
    let dir = prefix(TWO_USERS, None);
    chpasswd(&dir, &["-e"], "alice:$6$newhash\n").assert_code(0);
    let content = read_shadow(&dir);
    assert!(
        content.contains("bob:$6$oldhash:19500:0:99999:7:::"),
        "bob was modified: {content}"
    );
    let alice = content
        .lines()
        .find(|l| l.starts_with("alice:"))
        .expect("alice");
    // Only the hash and the last-change day may differ from the original.
    let fields: Vec<&str> = alice.split(':').collect();
    assert_eq!(fields[1], "$6$newhash");
    assert_eq!(&fields[3..], &["0", "99999", "7", "", "", ""]);
}
