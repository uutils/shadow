// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chgpasswd gshadow yescrypt

//! Integration tests for the `chgpasswd` utility.
//!
//! These feed the real binary on stdin and assert on what it writes to the
//! prefix tree, which is the only way to observe the two files it has to keep
//! agreeing: the hash belongs in `/etc/gshadow`, and `/etc/group` carries the
//! `x` that says so.

use std::process::Stdio;

use crate::common::{Output, skip_unless_root, tool};

/// A prefix tree with a group file and, optionally, a gshadow file.
///
/// Passing `None` for `gshadow` builds a host that keeps group passwords in
/// `/etc/group` itself, which is the layout `chgpasswd` has to detect.
fn prefix(group: &str, gshadow: Option<&str>, encrypt_method: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");
    std::fs::write(etc.join("group"), group).expect("failed to write group file");
    if let Some(gshadow) = gshadow {
        std::fs::write(etc.join("gshadow"), gshadow).expect("failed to write gshadow file");
    }
    if let Some(method) = encrypt_method {
        std::fs::write(etc.join("login.defs"), format!("ENCRYPT_METHOD {method}\n"))
            .expect("failed to write login.defs");
    }
    dir
}

fn read_file(dir: &tempfile::TempDir, name: &str) -> String {
    std::fs::read_to_string(dir.path().join("etc").join(name))
        .unwrap_or_else(|e| panic!("cannot read {name}: {e}"))
}

/// The password field of one line in `group` or `gshadow`.
fn field(dir: &tempfile::TempDir, file: &str, group: &str) -> String {
    read_file(dir, file)
        .lines()
        .find(|l| l.starts_with(&format!("{group}:")))
        .and_then(|l| l.split(':').nth(1))
        .unwrap_or_else(|| panic!("no {file} entry for {group}"))
        .to_string()
}

/// Run `chgpasswd --prefix <dir> <args...>` with `input` on stdin.
fn chgpasswd(dir: &tempfile::TempDir, args: &[&str], input: &str) -> Output {
    // stdin is a file, not a pipe. The tools exit as soon as a line is bad,
    // and a pipe whose reader has gone raises SIGPIPE in the writer. Rust
    // ignores that signal at startup, but every `uumain` run in-process by
    // another test puts it back to its default -- uucore does so for GNU
    // pipeline compatibility -- after which the write kills the whole test
    // binary. A file has no reader to lose.
    let stdin_path = dir.path().join("stdin.chgpasswd");
    std::fs::write(&stdin_path, input).expect("write stdin file");
    let stdin = std::fs::File::open(&stdin_path).expect("open stdin file");

    let mut cmd = tool("chgpasswd");
    cmd.arg("--prefix")
        .arg(dir.path())
        .args(args)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let out = cmd.output().expect("chgpasswd did not finish");
    Output {
        code: out.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

const GROUP: &str = "staff:x:100:alice\nwheel:x:101:\n";
const GSHADOW: &str = "staff:!::alice\nwheel:!::\n";

// ---------------------------------------------------------------------------
// Where the password lands
// ---------------------------------------------------------------------------

/// With a gshadow file the hash goes there and `/etc/group` keeps `x`. Writing
/// the hash into a world-readable `/etc/group` instead would publish it.
#[test]
fn test_the_hash_goes_to_gshadow() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), Some("SHA512"));
    chgpasswd(&dir, &[], "staff:secret\n").assert_code(0);

    assert!(
        field(&dir, "gshadow", "staff").starts_with("$6$"),
        "gshadow should hold the hash, got {:?}",
        field(&dir, "gshadow", "staff")
    );
    assert_eq!(
        field(&dir, "group", "staff"),
        "x",
        "/etc/group must keep the placeholder, not the hash"
    );
}

/// Without a gshadow file the hash goes into `/etc/group`, and no gshadow file
/// is conjured up: creating one changes how every other tool on the host reads
/// group passwords.
#[test]
fn test_without_gshadow_the_hash_goes_to_group() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, None, Some("SHA512"));
    chgpasswd(&dir, &[], "staff:secret\n").assert_code(0);

    assert!(
        field(&dir, "group", "staff").starts_with("$6$"),
        "group should hold the hash without a gshadow file"
    );
    assert!(
        !dir.path().join("etc/gshadow").exists(),
        "chgpasswd must not create a gshadow file"
    );
}

/// Setting a password must not disturb who administers or belongs to a group.
#[test]
fn test_membership_and_admins_survive() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some("staff:!:bob:alice\n"), Some("SHA512"));
    chgpasswd(&dir, &[], "staff:secret\n").assert_code(0);

    let line = read_file(&dir, "gshadow")
        .lines()
        .find(|l| l.starts_with("staff:"))
        .expect("staff line")
        .to_string();
    let fields: Vec<&str> = line.split(':').collect();
    assert_eq!(fields[2], "bob", "the administrator list changed");
    assert_eq!(fields[3], "alice", "the member list changed");
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// `-e` stores the field verbatim; nothing is hashed a second time.
#[test]
fn test_encrypted_is_stored_verbatim() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), None);
    chgpasswd(&dir, &["-e"], "staff:$6$salt$alreadyhashed\n").assert_code(0);
    assert_eq!(field(&dir, "gshadow", "staff"), "$6$salt$alreadyhashed");
}

/// `-e` may write an empty field: that is how a group password is cleared.
#[test]
fn test_encrypted_accepts_an_empty_field() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), None);
    chgpasswd(&dir, &["-e"], "staff:\n").assert_code(0);
    assert_eq!(field(&dir, "gshadow", "staff"), "");
}

/// An empty plaintext password would hash to something a bare Enter matches.
#[test]
fn test_empty_plaintext_is_refused() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), Some("SHA512"));
    chgpasswd(&dir, &[], "staff:\n")
        .assert_code(1)
        .assert_stderr_contains("no password supplied");
    assert_eq!(field(&dir, "gshadow", "staff"), "!", "nothing may change");
}

/// The default scheme is the system's, from login.defs -- not a hard-coded one.
#[test]
fn test_default_scheme_comes_from_login_defs() {
    if skip_unless_root() {
        return;
    }
    for (method, prefix_str) in [("SHA512", "$6$"), ("SHA256", "$5$")] {
        let dir = prefix(GROUP, Some(GSHADOW), Some(method));
        chgpasswd(&dir, &[], "staff:secret\n").assert_code(0);
        assert!(
            field(&dir, "gshadow", "staff").starts_with(prefix_str),
            "{method} should produce a {prefix_str} hash"
        );
    }
}

/// `-c` overrides the configured default.
#[test]
fn test_explicit_scheme_overrides() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), Some("SHA512"));
    chgpasswd(&dir, &["-c", "SHA256"], "staff:secret\n").assert_code(0);
    assert!(field(&dir, "gshadow", "staff").starts_with("$5$"));
}

/// GNU accepts `-c NONE` and stores the password as clear text. A readable
/// group password is worth no more than none at all, so it is refused -- and
/// the refusal must leave the file alone.
#[test]
fn test_none_is_refused() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), Some("SHA512"));
    chgpasswd(&dir, &["-c", "NONE"], "staff:secret\n")
        .assert_code(1)
        .assert_stderr_contains("unhashed");
    assert_eq!(field(&dir, "gshadow", "staff"), "!");
}

// ---------------------------------------------------------------------------
// All or nothing
// ---------------------------------------------------------------------------

/// The property that makes a batch tool safe: one bad line and the files are
/// untouched, including for the groups named on the good lines before it.
#[test]
fn test_an_unknown_group_changes_nothing() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), Some("SHA512"));
    let before = read_file(&dir, "gshadow");

    chgpasswd(
        &dir,
        &[],
        "staff:secret\nnosuchgroup:secret\nwheel:secret\n",
    )
    .assert_code(1)
    .assert_stderr_contains("group 'nosuchgroup' does not exist");

    assert_eq!(
        read_file(&dir, "gshadow"),
        before,
        "a failed batch must leave the file exactly as it was"
    );
}

/// The line number in the message is what makes a long batch debuggable.
#[test]
fn test_the_error_names_the_line() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), Some("SHA512"));
    chgpasswd(&dir, &[], "staff:secret\nnosuchgroup:secret\n")
        .assert_code(1)
        .assert_stderr_contains("line 2");
}

/// Several groups in one batch all land.
#[test]
fn test_a_whole_batch_applies() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), Some("SHA512"));
    chgpasswd(&dir, &[], "staff:one\nwheel:two\n").assert_code(0);
    assert!(field(&dir, "gshadow", "staff").starts_with("$6$"));
    assert!(field(&dir, "gshadow", "wheel").starts_with("$6$"));
    assert_ne!(
        field(&dir, "gshadow", "staff"),
        field(&dir, "gshadow", "wheel"),
        "each password must get its own salt"
    );
}

// ---------------------------------------------------------------------------
// Input handling
// ---------------------------------------------------------------------------

/// Empty input succeeds having done nothing, which is what a script driving
/// chgpasswd from a possibly-empty list depends on.
#[test]
fn test_empty_input_succeeds() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), Some("SHA512"));
    let before = read_file(&dir, "gshadow");
    chgpasswd(&dir, &[], "").assert_code(0);
    assert_eq!(read_file(&dir, "gshadow"), before);
}

/// A line carrying no password is an error rather than something to skip: a
/// blank line in the middle of a batch is a mistake worth reporting.
#[test]
fn test_a_line_without_a_password_is_refused() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), Some("SHA512"));
    for input in ["staff\n", "\n", "staff:secret\n\n"] {
        chgpasswd(&dir, &[], input)
            .assert_code(1)
            .assert_stderr_contains("missing new password");
    }
    assert_eq!(field(&dir, "gshadow", "staff"), "!");
}

/// Only the first colon separates the group from the password, so a field
/// containing colons is parsed as one value -- and then refused, because a
/// colon in a gshadow field would split the line and corrupt the file. The GNU
/// tool refuses it too, and likewise leaves the file untouched.
#[test]
fn test_a_colon_in_the_password_is_refused_without_corrupting_the_file() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), None);
    let before = read_file(&dir, "gshadow");
    chgpasswd(&dir, &["-e"], "staff:$6$a:b:c\n").assert_code(1);
    assert_eq!(
        read_file(&dir, "gshadow"),
        before,
        "a refused write must leave the file exactly as it was"
    );
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    let dir = prefix(GROUP, Some(GSHADOW), None);
    chgpasswd(&dir, &["--help"], "")
        .assert_code(0)
        .assert_stdout_contains("Usage:");
}

/// An unknown scheme is a usage error, exit 2, matching the GNU tool.
#[test]
fn test_unknown_scheme_is_a_usage_error() {
    let dir = prefix(GROUP, Some(GSHADOW), None);
    chgpasswd(&dir, &["-c", "BOGUS"], "staff:secret\n").assert_code(2);
}

/// MD5 is accepted by the GNU tool and refused here, deliberately.
#[test]
fn test_md5_is_refused() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix(GROUP, Some(GSHADOW), None);
    chgpasswd(&dir, &["-m"], "staff:secret\n")
        .assert_code(1)
        .assert_stderr_contains("MD5");
    assert_eq!(field(&dir, "gshadow", "staff"), "!");
}
