// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore vipw vigr gshadow

//! Integration tests for `vipw` and `vigr`.
//!
//! The editor is a shell script written into the prefix tree and named
//! through `EDITOR`, so each test decides what "the administrator typed".
//! Everything is asserted on the files afterwards: what was installed, what
//! was left alone, and whether the working copy was kept or cleaned up.

use std::os::unix::fs::PermissionsExt as _;

use crate::common::{Output, run_cmd, skip_unless_root, tool};

const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n";
const SHADOW: &str = "root:!:19000:0:99999:7:::\nalice:!:19000:0:99999:7:::\n";
const GROUP: &str = "root:x:0:\nalice:x:1000:\n";
const GSHADOW: &str = "root:!::\nalice:!::\n";

/// A prefix tree with all four files at their conventional modes.
fn prefix() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("etc");
    for (name, body, mode) in [
        ("passwd", PASSWD, 0o644),
        ("shadow", SHADOW, 0o640),
        ("group", GROUP, 0o644),
        ("gshadow", GSHADOW, 0o640),
    ] {
        let path = etc.join(name);
        std::fs::write(&path, body).expect(name);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }
    dir
}

/// An "editor": a script that runs `body` with the file to edit in `$1`.
fn editor(dir: &tempfile::TempDir, name: &str, body: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("editor");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path.to_string_lossy().into_owned()
}

fn read(dir: &tempfile::TempDir, name: &str) -> String {
    std::fs::read_to_string(dir.path().join("etc").join(name))
        .unwrap_or_else(|e| panic!("cannot read {name}: {e}"))
}

fn mode_of(dir: &tempfile::TempDir, name: &str) -> u32 {
    std::fs::metadata(dir.path().join("etc").join(name))
        .expect("stat")
        .permissions()
        .mode()
        & 0o777
}

fn edit_copy_exists(dir: &tempfile::TempDir, name: &str) -> bool {
    dir.path().join("etc").join(format!("{name}.edit")).exists()
}

/// Run `<tool> --prefix <dir> <args...>` with the given editor.
fn edit_with(which: &str, dir: &tempfile::TempDir, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = tool(which);
    cmd.arg("--prefix").arg(dir.path()).args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    run_cmd(&mut cmd)
}

// ---------------------------------------------------------------------------
// The edit lands
// ---------------------------------------------------------------------------

/// The core promise: what the editor saved is what is installed, with the
/// file's mode intact and the working copy gone. The editor here returns
/// within the second the copy was made -- the GNU tool would discard this
/// edit, because it compares timestamps in whole seconds.
#[test]
fn test_an_edit_is_installed_and_the_mode_kept() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let ed = editor(
        &dir,
        "ed",
        r#"printf 'bob:x:1001:1001::/home/bob:/bin/sh\n' >> "$1""#,
    );

    edit_with("vipw", &dir, &[], &[("EDITOR", &ed)])
        .assert_code(0)
        .assert_stdout_contains("You have modified")
        .assert_stdout_contains("vipw -s");

    assert!(read(&dir, "passwd").contains("bob:x:1001:1001"));
    assert_eq!(mode_of(&dir, "passwd"), 0o644, "the mode changed");
    assert!(
        !edit_copy_exists(&dir, "passwd"),
        "the working copy was left behind"
    );
}

/// Comments and blank lines the administrator writes survive verbatim: the
/// edited bytes are installed as they are, not re-rendered.
#[test]
fn test_the_bytes_are_installed_verbatim() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let ed = editor(
        &dir,
        "ed",
        r#"printf '# added by hand\n\ncarol:x:1002:1002::/home/carol:/bin/sh\n' >> "$1""#,
    );
    edit_with("vipw", &dir, &[], &[("EDITOR", &ed)]).assert_code(0);
    let after = read(&dir, "passwd");
    assert!(
        after.contains("# added by hand\n\ncarol:"),
        "layout was not preserved: {after:?}"
    );
}

#[test]
fn test_shadow_flag_edits_the_shadow_file() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let ed = editor(&dir, "ed", r#"printf 'bob:!:19000:0:99999:7:::\n' >> "$1""#);
    edit_with("vipw", &dir, &["-s"], &[("EDITOR", &ed)])
        .assert_code(0)
        .assert_stdout_contains("Please use the command 'vipw'");
    assert!(read(&dir, "shadow").contains("bob:!:19000"));
    assert_eq!(read(&dir, "passwd"), PASSWD, "passwd must be untouched");
    assert_eq!(mode_of(&dir, "shadow"), 0o640);
}

/// vigr is vipw with the group file as its default, and `-s` then means
/// gshadow. `vipw -g` reaches the same file.
#[test]
fn test_vigr_and_group_flags() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let ed = editor(&dir, "ed", r#"printf 'team:x:5000:alice\n' >> "$1""#);
    edit_with("vigr", &dir, &[], &[("EDITOR", &ed)])
        .assert_code(0)
        .assert_stdout_contains("vigr -s");
    assert!(read(&dir, "group").contains("team:x:5000:alice"));

    let ed = editor(&dir, "ed2", r#"printf 'team:!::alice\n' >> "$1""#);
    edit_with("vigr", &dir, &["-s"], &[("EDITOR", &ed)]).assert_code(0);
    assert!(read(&dir, "gshadow").contains("team:!::alice"));

    let ed = editor(&dir, "ed3", r#"printf 'other:x:5001:\n' >> "$1""#);
    edit_with("vipw", &dir, &["-g"], &[("EDITOR", &ed)]).assert_code(0);
    assert!(read(&dir, "group").contains("other:x:5001:"));
    assert_eq!(read(&dir, "passwd"), PASSWD);
}

// ---------------------------------------------------------------------------
// Nothing lands
// ---------------------------------------------------------------------------

#[test]
fn test_no_change_is_reported_and_nothing_is_written() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let ed = editor(&dir, "ed", "true");
    edit_with("vipw", &dir, &[], &[("EDITOR", &ed)])
        .assert_code(0)
        .assert_stderr_contains("is unchanged");
    assert_eq!(read(&dir, "passwd"), PASSWD);
    assert!(!edit_copy_exists(&dir, "passwd"));

    // -q silences the report; the result is the same.
    let out = edit_with("vipw", &dir, &["-q"], &[("EDITOR", &ed)]);
    out.assert_code(0);
    assert!(
        out.stderr.is_empty(),
        "-q should print nothing: {:?}",
        out.stderr
    );
}

/// An editor that fails has not finished the job, whatever it wrote.
#[test]
fn test_a_failing_editor_installs_nothing() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let ed = editor(
        &dir,
        "ed",
        r#"printf 'zed:x:6000:6000:::/bin/sh\n' >> "$1"; exit 1"#,
    );
    edit_with("vipw", &dir, &[], &[("EDITOR", &ed)])
        .assert_code(1)
        .assert_stderr_contains("returned with status 1")
        .assert_stderr_contains("is unchanged");
    assert_eq!(read(&dir, "passwd"), PASSWD);
    assert!(!edit_copy_exists(&dir, "passwd"));
}

/// The deliberate divergence from GNU, which installs whatever the editor
/// saved: a file the suite cannot parse is refused -- and the edit is kept,
/// so the refusal costs the administrator nothing but a second look.
#[test]
fn test_an_unparseable_result_is_refused_and_kept() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let ed = editor(&dir, "ed", r#"printf 'this line has no colons\n' >> "$1""#);
    edit_with("vipw", &dir, &[], &[("EDITOR", &ed)])
        .assert_code(1)
        .assert_stderr_contains("kept at")
        .assert_stderr_contains("is unchanged");

    assert_eq!(
        read(&dir, "passwd"),
        PASSWD,
        "the live file must be untouched"
    );
    assert!(
        edit_copy_exists(&dir, "passwd"),
        "the edit must be kept for the caller"
    );
    assert!(
        read(&dir, "passwd.edit").contains("this line has no colons"),
        "the kept copy must be the administrator's edit"
    );
}

/// A field the other tools would refuse to write is refused here too: the
/// working copy is not a way around the checks.
#[test]
fn test_a_field_that_would_corrupt_the_file_is_refused() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    // A group line with too many fields.
    let ed = editor(&dir, "ed", r#"printf 'team:x:5000:alice:extra\n' >> "$1""#);
    edit_with("vigr", &dir, &[], &[("EDITOR", &ed)]).assert_code(1);
    assert_eq!(read(&dir, "group"), GROUP);
}

/// A stale working copy from a crashed run is not offered as the file to
/// edit; the administrator sees the live contents.
#[test]
fn test_a_stale_working_copy_is_replaced() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    std::fs::write(dir.path().join("etc/passwd.edit"), "junk from a crash\n").expect("stale");
    let ed = editor(
        &dir,
        "ed",
        r#"cp "$1" "$1.seen"; printf 'dave:x:1003:1003::/home/dave:/bin/sh\n' >> "$1""#,
    );
    edit_with("vipw", &dir, &[], &[("EDITOR", &ed)]).assert_code(0);
    let seen = std::fs::read_to_string(dir.path().join("etc/passwd.edit.seen")).expect("seen");
    assert_eq!(
        seen, PASSWD,
        "the editor must be handed the live file, not the stale copy"
    );
    assert!(!read(&dir, "passwd").contains("junk"));
}

// ---------------------------------------------------------------------------
// Which editor
// ---------------------------------------------------------------------------

#[test]
fn test_visual_takes_precedence_over_editor() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let visual = editor(
        &dir,
        "visual",
        r#"printf 'fromvisual:x:1004:1004:::/bin/sh\n' >> "$1""#,
    );
    let ed = editor(
        &dir,
        "ed",
        r#"printf 'fromeditor:x:1005:1005:::/bin/sh\n' >> "$1""#,
    );
    edit_with("vipw", &dir, &[], &[("VISUAL", &visual), ("EDITOR", &ed)]).assert_code(0);
    let after = read(&dir, "passwd");
    assert!(after.contains("fromvisual:"));
    assert!(!after.contains("fromeditor:"));
}

/// An editor with arguments goes through the shell, as it does everywhere.
#[test]
fn test_an_editor_with_arguments_works() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    let ed = editor(
        &dir,
        "ed",
        r#"[ "$1" = --flag ] && shift; printf 'erin:x:1006:1006:::/bin/sh\n' >> "$1""#,
    );
    let with_flag = format!("{ed} --flag");
    edit_with("vipw", &dir, &[], &[("EDITOR", &with_flag)]).assert_code(0);
    assert!(read(&dir, "passwd").contains("erin:"));
}

#[test]
fn test_group_and_passwd_flags_conflict() {
    let dir = prefix();
    edit_with("vipw", &dir, &["-g", "-p"], &[]).assert_code(2);
}

#[test]
fn test_help_exits_zero() {
    let dir = prefix();
    edit_with("vipw", &dir, &["--help"], &[])
        .assert_code(0)
        .assert_stdout_contains("Usage:");
    edit_with("vigr", &dir, &["--help"], &[])
        .assert_code(0)
        .assert_stdout_contains("Usage:");
}
