// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore useradd nologin skel gecos gshadow

//! Integration tests for the `useradd` utility.
//!
//! Tests that require root are guarded by `crate::common::skip_unless_root()` and run inside
//! Docker CI containers. Non-root tests exercise clap parsing and error paths
//! that do not need privilege.

use std::ffi::OsString;

/// Run `uumain` with the given args, returning the exit code.
fn run(args: &[&str]) -> i32 {
    let os_args: Vec<OsString> = args.iter().map(|s| (*s).into()).collect();
    useradd::uumain(os_args.into_iter())
}

/// Helper to create a temp dir with the basic files useradd needs:
/// - etc/passwd (with root entry)
/// - etc/shadow (with root entry)
/// - etc/group (with root group)
/// - etc/login.defs (with UID/GID ranges)
fn setup_root_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("failed to create etc dir");

    std::fs::write(etc.join("passwd"), "root:x:0:0:root:/root:/bin/bash\n")
        .expect("failed to write passwd file");

    std::fs::write(etc.join("shadow"), "root:$6$hash:19500:0:99999:7:::\n")
        .expect("failed to write shadow file");

    std::fs::write(etc.join("group"), "root:x:0:\n").expect("failed to write group file");

    std::fs::write(
        etc.join("login.defs"),
        "\
UID_MIN 1000\n\
UID_MAX 60000\n\
SYS_UID_MIN 100\n\
SYS_UID_MAX 999\n\
GID_MIN 1000\n\
GID_MAX 60000\n\
SYS_GID_MIN 100\n\
SYS_GID_MAX 999\n\
USERGROUPS_ENAB yes\n\
CREATE_HOME no\n\
",
    )
    .expect("failed to write login.defs");

    dir
}

/// Run `uumain` with a `--root` dir prepended to the args.
fn run_with_root(dir: &tempfile::TempDir, extra_args: &[&str]) -> i32 {
    let root_str = dir.path().to_str().expect("non-UTF-8 temp path");
    let mut args = vec!["useradd", "-R", root_str];
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
    let code = run(&["useradd", "--help"]);
    assert_eq!(code, 0, "--help should exit 0");
}

#[test]
fn test_unknown_flag_exits_error() {
    let code = run(&["useradd", "--bogus"]);
    assert_eq!(code, 2, "unknown flag should exit 2");
}

#[test]
fn test_missing_login_exits_error() {
    let code = run(&["useradd"]);
    assert_eq!(code, 2, "missing LOGIN should exit 2");
}

#[test]
fn test_defaults_flag() {
    // -D should print defaults; requires root for login.defs read on real system,
    // but we only care that clap parses it without error. If not root, we expect
    // exit 1 (permission denied).
    let code = run(&["useradd", "-D"]);
    if rustix::process::getuid().is_root() {
        assert_eq!(code, 0, "-D should exit 0 when root");
    } else {
        assert_eq!(code, 1, "-D should exit 1 when not root");
    }
}

#[test]
fn test_defaults_flag_honors_key_overrides() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(
        &dir,
        &["-D", "-K", "HOME=/OVERRIDDEN", "-K", "SHELL=/bin/zsh"],
    );
    assert_eq!(code, 0, "useradd -D -K should exit 0");
}

#[test]
fn test_defaults_flag_invalid_key_exits_error() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-D", "-K", "UID_MIN"]);
    assert_eq!(code, 3, "useradd -D with invalid KEY=VALUE should exit 3");
}

#[test]
fn test_conflicting_create_no_create_home() {
    let code = run(&["useradd", "-m", "-M", "testuser"]);
    assert_eq!(code, 2, "-m -M conflict should exit 2");
}

#[test]
fn test_conflicting_user_group_no_user_group() {
    let code = run(&["useradd", "-U", "-N", "testuser"]);
    assert_eq!(code, 2, "-U -N conflict should exit 2");
}

// ---------------------------------------------------------------------------
// Root-only tests -- exercise real operations via --root
// ---------------------------------------------------------------------------

// A newline in -c once appended a second record — `evil::0:0::/:/bin/sh`, a
// passwordless UID 0 account — and a colon added a field that made the file
// unreadable for every tool. Both must be refused before anything is written.
#[test]
fn test_comment_with_newline_or_colon_is_rejected() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let original = read_passwd(&dir);

    let code = run_with_root(&dir, &["-N", "-c", "x\nevil::0:0::/:/bin/sh", "inj"]);
    assert_eq!(code, 3, "newline in comment must be a bad argument");
    let code = run_with_root(&dir, &["-N", "-c", "a:b", "inj"]);
    assert_eq!(code, 3, "colon in comment must be a bad argument");

    assert_eq!(read_passwd(&dir), original, "nothing may be written");
    assert!(!read_shadow(&dir).contains("inj:"));
}

#[test]
fn test_shell_and_password_fields_are_validated() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    assert_eq!(run_with_root(&dir, &["-N", "-s", "/bin/sh:x", "u"]), 3);
    assert_eq!(run_with_root(&dir, &["-N", "-p", "$6$a\nb", "u"]), 3);
    assert!(!read_passwd(&dir).contains("u:"));
}

// A `..` in -d used to abort the tool after passwd and shadow were written
// but before the home existed; -d and -k are created and chowned as root, so
// they must be absolute and must not climb.
#[test]
fn test_home_and_skel_must_be_absolute_without_parent_dirs() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let original = read_passwd(&dir);

    assert_eq!(
        run_with_root(&dir, &["-N", "-d", "/home/../srv/foo", "foo"]),
        3
    );
    assert_eq!(run_with_root(&dir, &["-N", "-d", "relative/foo", "foo"]), 3);
    assert_eq!(
        run_with_root(&dir, &["-N", "-m", "-k", "/etc/../root", "foo"]),
        3
    );

    assert_eq!(read_passwd(&dir), original, "nothing may be written");
    assert!(!dir.path().join("srv/foo").exists());
}

#[test]
fn test_create_user_basic() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-N", "testuser"]);
    assert_eq!(code, 0, "basic useradd should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("testuser:"),
        "passwd should contain testuser entry, got: {passwd}"
    );

    let shadow = read_shadow(&dir);
    assert!(
        shadow.contains("testuser:"),
        "shadow should contain testuser entry, got: {shadow}"
    );
}

#[test]
fn test_create_user_with_home() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    // Create skel directory so -m does not fail on missing skel.
    let skel = dir.path().join("etc/skel");
    std::fs::create_dir_all(&skel).expect("failed to create skel dir");
    // Create /home base directory so create_dir (not create_dir_all) succeeds.
    let home_base = dir.path().join("home");
    std::fs::create_dir_all(&home_base).expect("failed to create home base dir");

    let code = run_with_root(&dir, &["-m", "-N", "homeuser"]);
    assert_eq!(code, 0, "useradd -m should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("homeuser:"),
        "passwd should contain homeuser, got: {passwd}"
    );

    // Verify home directory was created.
    let home_path = dir.path().join("home/homeuser");
    assert!(
        home_path.exists(),
        "home directory should have been created at {}",
        home_path.display()
    );
}

#[test]
fn test_create_user_with_uid() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-u", "5000", "-N", "uiduser"]);
    assert_eq!(code, 0, "useradd -u 5000 should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("uiduser:x:5000:"),
        "passwd should contain UID 5000, got: {passwd}"
    );
}

#[test]
fn test_create_user_with_shell() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-s", "/bin/zsh", "-N", "shelluser"]);
    assert_eq!(code, 0, "useradd -s /bin/zsh should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains(":/bin/zsh\n") || passwd.contains(":/bin/zsh"),
        "passwd should contain /bin/zsh as shell, got: {passwd}"
    );
}

#[test]
fn test_create_user_system() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-r", "-N", "sysuser"]);
    assert_eq!(code, 0, "useradd -r should exit 0");

    let passwd = read_passwd(&dir);
    // Parse the UID from the passwd entry for sysuser.
    let sysuser_line = passwd
        .lines()
        .find(|l| l.starts_with("sysuser:"))
        .expect("sysuser entry should exist in passwd");
    let fields: Vec<&str> = sysuser_line.split(':').collect();
    let uid: u32 = fields[2].parse().expect("UID should be a valid number");
    assert!(
        (100..=999).contains(&uid),
        "system user UID should be in range 100-999, got: {uid}"
    );
}

#[test]
fn test_create_user_with_group() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    // useradd(8): the group given to -g must exist, named or numbered.
    std::fs::write(dir.path().join("etc/group"), "root:x:0:\nstaff:x:1000:\n")
        .expect("write group");

    let code = run_with_root(&dir, &["-g", "1000", "-N", "grpuser"]);
    assert_eq!(
        code, 0,
        "useradd -g 1000 should exit 0 when GID 1000 exists"
    );

    let passwd = read_passwd(&dir);
    // The GID (4th field) should be 1000.
    let grpuser_line = passwd
        .lines()
        .find(|l| l.starts_with("grpuser:"))
        .expect("grpuser entry should exist in passwd");
    let fields: Vec<&str> = grpuser_line.split(':').collect();
    assert_eq!(
        fields[3], "1000",
        "primary GID should be 1000, got: {}",
        fields[3]
    );
}

#[test]
fn test_duplicate_user_fails() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();

    // First creation should succeed.
    let code = run_with_root(&dir, &["-N", "dupuser"]);
    assert_eq!(code, 0, "first useradd should succeed");

    // Second creation with same name should fail (exit 9).
    let code = run_with_root(&dir, &["-N", "dupuser"]);
    assert_eq!(code, 9, "duplicate user should exit 9");
}

#[test]
fn test_create_user_with_comment() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-c", "Test User", "-N", "commentuser"]);
    assert_eq!(code, 0, "useradd -c should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("Test User"),
        "GECOS should contain comment, got: {passwd}"
    );
}

#[test]
fn test_create_user_creates_user_group() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    // Default behavior: create a user group with same name.
    let code = run_with_root(&dir, &["grpuser2"]);
    assert_eq!(code, 0, "useradd with user group should exit 0");

    let group = read_group(&dir);
    assert!(
        group.contains("grpuser2:"),
        "group file should contain user group entry, got: {group}"
    );
}

#[test]
fn test_create_user_preserves_existing_entries() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-N", "newuser"]);
    assert_eq!(code, 0, "useradd should succeed");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("root:x:0:0:root:/root:/bin/bash"),
        "root entry should be preserved, got: {passwd}"
    );
    assert!(
        passwd.contains("newuser:"),
        "newuser entry should be added, got: {passwd}"
    );

    let shadow = read_shadow(&dir);
    assert!(
        shadow.contains("root:$6$hash:19500:0:99999:7:::"),
        "root shadow entry should be preserved, got: {shadow}"
    );
}

#[test]
fn test_create_user_with_home_dir_flag() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-d", "/custom/home", "-N", "customhome"]);
    assert_eq!(code, 0, "useradd -d should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains(":/custom/home:"),
        "passwd should contain custom home path, got: {passwd}"
    );
}

#[test]
fn test_create_user_with_key_uid_range() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(
        &dir,
        &[
            "-K",
            "UID_MIN=9100",
            "-K",
            "UID_MAX=9100",
            "-M",
            "-N",
            "keyuser",
        ],
    );
    assert_eq!(code, 0, "useradd -K UID range should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("keyuser:x:9100:"),
        "passwd should contain UID 9100 from -K, got: {passwd}"
    );
}

#[test]
fn test_create_user_with_key_long_option() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(
        &dir,
        &[
            "--key",
            "UID_MIN=9101",
            "--key",
            "UID_MAX=9101",
            "-M",
            "-N",
            "keyuserlong",
        ],
    );
    assert_eq!(code, 0, "useradd --key should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("keyuserlong:x:9101:"),
        "passwd should contain UID 9101 from --key, got: {passwd}"
    );
}

#[test]
fn test_create_system_user_with_key_sys_uid_range() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(
        &dir,
        &[
            "-r",
            "-K",
            "SYS_UID_MIN=250",
            "-K",
            "SYS_UID_MAX=250",
            "-M",
            "-N",
            "syskeyuser",
        ],
    );
    assert_eq!(code, 0, "useradd -r -K SYS_UID range should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("syskeyuser:x:250:"),
        "passwd should contain UID 250 from -K, got: {passwd}"
    );
}

#[test]
fn test_create_user_with_key_gid_range_for_user_group() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    // Without -N, create a matching user group; both UID and GID from -K.
    let code = run_with_root(
        &dir,
        &[
            "-K",
            "UID_MIN=9200",
            "-K",
            "UID_MAX=9200",
            "-K",
            "GID_MIN=9200",
            "-K",
            "GID_MAX=9200",
            "-M",
            "keygrpuser",
        ],
    );
    assert_eq!(code, 0, "useradd -K with user group should exit 0");

    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("keygrpuser:x:9200:9200:"),
        "passwd should contain UID/GID 9200 from -K, got: {passwd}"
    );

    let group = read_group(&dir);
    assert!(
        group.contains("keygrpuser:x:9200:"),
        "group should contain GID 9200 from -K, got: {group}"
    );
}

#[test]
fn test_create_user_with_key_pass_max_days() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-K", "PASS_MAX_DAYS=-1", "-M", "-N", "ageuser"]);
    assert_eq!(code, 0, "useradd -K PASS_MAX_DAYS should exit 0");

    let shadow = read_shadow(&dir);
    let line = shadow
        .lines()
        .find(|l| l.starts_with("ageuser:"))
        .expect("ageuser shadow entry");
    // name:passwd:lstchg:min:max:warn:...
    let fields: Vec<&str> = line.split(':').collect();
    assert!(
        fields.len() >= 5,
        "shadow entry should have max field, got: {line}"
    );
    assert_eq!(
        fields[4], "-1",
        "PASS_MAX_DAYS override should set max age to -1, got: {line}"
    );
}

#[test]
fn test_key_missing_equals_exits_error() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let code = run_with_root(&dir, &["-K", "UID_MIN", "-M", "-N", "badkeyuser"]);
    assert_eq!(code, 3, "invalid KEY=VALUE should exit 3 (bad argument)");
}

// ---------------------------------------------------------------------------
// Comments and NIS compat lines survive a rewrite
// ---------------------------------------------------------------------------

#[test]
fn test_comments_and_compat_lines_survive_useradd() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let etc = dir.path().join("etc");
    std::fs::write(
        etc.join("passwd"),
        "# System accounts\n\
         root:x:0:0:root:/root:/bin/bash\n\
         \n\
         # pulled from the directory\n\
         +@staff\n\
         +::::::\n",
    )
    .unwrap();
    std::fs::write(etc.join("group"), "# Local groups\nroot:x:0:\n+:::\n").unwrap();

    let code = run_with_root(&dir, &["-N", "alice"]);
    assert_eq!(code, 0, "useradd must work on a compat host");

    let passwd = read_passwd(&dir);
    assert!(passwd.contains("alice:"), "the account was added");
    assert!(
        passwd.contains("# System accounts") && passwd.contains("# pulled from the directory"),
        "comments must survive the rewrite, got: {passwd}"
    );
    assert!(
        passwd.contains("+@staff") && passwd.contains("+::::::"),
        "NIS compat lines must survive the rewrite, got: {passwd}"
    );
    let group = read_group(&dir);
    assert!(
        group.contains("# Local groups") && group.contains("+:::"),
        "group comments and compat lines must survive, got: {group}"
    );
}

#[test]
fn test_primary_group_must_exist() {
    if crate::common::skip_unless_root() {
        return;
    }

    // useradd(8) exit 6: "specified group doesn't exist". A numeric GID that
    // names no group used to be accepted, leaving the account pointing at a
    // group that does not exist.
    let dir = setup_root_dir();
    assert_eq!(run_with_root(&dir, &["-g", "12345", "-N", "u"]), 6);
    assert_eq!(run_with_root(&dir, &["-g", "nosuchgroup", "-N", "u"]), 6);
    assert!(!read_passwd(&dir).contains("u:"), "nothing may be written");
}

#[test]
fn test_system_account_has_no_home_and_no_aging() {
    if crate::common::skip_unless_root() {
        return;
    }

    // useradd(8): -r creates no home "regardless of CREATE_HOME" and leaves
    // "no aging information in /etc/shadow" (both verified against GNU).
    let dir = setup_root_dir();
    let etc = dir.path().join("etc");
    let defs = std::fs::read_to_string(etc.join("login.defs")).unwrap();
    std::fs::write(
        etc.join("login.defs"),
        defs.replace("CREATE_HOME no", "CREATE_HOME yes"),
    )
    .unwrap();

    assert_eq!(run_with_root(&dir, &["-r", "svc"]), 0);
    assert!(
        !dir.path().join("home/svc").exists(),
        "-r must not create a home even with CREATE_HOME yes"
    );
    let shadow = read_shadow(&dir);
    let line = shadow
        .lines()
        .find(|l| l.starts_with("svc:"))
        .expect("svc in shadow");
    let fields: Vec<&str> = line.split(':').collect();
    assert_eq!(
        (fields[3], fields[4], fields[5]),
        ("", "", ""),
        "a system account carries no aging information, got: {line}"
    );
}

#[test]
fn test_defaults_are_persisted_and_reused() {
    if crate::common::skip_unless_root() {
        return;
    }

    // useradd(8): with -D, a value-carrying option changes the default and
    // saves it in /etc/default/useradd. It used to print and exit 0 without
    // changing anything.
    let dir = setup_root_dir();
    std::fs::create_dir_all(dir.path().join("etc/default")).unwrap();
    let prefix = dir.path().to_str().unwrap();

    assert_eq!(
        run(&[
            "useradd",
            "-P",
            prefix,
            "-D",
            "-s",
            "/bin/zsh",
            "-b",
            "/srv/home"
        ]),
        0
    );
    let saved = std::fs::read_to_string(dir.path().join("etc/default/useradd")).unwrap();
    assert!(
        saved.contains("SHELL=/bin/zsh") && saved.contains("HOME=/srv/home"),
        "the defaults must be saved, got: {saved}"
    );

    // A new account picks them up.
    assert_eq!(run(&["useradd", "-P", prefix, "-M", "picker"]), 0);
    let passwd = read_passwd(&dir);
    assert!(
        passwd.contains("picker:x:") && passwd.contains(":/srv/home/picker:/bin/zsh"),
        "the saved defaults must apply, got: {passwd}"
    );
}

#[test]
fn test_base_dir_flag_and_uid_sentinel() {
    if crate::common::skip_unless_root() {
        return;
    }

    let dir = setup_root_dir();
    let prefix = dir.path().to_str().unwrap();

    assert_eq!(
        run(&["useradd", "-P", prefix, "-M", "-b", "/opt/people", "b1"]),
        0
    );
    assert!(
        read_passwd(&dir).contains(":/opt/people/b1:"),
        "-b sets the home base"
    );

    // u32::MAX is (uid_t)-1, the "no change" sentinel of chown/setresuid.
    assert_eq!(
        run(&["useradd", "-P", prefix, "-M", "-u", "4294967295", "bad"]),
        3
    );
    assert!(!read_passwd(&dir).contains("bad:"), "nothing written");
}
