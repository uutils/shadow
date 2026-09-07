// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore subuid subgid

//! Integration tests for `usermod`'s subordinate id options.

use crate::common::{run, skip_unless_root};

fn prefix() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let etc = dir.path().join("etc");
    std::fs::create_dir_all(&etc).expect("etc");
    std::fs::write(
        etc.join("passwd"),
        "alice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n",
    )
    .expect("passwd");
    std::fs::write(
        etc.join("shadow"),
        "alice:!:19000:0:99999:7:::\nbob:!:19000:0:99999:7:::\n",
    )
    .expect("shadow");
    std::fs::write(etc.join("group"), "alice:x:1000:\nbob:x:1001:\n").expect("group");
    std::fs::write(etc.join("subuid"), "alice:100000:65536\nbob:165536:65536\n").expect("subuid");
    std::fs::write(etc.join("subgid"), "alice:100000:65536\nbob:165536:65536\n").expect("subgid");
    dir
}

fn usermod(dir: &tempfile::TempDir, args: &[&str]) -> crate::common::Output {
    let p = dir.path().to_str().expect("utf8").to_string();
    let mut all = vec!["--prefix", p.as_str()];
    all.extend_from_slice(args);
    run("usermod", &all)
}

fn lines(dir: &tempfile::TempDir, file: &str, user: &str) -> Vec<String> {
    std::fs::read_to_string(dir.path().join("etc").join(file))
        .expect("read")
        .lines()
        .filter(|l| l.starts_with(&format!("{user}:")))
        .map(str::to_string)
        .collect()
}

#[test]
fn test_add_and_remove_ranges() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    usermod(
        &dir,
        &["-v", "300000-300999", "-w", "300000-300999", "alice"],
    )
    .assert_code(0);
    assert_eq!(
        lines(&dir, "subuid", "alice"),
        vec!["alice:100000:65536", "alice:300000:1000"]
    );
    assert_eq!(
        lines(&dir, "subgid", "alice"),
        vec!["alice:100000:65536", "alice:300000:1000"]
    );

    // A covered range is not added twice.
    usermod(&dir, &["-v", "300500-300600", "alice"]).assert_code(0);
    assert_eq!(lines(&dir, "subuid", "alice").len(), 2);

    // A partial removal splits; the exact remainder disappears.
    usermod(&dir, &["-V", "300000-300499", "alice"]).assert_code(0);
    assert_eq!(
        lines(&dir, "subuid", "alice"),
        vec!["alice:100000:65536", "alice:300500:500"]
    );
    usermod(
        &dir,
        &["-V", "300500-300999", "-W", "300000-300999", "alice"],
    )
    .assert_code(0);
    assert_eq!(lines(&dir, "subuid", "alice"), vec!["alice:100000:65536"]);
    assert_eq!(lines(&dir, "subgid", "alice"), vec!["alice:100000:65536"]);

    // Someone else's entries are never touched.
    assert_eq!(lines(&dir, "subuid", "bob"), vec!["bob:165536:65536"]);
}

/// The option may be repeated, and a range no one held is a silent no-op.
#[test]
fn test_repeated_and_absent_ranges() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    usermod(
        &dir,
        &["-v", "310000-310009", "-v", "320000-320009", "alice"],
    )
    .assert_code(0);
    assert_eq!(lines(&dir, "subuid", "alice").len(), 3);
    usermod(&dir, &["-V", "500000-500010", "alice"]).assert_code(0);
    assert_eq!(lines(&dir, "subuid", "alice").len(), 3);
}

/// An invalid range is exit 3 with the GNU wording, before anything changes.
#[test]
fn test_invalid_range_is_refused() {
    if skip_unless_root() {
        return;
    }
    let dir = prefix();
    for bad in ["300999-300000", "a-b", "300000"] {
        usermod(&dir, &["-v", bad, "alice"])
            .assert_code(3)
            .assert_stderr_contains(&format!("invalid subordinate uid range '{bad}'"));
    }
    usermod(&dir, &["-w", "1-0", "alice"])
        .assert_code(3)
        .assert_stderr_contains("invalid subordinate gid range '1-0'");
    assert_eq!(lines(&dir, "subuid", "alice"), vec!["alice:100000:65536"]);
}
