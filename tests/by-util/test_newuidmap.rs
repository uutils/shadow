// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore newuidmap newgidmap subuid subgid setgroups unshare userns

//! Integration tests for `newuidmap` and `newgidmap`.
//!
//! The success path needs a user namespace to write into. A test user
//! creates one with `unshare -U` and keeps it alive; the helper is then run
//! *as that user*, unprivileged, against the child. The kernel lets an
//! unprivileged writer map its own id once into a namespace it owns, so that
//! single-line mapping is a real end-to-end write -- observable in the
//! child's `uid_map` afterwards. Everything the helper refuses is checked the
//! same way, against the same live target.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::{run, skip_unless_root};

/// A user, and a process of theirs sitting in a fresh user namespace.
struct Owner {
    name: String,
    uid: u32,
    gid: u32,
    ns: Child,
}

impl Owner {
    fn new(tag: &str) -> Option<Owner> {
        let name = format!("{tag}_{}", std::process::id());
        run("useradd", &["-M", &name]).assert_code(0);
        let entry = shadow_core::process::getpwnam(&name)
            .expect("nss")
            .expect("created");

        let mut cmd = Command::new("unshare");
        cmd.args(["-U", "sleep", "60"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut ns =
            shadow_core::process::spawn_as_user(&mut cmd, entry.uid, entry.gid, vec![entry.gid])
                .expect("spawn unshare");
        // Give unshare a moment to enter the namespace, and notice if it could
        // not (a kernel or seccomp that forbids it), in which case skip.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok(Some(_)) = ns.try_wait() {
                let _ = run("userdel", &[&name]);
                return None;
            }
            let map =
                std::fs::read_to_string(format!("/proc/{}/uid_map", ns.id())).unwrap_or_default();
            // An unmapped fresh namespace has an empty uid_map.
            if map.is_empty()
                && std::fs::read_to_string(format!("/proc/{}/status", ns.id()))
                    .is_ok_and(|s| s.contains("NSpid"))
            {
                std::thread::sleep(Duration::from_millis(200));
                return Some(Owner {
                    name,
                    uid: entry.uid,
                    gid: entry.gid,
                    ns,
                });
            }
            if Instant::now() > deadline {
                let _ = ns.kill();
                let _ = run("userdel", &[&name]);
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn pid(&self) -> String {
        self.ns.id().to_string()
    }

    /// Run `<tool> <args>` as this user, unprivileged.
    fn run_as(&self, tool: &str, args: &[&str]) -> crate::common::Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shadow-rs"));
        cmd.arg(tool)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child =
            shadow_core::process::spawn_as_user(&mut cmd, self.uid, self.gid, vec![self.gid])
                .expect("spawn tool");
        let out = child.wait_with_output().expect("wait");
        crate::common::Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn map(&self, which: &str) -> String {
        std::fs::read_to_string(format!("/proc/{}/{which}", self.ns.id())).unwrap_or_default()
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.ns.kill();
        let _ = self.ns.wait();
        let _ = run("userdel", &[&self.name]);
    }
}

/// Grant a subordinate range by writing the files directly, as an
/// administrator (or a package's postinst) would; the tools under test read
/// them, they do not manage them here.
fn grant_subids(name: &str, start: u32, count: u32) {
    use std::io::Write as _;
    for file in ["/etc/subuid", "/etc/subgid"] {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(file)
            .expect(file);
        writeln!(f, "{name}:{start}:{count}").expect("append");
    }
}

// ---------------------------------------------------------------------------
// Refusals that need no namespace
// ---------------------------------------------------------------------------

#[test]
fn test_help_and_usage() {
    run("newuidmap", &["--help"])
        .assert_code(0)
        .assert_stdout_contains("Usage:");
    run("newgidmap", &["--help"])
        .assert_code(0)
        .assert_stdout_contains("Usage:");
    run("newuidmap", &[])
        .assert_code(1)
        .assert_stderr_contains("usage:");
    run("newuidmap", &["1", "0", "100000"])
        .assert_code(1)
        .assert_stderr_contains("ranges:");
    run("newuidmap", &["1", "0", "100000", "many"])
        .assert_code(1)
        .assert_stderr_contains("usage:");
    run("newuidmap", &["1", "0", "100000", "0"])
        .assert_code(1)
        .assert_stderr_contains("subuid overflow detected.");
    run("newgidmap", &["1", "0", "100000", "0"])
        .assert_code(1)
        .assert_stderr_contains("subgid overflow detected.");
}

#[test]
fn test_no_such_process() {
    if skip_unless_root() {
        return;
    }
    // The range check comes before the process is looked at; root maps
    // itself once, so this reaches the target and finds nothing there.
    run("newuidmap", &["4194304", "0", "0", "1"])
        .assert_code(1)
        .assert_stderr_contains("Could not open proc directory for target 4194304");
}

/// A process that is not the caller's is refused by name and number.
#[test]
fn test_someone_elses_process_is_refused() {
    if skip_unless_root() {
        return;
    }
    let Some(owner) = Owner::new("nm_other") else {
        return;
    };
    // pid 1 belongs to root; the user asks to map only their own id, which is
    // allowed by range, so the refusal is about ownership.
    owner
        .run_as("newuidmap", &["1", "0", &owner.uid.to_string(), "1"])
        .assert_code(1)
        .assert_stderr_contains("Target process is owned by a different user");
}

// ---------------------------------------------------------------------------
// Against a live namespace
// ---------------------------------------------------------------------------

/// The one write an unprivileged caller may make: their own id, once. It has
/// to land in the kernel, not merely be allowed.
#[test]
fn test_own_uid_maps_once_and_the_kernel_shows_it() {
    if skip_unless_root() {
        return;
    }
    let Some(owner) = Owner::new("nm_own") else {
        return;
    };
    let uid = owner.uid.to_string();
    owner
        .run_as("newuidmap", &[&owner.pid(), "0", &uid, "1"])
        .assert_code(0);
    let map = owner.map("uid_map");
    let fields: Vec<&str> = map.split_whitespace().collect();
    assert_eq!(
        fields,
        vec!["0", uid.as_str(), "1"],
        "uid_map after the write: {map:?}"
    );
}

/// The same for gids. An unprivileged writer of `gid_map` must first deny
/// setgroups in the namespace; the helper, being setuid on a real system,
/// need not, so the test does it as the owner would.
#[test]
fn test_own_gid_maps_once() {
    if skip_unless_root() {
        return;
    }
    let Some(owner) = Owner::new("nm_gid") else {
        return;
    };
    std::fs::write(format!("/proc/{}/setgroups", owner.pid()), "deny").expect("deny setgroups");
    let gid = owner.gid.to_string();
    owner
        .run_as("newgidmap", &[&owner.pid(), "0", &gid, "1"])
        .assert_code(0);
    let map = owner.map("gid_map");
    assert_eq!(
        map.split_whitespace().collect::<Vec<_>>(),
        vec!["0", gid.as_str(), "1"],
        "{map:?}"
    );
}

/// A range outside the grant is refused before anything reaches the kernel,
/// with the range spelled out.
#[test]
fn test_range_outside_the_grant_is_refused() {
    if skip_unless_root() {
        return;
    }
    let Some(owner) = Owner::new("nm_range") else {
        return;
    };
    grant_subids(&owner.name, 100_000, 65_536);
    owner
        .run_as("newuidmap", &[&owner.pid(), "0", "165530", "10"])
        .assert_code(1)
        .assert_stderr_contains("uid range [0-10) -> [165530-165540) not allowed");
    assert!(
        owner.map("uid_map").is_empty(),
        "nothing may have been written"
    );
}

/// The kernel would refuse an overlap with a bare EINVAL; the helper names it.
#[test]
fn test_overlap_is_named() {
    if skip_unless_root() {
        return;
    }
    let Some(owner) = Owner::new("nm_overlap") else {
        return;
    };
    grant_subids(&owner.name, 100_000, 65_536);
    owner
        .run_as(
            "newuidmap",
            &[&owner.pid(), "0", "100000", "10", "5", "100100", "10"],
        )
        .assert_code(1)
        .assert_stderr_contains("overlap");
}

/// A second write to the same namespace is refused by the kernel, and the
/// helper reports it rather than pretending.
#[test]
fn test_a_map_is_written_once() {
    if skip_unless_root() {
        return;
    }
    let Some(owner) = Owner::new("nm_twice") else {
        return;
    };
    let uid = owner.uid.to_string();
    owner
        .run_as("newuidmap", &[&owner.pid(), "0", &uid, "1"])
        .assert_code(0);
    owner
        .run_as("newuidmap", &[&owner.pid(), "0", &uid, "1"])
        .assert_code(1)
        .assert_stderr_contains("write to uid_map failed");
}

/// The `fd:N` form: the caller hands over a descriptor on /proc/<pid>, and a
/// descriptor on anything else is a usage error.
#[test]
fn test_fd_form() {
    if skip_unless_root() {
        return;
    }
    let Some(owner) = Owner::new("nm_fd") else {
        return;
    };
    // Descriptor 5 in the child: open /proc/<pid> and pass it through.
    let dir = std::fs::File::open(format!("/proc/{}", owner.pid())).expect("open proc dir");
    let uid = owner.uid.to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shadow-rs"));
    cmd.args(["newuidmap", "fd:0", "0", &uid, "1"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::from(dir))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = shadow_core::process::spawn_as_user(&mut cmd, owner.uid, owner.gid, vec![owner.gid])
        .expect("spawn")
        .wait_with_output()
        .expect("wait");
    assert!(
        out.status.success(),
        "fd form failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        owner.map("uid_map").split_whitespace().collect::<Vec<_>>(),
        vec!["0", uid.as_str(), "1"]
    );

    let not_a_dir = std::fs::File::open("/etc/hostname").expect("open");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shadow-rs"));
    cmd.args(["newuidmap", "fd:0", "0", &uid, "1"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::from(not_a_dir))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = shadow_core::process::spawn_as_user(&mut cmd, owner.uid, owner.gid, vec![owner.gid])
        .expect("spawn")
        .wait_with_output()
        .expect("wait");
    assert_eq!(out.status.code(), Some(1));
}
