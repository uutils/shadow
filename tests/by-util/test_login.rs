// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore getty pts openpt grantpt unlockpt ptsname NOCTTY motd

//! Integration tests for `login`.
//!
//! `login` needs what getty gives it: a controlling terminal it is the
//! session leader of. So each test opens a pseudo-terminal, starts the tool
//! on its slave the way getty would, and talks to the master -- answering a
//! prompt only once it has appeared, and reading what the session prints.
//! Nothing here is driven through a pipe; nothing here would work through one.

// The session helpers serve the PAM-gated tests; without PAM only the refusal
// is tested and they go unused.
#![cfg_attr(not(feature = "pam"), allow(dead_code))]

use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::common::{run, skip_unless_root};

/// A poll timeout.
fn millis(ms: i64) -> rustix::event::Timespec {
    rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: ms * 1_000_000,
    }
}

/// A terminal session running the multicall binary as `login`.
struct Session {
    master: OwnedFd,
    child: Child,
    buf: String,
}

impl Session {
    /// Start `login <args>` on a fresh pty, as getty would.
    fn start(args: &[&str], env: &[(&str, &str)]) -> Session {
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("openpt");
        grantpt(&master).expect("grantpt");
        unlockpt(&master).expect("unlockpt");
        let slave_path = ptsname(&master, Vec::new()).expect("ptsname");
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave_path.to_str().expect("utf8"))
            .expect("open slave");

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shadow-rs"));
        cmd.arg("login").args(args);
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("TERM", "dumb");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::from(slave.try_clone().expect("dup")))
            .stdout(Stdio::from(slave.try_clone().expect("dup")))
            .stderr(Stdio::from(slave));
        // `login` must be a session leader with the slave as its controlling
        // tty; a plain spawn would leave it in the test's session.
        let child = shadow_core::process::spawn_with_controlling_tty(&mut cmd, 0).expect("spawn");
        // The pre_exec above claimed fd 0, which is the slave after the
        // redirections; the raw fd is only needed to satisfy the signature.
        let _ = cmd.get_program();
        Session {
            master,
            child,
            buf: String::new(),
        }
    }

    /// Read until `needle` shows up, or the deadline passes. Returns what
    /// was read up to and including the needle.
    fn expect(&mut self, needle: &str, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(pos) = self.buf.find(needle) {
                let end = pos + needle.len();
                let got: String = self.buf.drain(..end).collect();
                return got;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {needle:?}; had {:?}",
                self.buf
            );
            let mut chunk = [0u8; 4096];
            // Non-blocking read with a short poll.
            let mut fds = [rustix::event::PollFd::new(
                &self.master,
                rustix::event::PollFlags::IN,
            )];
            let _ = rustix::event::poll(&mut fds, Some(&millis(200)));
            match rustix::io::read(&self.master, &mut chunk) {
                Ok(0) | Err(rustix::io::Errno::AGAIN) => {}
                Ok(n) => self.buf.push_str(&String::from_utf8_lossy(&chunk[..n])),
                // EIO on a pty master means the slave side closed: session over.
                Err(rustix::io::Errno::IO) => {
                    assert!(
                        self.buf.contains(needle),
                        "session ended before {needle:?}; had {:?}",
                        self.buf
                    );
                }
                Err(e) => panic!("read from pty: {e}"),
            }
        }
    }

    fn send(&mut self, line: &str) {
        let mut f = std::fs::File::from(self.master.try_clone().expect("dup"));
        f.write_all(line.as_bytes()).expect("write");
        f.write_all(b"\n").expect("write");
    }

    /// Wait for the tool to exit, draining output meanwhile.
    fn finish(mut self, timeout: Duration) -> (i32, String) {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                let mut rest = String::new();
                let mut f = std::fs::File::from(self.master.try_clone().expect("dup"));
                let mut fds = [rustix::event::PollFd::new(
                    &self.master,
                    rustix::event::PollFlags::IN,
                )];
                if rustix::event::poll(&mut fds, Some(&millis(100))).is_ok() {
                    let _ = f.read_to_string(&mut rest);
                }
                self.buf.push_str(&rest);
                return (status.code().unwrap_or(-1), std::mem::take(&mut self.buf));
            }
            assert!(
                Instant::now() < deadline,
                "login did not exit; had {:?}",
                self.buf
            );
            let mut chunk = [0u8; 4096];
            let mut fds = [rustix::event::PollFd::new(
                &self.master,
                rustix::event::PollFlags::IN,
            )];
            let _ = rustix::event::poll(&mut fds, Some(&millis(100)));
            if let Ok(n) = rustix::io::read(&self.master, &mut chunk) {
                self.buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const PASSWORD: &str = "pw-for-login-tests";

/// Create a test account with a home, a known password and a shell.
///
/// The name carries the test's tag and this process's pid: the tests run in
/// parallel and the suite runs more than once per `make check`, and a shell
/// from an earlier session may still be winding down under the old name,
/// which makes `userdel` refuse and `useradd` report the name in use.
///
/// Under the full suite the account files are contended by dozens of tests
/// at once, and `useradd` gives up after the same 15 seconds the GNU tool
/// does. That timeout is right for a tool and wrong for a harness that only
/// wants an account to exist, so the wait is repeated -- on that failure and
/// no other.
fn ensure_account(tag: &str) -> String {
    let user = format!("{tag}_{}", std::process::id());
    // Either lock can be the one that timed out: the per-file `.lock` or the
    // suite-wide `/etc/.pwd.lock`.
    let contended = |stderr: &str| stderr.contains("timed out") && stderr.contains("lock");

    let mut out = run("useradd", &["-m", "-s", "/bin/sh", &user]);
    for _ in 0..4 {
        if out.code == 0 || !contended(&out.stderr) {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
        out = run("useradd", &["-m", "-s", "/bin/sh", &user]);
    }
    assert_eq!(out.code, 0, "useradd {user} failed: {}", out.stderr);

    for attempt in 0..5 {
        let mut cmd = crate::common::tool("chpasswd");
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("chpasswd");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(format!("{user}:{PASSWORD}\n").as_bytes())
            .expect("write");
        let out = child.wait_with_output().expect("wait");
        if out.status.success() {
            return user;
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            contended(&stderr) && attempt < 4,
            "chpasswd failed: {stderr}"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    user
}

/// Best-effort removal once a test is done; a shell still winding down makes
/// this fail harmlessly, and the name is never reused.
fn remove_account(user: &str) {
    let _ = run("userdel", &["-r", user]);
}

/// The prompt names the host unless -H asks otherwise.
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// Paths that need no terminal
// ---------------------------------------------------------------------------

#[test]
fn test_help_exits_zero() {
    run("login", &["--help"])
        .assert_code(0)
        .assert_stdout_contains("Usage:");
}

/// `-f` without a name is a usage error in shadow's login and is treated as
/// one here, before any prompt.
#[test]
fn test_f_needs_a_name() {
    if skip_unless_root() {
        return;
    }
    run("login", &["-f"])
        .assert_code(1)
        .assert_stderr_contains("requires a user name");
}

/// Without a controlling terminal there is nothing to log in on.
#[cfg(feature = "pam")]
#[test]
fn test_no_terminal_is_refused() {
    if skip_unless_root() {
        return;
    }
    run("login", &["-f", "root"])
        .assert_code(1)
        .assert_stderr_contains("terminal");
}

/// Without PAM there is no way to authenticate, and the applet says so rather
/// than pretending. The static musl archive is built this way.
#[cfg(not(feature = "pam"))]
#[test]
fn test_without_pam_login_refuses_clearly() {
    if skip_unless_root() {
        return;
    }
    let s = Session::start(&["-f", "root"], &[]);
    let (code, out) = s.finish(Duration::from_secs(10));
    assert_eq!(code, 1);
    assert!(out.contains("PAM support is not compiled in"), "{out:?}");
}

// ---------------------------------------------------------------------------
// Sessions on a pty -- these need a PAM stack
// ---------------------------------------------------------------------------

/// getty autologin: no prompt, a login shell as the user, in their home, with
/// a login environment and the terminal handed over.
#[cfg(feature = "pam")]
#[test]
fn test_f_starts_a_login_shell_as_the_user() {
    if skip_unless_root() {
        return;
    }
    let user = ensure_account("lg_shell");
    let user = user.as_str();
    let mut s = Session::start(&["-f", user], &[]);
    s.expect("$ ", Duration::from_secs(10));
    // The terminal echoes what is typed, so the marker is split in the
    // command and whole only in the output.
    s.send(
        "printf 'O''UT U=%s UID=%s HOME=%s USER=%s LOGNAME=%s SHELL=%s PWD=%s ARGV0=%s\\n' \
         \"$(id -un)\" \"$(id -u)\" \"$HOME\" \"$USER\" \"$LOGNAME\" \"$SHELL\" \"$PWD\" \"$0\"",
    );
    s.expect("OUT ", Duration::from_secs(5));
    let out = s.expect("\n", Duration::from_secs(5));
    assert!(out.contains(&format!("U={user} UID=")), "{out:?}");
    assert!(
        out.contains(&format!(
            "HOME=/home/{user} USER={user} LOGNAME={user} SHELL=/bin/sh PWD=/home/{user}"
        )),
        "{out:?}"
    );
    s.send("stat -c '%U %a' $(tty); exit");
    let (code, rest) = s.finish(Duration::from_secs(10));
    assert!(
        rest.contains(&format!("{user} 600")),
        "the terminal was not handed over: {rest:?}"
    );
    assert_eq!(code, 0, "login exits 0 when the shell exits");
    remove_account(user);
}

/// The environment of the caller is discarded -- except what the terminal
/// provides -- unless -p asks to keep it.
#[cfg(feature = "pam")]
#[test]
fn test_environment_dropped_unless_p() {
    if skip_unless_root() {
        return;
    }
    let user = ensure_account("lg_env");
    let user = user.as_str();
    let mut s = Session::start(&["-f", user], &[("PROBEVAR", "leaked"), ("TERM", "vt100")]);
    s.expect("$ ", Duration::from_secs(10));
    s.send("echo PROBEVAR=[$PROBEVAR] TERM=[$TERM]; exit");
    let (_, out) = s.finish(Duration::from_secs(10));
    assert!(out.contains("PROBEVAR=[] TERM=[vt100]"), "{out:?}");

    let mut s = Session::start(&["-p", "-f", user], &[("PROBEVAR", "kept")]);
    s.expect("$ ", Duration::from_secs(10));
    s.send("echo PROBEVAR=[$PROBEVAR]; exit");
    let (_, out) = s.finish(Duration::from_secs(10));
    assert!(out.contains("PROBEVAR=[kept]"), "{out:?}");
    remove_account(user);
}

/// The password path: the prompt carries the hostname, a wrong password gets
/// "Login incorrect" and another prompt, the right one gets a shell.
#[cfg(feature = "pam")]
#[test]
fn test_wrong_then_right_password() {
    if skip_unless_root() {
        return;
    }
    let user = ensure_account("lg_pw");
    let user = user.as_str();
    let mut s = Session::start(&[], &[]);
    let prompt = s.expect("login: ", Duration::from_secs(10));
    assert!(
        prompt.contains(&hostname()),
        "the prompt should name the host: {prompt:?}"
    );
    s.send(user);
    s.expect("assword:", Duration::from_secs(10));
    s.send("not-the-password");
    s.expect("Login incorrect", Duration::from_secs(15));
    s.expect("login: ", Duration::from_secs(10));
    s.send(user);
    s.expect("assword:", Duration::from_secs(10));
    s.send(PASSWORD);
    s.expect("$ ", Duration::from_secs(15));
    s.send("id -un; exit");
    let (code, out) = s.finish(Duration::from_secs(10));
    assert!(out.contains(user), "{out:?}");
    assert_eq!(code, 0);
    remove_account(user);
}

/// An unknown name is asked for a password all the same, and answered with
/// the same words as a wrong one: nothing tells accounts apart.
#[cfg(feature = "pam")]
#[test]
fn test_unknown_user_is_indistinguishable() {
    if skip_unless_root() {
        return;
    }
    let mut s = Session::start(&["-H"], &[]);
    let prompt = s.expect("login: ", Duration::from_secs(10));
    assert!(
        !prompt.contains(&hostname()),
        "-H must suppress the hostname: {prompt:?}"
    );
    s.send("no_such_user_lg");
    s.expect("assword:", Duration::from_secs(10));
    s.send("anything");
    s.expect("Login incorrect", Duration::from_secs(15));
}

/// After `LOGIN_RETRIES` failures login gives up and exits 1.
#[cfg(feature = "pam")]
#[test]
fn test_gives_up_after_the_retries() {
    if skip_unless_root() {
        return;
    }
    let user = ensure_account("lg_retry");
    let user = user.as_str();
    let retries = shadow_core::login_defs::LoginDefs::load(std::path::Path::new("/etc/login.defs"))
        .ok()
        .and_then(|d| d.get_i64("LOGIN_RETRIES"))
        .unwrap_or(3);
    let mut s = Session::start(&["-H"], &[]);
    for _ in 0..retries {
        s.expect("login: ", Duration::from_secs(10));
        s.send(user);
        s.expect("assword:", Duration::from_secs(10));
        s.send("wrong");
        s.expect("Login incorrect", Duration::from_secs(15));
    }
    let (code, _) = s.finish(Duration::from_secs(15));
    assert_eq!(code, 1);
    remove_account(user);
}

/// An account whose home is gone still gets a session, in `/`, with a notice.
#[cfg(feature = "pam")]
#[test]
fn test_missing_home_falls_back_to_root_directory() {
    if skip_unless_root() {
        return;
    }
    let user = ensure_account("lg_nohome");
    let user = user.as_str();
    std::fs::remove_dir_all(format!("/home/{user}")).expect("remove home");
    let mut s = Session::start(&["-f", user], &[]);
    s.expect(
        "No directory, logging in with HOME=/",
        Duration::from_secs(10),
    );
    s.expect("$ ", Duration::from_secs(10));
    s.send("echo HOME=$HOME PWD=$PWD; exit");
    let (_, out) = s.finish(Duration::from_secs(10));
    assert!(out.contains("HOME=/ PWD=/"), "{out:?}");
    remove_account(user);
}

/// The login is recorded where `who` looks, and the logout clears it.
#[cfg(feature = "pam")]
#[test]
fn test_login_is_recorded_in_utmp() {
    if skip_unless_root() {
        return;
    }
    if !std::path::Path::new("/var/run/utmp").exists()
        && !std::path::Path::new("/run/utmp").exists()
    {
        // No utmp on this system: nothing to record into, which is allowed.
        return;
    }
    let user = ensure_account("lg_utmp");
    let user = user.as_str();
    let mut s = Session::start(&["-h", "probe.example", "-f", user], &[]);
    s.expect("$ ", Duration::from_secs(10));
    s.send("who; exit");
    let (_, out) = s.finish(Duration::from_secs(10));
    assert!(
        out.contains(user) && out.contains("probe.example"),
        "utmp should carry the login and the host: {out:?}"
    );
    remove_account(user);
}
