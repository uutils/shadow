// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Shared test helpers for shadow-rs integration tests.
//!
//! Import with `#[path = "../common/mod.rs"] mod common;` in test files.

/// The variable that turns a root-only skip into a failure.
pub const REQUIRE_ROOT: &str = "SHADOW_TEST_REQUIRE_ROOT";

/// Skip the test when not running as root (euid != 0).
///
/// Returns `true` if the test should be skipped.
///
/// Roughly three quarters of this suite needs root, and a skipped test is
/// reported `ok`, so a run that exercised almost nothing looked exactly like a
/// run that exercised everything. Setting `SHADOW_TEST_REQUIRE_ROOT=1` makes
/// the skip a failure instead; the Docker images set it, so the root suite
/// cannot quietly stop running there.
#[must_use]
pub fn skip_unless_root() -> bool {
    if rustix::process::geteuid().is_root() {
        return false;
    }
    assert!(
        !require_root(),
        "{REQUIRE_ROOT} is set, but this test needs root and the suite is not \
         running as root"
    );
    true
}

/// Whether the run demands that root-only tests actually run.
///
/// An empty value counts as unset, so `-e SHADOW_TEST_REQUIRE_ROOT=` turns the
/// requirement off rather than leaving it mysteriously on.
#[must_use]
pub fn require_root() -> bool {
    std::env::var_os(REQUIRE_ROOT).is_some_and(|v| !v.is_empty())
}

/// A `Command` that runs the multicall binary as `argv[0] = <tool>`.
///
/// Tests that call `uumain` in-process assert on an exit code and nothing
/// else: no test in this suite has ever checked a byte of output, so
/// "bit-for-bit identical to GNU" was unverified. Running the real binary also
/// keeps `harden_process`, `setuid`, Landlock and umask changes from leaking
/// from one test into the next through a shared process.
#[must_use]
pub fn tool(name: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_shadow-rs"));
    cmd.arg(name);
    // A test must not inherit the developer's locale or PATH and then assert
    // on output shaped by them.
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    if require_root() {
        cmd.env(REQUIRE_ROOT, "1");
    }
    cmd
}

/// What a spawned tool did.
pub struct Output {
    /// Exit status, or 1 if the process was killed by a signal.
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    /// Assert the exit code, showing both streams when it does not match.
    pub fn assert_code(&self, expected: i32) -> &Self {
        assert_eq!(
            self.code, expected,
            "expected exit {expected}, got {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        );
        self
    }

    /// Assert that stdout contains `needle`.
    pub fn assert_stdout_contains(&self, needle: &str) -> &Self {
        assert!(
            self.stdout.contains(needle),
            "stdout does not contain {needle:?}\n--- stdout ---\n{}",
            self.stdout
        );
        self
    }

    /// Assert that stderr contains `needle`.
    pub fn assert_stderr_contains(&self, needle: &str) -> &Self {
        assert!(
            self.stderr.contains(needle),
            "stderr does not contain {needle:?}\n--- stderr ---\n{}",
            self.stderr
        );
        self
    }

    /// Assert that stdout is exactly `expected`.
    pub fn assert_stdout_is(&self, expected: &str) -> &Self {
        assert_eq!(self.stdout, expected, "stderr was:\n{}", self.stderr);
        self
    }
}

/// Run a tool and capture what it produced.
///
/// # Panics
///
/// Panics if the binary cannot be spawned, which means the test setup is
/// broken rather than the tool.
#[must_use]
pub fn run(name: &str, args: &[&str]) -> Output {
    run_cmd(tool(name).args(args))
}

/// Run an already-configured command and capture what it produced.
///
/// # Panics
///
/// Panics if the binary cannot be spawned.
pub fn run_cmd(cmd: &mut std::process::Command) -> Output {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("cannot run the shadow-rs binary: {e}"));
    Output {
        // A signal leaves no exit code; report it as a generic failure rather
        // than unwrapping None.
        code: out.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}
