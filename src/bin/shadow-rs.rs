// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Multicall binary entry point for shadow-rs.
//!
//! Dispatches to the appropriate utility based on `argv[0]`.
//! When invoked as `shadow-rs <util>`, uses the first argument instead.
//!
//! # Privileges
//!
//! The per-tool install makes only `passwd`, `chfn`, `chsh` and `newgrp`
//! setuid-root. A multicall install has to make the one binary setuid, which
//! would hand euid 0 to every applet — an unprivileged `pwck -s` rewriting
//! `/etc/passwd`. So before an applet outside that set runs, the binary drops
//! back to the caller's uid, and the two layouts have the same privilege
//! model.

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

type Applet = fn(&[OsString]) -> i32;

/// Applets that keep euid 0 for an unprivileged caller: the same five that
/// `make install` marks setuid.
const SETUID_APPLETS: [&str; 5] = ["passwd", "chfn", "chsh", "newgrp", "gpasswd"];

/// Every applet compiled into this binary, by name, in `--list` order.
// `#[cfg]` is not accepted on the elements of a `vec![]` literal, so the
// table is assembled push by push.
#[allow(clippy::vec_init_then_push)]
// A build that selects no applet at all -- `--no-default-features` -- pushes
// nothing, and the binding is then not mutated.
#[allow(unused_mut)]
fn applets() -> Vec<(&'static str, Applet)> {
    let mut table: Vec<(&'static str, Applet)> = Vec::with_capacity(14);
    #[cfg(feature = "chage")]
    table.push(("chage", |a| chage::uumain(a.iter().cloned())));
    #[cfg(feature = "chfn")]
    table.push(("chfn", |a| chfn::uumain(a.iter().cloned())));
    #[cfg(feature = "chpasswd")]
    table.push(("chpasswd", |a| chpasswd::uumain(a.iter().cloned())));
    #[cfg(feature = "chsh")]
    table.push(("chsh", |a| chsh::uumain(a.iter().cloned())));
    #[cfg(feature = "gpasswd")]
    table.push(("gpasswd", |a| gpasswd::uumain(a.iter().cloned())));
    #[cfg(feature = "groupadd")]
    table.push(("groupadd", |a| groupadd::uumain(a.iter().cloned())));
    #[cfg(feature = "groupdel")]
    table.push(("groupdel", |a| groupdel::uumain(a.iter().cloned())));
    #[cfg(feature = "groupmod")]
    table.push(("groupmod", |a| groupmod::uumain(a.iter().cloned())));
    #[cfg(feature = "grpck")]
    table.push(("grpck", |a| grpck::uumain(a.iter().cloned())));
    #[cfg(feature = "newgrp")]
    table.push(("newgrp", |a| newgrp::uumain(a.iter().cloned())));
    #[cfg(feature = "passwd")]
    table.push(("passwd", |a| passwd::uumain(a.iter().cloned())));
    #[cfg(feature = "pwck")]
    table.push(("pwck", |a| pwck::uumain(a.iter().cloned())));
    #[cfg(feature = "useradd")]
    table.push(("useradd", |a| useradd::uumain(a.iter().cloned())));
    #[cfg(feature = "userdel")]
    table.push(("userdel", |a| userdel::uumain(a.iter().cloned())));
    #[cfg(feature = "usermod")]
    table.push(("usermod", |a| usermod::uumain(a.iter().cloned())));
    table
}

fn find_applet(name: &str) -> Option<Applet> {
    applets()
        .into_iter()
        .find(|(applet, _)| *applet == name)
        .map(|(_, run)| run)
}

/// Whether `applet` may run with the setuid privilege on behalf of an
/// unprivileged caller.
fn keeps_privilege(applet: &str) -> bool {
    SETUID_APPLETS.contains(&applet)
}

/// Give the setuid privilege up unless `applet` is one of the tools it exists
/// for. Fails closed: if the kernel will not take the privilege away, the
/// applet does not run.
fn drop_privileges_for(applet: &str) -> Result<(), ExitCode> {
    let real = rustix::process::getuid();
    if real == rustix::process::geteuid() || keeps_privilege(applet) {
        return Ok(());
    }
    // setuid(2) called with euid 0 sets the real, effective and saved uid,
    // so the privilege is gone for good rather than parked in the saved uid.
    let result = shadow_core::process::setuid(real.as_raw());
    if result.is_err() || rustix::process::geteuid() != real {
        let _ = writeln!(
            std::io::stderr(),
            "shadow-rs: cannot drop privileges for {applet}: {}",
            result
                .err()
                .map_or_else(|| "effective uid unchanged".to_string(), |e| e.to_string())
        );
        return Err(ExitCode::FAILURE);
    }
    Ok(())
}

/// Convert a tool's `i32` exit code to `ExitCode`.
fn to_exit_code(code: i32) -> ExitCode {
    // Every documented exit code fits; anything else is a bug and must not
    // masquerade as success.
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn run_applet(applet: &str, run: Applet, args: &[OsString]) -> ExitCode {
    match drop_privileges_for(applet) {
        Ok(()) => to_exit_code(run(args)),
        Err(code) => code,
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();

    let binary_name = args
        .first()
        .and_then(|a| {
            Path::new(a)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
        })
        .unwrap_or_default();

    // In setuid context, reject spoofed argv[0] that doesn't match AT_EXECFN.
    // Only enforced when euid != uid (setuid active) — non-setuid invocations
    // are harmless since the caller already has full privileges.
    let is_setuid = rustix::process::getuid() != rustix::process::geteuid();
    if is_setuid && !shadow_core::process::verify_argv0_matches_execfn(&binary_name) {
        let _ = writeln!(
            std::io::stderr().lock(),
            "shadow-rs: argv[0] does not match executed binary, aborting"
        );
        return ExitCode::FAILURE;
    }

    // Direct invocation via symlink (e.g., argv[0] = "passwd")
    if let Some(run) = find_applet(&binary_name) {
        return run_applet(&binary_name, run, &args);
    }

    // Multicall: `shadow-rs <util> [args...]`
    if args.len() > 1 {
        let util_name = args[1].to_string_lossy().to_string();

        if util_name == "--list" {
            print_available_utils();
            return ExitCode::SUCCESS;
        }

        if util_name == "--version" || util_name == "-V" {
            let _ = writeln!(std::io::stdout(), "shadow-rs {}", shadow_core::cli::VERSION);
            return ExitCode::SUCCESS;
        }

        if util_name == "--help" || util_name == "-h" {
            print_multicall_help();
            return ExitCode::SUCCESS;
        }

        if let Some(run) = find_applet(&util_name) {
            return run_applet(&util_name, run, &args[1..]);
        }

        let _ = writeln!(
            std::io::stderr(),
            "shadow-rs: unknown utility '{util_name}'"
        );
        let _ = writeln!(
            std::io::stderr(),
            "Run 'shadow-rs --list' for available utilities."
        );
        return ExitCode::FAILURE;
    }

    let _ = writeln!(
        std::io::stderr(),
        "Usage: shadow-rs <utility> [arguments...]"
    );
    let _ = writeln!(
        std::io::stderr(),
        "Run 'shadow-rs --list' for available utilities."
    );
    ExitCode::FAILURE
}

fn print_multicall_help() {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "shadow-rs {}", shadow_core::cli::VERSION);
    let _ = writeln!(out);
    let _ = writeln!(out, "Usage: shadow-rs <utility> [arguments...]");
    let _ = writeln!(
        out,
        "   or: <name> [arguments...]   (when run through a symlink whose name is the utility, e.g. passwd)"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "Options:");
    let _ = writeln!(out, "  --list        List available utilities");
    let _ = writeln!(out, "  --version, -V Print version");
    let _ = writeln!(out, "  --help, -h    Print this help");
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", shadow_core::cli::AFTER_HELP);
}

fn print_available_utils() {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "Available utilities:");
    for (name, _) in applets() {
        let _ = writeln!(out, "  {name}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_TOOLS: [&str; 15] = [
        "chage", "chfn", "chpasswd", "chsh", "gpasswd", "groupadd", "groupdel", "groupmod",
        "grpck", "newgrp", "passwd", "pwck", "useradd", "userdel", "usermod",
    ];

    // The table drives both dispatch and `--list`, so it must contain only
    // real tools, each once, in a stable order.
    #[test]
    fn applet_table_is_sorted_unique_and_known() {
        let names: Vec<&str> = applets().into_iter().map(|(n, _)| n).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names, sorted);
        assert!(names.iter().all(|n| ALL_TOOLS.contains(n)));
    }

    // Exactly the four tools that the per-tool install marks setuid keep the
    // privilege; every other applet gives it up before running.
    #[test]
    fn only_self_service_tools_keep_privilege() {
        for tool in ALL_TOOLS {
            assert_eq!(
                keeps_privilege(tool),
                matches!(tool, "passwd" | "chfn" | "chsh" | "newgrp" | "gpasswd"),
                "{tool}"
            );
        }
        assert!(!keeps_privilege("shadow-rs"));
        assert!(!keeps_privilege(""));
    }

    // Without privilege to drop there is nothing to do; this must never fail
    // for an ordinary process.
    #[test]
    fn dropping_is_a_no_op_when_not_setuid() {
        assert!(drop_privileges_for("pwck").is_ok());
    }

    #[test]
    fn exit_codes_out_of_range_are_not_success() {
        assert_eq!(to_exit_code(0), ExitCode::from(0));
        assert_eq!(to_exit_code(12), ExitCode::from(12));
        assert_eq!(to_exit_code(-1), ExitCode::from(1));
        assert_eq!(to_exit_code(300), ExitCode::from(1));
    }
}
