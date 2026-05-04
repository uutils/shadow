// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Multicall binary entry point for shadow-rs.
//!
//! Dispatches to the appropriate utility based on `argv[0]`.
//! When invoked as `shadow-rs <util>`, uses the first argument instead.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

/// Convert a tool's `i32` exit code to `ExitCode`.
#[allow(clippy::cast_sign_loss)] // clamp(0, 255) guarantees non-negative
fn to_exit_code(code: i32) -> ExitCode {
    ExitCode::from(code.clamp(0, 255) as u8)
}

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();

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
    if let Some(code) = dispatch(&binary_name, &args) {
        return to_exit_code(code);
    }

    // Multicall: `shadow-rs <util> [args...]`
    if args.len() > 1 {
        let util_name = args[1].to_string_lossy().to_string();

        if util_name == "--list" {
            print_available_utils();
            return ExitCode::SUCCESS;
        }

        if util_name == "--version" || util_name == "-V" {
            let _ = writeln!(
                std::io::stdout(),
                "shadow-rs (uutils) {}",
                env!("CARGO_PKG_VERSION")
            );
            return ExitCode::SUCCESS;
        }

        if util_name == "--help" || util_name == "-h" {
            print_multicall_help();
            return ExitCode::SUCCESS;
        }

        if let Some(code) = dispatch(&util_name, &args[1..]) {
            return to_exit_code(code);
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
    let _ = writeln!(out, "shadow-rs (uutils) {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out);
    let _ = writeln!(out, "Usage: shadow-rs <utility> [arguments...]");
    let _ = writeln!(
        out,
        "       <utility> [arguments...]   (when invoked via symlink)"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "Options:");
    let _ = writeln!(out, "  --list        List available utilities");
    let _ = writeln!(out, "  --version, -V Print version");
    let _ = writeln!(out, "  --help, -h    Print this help");
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", shadow_core::cli::AFTER_HELP);
}

fn dispatch(name: &str, args: &[std::ffi::OsString]) -> Option<i32> {
    match name {
        #[cfg(feature = "chage")]
        "chage" => Some(chage::uumain(args.iter().cloned())),
        #[cfg(feature = "chfn")]
        "chfn" => Some(chfn::uumain(args.iter().cloned())),
        #[cfg(feature = "chpasswd")]
        "chpasswd" => Some(chpasswd::uumain(args.iter().cloned())),
        #[cfg(feature = "chsh")]
        "chsh" => Some(chsh::uumain(args.iter().cloned())),
        #[cfg(feature = "groupadd")]
        "groupadd" => Some(groupadd::uumain(args.iter().cloned())),
        #[cfg(feature = "groupdel")]
        "groupdel" => Some(groupdel::uumain(args.iter().cloned())),
        #[cfg(feature = "groupmod")]
        "groupmod" => Some(groupmod::uumain(args.iter().cloned())),
        #[cfg(feature = "grpck")]
        "grpck" => Some(grpck::uumain(args.iter().cloned())),
        #[cfg(feature = "newgrp")]
        "newgrp" => Some(newgrp::uumain(args.iter().cloned())),
        #[cfg(feature = "passwd")]
        "passwd" => Some(passwd::uumain(args.iter().cloned())),
        #[cfg(feature = "pwck")]
        "pwck" => Some(pwck::uumain(args.iter().cloned())),
        #[cfg(feature = "useradd")]
        "useradd" => Some(useradd::uumain(args.iter().cloned())),
        #[cfg(feature = "userdel")]
        "userdel" => Some(userdel::uumain(args.iter().cloned())),
        #[cfg(feature = "usermod")]
        "usermod" => Some(usermod::uumain(args.iter().cloned())),
        _ => None,
    }
}

fn print_available_utils() {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "Available utilities:");

    #[cfg(feature = "chage")]
    let _ = writeln!(out, "  chage");
    #[cfg(feature = "chfn")]
    let _ = writeln!(out, "  chfn");
    #[cfg(feature = "chpasswd")]
    let _ = writeln!(out, "  chpasswd");
    #[cfg(feature = "chsh")]
    let _ = writeln!(out, "  chsh");
    #[cfg(feature = "groupadd")]
    let _ = writeln!(out, "  groupadd");
    #[cfg(feature = "groupdel")]
    let _ = writeln!(out, "  groupdel");
    #[cfg(feature = "groupmod")]
    let _ = writeln!(out, "  groupmod");
    #[cfg(feature = "grpck")]
    let _ = writeln!(out, "  grpck");
    #[cfg(feature = "newgrp")]
    let _ = writeln!(out, "  newgrp");
    #[cfg(feature = "passwd")]
    let _ = writeln!(out, "  passwd");
    #[cfg(feature = "pwck")]
    let _ = writeln!(out, "  pwck");
    #[cfg(feature = "useradd")]
    let _ = writeln!(out, "  useradd");
    #[cfg(feature = "userdel")]
    let _ = writeln!(out, "  userdel");
    #[cfg(feature = "usermod")]
    let _ = writeln!(out, "  usermod");
}
