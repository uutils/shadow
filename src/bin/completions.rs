// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore completions

//! Shell completion generator for all shadow-rs tools.
//!
//! Generates completions by calling each tool's `uu_app()` function,
//! so completions always match the actual CLI definition.
//!
//! Usage:
//!   shadow-rs-completions passwd --shell bash
//!   shadow-rs-completions --all --shell zsh --dir completions/
//!
//! Supported shells: bash, zsh, fish, elvish, powershell

use clap::{Arg, ArgAction, Command};
use clap_complete::Shell;
use clap_complete::generate;
use std::io;
use std::io::Write as _;

fn get_tool_app(name: &str) -> Option<Command> {
    match name {
        #[cfg(feature = "chage")]
        "chage" => Some(chage::uu_app()),
        #[cfg(feature = "chfn")]
        "chfn" => Some(chfn::uu_app()),
        #[cfg(feature = "chgpasswd")]
        "chgpasswd" => Some(chgpasswd::uu_app()),
        #[cfg(feature = "chpasswd")]
        "chpasswd" => Some(chpasswd::uu_app()),
        #[cfg(feature = "chsh")]
        "chsh" => Some(chsh::uu_app()),
        #[cfg(feature = "groupadd")]
        "groupadd" => Some(groupadd::uu_app()),
        #[cfg(feature = "groupdel")]
        "groupdel" => Some(groupdel::uu_app()),
        #[cfg(feature = "groupmod")]
        "groupmod" => Some(groupmod::uu_app()),
        #[cfg(feature = "gpasswd")]
        "gpasswd" => Some(gpasswd::uu_app()),
        #[cfg(feature = "grpck")]
        "grpck" => Some(grpck::uu_app()),
        #[cfg(feature = "grpconv")]
        "grpconv" => Some(grpconv::uu_app()),
        #[cfg(feature = "grpunconv")]
        "grpunconv" => Some(grpunconv::uu_app()),
        #[cfg(feature = "login")]
        "login" => Some(login::uu_app()),
        #[cfg(feature = "newgidmap")]
        "newgidmap" => Some(newgidmap::uu_app()),
        #[cfg(feature = "newgrp")]
        "newgrp" => Some(newgrp::uu_app()),
        #[cfg(feature = "newuidmap")]
        "newuidmap" => Some(newuidmap::uu_app()),
        #[cfg(feature = "newusers")]
        "newusers" => Some(newusers::uu_app()),
        #[cfg(feature = "passwd")]
        "passwd" => Some(passwd::uu_app()),
        #[cfg(feature = "pwck")]
        "pwck" => Some(pwck::uu_app()),
        #[cfg(feature = "pwconv")]
        "pwconv" => Some(pwconv::uu_app()),
        #[cfg(feature = "pwunconv")]
        "pwunconv" => Some(pwunconv::uu_app()),
        #[cfg(feature = "sg")]
        "sg" => Some(sg::uu_app()),
        #[cfg(feature = "useradd")]
        "useradd" => Some(useradd::uu_app()),
        #[cfg(feature = "userdel")]
        "userdel" => Some(userdel::uu_app()),
        #[cfg(feature = "usermod")]
        "usermod" => Some(usermod::uu_app()),
        #[cfg(feature = "vigr")]
        "vigr" => Some(vigr::uu_app()),
        #[cfg(feature = "vipw")]
        "vipw" => Some(vipw::uu_app()),
        _ => None,
    }
}

#[allow(clippy::vec_init_then_push)] // cfg attributes on each push prevent using vec![]
fn all_tool_names() -> Vec<&'static str> {
    let mut names = Vec::new();
    #[cfg(feature = "chage")]
    names.push("chage");
    #[cfg(feature = "chfn")]
    names.push("chfn");
    #[cfg(feature = "chgpasswd")]
    names.push("chgpasswd");
    #[cfg(feature = "chpasswd")]
    names.push("chpasswd");
    #[cfg(feature = "chsh")]
    names.push("chsh");
    #[cfg(feature = "groupadd")]
    names.push("groupadd");
    #[cfg(feature = "groupdel")]
    names.push("groupdel");
    #[cfg(feature = "groupmod")]
    names.push("groupmod");
    #[cfg(feature = "gpasswd")]
    names.push("gpasswd");
    #[cfg(feature = "grpck")]
    names.push("grpck");
    #[cfg(feature = "grpconv")]
    names.push("grpconv");
    #[cfg(feature = "grpunconv")]
    names.push("grpunconv");
    #[cfg(feature = "login")]
    names.push("login");
    #[cfg(feature = "newgidmap")]
    names.push("newgidmap");
    #[cfg(feature = "newgrp")]
    names.push("newgrp");
    #[cfg(feature = "newuidmap")]
    names.push("newuidmap");
    #[cfg(feature = "newusers")]
    names.push("newusers");
    #[cfg(feature = "passwd")]
    names.push("passwd");
    #[cfg(feature = "pwck")]
    names.push("pwck");
    #[cfg(feature = "pwconv")]
    names.push("pwconv");
    #[cfg(feature = "pwunconv")]
    names.push("pwunconv");
    #[cfg(feature = "sg")]
    names.push("sg");
    #[cfg(feature = "useradd")]
    names.push("useradd");
    #[cfg(feature = "userdel")]
    names.push("userdel");
    #[cfg(feature = "usermod")]
    names.push("usermod");
    #[cfg(feature = "vigr")]
    names.push("vigr");
    #[cfg(feature = "vipw")]
    names.push("vipw");
    names
}

fn cli() -> Command {
    Command::new("shadow-rs-completions")
        .about("Generate shell completions for shadow-rs tools")
        .arg(
            Arg::new("tool")
                .help("Tool name (or use --all)")
                .required_unless_present("all"),
        )
        .arg(
            Arg::new("shell")
                .long("shell")
                .short('s')
                .help("Target shell: bash, zsh, fish, elvish, powershell")
                .required(true),
        )
        .arg(
            Arg::new("all")
                .long("all")
                .help("Generate completions for all tools")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dir")
                .long("dir")
                .help("Output directory (one file per tool; default: stdout)")
                .requires("all"),
        )
}

fn generate_for_tool(name: &str, shell: Shell, out: &mut dyn io::Write) -> Result<(), String> {
    if let Some(mut cmd) = get_tool_app(name) {
        generate(shell, &mut cmd, name, out);
        Ok(())
    } else {
        Err(format!(
            "unknown tool: {name}\navailable: {}",
            all_tool_names().join(", ")
        ))
    }
}

fn shell_extension(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => "bash",
        Shell::Zsh => "zsh",
        Shell::Fish => "fish",
        Shell::Elvish => "elv",
        Shell::PowerShell => "ps1",
        _ => "txt",
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(msg) => {
            let _ = writeln!(std::io::stderr(), "{msg}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let matches = cli().get_matches();

    // clap enforces `--shell` is required, so the value is always present.
    let shell_str = matches
        .get_one::<String>("shell")
        .expect("clap guarantees --shell is present");
    let shell: Shell = shell_str.parse().map_err(|e| {
        format!("invalid shell: {e}\nsupported: bash, zsh, fish, elvish, powershell")
    })?;

    if matches.get_flag("all") {
        let tools = all_tool_names();
        if let Some(dir) = matches.get_one::<String>("dir") {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot create directory '{dir}': {e}"))?;
            let ext = shell_extension(shell);
            for name in &tools {
                let path = format!("{dir}/{name}.{ext}");
                let mut file = std::fs::File::create(&path)
                    .map_err(|e| format!("cannot create '{path}': {e}"))?;
                if let Some(mut cmd) = get_tool_app(name) {
                    generate(shell, &mut cmd, *name, &mut file);
                }
            }
            let _ = writeln!(
                std::io::stderr(),
                "generated {} completions in {dir}/",
                tools.len()
            );
        } else {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            for name in &tools {
                if let Some(mut cmd) = get_tool_app(name) {
                    generate(shell, &mut cmd, *name, &mut out);
                }
            }
        }
    } else {
        // clap enforces `tool` is required when `--all` is absent.
        let tool = matches
            .get_one::<String>("tool")
            .expect("clap guarantees tool is present when --all is not set");
        let stdout = io::stdout();
        let mut out = stdout.lock();
        generate_for_tool(tool, shell, &mut out)?;
    }

    Ok(())
}
