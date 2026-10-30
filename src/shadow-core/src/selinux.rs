// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore selinux selinuxfs semanage seuser

//! The `SELinux` login mappings behind `-Z` in `useradd`, `usermod` and `userdel`.
//!
//! The mapping lives in the policy store, which only the policy tools write. The
//! tools here run `semanage login`, an administrator's own program on any system
//! with `SELinux`, and link nothing. With no such program the option fails: it
//! never reports a mapping it did not make.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::ShadowError;

/// Whether the running kernel has `SELinux` enabled.
#[must_use]
pub fn kernel_enabled() -> bool {
    Path::new("/sys/fs/selinux/enforce").exists()
}

/// Map a new `login` to `seuser`, with an optional MLS `range`.
///
/// # Errors
///
/// Returns `ShadowError::Other` if `semanage` cannot run or refuses.
pub fn add_login(login: &str, seuser: &str, range: Option<&str>) -> Result<(), ShadowError> {
    run(&mapping_args("-a", login, seuser, range))
}

/// Map `login` to `seuser`, whether or not it has a mapping yet.
///
/// # Errors
///
/// Returns `ShadowError::Other` if `semanage` cannot run or refuses both ways.
pub fn set_login(login: &str, seuser: &str, range: Option<&str>) -> Result<(), ShadowError> {
    run(&mapping_args("-m", login, seuser, range))
        .or_else(|_| run(&mapping_args("-a", login, seuser, range)))
}

/// Remove the mapping of `login`.
///
/// # Errors
///
/// Returns `ShadowError::Other` if `semanage` cannot run or refuses.
pub fn remove_login(login: &str) -> Result<(), ShadowError> {
    run(&["login", "-d", "--", login].map(str::to_owned))
}

/// The arguments for adding or changing a mapping. `--` keeps a login that a
/// `--badname` let through from reading as an option.
fn mapping_args(action: &str, login: &str, seuser: &str, range: Option<&str>) -> Vec<String> {
    let mut args = vec!["login", action, "-s", seuser];
    if let Some(range) = range {
        args.extend(["-r", range]);
    }
    args.extend(["--", login]);
    args.into_iter().map(str::to_owned).collect()
}

fn run(args: &[String]) -> Result<(), ShadowError> {
    let program = ["/usr/sbin/semanage", "/sbin/semanage"]
        .into_iter()
        .find(|path| Path::new(path).exists())
        .ok_or_else(|| ShadowError::Other("semanage is not installed".into()))?;
    run_program(Path::new(program), args)
}

fn run_program(program: &Path, args: &[String]) -> Result<(), ShadowError> {
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .map_err(|e| ShadowError::Other(format!("cannot run semanage: {e}").into()))?;
    if status.success() {
        Ok(())
    } else {
        Err(ShadowError::Other(
            format!("semanage failed: {status}").into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_args_keep_a_login_from_reading_as_an_option() {
        assert_eq!(
            mapping_args("-a", "-x", "user_u", Some("s0")),
            ["login", "-a", "-s", "user_u", "-r", "s0", "--", "-x"]
        );
        assert_eq!(
            mapping_args("-m", "bob", "user_u", None),
            ["login", "-m", "-s", "user_u", "--", "bob"]
        );
    }

    #[test]
    fn test_a_refusal_from_the_program_is_an_error() {
        assert!(run_program(Path::new("/bin/true"), &[]).is_ok());
        assert!(run_program(Path::new("/bin/false"), &[]).is_err());
        assert!(run_program(Path::new("/nonexistent/semanage"), &[]).is_err());
    }
}
