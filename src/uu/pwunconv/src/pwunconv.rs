// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore pwconv pwunconv grpconv grpunconv gshadow

//! `pwunconv` — move password hashes from /etc/shadow back into /etc/passwd.
//!
//! One of the four conversion tools built on the engine in `uu_pwconv`; this
//! crate only names which one.

use clap::Command;
use uucore::error::UResult;

/// Entry point for the `pwunconv` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    uu_pwconv::run(uu_pwconv::Tool::Pwunconv, args)
}

/// Build the clap `Command` for `pwunconv`.
#[must_use]
pub fn uu_app() -> Command {
    uu_pwconv::app(uu_pwconv::Tool::Pwunconv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_builds_under_its_own_name() {
        uu_app().debug_assert();
        assert_eq!(uu_app().get_name(), "pwunconv");
    }
}
