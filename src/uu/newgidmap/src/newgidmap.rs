// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore newgidmap newuidmap subgid

//! `newgidmap` — set the group ID mapping of a user namespace.
//!
//! The same program as `newuidmap`, writing `gid_map` against `/etc/subgid`;
//! see `uu_newuidmap`. This crate only names which map.

use clap::Command;
use uucore::error::UResult;

/// Entry point for the `newgidmap` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    uu_newuidmap::run(uu_newuidmap::Tool::Gid, args)
}

/// Build the clap `Command` for `newgidmap`.
#[must_use]
pub fn uu_app() -> Command {
    uu_newuidmap::app(uu_newuidmap::Tool::Gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_builds_under_its_own_name() {
        uu_app().debug_assert();
        assert_eq!(uu_app().get_name(), "newgidmap");
    }
}
