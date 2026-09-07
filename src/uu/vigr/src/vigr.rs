// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore vigr vipw gshadow

//! `vigr` — edit the group file under a lock.
//!
//! `vigr` is `vipw(8)` with `/etc/group` as the default target instead of
//! `/etc/passwd`; the GNU suite ships it as a symlink to `vipw`. Everything it
//! does lives in `uu_vipw`, and this crate only names the default.

use clap::Command;
use uucore::error::UResult;

/// Entry point for the `vigr` utility.
#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    uu_vipw::run(uu_vipw::Tool::Vigr, args)
}

/// Build the clap `Command` for `vigr`.
#[must_use]
pub fn uu_app() -> Command {
    uu_vipw::app(uu_vipw::Tool::Vigr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_builds() {
        uu_app().debug_assert();
    }

    /// The only thing vigr adds over vipw is the default, so that is what
    /// is worth pinning.
    #[test]
    fn test_defaults_to_the_group_file() {
        assert_eq!(uu_app().get_name(), "vigr");
    }
}
