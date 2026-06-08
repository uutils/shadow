// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Common CLI strings advertising shadow-rs as part of the uutils project.
//!
//! These are appended to every tool's clap [`Command`] so that `--help` and
//! `--version` make the project origin explicit (issue #161).

/// Suffix used as the clap version string. clap renders `--version` as
/// `<bin> <version>`, so `passwd --version` prints `passwd (uutils shadow-rs) <ver>`.
pub const VERSION: &str = concat!("(uutils shadow-rs) ", env!("CARGO_PKG_VERSION"));

/// Footer appended to `--help` to identify the project.
pub const AFTER_HELP: &str = "Part of the uutils project: https://github.com/uutils/shadow-rs";
