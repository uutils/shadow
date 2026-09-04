// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! `shadow-core` — shared library for shadow-rs utilities.
//!
//! Provides file format parsers, atomic file operations, file locking,
//! validation, and platform integration (PAM, `nscd`, `SELinux`, audit).

// Record parsers and the helpers around them. None of these pulls in a
// dependency, so none of them is behind a feature: gating them only made
// `cargo test -p shadow-core` compile a fraction of the crate and report a
// pass for it.
pub mod atomic;
pub mod audit;
pub mod cli;
pub mod date;
pub mod error;
pub mod group;
pub mod gshadow;
pub mod hardening;
pub mod lock;
pub mod login_defs;
pub mod nscd;
pub mod os_error;
pub mod passwd;
pub mod records;
pub mod shadow;
pub mod skel;
pub mod subid;
pub mod sysroot;
pub mod tty;
pub mod uid_alloc;
pub mod validate;

// PAM, crypt, and process are C library boundaries — FFI inherently
// requires unsafe. These are the ONLY modules where unsafe_code is permitted.
#[cfg(feature = "pam")]
#[allow(unsafe_code)]
pub mod pam;

#[cfg(feature = "crypt")]
#[allow(unsafe_code)]
pub mod crypt;

// Process-level POSIX wrappers (setuid, sigprocmask, etc.) — FFI requires unsafe.
#[allow(unsafe_code)]
pub mod process;
