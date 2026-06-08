// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! `shadow-core` — shared library for shadow-rs utilities.
//!
//! Provides file format parsers, atomic file operations, file locking,
//! validation, and platform integration (PAM, `nscd`, `SELinux`, audit).

pub mod cli;
pub mod error;
pub mod passwd;
pub mod validate;

#[cfg(feature = "shadow")]
pub mod shadow;

#[cfg(feature = "group")]
pub mod group;

#[cfg(feature = "gshadow")]
pub mod gshadow;

#[cfg(feature = "login-defs")]
pub mod login_defs;

#[cfg(feature = "subid")]
pub mod subid;

// PAM, crypt, and process are C library boundaries — FFI inherently
// requires unsafe. These are the ONLY modules where unsafe_code is permitted.
#[cfg(feature = "pam")]
#[allow(unsafe_code)]
pub mod pam;

#[cfg(feature = "crypt")]
#[allow(unsafe_code)]
pub mod crypt;

#[cfg(feature = "selinux")]
pub mod selinux;

// Process-level POSIX wrappers (setuid, sigprocmask, etc.) — FFI requires unsafe.
#[allow(unsafe_code)]
pub mod process;

pub mod atomic;
pub mod audit;
pub mod hardening;
pub mod lock;
pub mod nscd;
pub mod skel;
pub mod sysroot;

#[cfg(all(feature = "group", feature = "login-defs"))]
pub mod uid_alloc;
