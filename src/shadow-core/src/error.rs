// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Unified error types for shadow-rs utilities.

use std::borrow::Cow;
use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Result type alias used across all shadow-rs utilities.
pub type ShadowResult<T> = Result<T, ShadowError>;

/// Top-level error type for shadow-rs operations.
#[derive(Debug, Error)]
pub enum ShadowError {
    /// I/O error.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// I/O error with path context.
    #[error("{path}: {source}", path = .1.display(), source = .0)]
    IoPath(#[source] io::Error, PathBuf),
    /// File format parse error.
    #[error("parse error: {0}")]
    Parse(Cow<'static, str>),
    /// Lock acquisition failed.
    #[error("lock error: {0}")]
    Lock(Cow<'static, str>),
    /// Validation error (invalid username, UID range, etc.).
    #[error("{0}")]
    Validation(Cow<'static, str>),
    /// Authentication error (PAM failure, wrong password, etc.).
    #[error("authentication error: {0}")]
    Auth(Cow<'static, str>),
    /// Permission denied.
    #[error("permission denied: {0}")]
    Permission(Cow<'static, str>),
    /// Generic error with message.
    #[error("{0}")]
    Other(Cow<'static, str>),
}


