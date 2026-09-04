// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore pamu authtok chauthtok acct strerror conv appdata ECHONL

//! PAM (Pluggable Authentication Modules) integration.
//!
//! Provides a safe wrapper around the Linux-PAM C library for authentication,
//! account validation, and password changes. The conversation function supports
//! both interactive terminal mode (with echo control) and non-interactive stdin
//! mode.
//!
//! # Design
//!
//! This module is implemented from the public Linux-PAM specification and man
//! pages (`pam(3)`, `pam_start(3)`, `pam_authenticate(3)`, `pam_acct_mgmt(3)`,
//! `pam_chauthtok(3)`, `pam_conv(3)`). The conversation function pattern
//! follows sudo-rs (Apache-2.0/MIT).
//!
//! # Feature gate
//!
//! This module is only available when the `pam` feature is enabled, and it
//! cannot be built into a statically linked musl binary: Linux-PAM loads its
//! modules with `dlopen(3)`, which static musl does not support, and no
//! distribution ships a `libpam.a`. Requesting the feature there is a
//! configuration error and is rejected at compile time rather than producing
//! a binary whose authentication path can never work.

#[cfg(all(target_env = "musl", target_feature = "crt-static"))]
compile_error!(
    "the `pam` feature cannot be used in a statically linked musl build: Linux-PAM loads its \
     modules with dlopen(3), which static musl does not support. Build without `pam` — see \
     docs/PLATFORM-SUPPORT.md for what that changes."
);

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::os::unix::io::AsRawFd;
use std::ptr;

use zeroize::Zeroize;

use crate::error::ShadowError;

// ---------------------------------------------------------------------------
// PAM FFI constants
//
// Values from the Linux-PAM public header <security/pam_appl.h> and
// <security/pam_modules.h>. These are part of the stable ABI.
// ---------------------------------------------------------------------------

/// PAM return codes.
pub mod return_code {
    /// Successful operation.
    pub const PAM_SUCCESS: i32 = 0;
    /// Critical error — immediate abort.
    pub const PAM_ABORT: i32 = 26;
    /// `dlopen()` failure when dynamically loading a service module.
    pub const PAM_OPEN_ERR: i32 = 1;
    /// Symbol not found.
    pub const PAM_SYMBOL_ERR: i32 = 2;
    /// Error in service module.
    pub const PAM_SERVICE_ERR: i32 = 3;
    /// System error.
    pub const PAM_SYSTEM_ERR: i32 = 4;
    /// Memory buffer error.
    pub const PAM_BUF_ERR: i32 = 5;
    /// Permission denied.
    pub const PAM_PERM_DENIED: i32 = 6;
    /// Authentication failure.
    pub const PAM_AUTH_ERR: i32 = 7;
    /// Cannot access authentication data due to insufficient credentials.
    pub const PAM_CRED_INSUFFICIENT: i32 = 8;
    /// Cannot retrieve authentication information.
    pub const PAM_AUTHINFO_UNAVAIL: i32 = 9;
    /// User not known to the underlying authentication module.
    pub const PAM_USER_UNKNOWN: i32 = 10;
    /// Maximum number of retries exceeded.
    pub const PAM_MAXTRIES: i32 = 11;
    /// New authentication token required.
    pub const PAM_NEW_AUTHTOK_REQD: i32 = 12;
    /// User account has expired.
    pub const PAM_ACCT_EXPIRED: i32 = 13;
    /// Authentication token manipulation error.
    pub const PAM_AUTHTOK_ERR: i32 = 20;
    /// Authentication information cannot be recovered.
    pub const PAM_AUTHTOK_RECOVERY_ERR: i32 = 21;
    /// Authentication token lock busy.
    pub const PAM_AUTHTOK_LOCK_BUSY: i32 = 22;
    /// Authentication token aging disabled.
    pub const PAM_AUTHTOK_DISABLE_AGING: i32 = 23;
    /// Conversation error.
    pub const PAM_CONV_ERR: i32 = 19;
}

/// PAM message style constants (used in conversation functions).
pub mod msg_style {
    /// Prompt for input with echo disabled (e.g., password entry).
    pub const PAM_PROMPT_ECHO_OFF: i32 = 1;
    /// Prompt for input with echo enabled (e.g., username entry).
    pub const PAM_PROMPT_ECHO_ON: i32 = 2;
    /// Error message — display to user.
    pub const PAM_ERROR_MSG: i32 = 3;
    /// Informational message — display to user.
    pub const PAM_TEXT_INFO: i32 = 4;
}

/// PAM item types for `pam_set_item`.
pub mod item_type {
    /// The service name.
    pub const PAM_SERVICE: i32 = 1;
    /// The username.
    pub const PAM_USER: i32 = 2;
    /// The tty name.
    pub const PAM_TTY: i32 = 3;
    /// The remote host name.
    pub const PAM_RHOST: i32 = 4;
    /// The conversation structure.
    pub const PAM_CONV: i32 = 5;
    /// The authentication token (password).
    pub const PAM_AUTHTOK: i32 = 6;
    /// The old authentication token.
    pub const PAM_OLDAUTHTOK: i32 = 7;
    /// The remote user name.
    pub const PAM_RUSER: i32 = 8;
}

/// PAM flags.
pub mod flags {
    /// Do not emit any messages.
    pub const PAM_SILENT: i32 = 0x8000;
    /// Signal that the password should be changed only if it has expired.
    pub const PAM_CHANGE_EXPIRED_AUTHTOK: i32 = 0x0020;
    /// Don't update the last-changed timestamp.
    pub const PAM_DISALLOW_NULL_AUTHTOK: i32 = 0x0001;
}

// ---------------------------------------------------------------------------
// PAM FFI type definitions
// ---------------------------------------------------------------------------

/// Opaque PAM handle. Never dereferenced from Rust — only passed as a pointer.
#[repr(C)]
pub struct PamHandle {
    _opaque: [u8; 0],
}

/// A single message from the PAM module to the conversation function.
#[repr(C)]
pub struct PamMessage {
    /// The message style (`PAM_PROMPT_ECHO_OFF`, etc.).
    pub msg_style: libc::c_int,
    /// The message string (null-terminated).
    pub msg: *const libc::c_char,
}

/// A response from the conversation function back to the PAM module.
#[repr(C)]
pub struct PamResponse {
    /// The response string. Must be allocated with `libc::malloc` because PAM
    /// will call `free()` on it.
    pub resp: *mut libc::c_char,
    /// Unused — must be zero.
    pub resp_retcode: libc::c_int,
}

/// The conversation function type as defined by PAM.
pub type PamConvFn = extern "C" fn(
    num_msg: libc::c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut libc::c_void,
) -> libc::c_int;

/// The PAM conversation structure, passed to `pam_start`.
#[repr(C)]
pub struct PamConv {
    /// Pointer to the conversation function.
    pub conv: PamConvFn,
    /// Application-specific data passed to the conversation function.
    pub appdata_ptr: *mut libc::c_void,
}

// ---------------------------------------------------------------------------
// PAM FFI function declarations
// ---------------------------------------------------------------------------

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service_name: *const libc::c_char,
        user: *const libc::c_char,
        pam_conversation: *const PamConv,
        pamh: *mut *mut PamHandle,
    ) -> libc::c_int;

    fn pam_end(pamh: *mut PamHandle, pam_status: libc::c_int) -> libc::c_int;

    fn pam_authenticate(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int;

    fn pam_acct_mgmt(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int;

    fn pam_chauthtok(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int;

    fn pam_set_item(
        pamh: *mut PamHandle,
        item_type: libc::c_int,
        item: *const libc::c_void,
    ) -> libc::c_int;

    fn pam_strerror(pamh: *mut PamHandle, errnum: libc::c_int) -> *const libc::c_char;
}

// ---------------------------------------------------------------------------
// Conversation mode
// ---------------------------------------------------------------------------

/// Controls how the PAM conversation function obtains user input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvMode {
    /// Read from `/dev/tty` with echo control. This is the normal interactive
    /// mode: prompts are written to the terminal, and echo is disabled for
    /// `PAM_PROMPT_ECHO_OFF` messages (password entry).
    Tty,
    /// Read from stdin without writing prompts. Used when input is piped or
    /// when running non-interactively.
    Stdin,
}

/// Application data passed through the PAM conversation's `appdata_ptr`.
///
/// The conversation function casts the void pointer back to this type to
/// determine how to collect input.
struct ConvData {
    mode: ConvMode,
}

// ---------------------------------------------------------------------------
// Conversation function
// ---------------------------------------------------------------------------

/// PAM conversation function.
///
/// Handles all four message styles defined by PAM:
/// - `PAM_PROMPT_ECHO_OFF`: prompt for password (echo disabled in Tty mode)
/// - `PAM_PROMPT_ECHO_ON`: prompt for visible input (e.g., username)
/// - `PAM_ERROR_MSG`: display error message to stderr
/// - `PAM_TEXT_INFO`: display informational message to stderr
///
/// In `Tty` mode, opens `/dev/tty` directly for prompt I/O and uses termios
/// to suppress echo. In `Stdin` mode, reads from stdin silently.
extern "C" fn conversation(
    num_msg: libc::c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut libc::c_void,
) -> libc::c_int {
    // SAFETY: `appdata_ptr` points to a valid `ConvData` that lives for the
    // duration of the PAM session (owned by `PamContext`). PAM guarantees this
    // pointer is the same one we passed in `pam_start`.
    let conv_data = unsafe {
        if appdata_ptr.is_null() {
            return return_code::PAM_CONV_ERR;
        }
        &*(appdata_ptr.cast::<ConvData>())
    };

    if num_msg <= 0 || msg.is_null() || resp.is_null() {
        return return_code::PAM_CONV_ERR;
    }

    #[allow(clippy::cast_sign_loss)] // Validated positive above.
    let count = num_msg as usize;

    // Allocate response array with libc::calloc so PAM can free it.
    // SAFETY: `calloc` returns zeroed memory or null. We check for null below.
    let responses: *mut PamResponse =
        unsafe { libc::calloc(count, std::mem::size_of::<PamResponse>()).cast::<PamResponse>() };

    if responses.is_null() {
        return return_code::PAM_BUF_ERR;
    }

    for i in 0..count {
        // SAFETY: `msg` is an array of `num_msg` pointers, each pointing to a
        // valid `PamMessage`. Index `i` is within bounds by loop invariant.
        // Linux-PAM uses msg[i] (array of pointers) — this matches the Linux
        // convention rather than the Solaris (*msg)[i] convention.
        let message = unsafe {
            let msg_ptr = *msg.add(i);
            if msg_ptr.is_null() {
                free_responses(responses, i);
                return return_code::PAM_CONV_ERR;
            }
            &*msg_ptr
        };

        let result = match message.msg_style {
            msg_style::PAM_PROMPT_ECHO_OFF => prompt_for_input(message, false, conv_data.mode),
            msg_style::PAM_PROMPT_ECHO_ON => prompt_for_input(message, true, conv_data.mode),
            msg_style::PAM_ERROR_MSG => {
                display_message(message, true);
                Ok(ptr::null_mut())
            }
            msg_style::PAM_TEXT_INFO => {
                display_message(message, false);
                Ok(ptr::null_mut())
            }
            _ => {
                // Unknown message style — protocol error.
                Err(())
            }
        };

        if let Ok(resp_str) = result {
            // SAFETY: `i` is within the allocated range of `responses`.
            unsafe {
                let r = &mut *responses.add(i);
                r.resp = resp_str;
                r.resp_retcode = 0;
            }
        } else {
            // Clean up already-filled responses and the array itself.
            free_responses(responses, i);
            return return_code::PAM_CONV_ERR;
        }
    }

    // SAFETY: `resp` is a valid out-pointer provided by PAM.
    unsafe {
        *resp = responses;
    }

    return_code::PAM_SUCCESS
}

/// Display a PAM message to stderr.
///
/// Both error and informational messages go to stderr (matching traditional
/// PAM conversation behavior). The `_is_error` parameter is retained for
/// future differentiation (e.g., prefixing error messages).
fn display_message(message: &PamMessage, _is_error: bool) {
    if message.msg.is_null() {
        return;
    }

    // SAFETY: `msg` is a null-terminated C string provided by PAM.
    let text = unsafe { CStr::from_ptr(message.msg) };
    let text = text.to_string_lossy();

    {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock(), "{text}");
    }
}

/// Prompt for user input (with or without echo) and return a `malloc`-allocated
/// C string for the response, or `Err(())` on failure.
fn prompt_for_input(
    message: &PamMessage,
    echo: bool,
    mode: ConvMode,
) -> Result<*mut libc::c_char, ()> {
    let input = match mode {
        ConvMode::Tty => read_from_tty(message, echo),
        ConvMode::Stdin => read_from_stdin(),
    };

    match input {
        Ok(mut line) => {
            let result = alloc_c_response(&line);
            // Zeroize the Rust string so password data does not linger in
            // process memory after being copied to the C-allocated response.
            line.zeroize();
            result
        }
        Err(_) => Err(()),
    }
}

/// Read a line from `/dev/tty`, optionally disabling echo.
///
/// Opens `/dev/tty` once with read+write mode (not stdin) to ensure we talk
/// to the real terminal even if stdin has been redirected. Uses
/// `rustix::termios` to disable `ECHO` for password prompts and restores
/// the original settings afterward (including on error, via a drop guard).
fn read_from_tty(message: &PamMessage, echo: bool) -> io::Result<zeroize::Zeroizing<String>> {
    let mut tty = File::options().read(true).write(true).open("/dev/tty")?;

    // Show prompt.
    if !message.msg.is_null() {
        // SAFETY: `msg` is a null-terminated C string provided by PAM.
        let prompt = unsafe { CStr::from_ptr(message.msg) };
        tty.write_all(prompt.to_bytes())?;
        tty.flush()?;
    }

    // Disable echo if needed, with a guard to restore on drop.
    let _guard = if echo {
        None
    } else {
        Some(EchoGuard::disable(&tty)?)
    };

    // Read one line from the tty.
    let mut reader = io::BufReader::new(tty.try_clone()?);
    let mut line = zeroize::Zeroizing::new(String::new());
    reader.read_line(&mut line)?;

    // Print a newline after hidden input so the cursor moves down.
    // Best-effort — a cosmetic write failure shouldn't abort PAM auth.
    if !echo {
        let _ = tty.write_all(b"\n");
    }

    // Strip trailing newline.
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }

    Ok(line)
}

/// Read a line from stdin without prompting.
fn read_from_stdin() -> io::Result<zeroize::Zeroizing<String>> {
    let stdin = io::stdin();
    let mut line = zeroize::Zeroizing::new(String::new());
    stdin.lock().read_line(&mut line)?;

    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }

    Ok(line)
}

/// Allocate a C string with `libc::malloc` for use as a PAM response.
///
/// PAM will call `free()` on this pointer, so it must be allocated with the C
/// allocator rather than Rust's allocator.
fn alloc_c_response(s: &str) -> Result<*mut libc::c_char, ()> {
    let len = s.len() + 1; // +1 for null terminator

    // SAFETY: Allocating `len` bytes from the C heap. We check for null.
    let buf = unsafe { libc::malloc(len).cast::<libc::c_char>() };
    if buf.is_null() {
        return Err(());
    }

    // SAFETY: `buf` is valid for `len` bytes. We copy exactly `s.len()` bytes
    // and add a null terminator.
    unsafe {
        ptr::copy_nonoverlapping(s.as_ptr(), buf.cast::<u8>(), s.len());
        *buf.add(s.len()) = 0;
    }

    Ok(buf)
}

/// Free partially-filled PAM responses on error.
///
/// Frees the `resp` strings for responses `0..count`, then frees the array.
fn free_responses(responses: *mut PamResponse, count: usize) {
    for i in 0..count {
        // SAFETY: `i` is within the allocated range, and each `resp` was either
        // set to a `malloc`-allocated string or is null (from `calloc`).
        unsafe {
            let r = &mut *responses.add(i);
            if !r.resp.is_null() {
                // Zero out the response before freeing (may contain a password).
                let len = libc::strlen(r.resp.cast::<libc::c_char>());
                ptr::write_bytes(r.resp, 0, len);
                libc::free(r.resp.cast::<libc::c_void>());
            }
        }
    }
    // SAFETY: `responses` was allocated with `calloc`.
    unsafe {
        libc::free(responses.cast::<libc::c_void>());
    }
}

// ---------------------------------------------------------------------------
// Echo guard (RAII termios echo control)
// ---------------------------------------------------------------------------

/// RAII guard that disables terminal echo and restores it on drop.
///
/// Uses `rustix::termios` to manipulate the terminal's local flags. The
/// original settings are saved and restored when the guard is dropped, even
/// if the caller returns early or panics.
struct EchoGuard {
    fd: libc::c_int,
    original: rustix::termios::Termios,
}

impl EchoGuard {
    /// Disable echo on the given terminal file.
    fn disable(tty: &File) -> io::Result<Self> {
        use std::os::unix::io::AsFd;

        let fd = tty.as_raw_fd();
        let original = rustix::termios::tcgetattr(tty.as_fd()).map_err(io::Error::other)?;

        let mut noecho = original.clone();
        noecho.local_modes &=
            !(rustix::termios::LocalModes::ECHO | rustix::termios::LocalModes::ECHONL);

        rustix::termios::tcsetattr(tty.as_fd(), rustix::termios::OptionalActions::Now, &noecho)
            .map_err(io::Error::other)?;

        Ok(Self { fd, original })
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: `self.fd` is the raw fd from the tty file we opened. We use
        // `BorrowedFd` to avoid consuming or closing the fd. The fd is still
        // valid because the tty `File` that owns it outlives this guard in
        // every call site.
        use std::os::unix::io::BorrowedFd;
        let fd = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let _ =
            rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Now, &self.original);
    }
}

// ---------------------------------------------------------------------------
// Safe PAM context wrapper
// ---------------------------------------------------------------------------

/// A safe wrapper around a PAM session.
///
/// Manages the lifetime of a PAM handle and its associated conversation data.
/// The handle is closed with `pam_end` when the context is dropped.
///
/// # Examples
///
/// ```no_run
/// use shadow_core::pam::{PamContext, ConvMode};
///
/// let mut ctx = PamContext::new("passwd", "root", ConvMode::Tty)
///     .expect("pam_start failed");
/// ctx.authenticate(0).expect("authentication failed");
/// ctx.acct_mgmt(0).expect("account check failed");
/// ```
pub struct PamContext {
    handle: *mut PamHandle,
    last_status: i32,
    /// Conversation data — heap-allocated so the pointer stays stable for the
    /// lifetime of the PAM handle. Must be kept alive until `pam_end`.
    _conv_data: Box<ConvData>,
    /// The PAM conversation structure — must also live until `pam_end`, because
    /// PAM may call the conversation function at any point during the session.
    _conv: Box<PamConv>,
}

impl PamContext {
    /// Start a new PAM session.
    ///
    /// `service` is the PAM service name (e.g., `"passwd"`, `"login"`).
    /// `user` is the username being authenticated.
    /// `mode` controls how the conversation function collects user input.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Auth` if `pam_start` fails.
    pub fn new(service: &str, user: &str, mode: ConvMode) -> Result<Self, ShadowError> {
        let service_c = CString::new(service)
            .map_err(|_| ShadowError::Auth("service name contains null byte".into()))?;
        let user_c = CString::new(user)
            .map_err(|_| ShadowError::Auth("username contains null byte".into()))?;

        let conv_data = Box::new(ConvData { mode });
        let conv_data_ptr = (&raw const *conv_data).cast_mut();

        let conv = Box::new(PamConv {
            conv: conversation,
            appdata_ptr: conv_data_ptr.cast::<libc::c_void>(),
        });

        let mut handle: *mut PamHandle = ptr::null_mut();

        // SAFETY: All pointers passed to `pam_start` are valid:
        // - `service_c` and `user_c` are valid null-terminated C strings
        // - `conv` points to a valid `PamConv` struct that lives in a Box
        // - `handle` is a valid out-pointer on the stack
        // `pam_start` will allocate and initialize the PAM handle.
        let rc = unsafe {
            pam_start(
                service_c.as_ptr(),
                user_c.as_ptr(),
                &raw const *conv,
                &raw mut handle,
            )
        };

        if rc != return_code::PAM_SUCCESS {
            return Err(ShadowError::Auth(
                format!("pam_start failed with code {rc}").into(),
            ));
        }

        if handle.is_null() {
            return Err(ShadowError::Auth(
                "pam_start returned success but null handle".into(),
            ));
        }

        Ok(Self {
            handle,
            last_status: rc,
            _conv_data: conv_data,
            _conv: conv,
        })
    }

    /// Authenticate the user.
    ///
    /// This calls `pam_authenticate` which will invoke the conversation function
    /// to collect credentials (typically a password).
    ///
    /// `flags` can be `0` or a combination of PAM flags (e.g., `PAM_SILENT`).
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Auth` if authentication fails.
    pub fn authenticate(&mut self, flags: i32) -> Result<(), ShadowError> {
        // SAFETY: `self.handle` is a valid PAM handle from a successful
        // `pam_start` call. It remains valid until `pam_end` (called in Drop).
        let rc = unsafe { pam_authenticate(self.handle, flags) };
        self.last_status = rc;

        if rc != return_code::PAM_SUCCESS {
            return Err(ShadowError::Auth(self.strerror(rc).into()));
        }

        Ok(())
    }

    /// Check account validity (expiration, access restrictions, etc.).
    ///
    /// Should be called after successful authentication.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Auth` if the account check fails.
    pub fn acct_mgmt(&mut self, flags: i32) -> Result<(), ShadowError> {
        // SAFETY: `self.handle` is a valid PAM handle (same invariant as above).
        let rc = unsafe { pam_acct_mgmt(self.handle, flags) };
        self.last_status = rc;

        if rc != return_code::PAM_SUCCESS {
            return Err(ShadowError::Auth(self.strerror(rc).into()));
        }

        Ok(())
    }

    /// Change the user's authentication token (password).
    ///
    /// `flags` can include `PAM_CHANGE_EXPIRED_AUTHTOK` to only change expired
    /// passwords, or `0` to force a change.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Auth` if the token change fails.
    pub fn chauthtok(&mut self, flags: i32) -> Result<(), ShadowError> {
        // SAFETY: `self.handle` is a valid PAM handle (same invariant as above).
        let rc = unsafe { pam_chauthtok(self.handle, flags) };
        self.last_status = rc;

        if rc != return_code::PAM_SUCCESS {
            return Err(ShadowError::Auth(self.strerror(rc).into()));
        }

        Ok(())
    }

    /// Set a PAM item on the handle.
    ///
    /// Common items: `PAM_TTY`, `PAM_RHOST`, `PAM_RUSER`.
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::Auth` if `pam_set_item` fails.
    pub fn set_item_str(&mut self, item: i32, value: &str) -> Result<(), ShadowError> {
        let value_c = CString::new(value)
            .map_err(|_| ShadowError::Auth("item value contains null byte".into()))?;

        // SAFETY: `self.handle` is valid. `value_c` is a valid null-terminated
        // C string. PAM copies the value internally, so `value_c` does not need
        // to outlive this call.
        let rc =
            unsafe { pam_set_item(self.handle, item, value_c.as_ptr().cast::<libc::c_void>()) };
        self.last_status = rc;

        if rc != return_code::PAM_SUCCESS {
            return Err(ShadowError::Auth(self.strerror(rc).into()));
        }

        Ok(())
    }

    /// Get the human-readable error string for a PAM return code.
    fn strerror(&self, code: i32) -> String {
        // SAFETY: `self.handle` is valid, and `pam_strerror` returns a pointer
        // to a static string owned by PAM (not freed by caller).
        let msg = unsafe { pam_strerror(self.handle, code) };
        if msg.is_null() {
            return format!("PAM error {code}");
        }
        // SAFETY: `pam_strerror` returns a valid null-terminated C string.
        let cstr = unsafe { CStr::from_ptr(msg) };
        cstr.to_string_lossy().into_owned()
    }

    /// Return the last PAM status code.
    #[must_use]
    pub fn last_status(&self) -> i32 {
        self.last_status
    }
}

impl Drop for PamContext {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is a valid PAM handle. `pam_end` releases all
        // resources associated with the handle. After this call the handle is
        // invalid — but since we're in `Drop`, it will never be used again.
        unsafe {
            pam_end(self.handle, self.last_status);
        }
    }
}

// SAFETY: The raw pointer `handle` is exclusively owned by `PamContext`. No
// concurrent access is possible because all mutating methods require `&mut self`.
//
// Note: While sending the handle between threads is memory-safe, PAM module
// implementations are not guaranteed to be thread-safe. In practice, all
// shadow-rs tools are single-threaded, so this is not an issue. Do not use
// `PamContext` across threads without verifying the PAM modules in use.
unsafe impl Send for PamContext {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Verify PAM constant values match the Linux-PAM ABI. These values are
    // defined by the Linux-PAM specification and must be exact.

    #[test]
    fn test_return_codes() {
        assert_eq!(return_code::PAM_SUCCESS, 0);
        assert_eq!(return_code::PAM_AUTH_ERR, 7);
        assert_eq!(return_code::PAM_USER_UNKNOWN, 10);
        assert_eq!(return_code::PAM_MAXTRIES, 11);
        assert_eq!(return_code::PAM_NEW_AUTHTOK_REQD, 12);
        assert_eq!(return_code::PAM_ACCT_EXPIRED, 13);
        assert_eq!(return_code::PAM_CONV_ERR, 19);
        assert_eq!(return_code::PAM_AUTHTOK_ERR, 20);
        assert_eq!(return_code::PAM_AUTHTOK_RECOVERY_ERR, 21);
        assert_eq!(return_code::PAM_AUTHTOK_LOCK_BUSY, 22);
        assert_eq!(return_code::PAM_AUTHTOK_DISABLE_AGING, 23);
        assert_eq!(return_code::PAM_ABORT, 26);
        assert_eq!(return_code::PAM_PERM_DENIED, 6);
        assert_eq!(return_code::PAM_SERVICE_ERR, 3);
        assert_eq!(return_code::PAM_BUF_ERR, 5);
    }

    #[test]
    fn test_msg_styles() {
        assert_eq!(msg_style::PAM_PROMPT_ECHO_OFF, 1);
        assert_eq!(msg_style::PAM_PROMPT_ECHO_ON, 2);
        assert_eq!(msg_style::PAM_ERROR_MSG, 3);
        assert_eq!(msg_style::PAM_TEXT_INFO, 4);
    }

    #[test]
    fn test_item_types() {
        assert_eq!(item_type::PAM_SERVICE, 1);
        assert_eq!(item_type::PAM_USER, 2);
        assert_eq!(item_type::PAM_TTY, 3);
        assert_eq!(item_type::PAM_RHOST, 4);
        assert_eq!(item_type::PAM_CONV, 5);
        assert_eq!(item_type::PAM_AUTHTOK, 6);
        assert_eq!(item_type::PAM_OLDAUTHTOK, 7);
        assert_eq!(item_type::PAM_RUSER, 8);
    }

    #[test]
    fn test_flags() {
        assert_eq!(flags::PAM_SILENT, 0x8000);
        assert_eq!(flags::PAM_CHANGE_EXPIRED_AUTHTOK, 0x0020);
        assert_eq!(flags::PAM_DISALLOW_NULL_AUTHTOK, 0x0001);
    }

    #[test]
    fn test_conv_mode_enum() {
        // Verify the enum variants are distinct and constructible.
        assert_ne!(ConvMode::Tty, ConvMode::Stdin);
        let mode = ConvMode::Tty;
        assert_eq!(mode, ConvMode::Tty);
        let mode = ConvMode::Stdin;
        assert_eq!(mode, ConvMode::Stdin);
    }

    #[test]
    fn test_conv_mode_is_copy() {
        // ConvMode should implement Copy for ergonomic use.
        let a = ConvMode::Tty;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_pam_handle_is_opaque() {
        // PamHandle should be zero-sized (opaque type, never instantiated).
        assert_eq!(std::mem::size_of::<PamHandle>(), 0);
    }

    #[test]
    fn test_pam_message_layout() {
        // Verify PamMessage has a plausible C layout: it holds an int and a
        // pointer, so it must be at least their combined size and padded out
        // to its own alignment. Computing the exact padding here only
        // reimplements the compiler's layout rules, and the previous attempt
        // clamped an unsigned subtraction with `.max(0)`, which never did
        // anything.
        assert!(
            std::mem::size_of::<PamMessage>()
                >= std::mem::size_of::<libc::c_int>() + std::mem::size_of::<*const libc::c_char>()
        );
        assert_eq!(
            std::mem::size_of::<PamMessage>() % std::mem::align_of::<PamMessage>(),
            0
        );
    }

    #[test]
    fn test_pam_response_layout() {
        // PamResponse must contain a pointer and an int, with C layout.
        assert!(std::mem::size_of::<PamResponse>() >= std::mem::size_of::<*mut libc::c_char>());
    }

    #[test]
    fn test_alloc_c_response_empty_string() {
        let result = alloc_c_response("");
        assert!(result.is_ok());
        let ptr = result.expect("alloc should succeed");

        // SAFETY: we just allocated this pointer and it should contain a null
        // terminator at position 0.
        unsafe {
            assert_eq!(*ptr, 0);
            libc::free(ptr.cast::<libc::c_void>());
        }
    }

    #[test]
    fn test_alloc_c_response_nonempty() {
        let result = alloc_c_response("hello");
        assert!(result.is_ok());
        let ptr = result.expect("alloc should succeed");

        // SAFETY: we just allocated this and wrote "hello\0" into it.
        unsafe {
            let cstr = CStr::from_ptr(ptr);
            assert_eq!(cstr.to_str().expect("valid utf-8"), "hello");
            libc::free(ptr.cast::<libc::c_void>());
        }
    }

    #[test]
    fn test_conversation_null_appdata_returns_conv_err() {
        let mut resp: *mut PamResponse = ptr::null_mut();
        let rc = conversation(0, ptr::null_mut(), &raw mut resp, ptr::null_mut());
        assert_eq!(rc, return_code::PAM_CONV_ERR);
    }

    #[test]
    fn test_conversation_zero_messages_returns_conv_err() {
        let mut conv_data = ConvData {
            mode: ConvMode::Stdin,
        };
        let appdata = (&raw mut conv_data).cast::<libc::c_void>();
        let mut resp: *mut PamResponse = ptr::null_mut();

        let rc = conversation(0, ptr::null_mut(), &raw mut resp, appdata);
        assert_eq!(rc, return_code::PAM_CONV_ERR);
    }

    #[test]
    fn test_conversation_null_msg_returns_conv_err() {
        let mut conv_data = ConvData {
            mode: ConvMode::Stdin,
        };
        let appdata = (&raw mut conv_data).cast::<libc::c_void>();
        let mut resp: *mut PamResponse = ptr::null_mut();

        let rc = conversation(1, ptr::null_mut(), &raw mut resp, appdata);
        assert_eq!(rc, return_code::PAM_CONV_ERR);
    }
}
