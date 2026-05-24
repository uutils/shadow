// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Safe wrapper around POSIX `crypt(3)` for password hashing and verification.
//!
//! This is one of only two modules (along with `pam`) where `unsafe_code`
//! is permitted, because `crypt(3)` is a C library function.

use std::ffi::CString;

use subtle::ConstantTimeEq;

use crate::error::ShadowError;

#[link(name = "crypt")]
unsafe extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// crypt(3) salt alphabet (POSIX: [a-zA-Z0-9./]).
const SALT_CHARS: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// Modulo bias check: random u8 values (0-255) mapped via `% len` have zero
// bias only when `len` divides 256 evenly. Assert this at compile time.
const _: () = assert!(256 % SALT_CHARS.len() == 0);

/// Supported crypt(3) hash methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptMethod {
    /// SHA-256 ($5$)
    Sha256,
    /// SHA-512 ($6$) — recommended default
    Sha512,
    /// yescrypt ($y$)
    Yescrypt,
}

impl CryptMethod {
    /// The crypt(3) prefix for this method.
    fn prefix(self) -> &'static str {
        match self {
            Self::Sha256 => "$5$",
            Self::Sha512 => "$6$",
            Self::Yescrypt => "$y$j9T$",
        }
    }
}

/// Generate a random salt string for crypt(3).
fn generate_salt(method: CryptMethod, rounds: Option<u32>) -> Result<String, ShadowError> {
    let mut rand_bytes = [0u8; 16];
    // Use getrandom(2) syscall — works in chroot environments without /dev/urandom.
    rustix::rand::getrandom(&mut rand_bytes, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ShadowError::Other("getrandom(2) failed".into()))?;

    let salt_str: String = rand_bytes
        .iter()
        .map(|&b| SALT_CHARS[(b as usize) % SALT_CHARS.len()] as char)
        .collect();

    let prefix = method.prefix();
    match (method, rounds) {
        (CryptMethod::Sha256 | CryptMethod::Sha512, Some(r)) => {
            Ok(format!("{prefix}rounds={r}${salt_str}$"))
        }
        (CryptMethod::Yescrypt, Some(_)) => Err(ShadowError::Auth(
            "rounds parameter is not supported for yescrypt".into(),
        )),
        (_, None) => Ok(format!("{prefix}{salt_str}$")),
    }
}

/// Hash a plaintext password using crypt(3).
///
/// Returns the full crypt(3) hash string (e.g. `$6$salt$hash...`).
///
/// # Errors
///
/// Returns `ShadowError` if the password contains null bytes, the salt
/// cannot be generated, or crypt(3) fails.
///
/// # Thread safety
///
/// This function is NOT thread-safe. `crypt(3)` uses a process-wide
/// static buffer on glibc. Concurrent calls from multiple threads will
/// corrupt each other's results. All shadow-rs tools are single-threaded.
pub fn hash_password(
    password: &str,
    method: CryptMethod,
    rounds: Option<u32>,
) -> Result<String, ShadowError> {
    let salt = generate_salt(method, rounds)?;
    let c_password = CString::new(password)
        .map_err(|_| ShadowError::Auth("password contains null byte".into()))?;
    let c_salt = CString::new(salt.as_str())
        .map_err(|_| ShadowError::Auth("salt contains null byte".into()))?;

    // SAFETY: crypt() is provided by libcrypt/glibc. Both arguments are valid
    // null-terminated C strings. The returned pointer is to a static/thread-local
    // buffer managed by crypt().
    let result = unsafe { crypt(c_password.as_ptr(), c_salt.as_ptr()) };

    if result.is_null() {
        return Err(ShadowError::Auth("crypt(3) returned NULL".into()));
    }

    // SAFETY: crypt() returned a non-null pointer to a null-terminated string.
    let result_str = unsafe { std::ffi::CStr::from_ptr(result) };
    let hash = result_str
        .to_str()
        .map_err(|_| ShadowError::Auth("crypt(3) returned invalid UTF-8".into()))?;

    // crypt(3) returns "*0"/"*1" for unsupported methods (glibc/libxcrypt).
    // musl silently falls back to DES — detect by checking the method prefix.
    let prefix = method.prefix();
    if hash.starts_with('*') || !hash.starts_with(prefix) {
        return Err(ShadowError::Auth(
            format!("crypt(3) does not support {method:?} on this system").into(),
        ));
    }

    Ok(hash.to_string())
}

/// Verify a plaintext password against a crypt(3) hash.
///
/// Returns `true` if the password matches the hash, `false` otherwise.
///
/// # Errors
///
/// Returns `ShadowError` if the inputs contain null bytes.
///
/// # Thread safety
///
/// This function is NOT thread-safe. `crypt(3)` uses a process-wide
/// static buffer on glibc. Concurrent calls from multiple threads will
/// corrupt each other's results. All shadow-rs tools are single-threaded.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, ShadowError> {
    let c_password = CString::new(password)
        .map_err(|_| ShadowError::Auth("password contains null byte".into()))?;
    let c_hash =
        CString::new(hash).map_err(|_| ShadowError::Auth("hash contains null byte".into()))?;

    // SAFETY: crypt() is provided by libcrypt/glibc. Both arguments are valid
    // null-terminated C strings. The returned pointer is to a static/thread-local
    // buffer managed by crypt().
    let result = unsafe { crypt(c_password.as_ptr(), c_hash.as_ptr()) };

    if result.is_null() {
        return Ok(false);
    }

    // SAFETY: crypt() returned a non-null pointer to a null-terminated string.
    let result_str = unsafe { std::ffi::CStr::from_ptr(result) };
    let result_str = result_str.to_str().unwrap_or("");

    // Constant-time comparison prevents timing side-channel attacks
    // that could leak password hash information.
    Ok(result_str.as_bytes().ct_eq(hash.as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // crypt(3) uses a process-wide static buffer — serialize all tests
    // that call it to avoid SIGSEGV from concurrent access.
    static CRYPT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_hash_verify_sha512() {
        let _guard = CRYPT_LOCK.lock().expect("lock");
        let hash = hash_password("secret", CryptMethod::Sha512, None)
            .expect("hash_password should succeed");
        assert!(
            hash.starts_with("$6$"),
            "SHA-512 hash should start with $6$"
        );
        assert!(
            verify_password("secret", &hash).expect("verify should succeed"),
            "correct password should verify"
        );
        assert!(
            !verify_password("wrong", &hash).expect("verify should succeed"),
            "wrong password should not verify"
        );
    }

    #[test]
    fn test_hash_verify_sha256() {
        let _guard = CRYPT_LOCK.lock().expect("lock");
        let hash = hash_password("secret", CryptMethod::Sha256, None)
            .expect("hash_password should succeed");
        assert!(
            hash.starts_with("$5$"),
            "SHA-256 hash should start with $5$"
        );
        assert!(verify_password("secret", &hash).expect("verify should succeed"));
    }

    #[test]
    fn test_hash_verify_yescrypt() {
        let _guard = CRYPT_LOCK.lock().expect("lock");
        // musl libc doesn't support yescrypt — skip gracefully.
        let Ok(hash) = hash_password("secret", CryptMethod::Yescrypt, None) else {
            return;
        };
        assert!(
            hash.starts_with("$y$"),
            "yescrypt hash should start with $y$"
        );
        assert!(verify_password("secret", &hash).expect("verify should succeed"));
    }

    #[test]
    fn test_sha_rounds_applied() {
        let _guard = CRYPT_LOCK.lock().expect("lock");
        // musl libc doesn't support SHA rounds — skip gracefully.
        let Ok(hash) = hash_password("secret", CryptMethod::Sha512, Some(10000)) else {
            return;
        };
        assert!(
            hash.starts_with("$6$rounds=10000$"),
            "rounds should appear in hash"
        );
        assert!(verify_password("secret", &hash).expect("verify should succeed"));
    }

    #[test]
    fn test_yescrypt_rejects_rounds() {
        let result = hash_password("secret", CryptMethod::Yescrypt, Some(10000));
        assert!(result.is_err(), "yescrypt should reject rounds parameter");
    }

    #[test]
    fn test_generate_salt_unique() {
        let s1 = generate_salt(CryptMethod::Sha512, None).expect("salt gen");
        let s2 = generate_salt(CryptMethod::Sha512, None).expect("salt gen");
        assert_ne!(s1, s2, "two salts should differ");
    }
}
