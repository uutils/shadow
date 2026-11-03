// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Fuzz target for username validation.
//!
//! Ensures `validate_username` never panics on arbitrary string input.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Must not panic on any input — errors are fine.
        let _ = shadow_core::validate::validate_username(s);
    }
});
