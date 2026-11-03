// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Fuzz target for username validation.
//!
//! Ensures the user and group name checks never panic on arbitrary string input.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Must not panic on any input; either answer is fine.
        let _ = shadow_core::validate::is_valid_user_name(s);
        let _ = shadow_core::validate::is_valid_group_name(s);
    }
});
