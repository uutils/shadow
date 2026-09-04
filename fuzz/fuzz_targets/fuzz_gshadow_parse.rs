// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Fuzz target for `/etc/gshadow` line parsing.
//!
//! "Does not panic" is the floor, not the property that matters. For a record
//! file what matters is that a parsed entry survives being written back: if
//! `Display` can emit something that parses differently, a tool that rewrites
//! the file silently changes an account.
//!
//! Two properties are checked on every input that parses:
//!
//!   1. **Round trip.** Rendering an entry and parsing it again yields an
//!      entry that renders identically.
//!   2. **No stray separator.** The rendered line carries exactly the 3
//!      colons the format has. A field value holding one would shift every
//!      following field on the next read, which is how an injected account
//!      would appear.

#![no_main]
use libfuzzer_sys::fuzz_target;

use shadow_core::gshadow::GshadowEntry;

/// Field separators in a well-formed `/etc/gshadow` line.
const SEPARATORS: usize = 3;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(entry) = text.parse::<GshadowEntry>() else {
        return;
    };

    let rendered = entry.to_string();
    assert_eq!(
        rendered.matches(':').count(),
        SEPARATORS,
        "rendered gshadow record has the wrong number of separators: {rendered:?}"
    );

    let reparsed = rendered
        .parse::<GshadowEntry>()
        .expect("a rendered record must parse again");
    assert_eq!(
        reparsed.to_string(),
        rendered,
        "round trip changed the record"
    );
});
