// This file is part of the shadow-rs package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Replays the tracked fuzz corpus through the parsers on stable Rust.
//!
//! The fuzz targets need nightly and a fuzzing run; this does not. It takes
//! the inputs previous runs found interesting and asserts the same two
//! properties on every one of them, so a regression that a fuzzer once caught
//! cannot come back unnoticed between fuzzing sessions.
//!
//! The properties are the fuzz targets': a record that parses must render
//! with exactly the separators its format has, and must parse again to
//! something that renders identically. A `Display` that can emit a line
//! parsing differently means a tool rewriting the file silently changes an
//! account.

use std::path::{Path, PathBuf};

use shadow_core::group::GroupEntry;
use shadow_core::gshadow::GshadowEntry;
use shadow_core::passwd::PasswdEntry;
use shadow_core::shadow::ShadowEntry;
use shadow_core::subid::SubIdEntry;

/// The corpus directory for one target, or `None` when it has not been run yet.
fn corpus(target: &str) -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/corpus")
        .join(target);
    dir.is_dir().then_some(dir)
}

/// Every input in a corpus directory, as text; non-UTF-8 inputs are skipped,
/// as the targets skip them.
fn inputs(target: &str) -> Vec<String> {
    let Some(dir) = corpus(target) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| std::fs::read(e.path()).ok())
        .filter_map(|bytes| String::from_utf8(bytes).ok())
        .collect()
}

/// Assert the round-trip and separator-count properties for one record type.
fn check_round_trip<T>(target: &str, separators: usize)
where
    T: std::str::FromStr + std::fmt::Display,
{
    let mut parsed = 0_usize;
    for text in inputs(target) {
        let Ok(entry) = text.parse::<T>() else {
            continue;
        };
        parsed += 1;

        let rendered = entry.to_string();
        assert_eq!(
            rendered.matches(':').count(),
            separators,
            "{target}: rendered record has the wrong separator count: {rendered:?}"
        );

        let reparsed = rendered.parse::<T>().unwrap_or_else(|_| {
            panic!("{target}: a rendered record must parse again: {rendered:?}")
        });
        assert_eq!(
            reparsed.to_string(),
            rendered,
            "{target}: round trip changed the record"
        );
    }

    // A corpus that parses nothing would make this test vacuous.
    if corpus(target).is_some() {
        assert!(parsed > 0, "{target}: no corpus input parsed as a record");
    }
}

#[test]
fn test_passwd_corpus_round_trips() {
    check_round_trip::<PasswdEntry>("fuzz_passwd_parse", 6);
}

#[test]
fn test_shadow_corpus_round_trips() {
    check_round_trip::<ShadowEntry>("fuzz_shadow_parse", 8);
}

#[test]
fn test_group_corpus_round_trips() {
    check_round_trip::<GroupEntry>("fuzz_group_parse", 3);
}

#[test]
fn test_gshadow_corpus_round_trips() {
    check_round_trip::<GshadowEntry>("fuzz_gshadow_parse", 3);
}

#[test]
fn test_subid_corpus_round_trips() {
    check_round_trip::<SubIdEntry>("fuzz_subid_parse", 2);
}

/// The username corpus feeds a validator rather than a parser, so the property
/// is different: it must terminate and answer, never panic, on any input.
#[test]
fn test_username_corpus_is_answered() {
    for text in inputs("fuzz_validate_username") {
        let _ = shadow_core::validate::validate_username(&text);
    }
}
