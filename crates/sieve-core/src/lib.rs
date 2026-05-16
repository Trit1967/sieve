// SPDX-License-Identifier: MIT OR Apache-2.0
//! # sieve-core
//!
//! Vendor-neutral, offline-first prompt injection defense.
//!
//! The core crate is a synchronous, zero-network, zero-LLM-vendor-dependency
//! library that takes strings in and returns structured verdicts.
//!
//! Phase 0 scaffold: this module currently exposes only a placeholder
//! [`Scanner`] type. The Verdict schema lands in Phase 1; the real detector
//! pipeline follows in Phases 2 through 10. See `IMPLEMENTATION_PROMPT.md` at
//! the workspace root for the phase plan.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic, missing_docs, rust_2018_idioms)]
#![allow(clippy::module_name_repetitions)]

/// Placeholder scanner type.
///
/// Phase 0: constructable, no methods yet. The Verdict schema (Phase 1)
/// supplies the return types; the detector pipeline (Phase 10) supplies the
/// `scan_input` / `scan_output` implementations.
#[derive(Debug, Default, Clone)]
pub struct Scanner {
    _private: (),
}

impl Scanner {
    /// Construct the default scanner.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_constructible() {
        let _ = Scanner::default();
        let _ = Scanner::new();
    }
}
