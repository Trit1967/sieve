// SPDX-License-Identifier: MIT OR Apache-2.0
//! # sieve-core
//!
//! Vendor-neutral, offline-first prompt injection defense.
//!
//! The core crate is a synchronous, zero-network, zero-LLM-vendor-dependency
//! library that takes strings in and returns structured [`Verdict`]s.
//!
//! ```ignore
//! use sieve_core::{Scanner, Decision};
//! let scanner = Scanner::default();
//! let verdict = scanner.scan_input("system prompt", "user input");
//! match verdict.decision {
//!     Decision::Block => { /* refuse */ }
//!     Decision::Flag => { /* surface to caller */ }
//!     Decision::Allow => { /* proceed */ }
//! }
//! ```
//!
//! See `PRD.md` and `ARCHITECTURE.md` at the workspace root for the design
//! contract this crate implements. Phase plan in `IMPLEMENTATION_PROMPT.md`.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Production code must be panic-free (ADR-0009). Test modules are exempt via
// `cfg(not(test))` so test code can use unwrap/expect/assert! ergonomically.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![warn(clippy::pedantic, missing_docs, rust_2018_idioms)]
#![allow(clippy::module_name_repetitions)]

pub mod detectors;
pub mod error;
pub mod verdict;

pub use detectors::{
    NormalizationResult, PatternOpts, PatternScanner, UnicodeNormalizer, UnicodeOpts,
};
pub use error::{Error, Result};
pub use verdict::{
    CanaryLeak, CanaryState, Category, CommitmentViolation, Decision, Finding, Severity, Verdict,
};

/// Placeholder scanner type.
///
/// Phase 1 ships the Verdict schema and a stub Scanner that returns
/// `Verdict::allow_empty()` for any input. The real detector pipeline lands
/// in Phases 2 through 10.
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

    /// Scan a user input against a system prompt.
    ///
    /// Phase 1 stub: returns an Allow verdict with no findings. The real
    /// detector pipeline (`UnicodeNormalizer` in P2 onwards) is wired in via
    /// the Scanner orchestrator in Phase 10.
    #[must_use]
    pub fn scan_input(&self, _system_prompt: &str, _user_input: &str) -> Verdict {
        Verdict::allow_empty()
    }

    /// Scan a model output, given the canary state returned by `scan_input`.
    ///
    /// Phase 1 stub: returns an Allow verdict with no findings.
    #[must_use]
    pub fn scan_output(&self, _output: &str, _canary_state: &CanaryState) -> Verdict {
        Verdict::allow_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_default_returns_allow() {
        let scanner = Scanner::default();
        let v = scanner.scan_input("system", "hello world");
        assert!(v.is_allow());
        assert!(v.findings.is_empty());
    }

    #[test]
    fn scan_output_returns_allow() {
        let scanner = Scanner::new();
        let cs = CanaryState::default();
        let v = scanner.scan_output("ok", &cs);
        assert!(v.is_allow());
    }

    #[test]
    fn re_exports_compose() {
        // Smoke-check that public re-exports point at the right types.
        let _: Decision = Decision::Allow;
        let _: Severity = Severity::Info;
        let _: Category = Category::UnicodeSmuggling;
        let _: Finding = Finding {
            detector: "x".into(),
            severity: Severity::Info,
            message: String::new(),
            matched_span: None,
            score: 0.0,
            category: Category::UnicodeSmuggling,
        };
        let _: CanaryState = CanaryState::default();
        let _: CanaryLeak = CanaryLeak {
            canary: "A".into(),
            matched_span: (0, 1),
            exact: true,
        };
        let _: CommitmentViolation = CommitmentViolation {
            kind: "language".into(),
            expected: String::new(),
            observed: String::new(),
            confidence: 0.0,
        };
        let _: Verdict = Verdict::allow_empty();
    }
}
