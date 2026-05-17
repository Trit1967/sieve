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

pub mod canary;
pub mod classifier;
pub mod commitments;
pub mod context;
pub mod detectors;
pub mod error;
pub mod judge;
pub mod scanner;
pub mod streaming;
pub mod verdict;

pub use canary::{detect_leaks, inject_system_prompt, Canary};
pub use classifier::{ClassificationResult, Classifier, NoopClassifier};
pub use commitments::{extract_commitments, verify_commitments, Commitment};
pub use context::{ContextAnalyzer, ContextOpts, Instruction, InstructionKind, SystemPrompt};
pub use detectors::{
    AnomalyOpts, AnomalyScorer, DifferentialDetector, DifferentialOpts, EncodingOpts,
    EncodingScanner, HeuristicOpts, HeuristicScorer, NormalizationResult, PatternOpts,
    PatternScanner, SemanticOpts, SemanticScorer, SlotMatcher, SlotOpts, SpotlightDetector,
    SpotlightOpts, UnicodeNormalizer, UnicodeOpts,
};
pub use error::{Error, Result};
pub use judge::{Judgment, LlmJudge, NoopJudge};
pub use scanner::{Scanner, ScannerBuilder, ScannerMode};
pub use streaming::{IncrementalVerdict, StreamingOutputScanner};
pub use verdict::{
    CanaryLeak, CanaryState, Category, CommitmentViolation, Decision, Finding, Severity, Verdict,
};
