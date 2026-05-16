// SPDX-License-Identifier: MIT OR Apache-2.0
//! Detector implementations.
//!
//! Each detector is a focused module that examines an input and emits zero or
//! more [`Finding`]s. The Scanner orchestrator (Phase 10) composes them.
//!
//! Detectors landing in v0.1:
//! - Phase 2: [`unicode::UnicodeNormalizer`] — NFKC + zero-width strip + homoglyphs.
//! - Phase 3: `PatternScanner` (Aho-Corasick over the wordlist).
//! - Phase 4: `EncodingScanner` (base64 / hex / rot13).
//! - Phase 5: `HeuristicScorer` (instruction density, script-switch, entropy).

pub mod encoding;
pub mod heuristics;
pub mod patterns;
pub mod unicode;

pub use encoding::{EncodingOpts, EncodingScanner};
pub use heuristics::{HeuristicOpts, HeuristicScorer};
pub use patterns::{PatternOpts, PatternScanner};
pub use unicode::{NormalizationResult, UnicodeNormalizer, UnicodeOpts};
