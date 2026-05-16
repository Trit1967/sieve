// SPDX-License-Identifier: MIT OR Apache-2.0
//! System-prompt-aware context analyzer.
//!
//! Phase 7 implements a deterministic heuristic analyzer: it parses the
//! system prompt into atomic instructions and maps each user input against
//! that list to surface override attempts. ONNX-/LLM-based context analysis
//! is v0.3 work; this module is the v0.1 baseline.
//!
//! Public types:
//! - [`SystemPrompt`] — parsed system prompt with extracted atomic
//!   instructions.
//! - [`ContextAnalyzer`] — runs override-attempt detection against a parsed
//!   system prompt.
//! - [`ContextOpts`] — tuning knobs.

pub mod analyze;
pub mod parse;

pub use analyze::ContextAnalyzer;
pub use parse::{Instruction, InstructionKind, SystemPrompt};

/// Options for the context analyzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextOpts {
    /// Number of keyword overlaps (between user input and an instruction)
    /// required to consider it an override attempt. Default 2 — single
    /// overlapping words like "the" are too noisy.
    pub min_keyword_overlap: usize,
    /// Maximum number of atomic instructions to extract from a system
    /// prompt. Bounds work; system prompts longer than this are truncated.
    pub max_instructions: usize,
}

impl Default for ContextOpts {
    fn default() -> Self {
        Self {
            min_keyword_overlap: 2,
            max_instructions: 64,
        }
    }
}
