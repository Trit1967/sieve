// SPDX-License-Identifier: MIT OR Apache-2.0
//! Behavioral commitment extraction + verification.
//!
//! Phase 8 implements the deterministic half of the output verifier
//! (semantic / LLM-judge checks land in v0.3). Three commitment families
//! land here:
//!
//! - **Language** — system prompt says "respond in English"; output is
//!   scanned for English-ness via stopword density.
//! - **Persona** — system prompt asserts "you are Bob"; the output's
//!   first-person identification ("I am X") must match.
//! - **Refusal keyword** — system prompt forbids a topic ("never discuss
//!   medical advice"); the output is scanned for that topic phrase.
//!
//! The module is split into `extract` (commitment extraction from a system
//! prompt) and `verify` (commitment verification against an LLM output).

pub mod extract;
pub mod verify;

pub use extract::{extract_commitments, Commitment};
pub use verify::verify_commitments;
