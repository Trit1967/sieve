// SPDX-License-Identifier: MIT OR Apache-2.0
//! WASM binding for sieve.
//!
//! Phase 1: re-exports the core types so the binding crate compiles while the
//! wasm-bindgen module is built in Phase 12.

pub use sieve_core::{
    CanaryLeak, CanaryState, Category, CommitmentViolation, Decision, Finding, Scanner, Severity,
    Verdict,
};
