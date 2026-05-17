// SPDX-License-Identifier: MIT OR Apache-2.0
//! Streaming output scanner (v0.3).
//!
//! [`StreamingOutputScanner`] accumulates chunks from a token-streaming LLM
//! response and runs the canary-leak + commitment-violation checks
//! incrementally. It emits an [`IncrementalVerdict`] after each chunk so
//! callers can short-circuit a bad response before the full body lands.
//!
//! The scanner is intentionally simple: it concatenates chunks into an
//! internal buffer and re-runs the cheap detectors on the growing window
//! at every push. This matches what production agent stacks do today
//! (re-scan-on-tick); per-chunk delta detectors are deferred to v0.4
//! since they add complexity without changing the user-visible API.
//!
//! ```ignore
//! use sieve_core::{Scanner, StreamingOutputScanner};
//! let scanner = Scanner::default();
//! let pre = scanner.scan_input("system prompt", "user input");
//! let mut stream = StreamingOutputScanner::new(
//!     &scanner, "system prompt", pre.canary_state,
//! );
//! for chunk in llm_chunks {
//!     let v = stream.push(&chunk);
//!     if v.should_stop() {
//!         break;
//!     }
//! }
//! let final_verdict = stream.finalize();
//! ```

use crate::scanner::Scanner;
use crate::verdict::{CanaryState, Decision, Verdict};

/// Incremental verdict emitted after each `push`. Wraps the underlying
/// [`Verdict`] with a `should_stop()` helper for the common "break on
/// block" loop pattern.
#[derive(Debug, Clone)]
pub struct IncrementalVerdict {
    /// Underlying verdict from the current buffer.
    pub verdict: Verdict,
    /// Total bytes seen so far across all `push` calls.
    pub bytes_seen: usize,
}

impl IncrementalVerdict {
    /// True if the caller should stop streaming — i.e. the current verdict
    /// is `Block`. Convenience for the common `for chunk in ... { ... }`
    /// loop pattern.
    #[must_use]
    pub fn should_stop(&self) -> bool {
        self.verdict.decision == Decision::Block
    }
}

/// Streaming output scanner. Buffers chunks and re-scans on each push.
#[allow(missing_debug_implementations)]
pub struct StreamingOutputScanner<'a> {
    scanner: &'a Scanner,
    system_prompt: String,
    canary_state: CanaryState,
    buffer: String,
    bytes_seen: usize,
}

impl<'a> StreamingOutputScanner<'a> {
    /// Build a new streaming scanner. Pass the same `system_prompt` and
    /// `canary_state` returned by [`Scanner::scan_input`] for the request.
    #[must_use]
    pub fn new(
        scanner: &'a Scanner,
        system_prompt: impl Into<String>,
        canary_state: CanaryState,
    ) -> Self {
        Self {
            scanner,
            system_prompt: system_prompt.into(),
            canary_state,
            buffer: String::new(),
            bytes_seen: 0,
        }
    }

    /// Append a chunk and re-run the output-side detectors over the
    /// accumulated buffer.
    #[must_use]
    pub fn push(&mut self, chunk: &str) -> IncrementalVerdict {
        self.buffer.push_str(chunk);
        self.bytes_seen += chunk.len();
        let verdict =
            self.scanner
                .scan_output(&self.system_prompt, &self.buffer, &self.canary_state);
        IncrementalVerdict {
            verdict,
            bytes_seen: self.bytes_seen,
        }
    }

    /// Finalize: run the output-side detectors one more time and return
    /// the terminal verdict. Idempotent with the last `push` if no new
    /// data has been pushed.
    #[must_use]
    pub fn finalize(self) -> Verdict {
        self.scanner
            .scan_output(&self.system_prompt, &self.buffer, &self.canary_state)
    }

    /// Read-only view of the buffer accumulated so far. Useful for audit
    /// logs after a streaming session ends.
    #[must_use]
    pub fn buffer(&self) -> &str {
        &self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_stream_stays_allowed() {
        let scanner = Scanner::default();
        let pre = scanner.scan_input("You are a helpful assistant.", "hi");
        let mut stream =
            StreamingOutputScanner::new(&scanner, "You are a helpful assistant.", pre.canary_state);
        for chunk in ["Sure, here's ", "a friendly answer ", "to your question."] {
            let v = stream.push(chunk);
            assert!(!v.should_stop(), "benign chunk should not stop the stream");
        }
        let f = stream.finalize();
        assert_eq!(f.decision, Decision::Allow);
    }

    #[test]
    fn canary_leak_stops_stream_on_first_chunk_containing_token() {
        let scanner = Scanner::default();
        let pre = scanner.scan_input("system prompt", "hello");
        let token = pre.canary_state.canaries[0].clone();
        let mut stream =
            StreamingOutputScanner::new(&scanner, "system prompt", pre.canary_state.clone());
        let v1 = stream.push("Here's the answer: ");
        assert!(!v1.should_stop());
        let v2 = stream.push(&format!("the secret is {token}."));
        assert!(
            v2.should_stop(),
            "canary leak in chunk should trigger Block"
        );
    }

    #[test]
    fn finalize_idempotent_after_last_push() {
        let scanner = Scanner::default();
        let pre = scanner.scan_input("sp", "hi");
        let mut stream = StreamingOutputScanner::new(&scanner, "sp", pre.canary_state);
        let v_push = stream.push("hello").verdict.decision;
        let v_final = stream.finalize().decision;
        assert_eq!(v_push, v_final);
    }

    #[test]
    fn bytes_seen_tracks_all_chunks() {
        let scanner = Scanner::default();
        let pre = scanner.scan_input("sp", "hi");
        let mut stream = StreamingOutputScanner::new(&scanner, "sp", pre.canary_state);
        let _ = stream.push("abc");
        let v = stream.push("defg");
        assert_eq!(v.bytes_seen, 7);
    }

    #[test]
    fn buffer_accumulates() {
        let scanner = Scanner::default();
        let pre = scanner.scan_input("sp", "hi");
        let mut stream = StreamingOutputScanner::new(&scanner, "sp", pre.canary_state);
        let _ = stream.push("hello ");
        let _ = stream.push("world");
        assert_eq!(stream.buffer(), "hello world");
    }
}
