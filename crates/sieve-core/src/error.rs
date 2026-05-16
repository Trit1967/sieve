// SPDX-License-Identifier: MIT OR Apache-2.0
//! Error type for sieve-core.
//!
//! Bindings translate these to their host language's idiomatic error type
//! (`PromptInjectionError` in Python, `SieveError` in JS, etc.).

use thiserror::Error;

/// Crate-level result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors emitted by sieve-core.
///
/// Variants are stable across minor releases; new variants are non-breaking
/// additions and existing variants are only removed at major-version bumps.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A wordlist or pattern file could not be loaded.
    #[error("failed to load patterns: {0}")]
    PatternLoad(String),

    /// A user-supplied configuration was invalid.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// JSON (de)serialization error for canary state or verdicts.
    #[error("verdict serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// I/O error (file-based pattern load, etc.). Never network I/O — see R1.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages() {
        assert!(Error::PatternLoad("bad file".into())
            .to_string()
            .contains("bad file"));
        assert!(Error::Config("missing field".into())
            .to_string()
            .contains("missing field"));
    }

    #[test]
    fn serde_error_propagates() {
        let bad: core::result::Result<i32, serde_json::Error> = serde_json::from_str("not json");
        let err: Error = bad.unwrap_err().into();
        assert!(matches!(err, Error::Serde(_)));
    }

    #[test]
    fn io_error_propagates() {
        let bad: core::result::Result<std::fs::File, std::io::Error> =
            std::fs::File::open("/this/path/does/not/exist/sieve");
        let err: Error = bad.unwrap_err().into();
        assert!(matches!(err, Error::Io(_)));
    }
}
