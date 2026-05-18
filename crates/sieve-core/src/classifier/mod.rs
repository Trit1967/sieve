// SPDX-License-Identifier: MIT OR Apache-2.0
//! BYO-ONNX classifier interface.
//!
//! Per `research/goals/IMPLEMENTATION_PROMPT.md` Phase 9 and PRD G9, sieve does NOT bundle
//! ML weights. Users supply their own model (`HuggingFace`
//! `deepset/deberta-v3-base-injection`,
//! `protectai/deberta-v3-base-prompt-injection-v2`, or any compatible
//! classifier) and plug it in via the [`Classifier`] trait.
//!
//! v0.1 ships the trait + a [`NoopClassifier`] default. The
//! `ort`-backed reference implementation is feature-gated under `onnx`
//! and documented as v0.2 work; depending on `ort` outside that feature
//! would pull in 50+ MB of native `ONNX` Runtime binaries by default, which
//! conflicts with the embeddable-everywhere goal.
//!
//! Implementing the trait is one method:
//!
//! ```ignore
//! use sieve_core::classifier::{Classifier, ClassificationResult};
//!
//! struct MyClassifier { /* ... */ }
//!
//! impl Classifier for MyClassifier {
//!     fn classify(&self, input: &str) -> ClassificationResult {
//!         // run inference however you want; return score + label
//!         ClassificationResult {
//!             score: 0.0,
//!             label: "safe".into(),
//!             metadata: std::collections::HashMap::new(),
//!         }
//!     }
//! }
//! ```

use std::collections::HashMap;

/// Output of a single [`Classifier::classify`] call.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassificationResult {
    /// Score in `[0.0, 1.0]`. Convention: higher = more likely malicious.
    pub score: f32,
    /// Stable label string (model-dependent; e.g. `"INJECTION"` / `"SAFE"`).
    pub label: String,
    /// Free-form metadata for the model (logits, top-k, version, ...).
    pub metadata: HashMap<String, String>,
}

impl ClassificationResult {
    /// Convenience constructor for a "safe" verdict with score 0.
    #[must_use]
    pub fn safe() -> Self {
        Self {
            score: 0.0,
            label: "safe".into(),
            metadata: HashMap::new(),
        }
    }
}

/// Pluggable classifier interface.
///
/// All implementations MUST be `Send + Sync` so the Scanner orchestrator
/// (Phase 10) can call them from any thread. Classifiers run *after* the
/// deterministic detector pipeline, so they see the normalized + decoded
/// input.
pub trait Classifier: Send + Sync + std::fmt::Debug {
    /// Classify `input`. Must not panic and must not perform any network
    /// I/O — see R1.
    fn classify(&self, input: &str) -> ClassificationResult;

    /// A stable name identifying this classifier in findings / telemetry.
    /// Default returns the type's debug name; implementations should
    /// override for consistent metric labels.
    fn name(&self) -> &'static str {
        "classifier"
    }
}

/// A classifier that always reports "safe". The default when no
/// classifier is wired in.
///
/// Use this as your no-op when constructing a `ScannerBuilder` without
/// the optional classifier slot configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopClassifier;

impl Classifier for NoopClassifier {
    fn classify(&self, _input: &str) -> ClassificationResult {
        ClassificationResult::safe()
    }

    fn name(&self) -> &'static str {
        "noop"
    }
}

#[cfg(feature = "onnx")]
pub mod onnx {
    //! ONNX Runtime-backed reference implementation.
    //!
    //! Reserved for v0.2 — `ort` is in 2.0.0-rc and pulls in 50+ MB of
    //! native binaries by default. v0.1 ships the trait only and
    //! documents the recommended way to BYO ONNX inference: either wait
    //! for the v0.2 built-in or implement `Classifier` directly against
    //! your inference runtime of choice.

    use super::{ClassificationResult, Classifier};

    /// Placeholder for the v0.2 `ort`-backed classifier.
    ///
    /// In v0.1 this returns "safe" on every input and emits a runtime
    /// warning the first time `classify` is called. The full
    /// implementation lands in v0.2 once `ort` 2.0 stabilizes.
    #[derive(Debug, Default)]
    pub struct OnnxClassifier;

    impl OnnxClassifier {
        /// Construct a placeholder. Returns an instance that classifies
        /// everything as safe (no-op).
        #[must_use]
        pub const fn placeholder() -> Self {
            Self
        }
    }

    impl Classifier for OnnxClassifier {
        fn classify(&self, _input: &str) -> ClassificationResult {
            ClassificationResult::safe()
        }

        fn name(&self) -> &'static str {
            "onnx-placeholder"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_classifier_returns_safe() {
        let c = NoopClassifier;
        let r = c.classify("anything");
        assert_eq!(r.label, "safe");
        assert!(r.score.abs() < f32::EPSILON);
        assert_eq!(c.name(), "noop");
    }

    #[test]
    fn classifier_trait_is_implementable() {
        // Mock classifier exercises the trait surface.
        #[derive(Debug)]
        struct MockClassifier(f32);

        impl Classifier for MockClassifier {
            fn classify(&self, _input: &str) -> ClassificationResult {
                ClassificationResult {
                    score: self.0,
                    label: "mock".into(),
                    metadata: HashMap::new(),
                }
            }

            fn name(&self) -> &'static str {
                "mock"
            }
        }

        let m = MockClassifier(0.42);
        let r = m.classify("hi");
        assert!((r.score - 0.42).abs() < f32::EPSILON);
        assert_eq!(r.label, "mock");
    }

    #[test]
    fn classifier_is_object_safe() {
        // The trait must be object-safe so Scanner can hold a Box<dyn Classifier>.
        fn accepts_dyn(c: &dyn Classifier) {
            let _ = c.classify("");
        }
        accepts_dyn(&NoopClassifier);
    }

    #[test]
    fn classification_result_safe_constructor() {
        let r = ClassificationResult::safe();
        assert_eq!(r.label, "safe");
        assert!(r.score.abs() < f32::EPSILON);
        assert!(r.metadata.is_empty());
    }
}
