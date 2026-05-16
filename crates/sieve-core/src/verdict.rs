// SPDX-License-Identifier: MIT OR Apache-2.0
//! Verdict schema — the cross-language stable API surface.
//!
//! Bindings (`sieve-py`, `sieve-wasm`, future `@sieve/node`) reflect this
//! schema 1:1 in their host language. Changes to these types are public API
//! changes and must be reflected across all bindings, and verified by the
//! cross-language consistency test suite (see ADR-0010).
//!
//! The schema is JSON-stable: `serde_json::from_str(&serde_json::to_string(v))
//! == v` for any value `v` (verified by property test in this module).

use serde::{Deserialize, Serialize};

/// Final disposition the scanner has assigned to an input or output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Decision {
    /// No detector found anything blocking; the input/output is safe to use.
    Allow,
    /// At least one detector flagged the input; surfacing to the caller is
    /// recommended but the caller decides whether to proceed.
    Flag,
    /// At least one detector emitted a blocking finding; the caller MUST NOT
    /// forward this content to the model (input) or to the user (output).
    Block,
}

/// Severity of an individual finding.
///
/// `Block` findings escalate the verdict's decision to [`Decision::Block`].
/// `Warn` findings contribute to the aggregate score and may escalate to
/// [`Decision::Flag`]. `Info` findings are diagnostic and never change the
/// decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    /// Informational only; never escalates the decision.
    Info,
    /// Suspicious; contributes to score, may escalate to Flag.
    Warn,
    /// Conclusive injection signal; escalates to Block.
    Block,
}

/// Attack family a finding belongs to.
///
/// Variants are stable across minor releases. The enum is `#[non_exhaustive]`
/// because v0.2+ adds `ToolCallAnomaly` and `ConversationDrift` semantics;
/// downstream code should match with a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub enum Category {
    /// Zero-width chars, Unicode tag codepoints, homoglyph substitution, etc.
    UnicodeSmuggling,
    /// Matched a curated jailbreak phrase from the pattern corpus.
    KnownPattern,
    /// Base64 / hex / rot13-encoded payload detected.
    EncodingPayload,
    /// High density of imperative override verbs ("ignore", "disregard").
    InstructionDensity,
    /// Multiple Unicode scripts in a single sentence.
    LanguageSwitch,
    /// Repetition / entropy anomaly suggesting prompt-stuffing.
    HighEntropy,
    /// Canary token leaked in the model output (goal hijack signal).
    CanaryLeak,
    /// System prompt commitment was violated by the output.
    CommitmentViolation,
    /// Tool-call arguments diverged from declared invariants (v0.2+).
    ToolCallAnomaly,
    /// Cumulative cross-turn risk (v0.2+).
    ConversationDrift,
}

/// One observation made by a detector during a scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable detector name (`"unicode"`, `"patterns"`, `"encoding"`, ...).
    pub detector: String,
    /// Severity of this finding.
    pub severity: Severity,
    /// Human-readable explanation. Stable English; not localized.
    pub message: String,
    /// Byte offsets `(start, end)` into the *normalized* input where this
    /// finding applies, if applicable.
    pub matched_span: Option<(usize, usize)>,
    /// Per-finding score in `[0.0, 1.0]`.
    pub score: f32,
    /// Attack family this finding belongs to.
    pub category: Category,
}

/// State the scanner carries between `scan_input` and `scan_output`.
///
/// Contains the canary tokens injected into the system prompt so that
/// `scan_output` can detect leakage. Serializable to JSON for transport across
/// process / language boundaries (e.g. a stateless Edge worker handing the
/// canary state to a downstream LLM-call worker).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryState {
    /// Active canary tokens. The output scanner reports a [`CanaryLeak`] for
    /// each one it observes in the model response.
    pub canaries: Vec<String>,
}

/// A canary token that appeared in a model output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanaryLeak {
    /// The canary token that leaked.
    pub canary: String,
    /// Byte offsets into the output where the leak was observed.
    pub matched_span: (usize, usize),
    /// True if matched verbatim; false if matched after fuzzy normalization
    /// (whitespace, case, basic punctuation).
    pub exact: bool,
}

/// A system-prompt commitment the output failed to honor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitmentViolation {
    /// Stable kind identifier: `"language"`, `"persona"`, `"refusal_keyword"`, ...
    pub kind: String,
    /// Expected value from the system prompt (e.g. `"English"`).
    pub expected: String,
    /// Observed value from the output (e.g. `"French"`).
    pub observed: String,
    /// Confidence in this violation, `[0.0, 1.0]`.
    pub confidence: f32,
}

/// The full result of a single scan.
///
/// `Verdict` round-trips losslessly through JSON. Field names are camelCase-
/// adjacent (`canary_state`, `canaries_leaked`) in the source schema; the
/// `serde` derives use the default `snake_case` field naming, which matches
/// the published binding API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    /// Final decision after aggregating all findings.
    pub decision: Decision,
    /// Aggregate score in `[0.0, 1.0]`.
    pub score: f32,
    /// All findings emitted during the scan. Empty on a clean Allow.
    pub findings: Vec<Finding>,
    /// The input as seen by detectors after Unicode normalization. `None` if
    /// normalization was not run (e.g. on `scan_output`).
    pub normalized_input: Option<String>,
    /// Canary state to pass to `scan_output`. Empty for output scans.
    pub canary_state: CanaryState,
    /// Canary tokens detected in the model output. Always empty for input scans.
    pub canaries_leaked: Vec<CanaryLeak>,
    /// Commitments the output failed to honor. Always empty for input scans.
    pub commitments_violated: Vec<CommitmentViolation>,
    /// Wall-clock latency of the scan in microseconds.
    pub latency_us: u64,
}

impl Verdict {
    /// True if the decision is [`Decision::Allow`].
    #[must_use]
    pub fn is_allow(&self) -> bool {
        self.decision == Decision::Allow
    }

    /// True if the decision is [`Decision::Flag`].
    #[must_use]
    pub fn is_flag(&self) -> bool {
        self.decision == Decision::Flag
    }

    /// True if the decision is [`Decision::Block`].
    #[must_use]
    pub fn is_block(&self) -> bool {
        self.decision == Decision::Block
    }

    /// Build an empty Allow verdict. Useful as a default and during the
    /// Phase 0 scanner stub.
    #[must_use]
    pub fn allow_empty() -> Self {
        Self {
            decision: Decision::Allow,
            score: 0.0,
            findings: Vec::new(),
            normalized_input: None,
            canary_state: CanaryState::default(),
            canaries_leaked: Vec::new(),
            commitments_violated: Vec::new(),
            latency_us: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding() -> Finding {
        Finding {
            detector: "unicode".into(),
            severity: Severity::Warn,
            message: "zero-width chars present".into(),
            matched_span: Some((4, 8)),
            score: 0.42,
            category: Category::UnicodeSmuggling,
        }
    }

    fn sample_verdict() -> Verdict {
        Verdict {
            decision: Decision::Flag,
            score: 0.42,
            findings: vec![sample_finding()],
            normalized_input: Some("hello world".into()),
            canary_state: CanaryState {
                canaries: vec!["AAAA".into(), "BBBB".into()],
            },
            canaries_leaked: vec![CanaryLeak {
                canary: "AAAA".into(),
                matched_span: (0, 4),
                exact: true,
            }],
            commitments_violated: vec![CommitmentViolation {
                kind: "language".into(),
                expected: "English".into(),
                observed: "French".into(),
                confidence: 0.87,
            }],
            latency_us: 1234,
        }
    }

    #[test]
    fn decision_predicates() {
        let mut v = Verdict::allow_empty();
        assert!(v.is_allow() && !v.is_flag() && !v.is_block());
        v.decision = Decision::Flag;
        assert!(!v.is_allow() && v.is_flag() && !v.is_block());
        v.decision = Decision::Block;
        assert!(!v.is_allow() && !v.is_flag() && v.is_block());
    }

    #[test]
    fn allow_empty_invariants() {
        let v = Verdict::allow_empty();
        assert_eq!(v.decision, Decision::Allow);
        assert!(v.score.abs() < f32::EPSILON);
        assert!(v.findings.is_empty());
        assert!(v.normalized_input.is_none());
        assert!(v.canary_state.canaries.is_empty());
        assert!(v.canaries_leaked.is_empty());
        assert!(v.commitments_violated.is_empty());
        assert_eq!(v.latency_us, 0);
    }

    #[test]
    fn verdict_json_roundtrip() {
        let v = sample_verdict();
        let s = serde_json::to_string(&v).expect("serialize");
        let back: Verdict = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn canary_state_json_roundtrip() {
        let cs = CanaryState {
            canaries: vec!["X".into()],
        };
        let s = serde_json::to_string(&cs).expect("serialize");
        let back: CanaryState = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(cs, back);
    }

    #[test]
    fn finding_json_roundtrip() {
        let f = sample_finding();
        let s = serde_json::to_string(&f).expect("serialize");
        let back: Finding = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(f, back);
    }

    #[test]
    fn all_decision_variants_serialize() {
        for d in [Decision::Allow, Decision::Flag, Decision::Block] {
            let s = serde_json::to_string(&d).expect("ser");
            let back: Decision = serde_json::from_str(&s).expect("de");
            assert_eq!(d, back);
        }
    }

    #[test]
    fn all_severity_variants_serialize() {
        for s_in in [Severity::Info, Severity::Warn, Severity::Block] {
            let s = serde_json::to_string(&s_in).expect("ser");
            let back: Severity = serde_json::from_str(&s).expect("de");
            assert_eq!(s_in, back);
        }
    }

    #[test]
    fn all_category_variants_serialize() {
        let cats = [
            Category::UnicodeSmuggling,
            Category::KnownPattern,
            Category::EncodingPayload,
            Category::InstructionDensity,
            Category::LanguageSwitch,
            Category::HighEntropy,
            Category::CanaryLeak,
            Category::CommitmentViolation,
            Category::ToolCallAnomaly,
            Category::ConversationDrift,
        ];
        for c in cats {
            let s = serde_json::to_string(&c).expect("ser");
            let back: Category = serde_json::from_str(&s).expect("de");
            assert_eq!(c, back);
        }
    }

    #[test]
    fn decision_names_match_pascal_case() {
        assert_eq!(
            serde_json::to_string(&Decision::Allow).unwrap(),
            "\"Allow\""
        );
        assert_eq!(serde_json::to_string(&Decision::Flag).unwrap(), "\"Flag\"");
        assert_eq!(
            serde_json::to_string(&Decision::Block).unwrap(),
            "\"Block\""
        );
    }

    #[test]
    fn finding_serialized_keys_are_snake_case() {
        let s = serde_json::to_string(&sample_finding()).expect("ser");
        // snake_case field names — bindings depend on this contract.
        assert!(s.contains("\"matched_span\""));
        assert!(!s.contains("matchedSpan"));
    }

    #[test]
    fn verdict_serialized_keys_are_snake_case() {
        let s = serde_json::to_string(&sample_verdict()).expect("ser");
        for key in [
            "\"decision\"",
            "\"score\"",
            "\"findings\"",
            "\"normalized_input\"",
            "\"canary_state\"",
            "\"canaries_leaked\"",
            "\"commitments_violated\"",
            "\"latency_us\"",
        ] {
            assert!(
                s.contains(key),
                "missing key {key} in serialized verdict: {s}"
            );
        }
    }

    // ---------- Property tests --------------------------------------------

    use proptest::prelude::*;

    fn arb_decision() -> impl Strategy<Value = Decision> {
        prop_oneof![
            Just(Decision::Allow),
            Just(Decision::Flag),
            Just(Decision::Block),
        ]
    }

    fn arb_severity() -> impl Strategy<Value = Severity> {
        prop_oneof![
            Just(Severity::Info),
            Just(Severity::Warn),
            Just(Severity::Block),
        ]
    }

    fn arb_category() -> impl Strategy<Value = Category> {
        prop_oneof![
            Just(Category::UnicodeSmuggling),
            Just(Category::KnownPattern),
            Just(Category::EncodingPayload),
            Just(Category::InstructionDensity),
            Just(Category::LanguageSwitch),
            Just(Category::HighEntropy),
            Just(Category::CanaryLeak),
            Just(Category::CommitmentViolation),
            Just(Category::ToolCallAnomaly),
            Just(Category::ConversationDrift),
        ]
    }

    fn arb_score() -> impl Strategy<Value = f32> {
        // Restrict to finite, non-NaN values so equality after round-trip holds.
        (0.0f32..=1.0).prop_map(|x| (x * 1000.0).round() / 1000.0)
    }

    fn arb_finding() -> impl Strategy<Value = Finding> {
        (
            "[a-z_]{1,16}",
            arb_severity(),
            ".{0,64}",
            proptest::option::of((0usize..4096, 0usize..4096)),
            arb_score(),
            arb_category(),
        )
            .prop_map(
                |(detector, severity, message, matched_span, score, category)| Finding {
                    detector,
                    severity,
                    message,
                    matched_span,
                    score,
                    category,
                },
            )
    }

    fn arb_canary_state() -> impl Strategy<Value = CanaryState> {
        proptest::collection::vec("[A-Za-z0-9_-]{4,32}", 0..8)
            .prop_map(|c| CanaryState { canaries: c })
    }

    fn arb_canary_leak() -> impl Strategy<Value = CanaryLeak> {
        (
            "[A-Za-z0-9_-]{4,32}",
            (0usize..4096, 0usize..4096),
            any::<bool>(),
        )
            .prop_map(|(canary, matched_span, exact)| CanaryLeak {
                canary,
                matched_span,
                exact,
            })
    }

    fn arb_commitment_violation() -> impl Strategy<Value = CommitmentViolation> {
        ("[a-z_]{1,16}", ".{0,32}", ".{0,32}", arb_score()).prop_map(
            |(kind, expected, observed, confidence)| CommitmentViolation {
                kind,
                expected,
                observed,
                confidence,
            },
        )
    }

    fn arb_verdict() -> impl Strategy<Value = Verdict> {
        (
            arb_decision(),
            arb_score(),
            proptest::collection::vec(arb_finding(), 0..4),
            proptest::option::of(".{0,64}"),
            arb_canary_state(),
            proptest::collection::vec(arb_canary_leak(), 0..4),
            proptest::collection::vec(arb_commitment_violation(), 0..4),
            any::<u64>(),
        )
            .prop_map(
                |(
                    decision,
                    score,
                    findings,
                    normalized_input,
                    canary_state,
                    canaries_leaked,
                    commitments_violated,
                    latency_us,
                )| Verdict {
                    decision,
                    score,
                    findings,
                    normalized_input,
                    canary_state,
                    canaries_leaked,
                    commitments_violated,
                    latency_us,
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        #[test]
        fn prop_verdict_json_roundtrip(v in arb_verdict()) {
            let s = serde_json::to_string(&v).expect("serialize");
            let back: Verdict = serde_json::from_str(&s).expect("deserialize");
            prop_assert_eq!(v, back);
        }

        #[test]
        fn prop_finding_json_roundtrip(f in arb_finding()) {
            let s = serde_json::to_string(&f).expect("serialize");
            let back: Finding = serde_json::from_str(&s).expect("deserialize");
            prop_assert_eq!(f, back);
        }

        #[test]
        fn prop_canary_state_json_roundtrip(cs in arb_canary_state()) {
            let s = serde_json::to_string(&cs).expect("serialize");
            let back: CanaryState = serde_json::from_str(&s).expect("deserialize");
            prop_assert_eq!(cs, back);
        }
    }
}
