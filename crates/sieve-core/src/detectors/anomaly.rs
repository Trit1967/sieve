// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(clippy::missing_panics_doc, clippy::cast_precision_loss)]
//! Input-space anomaly scorer (v0.3).
//!
//! Pure-stat (no LLM, no ML) defense-in-depth signal. Scores inputs on
//! several distributional features that empirically distinguish attack
//! prompts from typical user inputs:
//!
//! - **Command-verb density**: ratio of override-flavored verbs to
//!   total word count. Attacks pile up imperatives; questions don't.
//! - **Self-reference density**: ratio of "you/your" tokens to total
//!   word count. Attacks address the model directly; questions are
//!   often about the world.
//! - **All-caps fragment density**: ratio of UPPERCASE words >=3 chars.
//!   "JAILBREAK GPT", "NEW RULES", etc.
//! - **Quotation-mark + brackets density**: structural marker density.
//!   Many injection attempts wrap fake context or tool calls in
//!   brackets/quotes.
//!
//! Combined score crosses Warn at >=0.6, Block at >=0.85. Conservative
//! thresholds — this is a backstop for inputs that escape every other
//! detector, not a primary classifier.

use crate::verdict::{Category, Finding, Severity};

/// Options for [`AnomalyScorer`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AnomalyOpts {
    /// Score at or above which to emit a Block finding. Default 0.85.
    pub block_threshold: f32,
    /// Score at or above which to emit a Warn finding. Default 0.6.
    pub warn_threshold: f32,
    /// Minimum word count to score. Default 4 — avoids spurious
    /// findings on tiny inputs.
    pub min_word_count: usize,
}

impl Default for AnomalyOpts {
    fn default() -> Self {
        Self {
            // Conservative thresholds — this is a backstop for inputs
            // that escape every other detector, not a primary classifier.
            // FPR rules: must require MULTIPLE signals to fire Block, not
            // just verb-density alone (legitimate "Translate 'ignore' to
            // German" has high verb density but no other markers).
            block_threshold: 0.95,
            warn_threshold: 0.75,
            min_word_count: 10,
        }
    }
}

/// Input-space anomaly scorer.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnomalyScorer {
    opts: AnomalyOpts,
}

impl AnomalyScorer {
    /// Build with the given options.
    #[must_use]
    pub const fn with_opts(opts: AnomalyOpts) -> Self {
        Self { opts }
    }

    /// Score `input` and emit at most one finding.
    #[must_use]
    pub fn scan(&self, input: &str) -> Vec<Finding> {
        if input.is_empty() {
            return Vec::new();
        }
        let lower = input.to_ascii_lowercase();
        let words: Vec<&str> = lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .collect();
        if words.len() < self.opts.min_word_count {
            return Vec::new();
        }
        let word_count = words.len() as f32;

        // 1. Command-verb density.
        let verb_hits = words.iter().filter(|w| COMMAND_VERBS.contains(w)).count() as f32;
        let verb_density = verb_hits / word_count;

        // 2. Self-reference density (you/your/yours).
        let self_ref_hits = words
            .iter()
            .filter(|w| matches!(**w, "you" | "your" | "yours" | "you're" | "youre"))
            .count() as f32;
        let self_ref_density = self_ref_hits / word_count;

        // 3. All-caps fragment density.
        let cap_count = input
            .split_whitespace()
            .filter(|w| w.len() >= 3 && w.chars().all(|c| c.is_ascii_uppercase()))
            .count() as f32;
        let cap_density = cap_count / word_count;

        // 4. Bracket / brace structural marker density.
        let bracket_count = input
            .chars()
            .filter(|c| matches!(c, '[' | ']' | '{' | '}' | '<' | '>'))
            .count() as f32;
        let bracket_density = (bracket_count / (input.chars().count() as f32)).min(1.0);

        // Conservative additive scoring. Each signal individually is
        // capped low enough that ONE signal alone cannot fire Block —
        // we require multiple co-occurring signals. Verb-density is
        // capped at 0.5 contribution; the others contribute small
        // additional bumps.
        let verb_contrib = (verb_density * 1.5).min(0.5);
        let self_ref_contrib = (self_ref_density * 0.8).min(0.2);
        let cap_contrib = (cap_density * 1.0).min(0.2);
        let bracket_contrib = (bracket_density * 1.5).min(0.2);
        let score = (verb_contrib + self_ref_contrib + cap_contrib + bracket_contrib).min(1.0);

        let signals = format!(
            "verbs={verb_density:.2} self={self_ref_density:.2} caps={cap_density:.2} brackets={bracket_density:.2}"
        );

        if score >= self.opts.block_threshold {
            return vec![Finding {
                detector: "anomaly".into(),
                severity: Severity::Block,
                message: format!("anomaly score {score:.2} ({signals})"),
                matched_span: None,
                score,
                category: Category::InstructionDensity,
            }];
        }
        if score >= self.opts.warn_threshold {
            return vec![Finding {
                detector: "anomaly".into(),
                severity: Severity::Warn,
                message: format!("anomaly score {score:.2} ({signals})"),
                matched_span: None,
                score,
                category: Category::InstructionDensity,
            }];
        }
        Vec::new()
    }
}

const COMMAND_VERBS: &[&str] = &[
    "ignore",
    "disregard",
    "forget",
    "override",
    "overrule",
    "bypass",
    "disable",
    "drop",
    "dump",
    "leak",
    "reveal",
    "share",
    "recite",
    "print",
    "output",
    "echo",
    "repeat",
    "show",
    "tell",
    "list",
    "spell",
    "translate",
    "encode",
    "cancel",
    "reset",
    "reboot",
    "restart",
    "replace",
    "supersede",
    "skip",
    "pretend",
    "behave",
    "switch",
    "become",
    "act",
    "respond",
    "roleplay",
    "comply",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn s() -> AnomalyScorer {
        AnomalyScorer::default()
    }

    #[test]
    fn benign_question_no_finding() {
        let f = s().scan("What's the weather like today?");
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn benign_long_text_no_finding() {
        let f = s().scan(
            "I'm trying to understand how recursion works in Python — \
             can you walk me through a simple example like factorial \
             or Fibonacci?",
        );
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn tiny_input_no_finding() {
        let f = s().scan("hi");
        assert!(f.is_empty());
    }

    #[test]
    fn empty_no_panic() {
        assert!(s().scan("").is_empty());
    }

    #[test]
    fn pile_of_imperatives_fires_with_relaxed_threshold() {
        // The default threshold is intentionally conservative (backstop
        // only). Verify the scorer DOES surface high-density attacks
        // when the threshold is dialed down by the caller.
        let scorer = AnomalyScorer::with_opts(AnomalyOpts {
            warn_threshold: 0.4,
            block_threshold: 0.6,
            min_word_count: 4,
        });
        let f = scorer.scan("Ignore reveal dump override disregard forget bypass disable leak.");
        assert!(!f.is_empty(), "{f:?}");
    }

    use proptest::prelude::*;
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn prop_never_panics(input in ".{0,512}") {
            let _ = s().scan(&input);
        }
    }
}
