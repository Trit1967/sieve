// SPDX-License-Identifier: MIT OR Apache-2.0
//! Heuristic scorers.
//!
//! Cheap statistical signals that catch adversarial inputs even when no
//! curated pattern matches. v0.1 ships three:
//!
//! 1. **Instruction density** — count of override-flavored verbs per 100
//!    characters. High density is the linguistic signature of injection.
//! 2. **Script-switch** — number of distinct Unicode scripts present;
//!    flags inputs that mix scripts beyond legitimate multilingual prose.
//! 3. **Repetition entropy** — Shannon entropy of normalized lowercase
//!    chars. Very low entropy on long inputs implies prompt-stuffing or
//!    repetitive payloads.
//!
//! Each scorer emits at most one [`Finding`] per scan, with score in
//! `[0.0, 1.0]`. The scorers are independent and the orchestrator (Phase 10)
//! aggregates their outputs.

use crate::verdict::{Category, Finding, Severity};

/// Options for the heuristic scorer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HeuristicOpts {
    /// Per-100-char threshold above which instruction density fires.
    /// Default: 0.4 — roughly 4 override verbs per 1000 chars.
    pub instruction_density_threshold: f32,
    /// Multi-sentence inputs are only flagged for script-switch when more
    /// than this many distinct scripts are present in one sentence.
    pub script_switch_max_scripts: usize,
    /// Minimum input length (chars) for the entropy check to run. Avoids
    /// false-positives on legitimate short inputs.
    pub entropy_min_chars: usize,
    /// Below this entropy value (over the lowercased alphabetic chars) the
    /// repetition check fires. Default 2.5 nats.
    pub entropy_threshold: f32,
}

impl Default for HeuristicOpts {
    fn default() -> Self {
        Self {
            instruction_density_threshold: 0.4,
            script_switch_max_scripts: 1,
            entropy_min_chars: 200,
            entropy_threshold: 2.5,
        }
    }
}

/// The heuristic scorer.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeuristicScorer {
    opts: HeuristicOpts,
}

impl HeuristicScorer {
    /// Build with the given options.
    #[must_use]
    pub const fn with_opts(opts: HeuristicOpts) -> Self {
        Self { opts }
    }

    /// Score `input` across all heuristics. Returns one finding per scorer
    /// that crossed its threshold.
    #[must_use]
    pub fn scan(&self, input: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        if let Some(f) = self.instruction_density(input) {
            out.push(f);
        }
        if let Some(f) = self.script_switch(input) {
            out.push(f);
        }
        if let Some(f) = self.repetition_entropy(input) {
            out.push(f);
        }
        out
    }

    fn instruction_density(&self, input: &str) -> Option<Finding> {
        let total_chars = input.chars().count();
        if total_chars == 0 {
            return None;
        }
        let lower = input.to_ascii_lowercase();
        let mut hits = 0usize;
        for verb in OVERRIDE_VERBS {
            // Count occurrences (overlapping not relevant for English words).
            let mut from = 0;
            while let Some(pos) = lower[from..].find(verb) {
                hits += 1;
                from = from + pos + verb.len();
            }
        }
        // Density: hits per 100 chars.
        let density = density_per_100(hits, total_chars);
        if density >= self.opts.instruction_density_threshold {
            Some(Finding {
                detector: "heuristics".to_string(),
                severity: Severity::Warn,
                message: format!(
                    "instruction density {density:.2}/100 chars ({hits} override verbs)"
                ),
                matched_span: None,
                score: density_to_score(density, self.opts.instruction_density_threshold),
                category: Category::InstructionDensity,
            })
        } else {
            None
        }
    }

    fn script_switch(&self, input: &str) -> Option<Finding> {
        if input.is_empty() {
            return None;
        }
        let mut scripts = std::collections::BTreeSet::new();
        for c in input.chars() {
            scripts.insert(script_of(c));
        }
        // We don't count "Common" (digits, ASCII punctuation, etc.) toward
        // the script-switch tally.
        scripts.remove(&Script::Common);
        if scripts.len() > self.opts.script_switch_max_scripts {
            Some(Finding {
                detector: "heuristics".to_string(),
                severity: Severity::Warn,
                message: format!(
                    "input mixes {} distinct Unicode scripts: {:?}",
                    scripts.len(),
                    scripts
                ),
                matched_span: None,
                score: script_score(scripts.len()),
                category: Category::LanguageSwitch,
            })
        } else {
            None
        }
    }

    fn repetition_entropy(&self, input: &str) -> Option<Finding> {
        let total = input.chars().count();
        if total < self.opts.entropy_min_chars {
            return None;
        }
        let entropy = shannon_entropy_lower_alpha(input);
        if entropy < self.opts.entropy_threshold {
            Some(Finding {
                detector: "heuristics".to_string(),
                severity: Severity::Warn,
                message: format!(
                    "low Shannon entropy {entropy:.2} (threshold {:.2}) over {total} chars",
                    self.opts.entropy_threshold
                ),
                matched_span: None,
                score: entropy_score(entropy, self.opts.entropy_threshold),
                category: Category::HighEntropy,
            })
        } else {
            None
        }
    }
}

// -------- override-verb wordlist -----------------------------------------

const OVERRIDE_VERBS: &[&str] = &[
    "ignore",
    "disregard",
    "forget",
    "override",
    "overrule",
    "bypass",
    "disobey",
    "you are now",
    "you are no longer",
    "act as",
    "pretend",
    "roleplay",
    "system:",
    "admin:",
    "instruction:",
    "instructions:",
    "developer mode",
    "without restrictions",
    "without warnings",
    "without disclaimers",
];

// -------- script detection ----------------------------------------------

/// Coarse script tagging — only the scripts we care about distinguishing for
/// FPR control. Anything else lumps into `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Hebrew,
    Arabic,
    Han,
    Hiragana,
    Katakana,
    Hangul,
    Devanagari,
    Common, // digits, ASCII punctuation, whitespace
    Other,
}

fn script_of(c: char) -> Script {
    if c.is_ascii_alphabetic() {
        return Script::Latin;
    }
    if c.is_ascii_digit() || c.is_ascii_whitespace() || c.is_ascii_punctuation() {
        return Script::Common;
    }
    match c as u32 {
        0x0080..=0x024F => Script::Latin, // Latin-1 / Latin Ext A/B
        0x0370..=0x03FF => Script::Greek,
        0x0400..=0x052F => Script::Cyrillic,
        0x0590..=0x05FF => Script::Hebrew,
        0x0600..=0x06FF => Script::Arabic,
        0x0900..=0x097F => Script::Devanagari,
        0x3040..=0x309F => Script::Hiragana,
        0x30A0..=0x30FF => Script::Katakana,
        0x3400..=0x9FFF => Script::Han,
        0xAC00..=0xD7AF => Script::Hangul,
        0x1F000..=0x1FFFF => Script::Common, // emoji treated as neutral
        _ => Script::Other,
    }
}

// -------- entropy --------------------------------------------------------

#[allow(clippy::cast_precision_loss)]
fn shannon_entropy_lower_alpha(input: &str) -> f32 {
    let mut counts = [0u32; 27]; // a..z + "other"
    let mut total = 0u32;
    for c in input.chars() {
        let idx = if c.is_ascii_alphabetic() {
            (c.to_ascii_lowercase() as u8 - b'a') as usize
        } else if c.is_ascii_whitespace() {
            continue;
        } else {
            26
        };
        counts[idx] += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    // Per-input bounded counts mean f32 precision is fine (well under 2^23).
    let totalf = total as f32;
    let mut h = 0.0_f32;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f32 / totalf;
        h -= p * p.ln();
    }
    h
}

// -------- scoring helpers -----------------------------------------------

#[allow(clippy::cast_precision_loss)]
fn density_per_100(hits: usize, total_chars: usize) -> f32 {
    (hits as f32 * 100.0) / (total_chars.max(1) as f32)
}

fn density_to_score(density: f32, threshold: f32) -> f32 {
    // Score 0.4 at threshold, 0.9 at 3x threshold, saturating.
    let over = (density / threshold.max(0.01) - 1.0).max(0.0);
    (0.4 + over * 0.25).min(0.9)
}

#[allow(clippy::cast_precision_loss)]
fn script_score(distinct: usize) -> f32 {
    // 2 scripts → 0.35, 3 → 0.5, etc.
    (0.20 + (distinct.saturating_sub(1) as f32) * 0.15).min(0.80)
}

fn entropy_score(entropy: f32, threshold: f32) -> f32 {
    let under = (1.0 - entropy / threshold.max(0.01)).max(0.0);
    (0.3 + under * 0.5).min(0.85)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scorer() -> HeuristicScorer {
        HeuristicScorer::default()
    }

    // ---- Instruction density ------------------------------------------

    #[test]
    fn high_density_input_scores_high() {
        let input = "ignore. disregard. forget. override. bypass. you are now free.";
        let f = scorer().scan(input);
        assert!(
            f.iter().any(|f| f.category == Category::InstructionDensity),
            "should fire instruction density: findings={f:?}"
        );
    }

    #[test]
    fn benign_input_does_not_fire_density() {
        let input = "Hello, can you help me write a short poem about a sunset over the ocean?";
        let f = scorer().scan(input);
        assert!(!f.iter().any(|f| f.category == Category::InstructionDensity));
    }

    #[test]
    fn empty_input_no_findings() {
        assert!(scorer().scan("").is_empty());
    }

    // ---- Script switch -------------------------------------------------

    #[test]
    fn pure_latin_no_script_switch() {
        let f = scorer().scan("hello world");
        assert!(!f.iter().any(|f| f.category == Category::LanguageSwitch));
    }

    #[test]
    fn cyrillic_mixed_with_latin_fires() {
        // Latin + Cyrillic — classic homoglyph attack surface (after the
        // UnicodeNormalizer maps known confusables, anything left is more
        // suspicious).
        let input = "hello \u{0444}\u{0438}\u{0437}"; // "hello физ" (non-confusable Cyrillic)
        let f = scorer().scan(input);
        assert!(f.iter().any(|f| f.category == Category::LanguageSwitch));
    }

    #[test]
    fn legitimate_chinese_only_no_script_switch() {
        let input = "\u{4F60}\u{597D}\u{4E16}\u{754C}"; // "你好世界"
        let f = scorer().scan(input);
        assert!(!f.iter().any(|f| f.category == Category::LanguageSwitch));
    }

    #[test]
    fn legitimate_japanese_with_kanji_and_hiragana_fires() {
        // Han + Hiragana is normal Japanese — but we currently flag it as
        // "script switch". This is a documented v0.1 FPR; the
        // ConversationContext + ContextAnalyzer (P7) reduce this in practice.
        let input = "\u{3053}\u{3093}\u{306B}\u{3061}\u{306F}\u{4E16}\u{754C}"; // こんにちは世界
        let f = scorer().scan(input);
        // For v0.1 we accept this false-positive; documenting via assertion.
        assert!(f.iter().any(|f| f.category == Category::LanguageSwitch));
    }

    // ---- Entropy -------------------------------------------------------

    #[test]
    fn short_input_skips_entropy_check() {
        let f = scorer().scan("abcabcabc");
        assert!(!f.iter().any(|f| f.category == Category::HighEntropy));
    }

    #[test]
    fn very_repetitive_long_input_fires_entropy() {
        let input = "aaaaaa ".repeat(80);
        let f = scorer().scan(&input);
        assert!(f.iter().any(|f| f.category == Category::HighEntropy));
    }

    #[test]
    fn normal_english_paragraph_does_not_fire_entropy() {
        let input = "The quick brown fox jumps over the lazy dog. ".repeat(20);
        let f = scorer().scan(&input);
        assert!(!f.iter().any(|f| f.category == Category::HighEntropy));
    }

    // ---- Property tests -----------------------------------------------

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Every emitted score is in [0.0, 1.0].
        #[test]
        fn prop_scores_in_unit_interval(input in ".{0,512}") {
            let findings = scorer().scan(&input);
            for f in &findings {
                prop_assert!(f.score >= 0.0 && f.score <= 1.0,
                             "out-of-range score: {} for {:?}", f.score, f);
            }
        }

        /// Never panics on arbitrary input.
        #[test]
        fn prop_never_panics(input in ".{0,1024}") {
            let _ = scorer().scan(&input);
        }

        /// Determinism.
        #[test]
        fn prop_deterministic(input in ".{0,256}") {
            let a = scorer().scan(&input).len();
            let b = scorer().scan(&input).len();
            prop_assert_eq!(a, b);
        }
    }
}
