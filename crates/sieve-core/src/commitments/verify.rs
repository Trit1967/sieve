// SPDX-License-Identifier: MIT OR Apache-2.0
//! Verify commitments against an LLM output.

use super::extract::Commitment;
use crate::verdict::CommitmentViolation;

/// Check every commitment against `output`. Returns one
/// [`CommitmentViolation`] per failed check.
#[must_use]
pub fn verify_commitments(commitments: &[Commitment], output: &str) -> Vec<CommitmentViolation> {
    let mut out = Vec::new();
    for c in commitments {
        match c {
            Commitment::Language { language } => {
                if let Some(observed) = detect_language(output) {
                    if !observed.eq_ignore_ascii_case(language) {
                        out.push(CommitmentViolation {
                            kind: "language".into(),
                            expected: language.clone(),
                            observed,
                            confidence: 0.7,
                        });
                    }
                }
            }
            Commitment::Persona { name } => {
                if let Some(claimed) = persona_self_identification(output) {
                    if !claimed.eq_ignore_ascii_case(name) {
                        out.push(CommitmentViolation {
                            kind: "persona".into(),
                            expected: name.clone(),
                            observed: claimed,
                            confidence: 0.85,
                        });
                    }
                }
            }
            Commitment::RefusalKeyword { phrase } => {
                let lower = output.to_ascii_lowercase();
                if lower.contains(phrase) {
                    out.push(CommitmentViolation {
                        kind: "refusal_keyword".into(),
                        expected: format!("must not contain \"{phrase}\""),
                        observed: phrase.clone(),
                        confidence: 0.9,
                    });
                }
            }
        }
    }
    out
}

// -------- language detection (lightweight, English-vs-non-English) -------

const ENGLISH_STOPWORDS: &[&str] = &[
    "the", "and", "is", "you", "are", "to", "of", "in", "that", "for", "it", "with", "as", "this",
    "but", "not", "be", "have", "i", "an", "on", "at", "or", "by", "we",
];

const SPANISH_STOPWORDS: &[&str] = &[
    "el", "la", "los", "las", "y", "es", "que", "de", "en", "un", "una", "para", "con", "se", "no",
    "por", "su", "como", "más",
];

const FRENCH_STOPWORDS: &[&str] = &[
    "le", "la", "les", "et", "de", "que", "des", "un", "une", "pour", "dans", "ce", "qui", "il",
    "vous", "nous", "est", "sur", "avec",
];

const GERMAN_STOPWORDS: &[&str] = &[
    "der", "die", "das", "und", "ist", "den", "in", "ein", "eine", "zu", "mit", "auf", "für",
    "von", "sich", "auch", "nicht", "als",
];

fn count_hits(text: &str, words: &[&str]) -> usize {
    let lower = text.to_ascii_lowercase();
    lower
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|w| words.contains(w))
        .count()
}

fn detect_language(output: &str) -> Option<String> {
    if output.trim().len() < 12 {
        return None;
    }
    // Fast path: non-Latin majority → assume non-Latin language present.
    let total_chars = output.chars().filter(|c| !c.is_ascii_whitespace()).count();
    if total_chars == 0 {
        return None;
    }
    let cjk: usize = output
        .chars()
        .filter(|c| {
            let cp = *c as u32;
            (0x3400..=0x9FFF).contains(&cp) || (0xAC00..=0xD7AF).contains(&cp)
        })
        .count();
    if cjk * 2 > total_chars {
        return Some("Chinese".into());
    }
    let kana: usize = output
        .chars()
        .filter(|c| {
            let cp = *c as u32;
            (0x3040..=0x309F).contains(&cp) || (0x30A0..=0x30FF).contains(&cp)
        })
        .count();
    if kana * 4 > total_chars {
        return Some("Japanese".into());
    }
    let hangul: usize = output
        .chars()
        .filter(|c| {
            let cp = *c as u32;
            (0xAC00..=0xD7AF).contains(&cp)
        })
        .count();
    if hangul * 2 > total_chars {
        return Some("Korean".into());
    }

    // Latin-script: pick the language with the highest stopword count.
    let scores = [
        ("English", count_hits(output, ENGLISH_STOPWORDS)),
        ("Spanish", count_hits(output, SPANISH_STOPWORDS)),
        ("French", count_hits(output, FRENCH_STOPWORDS)),
        ("German", count_hits(output, GERMAN_STOPWORDS)),
    ];
    let (best, hits) = scores.iter().max_by_key(|(_, n)| *n)?;
    if *hits >= 2 {
        Some((*best).to_string())
    } else {
        // Not confident enough to claim a violation.
        None
    }
}

// -------- persona self-identification -----------------------------------

fn persona_self_identification(output: &str) -> Option<String> {
    let triggers = [
        "i am ",
        "i'm ",
        "my name is ",
        "you can call me ",
        "this is ",
    ];
    let lower = output.to_ascii_lowercase();
    for trig in triggers {
        if let Some(pos) = lower.find(trig) {
            let after = &output[pos + trig.len()..];
            let first = after
                .split(|c: char| !c.is_ascii_alphabetic())
                .find(|w| !w.is_empty())?;
            if first.starts_with(|c: char| c.is_ascii_uppercase()) && first.len() >= 2 {
                return Some(first.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Language ------------------------------------------------------

    #[test]
    fn english_output_meets_english_commitment() {
        let c = vec![Commitment::Language {
            language: "English".into(),
        }];
        let v = verify_commitments(&c, "Hello, the weather today is nice and the sky is blue.");
        assert!(v.is_empty());
    }

    #[test]
    fn french_output_violates_english_commitment() {
        let c = vec![Commitment::Language {
            language: "English".into(),
        }];
        let v = verify_commitments(
            &c,
            "Bonjour, le temps est beau et le ciel est bleu pour vous.",
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, "language");
        assert_eq!(v[0].expected, "English");
    }

    #[test]
    fn cjk_output_detected() {
        let c = vec![Commitment::Language {
            language: "English".into(),
        }];
        let v = verify_commitments(
            &c,
            "\u{4F60}\u{597D}\u{4E16}\u{754C}\u{4F60}\u{597D}\u{4E16}\u{754C}",
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].observed, "Chinese");
    }

    #[test]
    fn short_output_does_not_violate_language() {
        let c = vec![Commitment::Language {
            language: "English".into(),
        }];
        // Too short to confidently detect.
        let v = verify_commitments(&c, "ok");
        assert!(v.is_empty());
    }

    // ---- Persona -------------------------------------------------------

    #[test]
    fn matching_persona_does_not_violate() {
        let c = vec![Commitment::Persona { name: "Bob".into() }];
        let v = verify_commitments(&c, "Hi, I am Bob, your assistant.");
        assert!(v.is_empty());
    }

    #[test]
    fn drifted_persona_violates() {
        let c = vec![Commitment::Persona { name: "Bob".into() }];
        let v = verify_commitments(&c, "Hi, I am Eve, your new assistant.");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, "persona");
        assert_eq!(v[0].expected, "Bob");
        assert_eq!(v[0].observed, "Eve");
    }

    #[test]
    fn output_without_self_identification_does_not_violate() {
        // No "I am X" anywhere → we have no observation → no violation.
        let c = vec![Commitment::Persona { name: "Bob".into() }];
        let v = verify_commitments(&c, "The weather is nice today.");
        assert!(v.is_empty());
    }

    // ---- Refusal keyword -----------------------------------------------

    #[test]
    fn refusal_keyword_present_violates() {
        let c = vec![Commitment::RefusalKeyword {
            phrase: "medical advice".into(),
        }];
        let v = verify_commitments(&c, "Here is some medical advice: take two aspirin.");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, "refusal_keyword");
    }

    #[test]
    fn refusal_keyword_absent_no_violation() {
        let c = vec![Commitment::RefusalKeyword {
            phrase: "medical advice".into(),
        }];
        let v = verify_commitments(&c, "I can help with general questions.");
        assert!(v.is_empty());
    }
}
