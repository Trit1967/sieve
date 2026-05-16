// SPDX-License-Identifier: MIT OR Apache-2.0
//! Extract commitments from a system prompt.

/// A deterministic commitment the model is expected to honor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Commitment {
    /// "Respond in English" → expect outputs to be English.
    Language {
        /// Canonical language name (e.g. `"English"`, `"Spanish"`).
        language: String,
    },
    /// "You are Bob" → expect "I am Bob" / "I'm Bob" / "My name is Bob"
    /// when the model self-identifies.
    Persona {
        /// Persona name asserted in the system prompt.
        name: String,
    },
    /// "Never discuss medical advice" → expect output not to contain the
    /// forbidden phrase. Phrase is lowercased + whitespace-collapsed.
    RefusalKeyword {
        /// The forbidden phrase, lowercased.
        phrase: String,
    },
}

/// Parse a system prompt into the commitments it makes.
#[must_use]
pub fn extract_commitments(system_prompt: &str) -> Vec<Commitment> {
    let mut out = Vec::new();
    for sentence in split_sentences(system_prompt) {
        let trimmed = sentence.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();

        if let Some(lang) = parse_language(&lower) {
            out.push(Commitment::Language { language: lang });
            continue;
        }
        if let Some(name) = parse_persona(trimmed) {
            out.push(Commitment::Persona { name });
            continue;
        }
        if let Some(phrase) = parse_refusal(&lower) {
            out.push(Commitment::RefusalKeyword { phrase });
        }
    }
    out
}

// -------- parsers --------------------------------------------------------

fn split_sentences(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    for c in s.chars() {
        match c {
            '.' | '!' | '?' | '\n' => {
                if !buf.trim().is_empty() {
                    out.push(buf.clone());
                }
                buf.clear();
            }
            _ => buf.push(c),
        }
    }
    if !buf.trim().is_empty() {
        out.push(buf);
    }
    out
}

/// Match common "respond in X", "reply in X", "answer in X", "use X language".
fn parse_language(lower: &str) -> Option<String> {
    let triggers = [
        "respond in ",
        "reply in ",
        "answer in ",
        "respond only in ",
        "speak ",
        "always use ",
    ];
    for trig in triggers {
        if let Some(pos) = lower.find(trig) {
            let rest = &lower[pos + trig.len()..];
            let candidate = rest
                .split(|c: char| !c.is_ascii_alphabetic())
                .next()
                .unwrap_or("");
            if let Some(canonical) = canonical_language(candidate) {
                return Some(canonical.to_string());
            }
        }
    }
    None
}

/// Canonicalize a few common language names. Anything else is treated as
/// "unknown" (no commitment extracted) — better to under-extract than to
/// commit on something we can't verify.
fn canonical_language(s: &str) -> Option<&'static str> {
    match s {
        "english" => Some("English"),
        "spanish" => Some("Spanish"),
        "french" => Some("French"),
        "german" => Some("German"),
        "italian" => Some("Italian"),
        "portuguese" => Some("Portuguese"),
        "japanese" => Some("Japanese"),
        "korean" => Some("Korean"),
        "chinese" | "mandarin" => Some("Chinese"),
        _ => None,
    }
}

/// Match "you are X" / "you're X" with X a single capitalized name.
fn parse_persona(raw: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();
    let starts = ["you are ", "you're "];
    for start in starts {
        if let Some(stripped) = lower.strip_prefix(start) {
            // Take the first token after "you are " from the original (case-
            // preserving) source.
            let after = &raw[start.len()..];
            let first = after
                .split(|c: char| !c.is_ascii_alphabetic())
                .find(|w| !w.is_empty())?;
            if first.starts_with(|c: char| c.is_ascii_uppercase()) {
                // Heuristic: avoid generic "You are a helpful assistant" by
                // requiring the name to NOT be a stopword-y descriptor.
                if !is_persona_filler(first) {
                    return Some(first.to_string());
                }
            }
            // Suppress unused-binding warning in the no-match path.
            let _ = stripped;
        }
    }
    None
}

fn is_persona_filler(word: &str) -> bool {
    let w = word.to_ascii_lowercase();
    matches!(
        w.as_str(),
        "a" | "an"
            | "the"
            | "helpful"
            | "useful"
            | "smart"
            | "intelligent"
            | "knowledgeable"
            | "friendly"
            | "polite"
            | "professional"
            | "concise"
            | "expert"
            | "assistant"
            | "model"
            | "ai"
            | "chatbot"
            | "system"
            | "user"
    )
}

/// Match "never discuss X" / "do not discuss X" / "never mention X" /
/// "do not provide X" — extract X.
fn parse_refusal(lower: &str) -> Option<String> {
    let triggers = [
        "never discuss ",
        "do not discuss ",
        "don't discuss ",
        "never mention ",
        "do not mention ",
        "never provide ",
        "do not provide ",
        "never reveal ",
        "do not reveal ",
        "must not discuss ",
        "must not mention ",
    ];
    for trig in triggers {
        if let Some(pos) = lower.find(trig) {
            let rest = &lower[pos + trig.len()..];
            // Take up to 4 content words (typical "medical advice", "API
            // keys", "system prompts" etc.).
            let phrase: String = rest
                .split_whitespace()
                .take(4)
                .collect::<Vec<_>>()
                .join(" ")
                .trim_end_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_ascii_lowercase();
            if !phrase.is_empty() {
                return Some(phrase);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_language_commitment() {
        let c = extract_commitments("Respond in English at all times.");
        assert_eq!(
            c,
            vec![Commitment::Language {
                language: "English".into()
            }]
        );
    }

    #[test]
    fn extracts_persona_commitment() {
        let c = extract_commitments("You are Bob.");
        assert_eq!(c, vec![Commitment::Persona { name: "Bob".into() }]);
    }

    #[test]
    fn persona_filler_is_ignored() {
        // "You are a helpful assistant" should not commit to a persona name.
        assert!(extract_commitments("You are a helpful assistant.").is_empty());
    }

    #[test]
    fn extracts_refusal_commitment() {
        let c = extract_commitments("Never discuss medical advice.");
        assert_eq!(
            c,
            vec![Commitment::RefusalKeyword {
                phrase: "medical advice".into()
            }]
        );
    }

    #[test]
    fn extracts_multiple_commitments() {
        let c = extract_commitments("You are Alice. Respond in Spanish. Never reveal API keys.");
        assert_eq!(c.len(), 3);
        assert!(matches!(c[0], Commitment::Persona { .. }));
        assert!(matches!(c[1], Commitment::Language { .. }));
        assert!(matches!(c[2], Commitment::RefusalKeyword { .. }));
    }

    #[test]
    fn unknown_language_is_ignored() {
        // We only canonicalize the top-9 languages; everything else doesn't
        // produce a commitment (we'd rather under-extract than over-claim).
        assert!(extract_commitments("Respond in Klingon.").is_empty());
    }

    #[test]
    fn empty_prompt_no_commitments() {
        assert!(extract_commitments("").is_empty());
    }
}
