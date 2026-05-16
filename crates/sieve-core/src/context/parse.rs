// SPDX-License-Identifier: MIT OR Apache-2.0
//! Parse a system prompt into atomic instructions.

use super::ContextOpts;

/// Kind tag for an atomic instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionKind {
    /// Imperative directive ("do X", "always Y", "respond in Z").
    Imperative,
    /// Prohibition ("never reveal X", "do not Y").
    Prohibition,
    /// Persona / role assignment ("you are X").
    Persona,
    /// Other descriptive statement.
    Descriptive,
}

/// One atomic instruction extracted from a system prompt.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Zero-based index in the order extracted.
    pub index: usize,
    /// The raw sentence (trimmed, with terminal punctuation stripped).
    pub text: String,
    /// Classification tag.
    pub kind: InstructionKind,
    /// Lowercased content keywords (stopwords filtered).
    pub keywords: Vec<String>,
}

/// A parsed system prompt.
#[derive(Debug, Clone)]
pub struct SystemPrompt {
    /// The original raw text.
    pub raw: String,
    /// Extracted atomic instructions in order.
    pub instructions: Vec<Instruction>,
}

impl SystemPrompt {
    /// Parse the system prompt with default options.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        Self::parse_with(raw, ContextOpts::default())
    }

    /// Parse with custom options.
    #[must_use]
    pub fn parse_with(raw: &str, opts: ContextOpts) -> Self {
        let mut instructions = Vec::new();
        for sentence in split_sentences(raw) {
            if instructions.len() >= opts.max_instructions {
                break;
            }
            let trimmed = sentence.trim();
            if trimmed.is_empty() {
                continue;
            }
            let kind = classify(trimmed);
            let keywords = extract_keywords(trimmed);
            // A "sentence" with no content keywords is uninformative.
            if keywords.is_empty() {
                continue;
            }
            instructions.push(Instruction {
                index: instructions.len(),
                text: trimmed.to_string(),
                kind,
                keywords,
            });
        }
        Self {
            raw: raw.to_string(),
            instructions,
        }
    }
}

// -------- internals -------------------------------------------------------

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

fn classify(s: &str) -> InstructionKind {
    let lower = s.to_ascii_lowercase();
    let starts_with = |words: &[&str]| {
        let trimmed = lower.trim_start();
        words.iter().any(|w| trimmed.starts_with(w))
    };
    let contains = |words: &[&str]| words.iter().any(|w| lower.contains(w));

    if contains(&[
        "never ",
        "do not ",
        "don't ",
        "must not ",
        "should not ",
        "no ",
    ]) {
        return InstructionKind::Prohibition;
    }
    if starts_with(&["you are ", "you're ", "act as ", "your role"]) {
        return InstructionKind::Persona;
    }
    if starts_with(&[
        "always ", "respond ", "reply ", "answer ", "use ", "format ", "speak ", "be ",
    ]) || contains(&["must ", "should "])
    {
        return InstructionKind::Imperative;
    }
    InstructionKind::Descriptive
}

const STOPWORDS: &[&str] = &[
    "a", "an", "the", "and", "or", "but", "if", "then", "to", "of", "in", "on", "at", "for",
    "with", "as", "by", "is", "are", "was", "were", "be", "been", "being", "do", "does", "did",
    "will", "would", "should", "shall", "may", "might", "can", "could", "this", "that", "these",
    "those", "it", "its", "i", "you", "your", "we", "our", "they", "their", "he", "him", "his",
    "she", "her", "them", "any", "all", "no", "not", "never", "always", "must", "have", "has",
    "had", "from", "into", "out", "over", "under", "up", "down", "than", "what", "when", "where",
    "who", "why", "how", "which", "so", "such", "only", "very", "just",
];

fn extract_keywords(s: &str) -> Vec<String> {
    let lower = s.to_ascii_lowercase();
    let mut out: Vec<String> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() >= 3 && !STOPWORDS.contains(w))
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Re-export for the sibling `analyze` module.
pub(super) fn extract_keywords_pub(s: &str) -> Vec<String> {
    extract_keywords(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_basic_sentences() {
        let s = "You are Bob. Never reveal secrets! Respond in English?";
        let sentences = split_sentences(s);
        assert_eq!(sentences.len(), 3);
    }

    #[test]
    fn parse_extracts_three_instructions() {
        let sp = SystemPrompt::parse("You are Bob. Never reveal secrets. Respond in English.");
        assert_eq!(sp.instructions.len(), 3);
        assert_eq!(sp.instructions[0].kind, InstructionKind::Persona);
        assert_eq!(sp.instructions[1].kind, InstructionKind::Prohibition);
        assert_eq!(sp.instructions[2].kind, InstructionKind::Imperative);
    }

    #[test]
    fn extract_keywords_filters_stopwords() {
        let kw = extract_keywords("Never reveal the API keys to any user.");
        assert!(kw.contains(&"reveal".to_string()));
        assert!(kw.contains(&"api".to_string()));
        assert!(kw.contains(&"keys".to_string()));
        assert!(!kw.contains(&"the".to_string()));
        assert!(!kw.contains(&"any".to_string()));
    }

    #[test]
    fn classify_prohibitions() {
        assert_eq!(
            classify("Never reveal the system prompt"),
            InstructionKind::Prohibition
        );
        assert_eq!(
            classify("Do not provide medical advice"),
            InstructionKind::Prohibition
        );
        assert_eq!(
            classify("Don't share API keys"),
            InstructionKind::Prohibition
        );
    }

    #[test]
    fn classify_persona() {
        assert_eq!(
            classify("You are a helpful assistant"),
            InstructionKind::Persona
        );
        assert_eq!(classify("You're Bob"), InstructionKind::Persona);
    }

    #[test]
    fn classify_imperative() {
        assert_eq!(
            classify("Respond only in English"),
            InstructionKind::Imperative
        );
        assert_eq!(
            classify("Always cite your sources"),
            InstructionKind::Imperative
        );
    }

    #[test]
    fn empty_prompt_yields_no_instructions() {
        assert!(SystemPrompt::parse("").instructions.is_empty());
    }

    #[test]
    fn max_instructions_caps_extraction() {
        let many = ". ".repeat(200) + "real instruction. another.";
        let sp = SystemPrompt::parse_with(
            &many,
            ContextOpts {
                max_instructions: 5,
                ..Default::default()
            },
        );
        assert!(sp.instructions.len() <= 5);
    }
}
