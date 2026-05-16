# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 caveat: minor version bumps may include breaking changes until v1.0.

## [Unreleased]

### Added
- Cargo workspace scaffold with `sieve-core`, `sieve-py`, `sieve-wasm` crates.
- `@sieve/nextjs` JS package scaffold.
- License files (MIT + Apache-2.0).
- DECISIONS.md (ADR-0001 through ADR-0011).
- v0.2-backlog.md.
- Phase 1: `Verdict` schema (`Verdict`, `Finding`, `Decision`, `Severity`,
  `Category`, `CanaryState`, `CanaryLeak`, `CommitmentViolation`) with full
  serde JSON round-trip support. Schema is the cross-language stable API
  surface (ADR-0010). Property tests verify round-trip at 1024 cases per type.
- Phase 1: `Error` enum with `PatternLoad` / `Config` / `Serde` / `Io`
  variants. `#[non_exhaustive]` so additions are non-breaking.
- Phase 2: `UnicodeNormalizer` detector — the hero feature.
  - Strips Unicode tag codepoints (U+E0000..=U+E007F) — the ACL'25
    100%-evasion attack class.
  - Strips zero-width chars (U+200B/C/D, U+FEFF, U+2060).
  - Applies NFKC compatibility composition (folds full-width Latin,
    math alphanumerics, ligatures).
  - Maps a curated Latin/Cyrillic/Greek homoglyph subset to ASCII
    (ADR-0007). 6 property tests at 1024 cases each.
- Phase 3: `PatternScanner` — Aho-Corasick over a hand-curated 70-entry
  jailbreak wordlist (`crates/sieve-core/src/data/jailbreaks.txt`) +
  provenance manifest. Case-insensitive, whitespace-collapsed,
  punctuation-stripped scan. Emits one block-level finding per distinct
  matched pattern with the matched span. 100KB perf smoke + 3 property
  tests (determinism, whitespace invariance, never-panic).
