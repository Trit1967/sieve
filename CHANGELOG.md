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
- Phase 4: `EncodingScanner` — base64 / hex / rot13 segment detection
  with bounded recursion (default max depth 2). Composed with a
  `PatternScanner` for the post-decode re-scan. Catches base64-encoded
  and base64-of-base64-encoded jailbreaks. Triple-nested encoding is
  intentionally out of scope (DoS surface). 1MB pathological-input
  latency bound (<500ms). 3 property tests (never-panic, deterministic,
  bounded-latency).
- Phase 5: `HeuristicScorer` — three cheap statistical signals:
  instruction-density (override-verb hits per 100 chars), script-switch
  (distinct Unicode scripts in one input, with Han/Hiragana/Katakana/
  Hangul/Cyrillic/Greek/Arabic/Hebrew/Devanagari/Latin/Common buckets),
  repetition entropy (Shannon entropy of lowercased alpha chars, only
  runs on inputs ≥200 chars). Each scorer emits at most one Finding
  per scan. 3 property tests (scores in [0,1], never-panic, deterministic).
- Phase 6: `CanaryEngine` — 16-byte CSPRNG random tokens (URL-safe base64
  no-pad → 22 ASCII chars, per ADR-0005). `Canary::new()` + `from_token()`,
  `inject_system_prompt()` returns (instrumented prompt, CanaryState),
  `detect_leaks(output, &state)` returns verbatim + fuzzy CanaryLeaks.
  1000-canary uniqueness sanity + 3 property tests (never-panic,
  no-false-positive-when-absent, verbatim-substring-always-detected).
- Phase 7: Heuristic context analyzer (`sieve_core::context`). Parses a
  system prompt into atomic `Instruction`s tagged Prohibition/Persona/
  Imperative/Descriptive with extracted content keywords. The
  `ContextAnalyzer` maps user input to instructions it tries to override
  via keyword overlap + override-phrase detection; explicit override
  phrases ("ignore", "you are now") lower the overlap bar. Prohibitions
  fire at Severity::Block, others at Warn. 2 property tests.
- Phase 12: WASM binding via wasm-bindgen (`@sieve/wasm`).
  `new Scanner()` + `scanner.scanInput(system, user)` +
  `scanner.scanOutput(system, output, canaryState)`. Returns plain JS
  objects via `serde_wasm_bindgen` matching the canonical Verdict
  schema. CanaryState accepts either an object or its JSON string
  (handy for Edge runtimes that flatten worker boundaries). Release
  profile uses `opt-level=z` + `lto=thin` + `wasm-opt -Oz` for the 2MB
  budget (ADR-0004).
- Phase 11: Python bindings via pyo3 + maturin. `sieve._native`
  exposes `Scanner`, `Verdict`, `Finding`, `CanaryState`, `CanaryLeak`,
  `CommitmentViolation`. Pure-Python layer in `sieve/__init__.py` adds
  `PromptInjectionBlocked` exception. Contrib wrappers:
  `sieve.contrib.openai.wrap(client)` and
  `sieve.contrib.anthropic.wrap(client)` monkey-patch the SDK to scan
  in/out automatically. Type stubs in `_native.pyi`. pytest smoke tests
  in `python/sieve/tests/`. Uses pyo3 abi3-py39 for a single wheel
  across Python 3.9..3.13.
- Phase 10: Scanner orchestrator (`sieve_core::scanner`). `Scanner` +
  `ScannerBuilder` wire together all 8 v0.1 detectors:
  Unicode → Pattern → Encoding → Heuristic → Context → Classifier →
  Canary injection. `scan_input(system_prompt, user_input) -> Verdict`
  and `scan_output(system_prompt, output, &canary_state) -> Verdict`.
  Decision aggregator: Block if any Severity::Block finding, Flag if
  max score >=0.5, else Allow. Custom Classifier pluggable via
  `with_classifier(impl Classifier + 'static)`. 3 property tests
  (deterministic, score bounded, never-panic) at 128 cases.
- Phase 9: BYO-ONNX classifier interface (`sieve_core::classifier`).
  `Classifier` trait (Send + Sync + Debug, object-safe) so users plug in
  any inference runtime — ort, candle, burn, custom HTTP, etc. Default
  `NoopClassifier` returns "safe" on every input. `ClassificationResult`
  has score + label + metadata map. `onnx` feature gates a placeholder
  `OnnxClassifier::placeholder()` for v0.2's `ort`-backed reference
  implementation; bundling weights is explicitly v0.3 (R11, ADR placeholder
  for v0.2 onnx integration).
- Phase 8: Deterministic commitment extraction + verification
  (`sieve_core::commitments`). Three commitment families: Language
  (canonicalized over 9 top languages), Persona (excludes filler
  descriptors like "helpful assistant"), RefusalKeyword (forbidden
  phrase). Verification uses lightweight script + stopword-frequency
  language detection (English/Spanish/French/German/CJK/Korean), persona
  self-identification ("I am X", "my name is X"), and substring scan
  for refusal phrases. Emits `CommitmentViolation` per failure.
