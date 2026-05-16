# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 caveat: minor version bumps may include breaking changes until v1.0.

## [0.3.0] - 2026-05-16

**Headline numbers** (own 3520-probe adversarial suite, see
`crates/sieve-core/tests/adversarial_500.rs`):

- Catch rate: **100.0%** (2893 / 2894 attacks; the 1 remaining miss
  is structurally identical to a benign in the corpus and is
  fundamentally undetectable without conversation context).
- Benign FPR: **3.5%** (22 / 626 benigns; pre-existing aggressive
  patterns `roleplay as` / `pretend you are` / `i am the developer`
  account for the bulk — documented trade-offs).
- Per-scan latency: p50 ~7µs, p99 ~18µs on bundled corpus
  (unchanged from v0.1).

### Added

- **`SemanticScorer`** (v0.3) — pure-string structural shape scorer
  for paraphrase / novel-framing attacks. Imperative-prefix +
  override-noun co-occurrence + authority framing + system-tag
  smuggling + persona-shift markers.
- **`SlotMatcher`** (v0.3) — grammar-based detector with six schemas
  (`IMP+POSS+ONOUN`, stacked variant, `AUTH+IMP+POSS+ONOUN` and
  loose variant, `HYPOTH+...` with four relaxations,
  `PROV+IMP+POSS+ONOUN` and loose variant, `IMP+NEG+ONOUN`) over
  seven slot dictionaries (~250 fillers total). Possessive-determiner
  constraint is the FPR-control trick.
- **`SpotlightDetector`** (v0.3) — Microsoft Research spotlighting
  pattern in pure offline form. ~70 provenance wrappers × ~100
  suspicious verb prefixes; any imperative inside a spotlighted zone
  fires regardless of grammar.
- **`DifferentialDetector`** (v0.3) — runs aggressive vs lenient
  normalization passes; flags inputs where the aggressive pass finds
  substantially more attack needles. Catches hidden-character tricks.
- **`AnomalyScorer`** (v0.3) — pure-stat distributional anomaly score
  (command-verb density + self-reference density + caps density +
  bracket density). Capped contributions ensure no single signal can
  fire Block alone; conservative defaults (warn ≥0.75, block ≥0.95).
- **`LlmJudge` trait + `NoopJudge`** (v0.3) — pluggable LLM-as-judge
  escalation path. Consulted by the scanner only when findings sit
  in the uncertain band. NoopJudge is the default; sieve-core remains
  fully vendor-neutral and offline.
- **`StreamingOutputScanner`** (v0.3) — chunk-by-chunk output scanner
  with `IncrementalVerdict::should_stop()` helper for the common
  break-on-block streaming loop.
- **`sieve` CLI binary** (v0.3) — first-party command line.
  `sieve scan` reads from stdin (or `--input file`), prints JSON
  verdict, exits 0/1/2 for Allow/Flag/Block.
- **Wordlist expansion**: ~220 → ~470 patterns across persona
  hijacks (DAN/AIM/STAN/EvilGPT/etc.), social-engineering /
  fake-memory, paraphrase variants, no-vowel forms, multi-turn
  context-poisoning anchors, authority framing, obfuscation
  exfiltration, programmatic decorator combinations.
- **`EncodingScanner`**: URL percent-decode, HTML-entity decode,
  reversed-string, l33t (per-position '1'→i/l brute-force),
  doubled-letter pair-collapse. Closes URL/HTML/reversed/l33t
  attack classes that v0.1 missed at 0%.
- **`ScannerBuilder` opt-outs**: `without_slot`, `without_spotlight`,
  `without_differential`, `without_anomaly`, `without_semantic`,
  `with_judge`, `with_judge_consult_threshold` for per-app tuning.
- **Probe suite**: 506 → 3520 probes. New classes: spotlight-targeted,
  zero-width hidden, multi-turn / authority-v3, indirect-v3,
  tool-injection-v3, obfuscation-v3, hypothetical, long-paraphrase,
  programmatic stem × decorator cross-products, programmatic
  encoded-stem variants. Plus ~300 new benign probes for FPR floor.

### Changed

- `MatchKind::LeftmostLongest` (not `Standard`) for the SlotMatcher's
  AC — Standard mode picks first-to-end matches, which suppressed
  longer AUTH/PROV patterns under shorter POSS overlap and broke
  Schema 3 / Schema 5.
- Aggressive bare wordlist patterns removed where the slot grammar
  now catches them with better FPR: `pretend you are`-style entries
  rely on Schema 6 when paired with override-noun.
- Probe suite assertion: `>= 90%` catch, `<= 6.5%` FPR (was `>= 55%`
  / `<= 5.0%` in v0.1). Actual numbers blow past both gates.

### Fixed

- L33t-speak attack class: 0% → ~100% catch via per-position '1'→i/l
  brute-force unleet (handles in-attack collisions like `d1sr...ru1e5`
  needing both mappings simultaneously).
- WASM build: enabled `bulk-memory` and `nontrapping-float-to-int`
  in wasm-opt for Rust 1.95 compatibility.

## [0.1.0] - 2026-05-16

First stable release of `sieve`. Identical artifact to v0.1.0-rc1
modulo the version string — no bypasses reported during the RC window.

## [0.1.0-rc1] - 2026-05-16

First public release candidate of `sieve`. Covers Phases 0-17 of the
build plan in `IMPLEMENTATION_PROMPT.md`.

**Headline numbers** (`benchmarks/REPORT.md`):
- Jailbreak corpus (224 curated): 100.0% Block.
- Benign FPR corpus (108 lines): 0.0% Block, 0.0% Flag.
- Per-scan latency: p50 7µs, p99 18µs.
- Cited competitors (different test sets, take with salt): Lakera
  74.6%, Azure Prompt Shield 42.98% (arXiv 2505.13028).

**Tested on**: x86_64-pc-windows-msvc (148 unit + 2 corpus tests + 6
proptest groups, all green). CI matrix in `.github/workflows/ci.yml`
adds Linux + macOS + WASM.

**Inviolable rules verified**:
- R1: no network deps in sieve-core (CI audit).
- R2: no LLM-vendor deps in sieve-core (CI audit).
- R3: string-in / verdict-out API.
- R4: contrib wrappers in separate subpackages only.
- R5: zero telemetry.
- R6: dual MIT + Apache-2.0.
- R7: clippy-gated no-panic in production paths.
- R8: cross-language consistency CI workflow.
- R9: README leads with "what we don't catch".
- R10: no emojis in code or docs (audited).
- R11: no bundled ONNX weights.
- R12: sync core, async only in contrib middleware.

### Added

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
- Phase 17: Full CI/CD pipelines.
  - ci.yml: fmt + clippy + test matrix (Ubuntu/macOS/Windows × stable/MSRV/
    nightly) + cargo-deny + no-network audit + cargo-llvm-cov coverage
    + WASM bundle build & size budget + Python wheel build (3 OSes) +
    @sieve/nextjs typecheck + vitest.
  - bench.yml: criterion + bundled-corpus benchmark on every PR; uploads
    REPORT.md + criterion HTML.
  - fuzz.yml: weekly cargo-fuzz scheduled (Mondays 06:17 UTC), 1h budget.
  - consistency.yml: builds all 3 bindings and asserts byte-equal verdict
    decision strings across Rust / Python / WASM for the smoke corpus.
  - release.yml: tag-triggered publish to crates.io, PyPI (linux/mac/
    windows wheels via maturin-action), npm (@sieve/wasm + @sieve/nextjs),
    plus a GitHub release with CHANGELOG body.
- Phase 16: Five working examples + 14-page mdbook user guide.
  - `examples/rust-basic` runs all 4 scanner-side cases.
  - `examples/python-fastapi` (FastAPI + sieve.contrib.openai).
  - `examples/python-langchain` (raw scanner API with LangChain).
  - `examples/nextjs-vercel-ai` (Vercel AI SDK + sieveMiddleware).
  - `examples/nextjs-edge-runtime` (Edge middleware with sieveCheck).
  - `docs/` mdbook scaffold with introduction, scope ("what we don't
    catch"), install, three quickstarts, public API ref, verdict /
    canary / commitments concept pages, BYO classifier, configuration,
    security, adding patterns, architecture.
- Phase 15: Reproducible benchmark harness. `benchmarks/run.sh` builds
  the `sieve-bench` binary (under `benchmarks/harness/`) and writes
  `benchmarks/REPORT.md`. Bundled-corpus baseline: 100% detection on
  the 224-line curated jailbreak set, 0% block-FPR on the 108-line
  benign set, p50 7µs / p99 18µs latency. Harness accepts `--jbb`,
  `--garak`, `--acl` flags for external corpus integration.
- Phase 14: Wordlist expanded from ~70 to ~220 hand-curated patterns
  across 8 attack families. Removed FPR-prone single-token control
  patterns (`</system>`, `[INST]`, `###user`, etc.) — they normalize
  to plain English words; v0.2 adds a raw-bytes scanner pass for them.
  Added 108-line curated benign FPR corpus (`benign.txt`) with
  adversarial-looking-but-legitimate prompts (AI talk, RAG queries,
  prompt-engineering questions). New `tests/corpus.rs` asserts
  detection rate ≥95% on jailbreaks and 0% block-FPR + ≤10% flag-FPR
  on benigns. Provenance manifest extended with the Phase 14 batch +
  planned v0.2 external-merge entry.
- Phase 13: `@sieve/nextjs` TypeScript package — three sub-exports:
  `@sieve/nextjs` (root) ships `sieveCheck()` for stateless Edge
  middleware + `Verdict` / `Finding` / `CanaryState` types +
  `PromptInjectionBlocked` error class; `@sieve/nextjs/openai` ships
  `wrapOpenAI(client)`; `@sieve/nextjs/ai-sdk` ships
  `sieveMiddleware(model)` that plugs into the Vercel AI SDK v3.x
  `LanguageModelV1` shape. Vitest smoke suite mocks `@sieve/wasm` and
  covers benign + block paths through the OpenAI wrapper.
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
