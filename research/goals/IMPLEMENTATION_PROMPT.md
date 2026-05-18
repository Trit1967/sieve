# Implementation Prompt — Sieve v0.1

> Target: implementation agent (Claude Code, Cursor, devin, or human dev) executing against [docs/project/PRD.md](../../docs/project/PRD.md), [docs/project/ARCHITECTURE.md](../../docs/project/ARCHITECTURE.md), and [research/LANDSCAPE.md](../LANDSCAPE.md).
> Scope: ship **v0.1 only** to crates.io + PyPI + npm.
> Working title: `sieve` (replace globally if renamed).

---

## 0. Mission

You are building `sieve` — a vendor-neutral, embeddable, offline-first library for detecting prompt injection attacks against LLM applications. It operates on **strings** and emits structured **verdicts**. It never makes a network call, never requires a specific LLM vendor, never phones home.

The library has three audiences:
1. **Rust LLM-app developers** who currently have no native option
2. **Python teams** (FastAPI / Django / LangChain / LlamaIndex / raw scripts)
3. **Next.js teams** (Edge runtime + Node runtime via WASM)

The launch artifact is a working v0.1 with:
- Pure-Rust `sieve-core` crate
- `sieve` Python wheel on PyPI
- `sieve-guard-wasm` + `sieve-guard-nextjs` npm packages
- A reproducible benchmark suite vs. JailbreakBench / garak / ACL LLMSec 2025 bypasses
- A README that punches with the Unicode-smuggling bypass demo as the opening artifact

Reference docs (canonical truth — read them first):
- `docs/project/PRD.md` — what we're building, success criteria, scope decisions
- `docs/project/ARCHITECTURE.md` — layered design, module structure, data flow diagrams
- `research/LANDSCAPE.md` — competitive intel; what existing tools do and what they miss

When this prompt and the canonical docs disagree, the canonical docs win.

---

## 1. Inviolable rules (read every commit against these)

These cannot be violated under any condition. Violation = revert and redo.

| # | Rule | How to verify |
|---|---|---|
| R1 | `sieve-core` makes **zero** network calls | `cargo tree` shows no http/network deps; grep verifies no `reqwest`, `tokio::net`, `std::net` in core |
| R2 | `sieve-core` has **zero** LLM-vendor dependencies | `cargo tree` shows no `async-openai`, `anthropic-*`, `langchain-*`, etc. |
| R3 | `sieve` Python core has **zero** LLM-vendor deps | `pip show sieve` requires no LLM-vendor package |
| R4 | The library **never** phones home — no telemetry, no remote update, no analytics | CI greps for forbidden patterns; documented in README |
| R5 | The primary API is **string-in, verdict-out** | `scan_input(&str, &str) -> Verdict`, `scan_output(&str, &CanaryState) -> Verdict` are public; no SDK objects in core signatures |
| R6 | SDK convenience wrappers live in `contrib` subpackages, **never** in core | `sieve-py/python/sieve/contrib/openai.py`, etc. — installed via extras |
| R7 | The library **never** requires user credentials, API keys, or accounts | Code review: no env var access for vendor keys in core |
| R8 | Same input → same verdict, **always**, across Rust / Python / WASM | Cross-language consistency tests (§11.8 PRD) pass on every commit |
| R9 | Dual-licensed MIT + Apache-2.0 | SPDX headers in every source file; `LICENSE-MIT` and `LICENSE-APACHE` at repo root |
| R10 | No `unwrap()` / `expect()` / `panic!()` in production code paths | Clippy lint `unwrap_used = "deny"` in core; test code exempt |
| R11 | Honest README: leads with **what we don't catch** | README first 200 lines include the threat-model boundary from PRD §13 |
| R12 | No emojis in code or docs unless explicitly requested by the user | Code review rule |

---

## 2. Scope discipline — v0.1 ships exactly this

### v0.1 in-scope (MUST ship)

**Detectors (all input-side, all in `sieve-core`)**
- `UnicodeNormalizer` — NFKC + zero-width strip + TR39 homoglyph subset (Latin/Cyrillic/Greek)
- `PatternScanner` — Aho-Corasick over curated ~5,000-entry wordlist
- `EncodingScanner` — base64 / hex / rot13 detect → decode → recursive re-scan (max depth 2)
- `HeuristicScorer` — instruction density, script-switch detection, repetition entropy
- `CanaryEngine` — generate per-call canaries, inject into system prompt, scan output for leakage
- Context analyzer (**heuristic v0.1**, NOT ONNX, NOT LLM-judge) — extract atomic instructions from system prompt, map input to override attempts
- Deterministic commitment checks — language (via `whichlang` or similar), persona-name consistency, refusal-keyword commitments

**Optional features (Cargo flags, no default deps)**
- `ort` — BYO-ONNX classifier trait + reference impl (interface only; ship no weights)

**Bindings (must ship in v0.1)**
- `sieve-py` — pyo3 + maturin → PyPI as `sieve`
- `sieve-wasm` — wasm-bindgen → npm as `sieve-guard-wasm`
- `sieve-guard-nextjs` — thin JS package wrapping `sieve-guard-wasm` with Vercel AI SDK + OpenAI helpers

**Contrib wrappers (optional, separate package extras)**
- Python: `sieve.contrib.openai`, `sieve.contrib.anthropic`
- JS: `sieve-guard-nextjs/openai`, `sieve-guard-nextjs/ai-sdk` (Vercel AI SDK)

### v0.1 out-of-scope (DO NOT BUILD — defer to v0.2+)

| Out-of-scope | Defer to |
|---|---|
| Tool-call linter | v0.2 |
| Conversation state tracker | v0.2 |
| Provenance / RAG / spotlighting | v0.2 |
| Piggyback LLM context analyzer | v0.2 |
| napi-rs Node binding | v0.2 |
| Go binding | v0.2 |
| LangChain / LlamaIndex / LiteLLM wrappers | v0.2 |
| Bundled ONNX classifier (weights) | v0.3 |
| Semantic commitment checks (LLM-judge) | v0.3 |
| Differential testing | v0.3 |
| Streaming output scanning | v0.3 |
| PII detection | v0.4+ |
| CLI tool | v0.3 |
| HTTP sidecar | v0.3 |

If during implementation you discover something feels missing from v0.1, **add it to a `docs/release/v0.2-backlog.md` file**; do not expand scope.

---

## 3. Workspace structure (exact)

Create this exact layout. Do not rename, do not nest differently:

```
sieve/
├── Cargo.toml                        # workspace root
├── README.md                         # the launch artifact
├── docs/project/PRD.md                            # already exists
├── docs/project/ARCHITECTURE.md                   # already exists
├── research/goals/IMPLEMENTATION_PROMPT.md          # this file
├── LICENSE-MIT
├── LICENSE-APACHE
├── CONTRIBUTING.md
├── SECURITY.md                       # bypass-reporting workflow
├── CHANGELOG.md
├── .github/
│   └── workflows/
│       ├── ci.yml                    # platform matrix, all tests
│       ├── bench.yml                 # criterion benchmarks on PR
│       ├── fuzz.yml                  # cargo-fuzz weekly
│       ├── release.yml               # crates.io / PyPI / npm publish
│       └── consistency.yml           # cross-binding verdict consistency
├── crates/
│   ├── sieve-core/
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── verdict.rs            # Verdict, Finding, Decision, Severity, Category
│   │   │   ├── scanner.rs            # Scanner builder + run loop
│   │   │   ├── context/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── parse.rs          # system-prompt → atomic instructions
│   │   │   │   └── analyze.rs        # input → override-attempt mapping
│   │   │   ├── detectors/
│   │   │   │   ├── mod.rs            # Detector trait
│   │   │   │   ├── unicode.rs
│   │   │   │   ├── patterns.rs
│   │   │   │   ├── encoding.rs
│   │   │   │   └── heuristics.rs
│   │   │   ├── canary/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── generate.rs
│   │   │   │   ├── inject.rs
│   │   │   │   └── detect.rs
│   │   │   ├── commitments/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── extract.rs        # parse system prompt commitments
│   │   │   │   └── verify.rs         # check output against commitments
│   │   │   ├── classifier/
│   │   │   │   ├── mod.rs            # Classifier trait
│   │   │   │   └── onnx.rs           # ort-backed reference impl (feature-gated)
│   │   │   ├── telemetry.rs          # local-only counters
│   │   │   ├── data/
│   │   │   │   ├── jailbreaks.txt    # ~5,000-entry curated wordlist
│   │   │   │   └── confusables.bin   # TR39 confusables subset
│   │   │   └── error.rs
│   │   ├── tests/
│   │   │   ├── integration.rs
│   │   │   ├── corpus/
│   │   │   │   ├── jailbreakbench/
│   │   │   │   ├── garak/
│   │   │   │   ├── acl2025_bypasses/
│   │   │   │   ├── benign/
│   │   │   │   └── regression/
│   │   │   ├── property/             # proptest cases
│   │   │   └── adversarial/          # red-team probes
│   │   ├── benches/
│   │   │   └── scan.rs               # criterion benches
│   │   └── fuzz/                     # cargo-fuzz targets
│   ├── sieve-py/
│   │   ├── Cargo.toml
│   │   ├── pyproject.toml            # maturin config
│   │   ├── src/
│   │   │   └── lib.rs                # pyo3 module
│   │   └── python/
│   │       └── sieve/
│   │           ├── __init__.py
│   │           ├── _native.pyi       # type stubs
│   │           ├── contrib/
│   │           │   ├── __init__.py
│   │           │   ├── openai.py
│   │           │   └── anthropic.py
│   │           └── tests/
│   │               ├── test_basic.py
│   │               ├── test_contrib_openai.py
│   │               ├── test_contrib_anthropic.py
│   │               └── test_consistency.py
│   └── sieve-wasm/
│       ├── Cargo.toml
│       ├── src/
│       │   └── lib.rs                # wasm-bindgen module
│       └── tests/
│           └── web.rs
├── packages/                          # JS packages
│   └── nextjs/
│       ├── package.json
│       ├── tsconfig.json
│       ├── src/
│       │   ├── index.ts
│       │   ├── openai.ts
│       │   └── ai-sdk.ts
│       ├── test/
│       │   ├── openai.test.ts
│       │   ├── ai-sdk.test.ts
│       │   └── edge-runtime.test.ts
│       └── README.md
├── examples/
│   ├── rust-basic/                   # cargo run example
│   ├── python-fastapi/
│   ├── python-langchain/
│   ├── nextjs-vercel-ai/
│   └── nextjs-edge-runtime/
├── benchmarks/
│   ├── run.sh                        # reproducible bench script
│   ├── corpus/                       # benchmark inputs
│   ├── results/
│   └── REPORT.md                     # published numbers
├── docs/                              # mdbook source
│   ├── book.toml
│   └── src/
└── docs/release/v0.2-backlog.md                    # scope-creep capture file
```

---

## 4. Phase-sequenced implementation order

Build in this order. Each phase ends with a passing CI run and an atomic commit. **Do not start phase N+1 until phase N is green.**

### Phase 0 — Project bootstrap (1 commit)
- Initialize cargo workspace, license files, gitignore, basic README skeleton
- Create empty crates per §3 layout
- Set up `.github/workflows/ci.yml` skeleton
- Verify `cargo check` passes on empty workspace
- **Commit**: `chore: scaffold cargo workspace + license files`

### Phase 1 — Verdict schema (must be stable before any detector)
- Implement `verdict.rs` with `Verdict`, `Finding`, `Decision`, `Severity`, `Category`
- Serde derive for all (JSON round-trip)
- 100% unit test coverage
- Property test: serialize/deserialize idempotence
- **Commit**: `feat(core): verdict schema with serde round-trip`

### Phase 2 — UnicodeNormalizer (the hero feature)
- Implement NFKC normalization via `unicode-normalization` crate
- Strip zero-width chars: U+200B, U+200C, U+200D, U+FEFF, U+2060, U+E0000–U+E007F (Unicode tags)
- TR39 homoglyph map: build `confusables.bin` from Unicode confusables.txt at build-time via `build.rs`; subset to Latin/Cyrillic/Greek; optional via builder
- Return both original + normalized
- **Tests**:
  - Property: `normalize(normalize(x)) == normalize(x)`
  - Property: `len(normalize(x)) <= len(x)`
  - Property: all zero-width chars stripped
  - Unit: every documented bypass from ACL 2025 paper is normalized to its non-smuggled form
  - Unit: legitimate Unicode (emoji in benign messages, non-Latin scripts) is preserved
  - Fuzz target: never panics on arbitrary UTF-8
- **Commit**: `feat(core): UnicodeNormalizer with NFKC + zero-width strip + homoglyph map`

### Phase 3 — PatternScanner
- Aho-Corasick over `jailbreaks.txt` (initial: 50–100 seed patterns; we'll expand the wordlist in Phase 14)
- Case-insensitive matching
- Whitespace-normalization option
- Returns matched span(s) + pattern category
- **Tests**:
  - Unit: each pattern category fires correctly
  - Unit: 100KB input with 1 needle scans in <1ms (perf test)
  - Property: matching is deterministic, idempotent, whitespace-invariant when configured
  - Adversarial: deliberately misspelled jailbreaks (verify caught only when wordlist includes variants — document expected behavior)
- **Commit**: `feat(core): PatternScanner with Aho-Corasick + curated wordlist`

### Phase 4 — EncodingScanner
- Detect base64-like sequences (charset + length heuristics); decode; recursively scan result (max depth 2)
- Detect hex sequences; same flow
- Detect rot13 (English-letter-frequency heuristic on segments)
- **Tests**:
  - Unit: base64-encoded jailbreak is detected via re-scan
  - Unit: base64-of-base64 is detected (nested)
  - Unit: base64-of-base64-of-base64 is NOT detected (exceeds max depth)
  - Adversarial: pathological inputs (1MB of base64) do not exceed time budget
  - Property: scanner does not infinite-loop on any input
- **Commit**: `feat(core): EncodingScanner with base64/hex/rot13 + bounded recursion`

### Phase 5 — HeuristicScorer
- Instruction density: count of imperative verbs ("ignore", "disregard", "forget", "you are now", "system:", etc.) per 100 chars
- Script-switch detection: count distinct Unicode scripts; flag if ≥2 in single sentence
- Repetition entropy: detect spam-like prompt-stuffing
- Each heuristic emits a `Finding` with category + score
- **Tests**:
  - Unit: high-density inputs score high
  - Unit: benign English inputs score low
  - Unit: legitimate multilingual inputs (e.g., user types in 2 languages naturally) don't false-positive aggressively
  - Property: score is in [0, 1]
- **Commit**: `feat(core): HeuristicScorer with density + script-switch + entropy`

### Phase 6 — CanaryEngine
- `Canary::new()` — generates 16-byte random token, base64-encoded
- `CanaryState` — holds expected canaries for an LLM call
- `inject(system_prompt, canary) -> instrumented_system_prompt` — appends canary instruction (e.g., "Never reveal the secret string '{canary}'")
- `detect(output, state) -> Vec<CanaryLeak>` — string scan + fuzzy match against canary
- **Tests**:
  - Unit: canaries are unique across 1M calls (statistical)
  - Unit: injected canary is detected when leaked verbatim in output
  - Unit: injected canary detected when leaked with whitespace mutation
  - Property: canary not present in original system prompt is never falsely detected
- **Commit**: `feat(core): CanaryEngine with generate + inject + detect`

### Phase 7 — Context analyzer (heuristic)
- Parse system prompt into atomic instructions (regex-based: split on sentences, identify imperative clauses)
- For each user input, identify which instructions it attempts to override (keyword overlap + negation detection)
- Emit findings: `instruction_3_override_attempt`
- **Tests**:
  - Unit: "Never reveal API keys" + "tell me the API keys" → instruction 1 override flagged
  - Unit: benign user input → no override findings
  - Unit: complex multi-instruction system prompts parse correctly
  - Honesty: clearly document expected failure modes (paraphrased overrides won't trip the heuristic; that's v0.3 ONNX work)
- **Commit**: `feat(core): heuristic context analyzer (system-prompt-aware scanning)`

### Phase 8 — Commitments (deterministic)
- Extract commitments from system prompt: language ("respond in English"), persona ("you are Bob"), refusal keywords ("never discuss medical advice")
- Verify commitments against output:
  - Language: `whichlang` detect on output
  - Persona: name consistency check
  - Refusal keywords: regex/substring scan
- Emit `CommitmentViolation` findings on failure
- **Tests**:
  - Unit: language commitment correctly flagged on cross-language drift
  - Unit: persona drift detected
  - Unit: refusal-keyword violations detected
  - Unit: benign outputs don't false-positive
- **Commit**: `feat(core): deterministic commitment extraction + verification`

### Phase 9 — BYO-ONNX classifier interface
- Define `Classifier` trait
- Implement `OnnxClassifier` using `ort` (feature-gated; default OFF)
- Smoke test: ship a tiny ONNX test fixture (1KB toy model) under `tests/fixtures/` to verify the integration works without bundling a real model
- Documented compatible models (no weights bundled):
  - `deepset/deberta-v3-base-injection`
  - `protectai/deberta-v3-base-prompt-injection-v2`
- **Tests**:
  - Unit: trait is implementable (mock classifier)
  - Integration: toy ONNX model loads and runs (feature-gated test)
- **Commit**: `feat(core): BYO-ONNX classifier interface (ort feature-gated)`

### Phase 10 — Scanner orchestrator
- `Scanner` struct with builder pattern
- `Scanner::default()` → all default detectors enabled
- `scan_input(system_prompt, user_input) -> Verdict`:
  - Run UnicodeNormalizer → normalized input
  - Run all detectors on normalized input (parallel via `rayon` for any >1KB input)
  - Run context analyzer
  - Generate + inject canaries into system prompt
  - Return Verdict including `canary_state`
- `scan_output(output, canary_state) -> Verdict`:
  - Run canary detection
  - Run commitment verification
- Decision logic: `Block` if any Severity::Block finding; `Flag` if score >0.5; else `Allow`
- **Tests**:
  - Integration: full pipeline on all attack categories
  - Integration: full pipeline on benign inputs (FPR measurement)
  - Property: deterministic verdicts
  - Property: verdict round-trips through JSON
  - Concurrency: 100 concurrent scans → no data races (loom-style if feasible, otherwise tsan)
- **Commit**: `feat(core): Scanner orchestrator with builder + scan_input/scan_output`

### Phase 11 — Python binding (`sieve-py`)
- pyo3 module exposing `Scanner`, `Verdict`, `Finding`, `CanaryState`, all enums
- maturin config + `pyproject.toml`
- Type stubs (`.pyi`)
- Optional extras: `sieve[openai]`, `sieve[anthropic]`
- **Contrib wrappers**:
  - `sieve.contrib.openai.wrap(client)` — monkey-patches `chat.completions.create` to scan in/out + inject canary
  - `sieve.contrib.anthropic.wrap(client)` — same for `messages.create`
- **Tests**:
  - pytest suite for native bindings
  - Pytest for each contrib wrapper (mocked HTTP via `respx` / `httpx`)
  - Cross-language consistency tests (vs Rust CLI output)
- **Commit**: `feat(py): pyo3 bindings + contrib openai/anthropic wrappers`

### Phase 12 — WASM binding (`sieve-wasm`)
- wasm-bindgen exposing same API surface
- TypeScript definitions
- Size budget: <2MB compressed (fail build if exceeded)
- **Tests**:
  - wasm-bindgen-test for native parity
  - Headless browser test (Playwright)
  - Cloudflare Workers integration test (`wrangler dev` in CI)
  - Vercel Edge runtime test
- **Commit**: `feat(wasm): wasm-bindgen binding + size-budget enforcement`

### Phase 13 — `sieve-guard-nextjs` package
- TS package, depends on `sieve-guard-wasm`
- `wrapOpenAI(client)` helper for Node-runtime Next.js
- `sieveMiddleware(model)` for Vercel AI SDK
- `sieveCheck()` for Next.js middleware (Edge runtime)
- **Tests**:
  - Vitest suite per wrapper
  - Edge runtime compatibility test (using `@edge-runtime/vm`)
  - Streaming response handling
- **Commit**: `feat(nextjs): wrappers for OpenAI SDK, Vercel AI SDK, edge middleware`

### Phase 14 — Wordlist expansion + community corpus repo
- Aggregate wordlists from JailbreakBench (MIT), garak probes (Apache), LLM Guard wordlist (MIT — with credit), Rebuff vector DB corpus (Apache — with credit)
- Dedupe + categorize
- Final wordlist target: ~5,000 patterns, <500KB
- Create separate repo `sieve-corpus` (publish empty stub for v0.1; full launch in v0.2)
- **Tests**:
  - Detection rate against aggregated corpus
  - FPR against curated benign set
- **Commit**: `feat(data): expand jailbreaks.txt to 5000 entries; add provenance manifest`

### Phase 15 — Benchmarks (the credibility artifact)
- `benchmarks/run.sh` reproducible script
- Run sieve against:
  - JailbreakBench (full set)
  - garak probes (curated subset)
  - ACL 2025 bypasses
  - Benign corpus (FPR)
- Report per-category detection rate, FPR, p50/p99 latency
- Comparison tables against published Lakera (74.6%) / Azure (42.98%) numbers — clearly cited, with caveats about test-set differences
- Write `benchmarks/REPORT.md` with results
- **Commit**: `bench: full benchmark suite + REPORT.md`

### Phase 16 — README + examples + docs
- README structure (in order):
  1. The one-line elevator pitch
  2. The Unicode bypass demo (5-line code block, side-by-side: input with zero-width chars → normalized + flagged)
  3. **What this does NOT catch** (PRD §13, full table)
  4. Install instructions for Rust / Python / Next.js
  5. Quickstart: vendor-neutral primary API examples (with Ollama / OpenAI / Anthropic / custom HTTP)
  6. Optional contrib helpers
  7. Benchmark headlines (link to REPORT.md)
  8. Comparison table vs. existing tools (cite licenses, M&A status)
  9. Honest claims + limits
  10. Contributing + license
- All code blocks in README are executable via doctests / example crates
- `examples/` directory: 5 working examples (`rust-basic`, `python-fastapi`, `python-langchain`, `nextjs-vercel-ai`, `nextjs-edge-runtime`)
- mdbook user guide under `docs/`
- **Commit**: `docs: README + examples + mdbook scaffolding`

### Phase 17 — CI/CD pipelines
- `ci.yml`: platform matrix (per PRD §11.13), runs unit + property + integration + corpus tests on every PR
- `bench.yml`: criterion benchmarks on PR; comments on PR with regression deltas; fails if any benchmark regresses >10%
- `fuzz.yml`: cargo-fuzz weekly; OSS-Fuzz integration submitted
- `consistency.yml`: cross-language verdict consistency test (Rust CLI vs Python vs WASM)
- `release.yml`: tag-triggered publish to crates.io / PyPI / npm
- All workflows green before v0.1.0 tag
- **Commit**: `ci: full CI matrix + bench + fuzz + cross-language consistency + release pipelines`

### Phase 18 — v0.1.0-rc1 release
- Cut prerelease tag
- Publish to crates.io / PyPI / npm under `0.1.0-rc1`
- Internal red-team pass: run adversarial probe suite, file any bypasses as issues, add as regression tests, fix
- Run real-LLM nightly tests (opt-in, secrets-gated) for soak

### Phase 19 — v0.1.0 release
- All RC bypasses fixed and regression-tested
- Tag `v0.1.0`
- Publish final
- Write launch blog post
- Show HN draft prepared

---

## 5. Public API contracts (exact signatures)

These are the locked-in public APIs. Implementation must match these signatures. Internal helpers may differ; public ones cannot.

### 5.1 Rust core

```rust
// crates/sieve-core/src/lib.rs

pub use scanner::{Scanner, ScannerBuilder};
pub use verdict::{Verdict, Finding, Decision, Severity, Category, CanaryState, CanaryLeak, CommitmentViolation};
pub use detectors::{UnicodeNormalizer, PatternScanner, EncodingScanner, HeuristicScorer};
pub use canary::Canary;
pub use commitments::{Commitment, CommitmentVerifier};
pub use classifier::Classifier;
pub use error::{Error, Result};

impl Scanner {
    pub fn default() -> Self;
    pub fn builder() -> ScannerBuilder;
    pub fn scan_input(&self, system_prompt: &str, user_input: &str) -> Verdict;
    pub fn scan_output(&self, output: &str, canary_state: &CanaryState) -> Verdict;
    pub fn metrics(&self) -> Metrics;  // local-only
}

impl ScannerBuilder {
    pub fn with_unicode(self, opts: UnicodeOpts) -> Self;
    pub fn with_patterns(self, patterns: Patterns) -> Self;
    pub fn with_patterns_from_file<P: AsRef<Path>>(self, path: P) -> Result<Self>;
    pub fn with_encoding(self, opts: EncodingOpts) -> Self;
    pub fn with_heuristics(self, opts: HeuristicOpts) -> Self;
    pub fn with_canary(self, opts: CanaryOpts) -> Self;
    pub fn with_commitments(self, opts: CommitmentOpts) -> Self;
    pub fn with_context_analyzer(self, enable: bool) -> Self;
    pub fn with_classifier<C: Classifier + 'static>(self, classifier: C) -> Self;
    pub fn build(self) -> Scanner;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Verdict {
    pub decision: Decision,
    pub score: f32,
    pub findings: Vec<Finding>,
    pub normalized_input: Option<String>,
    pub canary_state: CanaryState,
    pub canaries_leaked: Vec<CanaryLeak>,
    pub commitments_violated: Vec<CommitmentViolation>,
    pub latency_us: u64,
}

impl Verdict {
    pub fn is_allow(&self) -> bool;
    pub fn is_flag(&self) -> bool;
    pub fn is_block(&self) -> bool;
}
```

### 5.2 Python

```python
# Type signatures (from .pyi)
class Scanner:
    def __init__(self) -> None: ...
    @classmethod
    def builder(cls) -> ScannerBuilder: ...
    def scan_input(self, system_prompt: str, user_input: str) -> Verdict: ...
    def scan_output(self, output: str, canary_state: CanaryState) -> Verdict: ...
    def metrics(self) -> Metrics: ...

class Verdict:
    decision: Decision        # enum: ALLOW | FLAG | BLOCK
    score: float
    findings: list[Finding]
    normalized_input: str | None
    canary_state: CanaryState
    canaries_leaked: list[CanaryLeak]
    commitments_violated: list[CommitmentViolation]
    latency_us: int
    def is_allow(self) -> bool: ...
    def is_flag(self) -> bool: ...
    def is_block(self) -> bool: ...
    def to_dict(self) -> dict: ...
    def to_json(self) -> str: ...
```

```python
# Contrib wrappers (separate optional install)
# sieve/contrib/openai.py
from openai import OpenAI
def wrap(client: OpenAI) -> OpenAI: ...
# Returned client has .chat.completions.create patched to:
#  - call scanner.scan_input(system_prompt, user_input)
#  - inject canary into system prompt
#  - forward to underlying create()
#  - call scanner.scan_output(response, canary_state)
#  - attach verdict as response.sieve
# If verdict.is_block(): raise sieve.PromptInjectionBlocked
```

### 5.3 WASM / TS

```typescript
// sieve-guard-wasm public types
export class Scanner {
  constructor();
  static builder(): ScannerBuilder;
  scan_input(system_prompt: string, user_input: string): Verdict;
  scan_output(output: string, canary_state: CanaryState): Verdict;
}

export interface Verdict {
  decision: "Allow" | "Flag" | "Block";
  score: number;
  findings: Finding[];
  normalized_input: string | null;
  canary_state: CanaryState;
  canaries_leaked: CanaryLeak[];
  commitments_violated: CommitmentViolation[];
  latency_us: number;
}
```

```typescript
// sieve-guard-nextjs public API
import type { OpenAI } from 'openai';
export function wrapOpenAI(client: OpenAI): OpenAI;
export function sieveMiddleware(model: LanguageModelV1): LanguageModelV1;
export function sieveCheck(messages: Message[]): Promise<Verdict>;
```

---

## 6. Testing requirements (extensive — this is the credibility moat)

Implement the full test pyramid from PRD §11. Below are operational specifics.

### 6.1 Unit tests — coverage targets

- `sieve-core` lines: ≥90%, branches: ≥85%
- Every public function called by at least one test
- Every error variant triggered by at least one test
- Coverage measured via `cargo-llvm-cov`; report uploaded to Codecov on every PR
- CI fails if coverage drops by >1% relative to main

### 6.2 Property tests (proptest) — required properties

| Module | Property |
|---|---|
| UnicodeNormalizer | `normalize(normalize(x)) == normalize(x)` |
| UnicodeNormalizer | `len(normalize(x)) <= len(x.as_bytes())` |
| UnicodeNormalizer | All zero-width codepoints absent in output |
| UnicodeNormalizer | Valid UTF-8 in → valid UTF-8 out |
| PatternScanner | Same input → same matches across runs |
| PatternScanner | Matching is whitespace-invariant when configured |
| EncodingScanner | Bounded recursion (≤2 levels) |
| EncodingScanner | No infinite loops |
| HeuristicScorer | Score in [0.0, 1.0] |
| CanaryEngine | Two canaries with different seeds produce different tokens |
| CanaryEngine | Canary detected in output iff present after string normalization |
| Verdict | JSON round-trip: `from_json(to_json(v)) == v` |
| Scanner | `scan_input(x) == scan_input(x)` deterministic |

Each property runs with 1,000+ cases per CI run.

### 6.3 Fuzz tests (cargo-fuzz)

- Targets:
  - `fuzz_scan_input` — arbitrary UTF-8, never panic, never >100MB alloc
  - `fuzz_scan_output` — same
  - `fuzz_normalize` — never panic, output is valid UTF-8
  - `fuzz_decode` — bounded recursion, bounded latency
  - `fuzz_pattern_scan` — bounded latency on adversarial wordlist
- Initial corpus seeded with: JailbreakBench inputs, garak probes, ACL'25 bypass samples, random bytes
- Run weekly in CI; submit to OSS-Fuzz for continuous fuzzing

### 6.4 Integration tests

- Each detector + Scanner combination tested end-to-end
- Full builder configurations tested
- 1MB input → latency bounded, no OOM
- 1M sequential scans → no memory growth (heaptrack snapshot)
- 100 concurrent scans → no data races, thread safety verified

### 6.5 Corpus tests (the numbers we publish)

Datasets to integrate:
- **JailbreakBench** — full attack set; measure detection rate per category
- **garak** — curated subset (avoid running models, just use the static probe strings)
- **ACL LLMSec 2025 bypasses** — every documented bypass technique must be caught (this is the hero claim)
- **HarmBench** — behavioral commitment violation tests
- **Curated benign** — we maintain ~500 hand-curated benign inputs that look "suspicious-but-legitimate" (multilingual user queries, code snippets, prompts about prompts, etc.) — measure FPR

For each corpus run, emit:
- Detection rate (% flagged or blocked)
- False positive rate on benign set
- Per-category breakdown
- p50 / p99 latency
- Disk-cached JSON output for diffing across releases

The numbers go in `benchmarks/REPORT.md`. CI generates the report; reviewer signs off.

### 6.6 Regression tests

Every reported bypass becomes a permanent test case. Workflow:
1. Bug report comes in with bypassing input
2. Test file added to `tests/regression/{issue_number}.rs` (Rust) or `tests/regression/test_{issue}.py` (Python)
3. Test expects current (failing) verdict + asserts desired verdict
4. Fix implemented; test now passes
5. Test never removed

### 6.7 Cross-language consistency tests

The cross-language consistency story is a HARD GUARANTEE. Implementation:

- Build a Rust CLI binary (`sieve-cli` in tests) that reads input from stdin, emits Verdict as JSON
- Python and WASM produce the same Verdict for the same input
- Test harness runs every input in the corpus through all three, asserts identical:
  - `decision`
  - `score` (within 0.001)
  - `findings` (canonical-sorted, same content)
- Runs on every commit; failure blocks merge

### 6.8 Performance regression tests

Criterion benches in `crates/sieve-core/benches/scan.rs`:
- `scan_input_small` — 100B input
- `scan_input_medium` — 1KB input
- `scan_input_large` — 10KB input
- `scan_output_with_canary`
- `unicode_normalize` (1KB)
- `pattern_scan_10kb`

CI uses `bencher.dev` or `criterion-compare` to comment on PRs. Fail if any benchmark regresses >10% vs base branch.

### 6.9 Memory tests

- Valgrind / Memcheck nightly
- ASAN every commit (via custom CI target)
- Heaptrack snapshot for 1M sequential scans; assert no allocator growth >10MB
- Per-scan peak allocation budget: <10MB

### 6.10 WASM-specific tests

- Bundle size: <2MB compressed; fail build if exceeded
- Cold-start in Cloudflare Workers: <50ms (CI uses `wrangler dev` + timing harness)
- Cold-start in Vercel Edge: tested via `@edge-runtime/vm`
- Functional parity with native Rust verified by cross-language test suite

### 6.11 Real-LLM tests (opt-in, nightly, secrets-gated)

Gated on `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_URL` repository secrets. Run nightly only on `main`.

For each provider:
- 100 known-attack inputs → measure catch rate (input + output stage)
- 100 benign inputs → measure FPR
- 50 system-prompt-override attempts → measure context-aware detection rate
- 50 canary leak attempts → measure leak detection rate

Results uploaded to a results bucket; trend tracked over time. These numbers fuel the launch blog post.

### 6.12 Adversarial / red-team tests

Automated probes:
- Every Unicode trick variant: zero-width, tags, homoglyphs, combining chars, RTL overrides, math alphanumerics
- Encoding combinations: base64-of-base64, base64-of-hex
- Wordlist evasion: l33t speak, Unicode-substituted letters, deliberate misspellings
- Heuristic gaming: high-entropy benign inputs (code, JSON, math)
- Canary leak forgery: outputs that contain strings similar to canaries without actual hijack
- Commitment bypass: outputs that technically meet commitments while violating spirit

Targets: catch rate ≥95% on the bypass set, FPR ≤2% on benign set.

### 6.13 Documentation tests

- Every code block in README executable via doctest / example crate
- Every example in `examples/` runs in CI
- `cargo doc` builds with zero warnings
- `mdbook build` succeeds; `mdbook-linkcheck` finds no broken links

### 6.14 Platform matrix (CI)

| OS | Arch | Rust | Python |
|---|---|---|---|
| Ubuntu 22.04 | x86_64 | stable / MSRV / nightly | 3.9 / 3.10 / 3.11 / 3.12 |
| Ubuntu 22.04 | aarch64 | stable | 3.11 |
| macOS 13 | x86_64 | stable | 3.11 |
| macOS 14 | aarch64 | stable | 3.11 |
| Windows 2022 | x86_64 | stable | 3.11 |
| wasm32-unknown-unknown | — | stable | — |

All combinations green before v0.1.0 tag.

### 6.15 Soak tests (pre-release only)

- 24h continuous random-input scan loop → no crashes, no memory growth
- 1,000 concurrent scan threads × 1h → bounded latency, no panics

---

## 7. Quality gates / definition of done per phase

Each phase commit must pass:
1. `cargo fmt --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test --all-features` (unit + property + integration)
4. `cargo deny check` (license + advisory audit)
5. `cargo-llvm-cov` coverage report (no drop >1%)
6. New code in this phase has tests
7. Documentation updated if public API changed
8. CHANGELOG.md updated

A phase is "done" when:
- All tests added per phase plan are present and passing
- CI is green
- Code reviewed (self-review at minimum; if PR-based, by a reviewer)
- Atomic commit pushed with clear conventional-commit message

---

## 8. Anti-patterns / things you must NOT do

| Don't | Why |
|---|---|
| Add network calls anywhere in `sieve-core` | Violates R1 |
| Add LLM SDK dependencies in core or core's `Cargo.toml` | Violates R2 |
| Make contrib wrappers required dependencies | Violates R6 |
| Add telemetry, analytics, "anonymous usage stats", phone-home, version check, anything network-touching | Violates R4 |
| `unwrap()` / `expect()` / `panic!()` in production code paths | Violates R10 |
| Mark v0.2 features as "while we're here" v0.1 inclusions | Violates §2 scope discipline |
| Make API ergonomic for one language at the cost of another's idioms | Violates cross-binding consistency |
| Bundle ONNX weights or any third-party model files | License risk; defer to v0.3 with explicit user choice |
| Claim detection rates without published reproducible benchmarks | Violates R11 honesty rule |
| Suppress findings to make benchmarks look better | Reputation suicide |
| Refactor existing code "while you're there" unrelated to the current phase | Scope creep; atomic commit discipline |
| Add dependencies casually | Every new dep needs justification + `cargo deny` audit |
| Add async to the core | Sync core, async only in middleware/orchestrator layer |
| Couple to a specific async runtime (tokio, async-std) in core | Core stays runtime-agnostic |
| Hide bypasses by adjusting test expectations | Always treat new bypasses as bugs, not test failures |
| Use emojis in code or docs | Violates R12 |
| Skip writing the "what we don't catch" section in README | Violates R11 |

---

## 9. Atomic commit discipline

- One logical change per commit
- Conventional Commits format: `feat(scope): description`, `fix(scope): description`, `test(scope): description`, `docs: description`, `chore: description`, `bench: description`, `ci: description`, `refactor(scope): description`
- Each commit passes CI on its own (no "fix CI" commits unless reverting)
- No merge commits in PRs (rebase + squash if needed)
- Tag releases with `v0.1.0`, `v0.1.0-rc1`, etc.

---

## 10. Deliverables — what "v0.1.0 done" looks like

When v0.1 is complete you have:

1. **Published packages:**
   - `sieve` on crates.io
   - `sieve` on PyPI (with extras `[openai]`, `[anthropic]`)
   - `sieve-guard-wasm` on npm
   - `sieve-guard-nextjs` on npm

2. **Working examples** (each runs end-to-end):
   - Rust: `cargo run --example rust-basic`
   - Python FastAPI app with `sieve.wrap(OpenAI())`
   - Python LangChain example
   - Next.js app on Vercel AI SDK with `sieveMiddleware()`
   - Next.js app using `runtime: 'edge'` with `sieveCheck()`

3. **Test pyramid:**
   - All unit + property + integration tests green
   - Fuzz targets running in CI (weekly schedule + OSS-Fuzz submission)
   - Cross-language consistency tests green
   - Corpus tests producing `benchmarks/REPORT.md`
   - Coverage ≥90% on `sieve-core`

4. **Benchmark report** (`benchmarks/REPORT.md`):
   - Detection rate per attack category
   - FPR on curated benign set
   - p50 / p99 latency per detector
   - WASM cold-start numbers
   - Comparison table vs. Lakera (74.6%), Azure (42.98%), LLM Guard (latency)

5. **Documentation:**
   - README leading with Unicode bypass demo + "what we don't catch"
   - mdbook user guide
   - API docs published (docs.rs for Rust; readthedocs or equivalent for Python)
   - SECURITY.md describing bypass reporting workflow
   - CONTRIBUTING.md

6. **CI/CD:**
   - Full platform matrix
   - Bench regression detection on every PR
   - Release pipeline that publishes to crates.io / PyPI / npm on tag push

7. **Launch artifacts:**
   - Blog post draft: "Why your prompt injection defense doesn't catch zero-width characters"
   - Show HN post draft with side-by-side bypass demo
   - Comparison screenshots

---

## 11. Open decisions to resolve before starting

Resolve these by writing them into a `docs/project/DECISIONS.md` ADR file before Phase 1:

1. **Final name** — `sieve` (placeholder) vs. `shibboleth` / `prompt-sieve` / `latch` / other. **Verify crates.io + PyPI + npm availability before locking.**
2. **Async runtime for middleware** — `tokio` (likely) vs. runtime-agnostic via traits.
3. **Cargo MSRV** — stable -2 (default) vs. tighter.
4. **WASM build config** — `wee_alloc`? Disabled feature flags to hit <2MB?
5. **Canary token format** — random bytes (default) vs. format-constrained (more leak-detectable but more obvious to attackers).

---

## 12. References (open these and read them)

- `docs/project/PRD.md` — canonical product spec
- `docs/project/ARCHITECTURE.md` — layered design and module structure
- `research/LANDSCAPE.md` — competitor analysis; understand what's missing
- arXiv 2504.11168 (ACL LLMSec 2025) — Unicode bypass paper; your hero feature targets these attacks
- arXiv 2505.13028 (Palit 2025) — independent benchmark of Lakera
- JailbreakBench: https://jailbreakbench.github.io
- garak: https://github.com/NVIDIA/garak
- Unicode TR39 (confusables): https://www.unicode.org/reports/tr39/
- pyo3 + maturin: https://www.maturin.rs/
- wasm-bindgen: https://rustwasm.github.io/wasm-bindgen/
- aho-corasick crate docs
- unicode-normalization crate docs
- proptest book
- cargo-fuzz book
- OSS-Fuzz integration guide

---

## 13. How to start

1. Read `docs/project/PRD.md`, `docs/project/ARCHITECTURE.md`, `research/LANDSCAPE.md` in full.
2. Resolve the open decisions in §11 — write `docs/project/DECISIONS.md`.
3. Check `sieve` (or chosen name) availability on crates.io, PyPI, npm. Lock the name.
4. Execute Phase 0 (scaffold). Commit. Verify CI passes.
5. Execute Phase 1. Commit. CI green. Move on.
6. **Do not skip phases. Do not bundle phases. Each phase is an atomic commit that passes on its own.**

If you hit a blocker mid-phase: pause, write the blocker into `docs/project/DECISIONS.md`, ask, and resume.

If you find scope creep urge: open `docs/release/v0.2-backlog.md` and add a line. Don't expand v0.1.

If you find a bypass while building: add a regression test, fix it, ship as part of the relevant phase.

When v0.1.0 is tagged, run the launch plan (PRD §15).

Good luck.
