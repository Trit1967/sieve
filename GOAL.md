# Goal: Ship `sieve` v0.1 — vendor-neutral prompt injection defense library

Build a Rust-core library with Python (pyo3) and WASM (wasm-bindgen) bindings that detects prompt injection in any LLM application, regardless of vendor or framework. Ship to crates.io, PyPI, and npm.

## Read first (canonical, authoritative)
- `IMPLEMENTATION_PROMPT.md` — operational plan, 19 phases, test pyramid, API contracts
- `PRD.md` — product spec, success criteria, scope
- `ARCHITECTURE.md` — system design
- `research/LANDSCAPE.md` — competitor analysis

When this goal and the canonical docs disagree, the canonical docs win.

## Inviolable rules
R1: `sieve-core` makes ZERO network calls. Ever.
R2: `sieve-core` has ZERO LLM-vendor dependencies (no openai, anthropic, etc.)
R3: Primary API is string-in/verdict-out: `scan_input(system_prompt, user_input) -> Verdict`, `scan_output(output, canary_state) -> Verdict`
R4: SDK convenience wrappers live ONLY in `contrib` subpackages, never in core
R5: No telemetry, phone-home, remote update, or analytics — anywhere, ever
R6: Dual-licensed MIT + Apache-2.0
R7: No `unwrap()`/`expect()`/`panic!()` in production code paths
R8: Cross-language consistency — same input produces same verdict in Rust, Python, WASM
R9: README leads with "what we don't catch" — honesty as reputational moat
R10: No emojis in code or docs
R11: No bundled ONNX weights (BYO-ONNX interface only)
R12: Sync core; async only in middleware layer

## v0.1 must ship
Detectors in `sieve-core`: UnicodeNormalizer, PatternScanner, EncodingScanner, HeuristicScorer, CanaryEngine, heuristic context analyzer, deterministic commitment checks, BYO-ONNX trait. Bindings: Rust crate, Python wheel, WASM, `@sieve/nextjs`. Contrib helpers: OpenAI + Anthropic (Python), Vercel AI SDK + OpenAI (Next.js).

## v0.1 out of scope (capture in `v0.2-backlog.md`, do not build)
Tool-call linter, conversation tracker, RAG/spotlighting, piggyback LLM analyzer, napi-rs Node binding, Go binding, bundled ONNX weights, LLM-judge, differential testing, streaming, PII, CLI, HTTP sidecar, LangChain/LlamaIndex/LiteLLM wrappers.

## Execution
Follow `IMPLEMENTATION_PROMPT.md` phases 0–19 sequentially. Each phase ends with an atomic commit and green CI. Never skip or bundle phases.

## Test pyramid (every phase contributes)
Unit (≥90% coverage), property (proptest 1000+ cases), fuzz (cargo-fuzz + OSS-Fuzz), integration, corpus (JailbreakBench / garak / ACL 2025 bypasses / curated benign), regression (every reported bypass becomes a permanent test), cross-language consistency (Rust/Python/WASM identical verdicts), performance regression (criterion, fail >10%), memory (Valgrind, ASAN), WASM-specific (<2MB, Cloudflare Workers + Vercel Edge), real-LLM nightly (secrets-gated), adversarial probes (≥95% catch, ≤2% FPR).

## Quality gates per commit
`cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all-features`, `cargo deny check`, coverage report (no drop >1%), cross-language consistency tests green.

## Anti-patterns — DO NOT
Add network or LLM deps to core. Add telemetry. Bundle ONNX weights. Add async to core. Pull v0.2 features forward. Suppress findings to flatter benchmarks. Refactor unrelated code mid-phase. Skip the "what we don't catch" README section.

## Start
1. Read all canonical docs in full.
2. Resolve open decisions (§11 of IMPLEMENTATION_PROMPT.md) into `DECISIONS.md`. Verify name availability on crates.io/PyPI/npm before locking.
3. Execute Phase 0 (scaffold workspace) → atomic commit → CI green.
4. Proceed phase-by-phase. Do not skip or bundle.
5. When v0.1.0 is tagged: run the launch plan (PRD §15).
