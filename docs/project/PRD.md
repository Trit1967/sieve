# PRD: Vendor-Neutral Prompt Injection Defense Library

> Status: Draft v0.2 (replaces v0.1, reflects vendor-neutral pivot + novel-mechanism roadmap)
> Author: Rob
> Last updated: 2026-05-16
> Working title: `sieve` (final name TBD)
> Companion docs: [ARCHITECTURE.md](ARCHITECTURE.md), [research/LANDSCAPE.md](../../research/LANDSCAPE.md)

---

## 0. Executive summary

`sieve` is a vendor-neutral, embeddable, offline-first library for detecting prompt injection attacks against LLM applications. It operates on strings — system prompts, user inputs, model outputs — and emits structured verdicts. It never makes a network call, never requires a specific LLM vendor, and never phones home.

Built in Rust with bindings for Python, WASM (v0.1), Node, and Go (v0.2). Designed to drop into any existing project in any major LLM ecosystem in one line.

Differentiators vs. existing tools (Lakera, LLM Guard, Rebuff, Azure Prompt Shields, etc.):

1. **Vendor-neutral by architecture.** Strings in, verdicts out. No SDK lock-in, no service, no telemetry.
2. **Catches Unicode/emoji smuggling** — documented as 100% effective bypass against all named competitors (ACL LLMSec 2025).
3. **Output-first signal** — primary detection is canary leak + behavioral commitment violation in model output, not input pattern matching.
4. **Context-aware verdicts** — analyzes input against the system prompt's specific instructions, not in isolation.
5. **Tool-call linter** for agentic systems (no incumbent ships this).
6. **BYO-ONNX classifier interface** — decouples model from runtime; users plug in any HuggingFace prompt-injection classifier.
7. **Open community corpus** — separate repo, MIT-licensed attack patterns, contributor-driven curation.

---

## 1. Vendor neutrality — first principles

These are inviolable architectural rules. Violation requires rewriting the PRD.

| Principle | Implication |
|---|---|
| **The library operates on strings, not SDK objects** | `scan_input(system_prompt: &str, user_input: &str) -> Verdict`. No `OpenAI`, `Anthropic`, etc. in core signatures. |
| **The library makes zero network calls** | No telemetry, no remote rule updates, no model downloads at runtime, no provider API calls. Wordlists and weights ship in the binary or are loaded from disk by the user. |
| **The library has zero vendor SDK dependencies in core** | `Cargo.toml` for `sieve-core` lists no LLM provider crate. PyPI `sieve` package has no LLM provider dependency. |
| **Optional convenience wrappers live in separate sub-packages** | `sieve.contrib.openai`, `sieve.contrib.anthropic`, etc. Users install only what they use. |
| **The library never requires user credentials** | Library never sees API keys. If a user opts into LLM-piggyback context analysis (v0.2), the LLM call happens in user code, not ours. |
| **The library never requires an account or signup** | No hosted version, ever. There is no "sieve.io". |
| **The library is dual-licensed MIT + Apache-2.0** | Rust ecosystem default. Maximum adoption, zero surprises. |
| **Telemetry is opt-in, local-only, and explicitly documented** | Counters and latency histograms available via `scanner.metrics()`, never auto-exported anywhere. |

### What this looks like in practice

The primary API works with **any** LLM source — including no LLM at all:

```rust
// Pure local Llama via mistral.rs
let response = mistral.generate(&prompt).await?;
scanner.scan_output(&response, &canary_state);

// Ollama
let response = ollama_client.generate(prompt).await?;
scanner.scan_output(&response, &canary_state);

// Anthropic
let response = anthropic.messages_create(...).await?;
scanner.scan_output(&response.content[0].text, &canary_state);

// Internal custom HTTP model
let response: String = reqwest::post(internal_url).send().await?.text().await?;
scanner.scan_output(&response, &canary_state);

// No LLM at all — just filtering input before a downstream system
let verdict = scanner.scan_input(&system_prompt, &user_input);
```

---

## 2. Problem statement

LLM applications are vulnerable to prompt injection: malicious input that hijacks the model's instructions, exfiltrates the system prompt, or causes policy-violating behavior. The current defense landscape has structural problems:

1. **Language lock-in.** Every credible OSS tool (LLM Guard, Rebuff, Vigil, NeMo Guardrails, Guardrails AI) is Python-only with no FFI. Compiled-language teams have no native option.
2. **Documented bypasses.** Unicode zero-width chars, emoji smuggling, and homoglyphs achieve up to **100% evasion** against Azure Prompt Shields, Meta Prompt Guard, and four other major systems (arXiv 2504.11168, ACL LLMSec 2025). No published defense has shipped a fix.
3. **Vendor consolidation.** Rebuff and LLM Guard → Palo Alto (Jul 2025, $500M). Lakera → Cisco (May 2025). CalypsoAI → F5 (Sep 2025, $180M). Robust Intelligence → Cisco (Oct 2024). The community's open alternatives are all now under enterprise control. Trust positioning is unusually open.
4. **Bolt-on integration.** Existing tools require manual `scan()` calls. Teams forget output scanning, skip canary tokens, miss tool-call args. Integration friction kills correctness.
5. **Context-blind scanning.** Existing tools scan input in isolation, without knowledge of the system prompt. Structurally high FPR.
6. **No tool-call defense.** Agentic systems with tool access are the fastest-growing attack surface. No incumbent ships protection at this layer.

## 3. Goals and non-goals

### Goals

| ID | Goal | Measurable success |
|---|---|---|
| G1 | Detect common prompt injection in <10ms p99 overhead per call | Benchmark suite passes; documented in README |
| G2 | 100% catch rate on documented Unicode/emoji bypass attacks | Test corpus from ACL 2025 paper passes |
| G3 | Vendor-neutral core: zero network, zero LLM SDK deps | `cargo tree` and `pip show` audits in CI |
| G4 | First-class bindings for Python (PyPI) and WASM (npm) in v0.1 | Published wheels and packages |
| G5 | Drop-in integration in any Python or Next.js project in one line via optional contrib helpers | Working examples in README |
| G6 | Reproducible benchmark suite vs. JailbreakBench + garak + ACL'25 | Public benchmark.md in repo |
| G7 | Earn community trust through honest scope, permissive license, no telemetry | Public statement in README; audited by independent reviewer |
| G8 | Ship a tool-call linter no incumbent offers (v0.2) | Working module + tests |
| G9 | Provide a BYO-ONNX classifier interface | Trait + reference impl with public HF model |

### Non-goals

| ID | Non-goal | Why |
|---|---|---|
| N1 | Defeating adaptive adversarial attackers | Industry-wide unsolved (<50% effective everywhere). We won't claim to. |
| N2 | Replacing enterprise AI security platforms | Cisco AI Defense / Prisma AIRS are different products. |
| N3 | Training/distributing our own ML weights | License complexity; users bring their own model via BYO-ONNX. |
| N4 | LLM-as-judge as the primary defense | Adds latency + cost; optional integration only. |
| N5 | A hosted service or SaaS | Library only. No `sieve.io` will ever exist. |
| N6 | PII detection | Adjacent problem; deferred to v0.4+ or sister project. |
| N7 | Telemetry / phone-home of any kind | Permanent commitment. |
| N8 | Generic content moderation (toxicity, hate, etc.) | Llama Guard's job, not ours. |

## 4. Target users

| Persona | Pain | Adoption motivation |
|---|---|---|
| **Rust LLM-app developer** | No native Rust option; Python sidecar = operational burden | Drop-in crate, zero network deps |
| **Python team on FastAPI/Flask/Django** | LLM Guard adds 1-5 sec/request; Lakera = vendor lock-in | One-line `sieve.wrap(client)`, sub-30ms overhead |
| **Next.js / Vercel AI SDK developer** | No Edge-runtime-compatible defense exists | WASM build works in Edge runtime + Node runtime |
| **Privacy-constrained team** (healthcare/finance/gov) | Cannot send prompts to cloud APIs | 100% offline, deterministic, auditable |
| **Edge/serverless developer** | Cloud guardrails add 50–200ms cold start | <2MB WASM, runs in Cloudflare Workers / Vercel Edge / Deno |
| **Open-source LLM project** (Ollama, vLLM, llama.cpp wrappers) | Existing tools assume OpenAI/Anthropic | Works on raw strings, no vendor coupling |
| **Agentic framework builder** (custom MCP, agent SDK, etc.) | No defense layer for tool-call injection | Tool-call linter (v0.2) |
| **Security researcher** | Wants to benchmark / probe defenses | Open source, permissive license, no signup |

## 5. Core principles

1. **Library, not framework.** Closer in spirit to `serde` or `tokio` than to LangChain.
2. **Strings in, verdicts out.** The core API operates on `&str`. Nothing else.
3. **Fail open, fail loud.** Default to flag-not-block on ambiguous cases. Always emit structured findings even on allow.
4. **No magic.** Deterministic, inspectable, debuggable. Same input → same verdict, always.
5. **Honest scope.** README leads with what we don't catch.
6. **One sharp tool, not a toolkit.** PII, toxicity, hate speech — out of scope. We are a prompt-injection defense library.

## 6. Public API

### 6.1 Rust — primary, vendor-neutral

```rust
use sieve::{Scanner, Verdict};

let scanner = Scanner::default();

// Pre-flight
let pre: Verdict = scanner.scan_input(&system_prompt, &user_input);

if pre.is_block() {
    return Err(MyError::InjectionBlocked);
}

// User calls THEIR LLM however they want
let response: String = my_llm.generate(...).await?;

// Post-flight
let post: Verdict = scanner.scan_output(&response, pre.canary_state());

println!("{:#?}", post);
// Verdict {
//   decision: Allow,
//   score: 0.12,
//   findings: [...],
//   normalized_input: Some("..."),  // post-Unicode-normalization
//   canaries_leaked: [],
//   commitments_violated: [],
//   latency_us: 1842,
// }
```

### 6.2 Rust — builder for customization

```rust
let scanner = Scanner::builder()
    .with_unicode(UnicodeOpts { strip_zero_width: true, homoglyph_map: true, .. })
    .with_patterns(Patterns::builtin())
    .with_patterns_from_file("custom_patterns.txt")
    .with_encoding(Encoding::default())
    .with_heuristics(Heuristics::default())
    .with_canary(CanaryOpts::auto_from_system_prompt())
    .with_commitments(Commitments::extract_from_system_prompt())
    .with_classifier(MyOnnxClassifier::load("model.onnx")?)  // optional BYO-ONNX
    .build();
```

### 6.3 Python — primary, vendor-neutral

```python
import sieve

scanner = sieve.Scanner()

pre = scanner.scan_input(system_prompt, user_input)
if pre.is_block():
    raise InjectionBlocked()

response = your_llm_call()  # Ollama, OpenAI, Anthropic, custom — doesn't matter

post = scanner.scan_output(response, pre.canary_state)
print(post.decision, post.findings)
```

### 6.4 Python — optional convenience wrappers (contrib)

Installed separately, vendor-specific sugar over the primary API:

```python
# pip install sieve-guard[openai]
from sieve.contrib.openai import wrap
from openai import OpenAI

client = wrap(OpenAI())
resp = client.chat.completions.create(...)
print(resp.sieve.decision)
```

```python
# pip install sieve-guard[anthropic]
from sieve.contrib.anthropic import wrap
from anthropic import Anthropic

client = wrap(Anthropic())
resp = client.messages.create(...)
print(resp.sieve.decision)
```

### 6.5 WASM / Next.js — primary

```typescript
import init, { Scanner } from 'sieve-guard-wasm';
await init();

const scanner = new Scanner();
const pre = scanner.scan_input(systemPrompt, userInput);
if (pre.is_block()) return Response.json({ error: 'blocked' }, { status: 400 });

const response = await yourLlmCall();
const post = scanner.scan_output(response, pre.canary_state);
```

### 6.6 Next.js — optional contrib wrappers

```typescript
// npm install sieve-guard-nextjs sieve-guard-wasm
import { wrapOpenAI } from 'sieve-guard-nextjs/openai';
import OpenAI from 'openai';

const client = wrapOpenAI(new OpenAI());
// All calls auto-protected. Response includes .sieve metadata.
```

```typescript
// Vercel AI SDK middleware
import { sieveMiddleware } from 'sieve-guard-nextjs/ai-sdk';
import { openai } from '@ai-sdk/openai';

const protectedModel = sieveMiddleware(openai('gpt-4o'));
```

### 6.7 Verdict schema (cross-language stable)

```rust
pub struct Verdict {
    pub decision: Decision,
    pub score: f32,                   // 0.0 safe → 1.0 malicious
    pub findings: Vec<Finding>,
    pub normalized_input: Option<String>,
    pub canary_state: CanaryState,
    pub canaries_leaked: Vec<CanaryLeak>,
    pub commitments_violated: Vec<CommitmentViolation>,
    pub latency_us: u64,
}

pub enum Decision { Allow, Flag, Block }

pub struct Finding {
    pub detector: &'static str,
    pub severity: Severity,
    pub message: String,
    pub matched_span: Option<(usize, usize)>,
    pub score: f32,
    pub category: Category,
}

pub enum Severity { Info, Warn, Block }
pub enum Category {
    UnicodeSmuggling,
    KnownPattern,
    EncodingPayload,
    InstructionDensity,
    LanguageSwitch,
    HighEntropy,
    CanaryLeak,
    CommitmentViolation,
    ToolCallAnomaly,        // v0.2+
    ConversationDrift,      // v0.2+
}
```

JSON-serializable. Stable schema across Rust/Python/WASM/Node.

## 7. Core mechanisms

### 7.1 Detectors (v0.1)

| Detector | Approach | Latency target | Catches |
|---|---|---|---|
| **UnicodeNormalizer** | NFKC normalization → strip zero-width (U+200B/C/D, U+FEFF, U+2060, U+E0000–U+E007F) → optional homoglyph map (TR39 confusables subset) → return original + normalized | <500µs | Documented 100%-evasion attacks (ACL 2025) |
| **PatternScanner** | Aho-Corasick over curated ~5,000 phrase wordlist; case-insensitive, whitespace-normalized | <1ms / 10KB | Known jailbreak phrasings |
| **EncodingScanner** | Detect base64/hex/rot13 segments; recursively decode (max 2 levels); re-scan decoded content | <2ms | Smuggled payloads in encoded form |
| **HeuristicScorer** | Instruction-density (verb proximity to "ignore/disregard/forget"), script-switch detection, repetition entropy | <1ms | Adversarial inputs lacking known patterns |
| **CanaryEngine** | Generate per-call canary tokens from system prompt; inject markers; scan output for leakage | <100µs inject; <500µs scan | Goal hijacking (model leaks system prompt) |

### 7.2 Novel mechanisms (v0.1 ships some, v0.2 ships rest)

| Mechanism | Ships in | Status today (industry) | Our approach |
|---|---|---|---|
| **BYO-ONNX classifier interface** | v0.1 | Python tools bundle weights, license-coupled | Trait + `ort` runtime; ship without weights; document plugging in HF models |
| **Context-aware scanning (heuristic)** | v0.1 | Nobody does | Parse system prompt → atomic instructions; map input to override attempts |
| **Open community corpus** (`sieve-corpus` repo) | v0.1 | Nobody does | Independent repo, MIT, weekly curated releases, contributor-driven |
| **Behavioral commitment checking (deterministic)** | v0.1 | Nobody does | Extract commitments (language, persona, refusal keywords) → verify in output |
| **Piggyback LLM context analyzer** | v0.2 | Nobody does | Generic `LlmCallable` trait — user supplies any callable; one extra call analyzes input vs system prompt |
| **Provenance-aware RAG scanning + spotlighting** | v0.2 | Microsoft has spotlighting only | `scan_retrieved(text, provenance)` API; auto-wrap retrieved content in spotlight markers |
| **Tool-call linter** | v0.2 | Nobody does | Inspect tool calls before execution; declarative invariants per tool; block calls violating contract |
| **Conversation state tracker** | v0.2 | Nobody does | Track cumulative risk + canary state + topic drift across turns |
| **Behavioral commitment checking (semantic, LLM-judge optional)** | v0.3 | Nobody does | LLM-as-judge fallback for non-deterministic commitments |
| **Differential testing** | v0.3 | Nobody does | Optional re-run with normalized input; compare output divergence |

### 7.3 BYO-ONNX interface (v0.1 detail)

```rust
pub trait Classifier: Send + Sync {
    fn classify(&self, input: &str) -> ClassificationResult;
}

pub struct ClassificationResult {
    pub score: f32,
    pub label: String,
    pub metadata: HashMap<String, String>,
}

// Reference implementation using `ort` (ONNX Runtime)
pub struct OnnxClassifier { /* ... */ }
impl OnnxClassifier {
    pub fn load(path: &Path) -> Result<Self>;
    pub fn from_bytes(bytes: &[u8]) -> Result<Self>;
}
```

Documented compatible models (no weights bundled):
- `deepset/deberta-v3-base-injection`
- `protectai/deberta-v3-base-prompt-injection-v2`
- Any compatible HuggingFace model exported via `optimum`

## 8. Architecture overview

Full detail in [ARCHITECTURE.md](ARCHITECTURE.md). Layered view:

```
L1 (Optional) SDK Middleware (contrib) — convenience wrappers per SDK
L2 Public API — vendor-neutral string-in/verdict-out
L3 Pipeline:
   L3a Context Analyzer
   L3b Detector Pipeline (Unicode / Patterns / Encoding / Heuristics)
   L3c Canary Engine
   L3d Optional BYO Classifier
L4 Output Verifier (canary leak + commitment check)
L5 Verdict Synthesis
L6 Telemetry (local-only, opt-in)
```

Cross-language: pure Rust core, FFI in bindings only.

```
sieve-core (pure Rust, zero LLM deps)
   ├── sieve-py     (pyo3 binding + Python contrib middleware)
   ├── sieve-wasm   (wasm-bindgen)
   ├── sieve-node   (napi-rs — v0.2)
   └── sieve-go     (cgo + cbindgen — v0.2)
```

## 9. Functional requirements

### 9.1 Detection capability

| Capability | v0.1 | v0.2 | v0.3 |
|---|---|---|---|
| Unicode normalization | ✓ | | |
| Known-pattern scanning | ✓ | | |
| Encoding scanner | ✓ | | |
| Heuristic scorer | ✓ | | |
| Canary engine | ✓ | | |
| BYO-ONNX classifier interface | ✓ | | |
| Context-aware analyzer (heuristic) | ✓ | | |
| Deterministic commitment checks | ✓ | | |
| Tool-call linter | | ✓ | |
| Provenance/RAG scanning + spotlighting | | ✓ | |
| Conversation state tracker | | ✓ | |
| Piggyback LLM context analyzer | | ✓ | |
| Bundled reference ONNX classifier (optional feature) | | | ✓ |
| Semantic commitment checks (LLM-judge optional) | | | ✓ |
| Differential testing | | | ✓ |
| Streaming output scan | | | ✓ |

### 9.2 Binding/distribution

| Binding | v0.1 | v0.2 | v0.3 |
|---|---|---|---|
| Rust crate (crates.io) | ✓ | | |
| Python wheel (PyPI) | ✓ | | |
| WASM (npm: `sieve-guard-wasm`) | ✓ | | |
| Next.js helpers (npm: `sieve-guard-nextjs`) | ✓ | | |
| Node native (napi-rs, npm: `sieve-guard-node`) | | ✓ | |
| Go (cgo + cbindgen) | | ✓ | |
| Swift/Kotlin (uniffi) | | | ✓ |
| CLI tool | | | ✓ |
| HTTP sidecar mode | | | ✓ |

### 9.3 Optional contrib wrappers

| Wrapper | v0.1 | v0.2 |
|---|---|---|
| `sieve.contrib.openai` (Python) | ✓ | |
| `sieve.contrib.anthropic` (Python) | ✓ | |
| `sieve-guard-nextjs/openai` | ✓ | |
| `sieve-guard-nextjs/ai-sdk` (Vercel AI SDK) | ✓ | |
| `sieve.contrib.litellm` | | ✓ |
| `sieve.contrib.langchain` | | ✓ |
| `sieve.contrib.llamaindex` | | ✓ |

## 10. Non-functional requirements

| Requirement | Target | Verification |
|---|---|---|
| **Latency** — default pipeline, 1KB input | p50 <5ms, p99 <10ms on modern x86_64 | criterion bench in CI |
| **Throughput** — single-threaded | >10K req/sec | criterion bench |
| **Memory** — resident with default config | <50MB | RSS measurement in CI |
| **Crate binary size** (release) | <5MB | size check in CI |
| **WASM size** (release, default features) | <2MB | size check in CI; fail build if exceeded |
| **WASM cold start** | <50ms in Cloudflare Workers / Vercel Edge | Edge runtime integration test |
| **Dependencies** (core) | aho-corasick, unicode-normalization, regex, serde, ort (optional feature) | `cargo tree` in CI |
| **MSRV** | Stable Rust -2 | CI matrix |
| **Platforms** | Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64, WASM32 | CI matrix |
| **License** | Dual MIT + Apache-2.0 | SPDX in every file |
| **Telemetry** | None by default; opt-in local-only metrics API | Audit in CI (grep for forbidden patterns) |
| **Cross-binding consistency** | Same input → same verdict across Rust/Python/WASM | Cross-language consistency test suite |

## 11. Test strategy

Security-adjacent code requires deeper testing than typical libraries. The following is the canonical test plan.

### 11.1 Test pyramid

```
                  ┌─────────────────────┐
                  │  Real-LLM tests     │   nightly, opt-in, gated on secrets
                  │  (live OpenAI/      │
                  │  Anthropic/Ollama)  │
                  └─────────────────────┘
              ┌───────────────────────────┐
              │  E2E / corpus tests       │   JailbreakBench, garak, ACL'25
              │  (every commit)           │   curated benign + malicious sets
              └───────────────────────────┘
        ┌─────────────────────────────────┐
        │  Integration tests              │   full pipeline; cross-binding
        │  (every commit)                 │   consistency tests
        └─────────────────────────────────┘
    ┌─────────────────────────────────────┐
    │  Property tests (proptest)          │   Unicode, parsers, AhoCorasick
    │  (every commit, 1000+ cases)        │
    └─────────────────────────────────────┘
┌─────────────────────────────────────────┐
│  Unit tests + Fuzz (cargo-fuzz)         │   per module; continuous fuzzing
│  (every commit)                         │   via oss-fuzz integration
└─────────────────────────────────────────┘
```

### 11.2 Unit tests

- Every public function and trait method has at least one happy-path and one edge-case test
- Every detector module has 95%+ line coverage (tracked by `cargo-tarpaulin` or `cargo-llvm-cov`)
- Every error variant has a test that triggers it
- No `unwrap()` outside tests in production code; verified by `cargo-deny` rule

### 11.3 Property tests (proptest)

| Property | Module |
|---|---|
| `normalize(normalize(x)) == normalize(x)` (idempotence) | UnicodeNormalizer |
| `len(normalize(x)) <= len(x)` (normalization never grows) | UnicodeNormalizer |
| All zero-width chars stripped from output | UnicodeNormalizer |
| `scan(x) == scan(x)` deterministic across runs | Scanner |
| Verdict serialization round-trips (`from_json(to_json(v)) == v`) | Verdict |
| Canary generation produces unique tokens per call | CanaryEngine |
| Pattern matching is whitespace-invariant where configured | PatternScanner |
| Encoding scanner does not infinite-loop on adversarial input | EncodingScanner |

Run 1,000+ cases per property in CI.

### 11.4 Fuzz tests (cargo-fuzz)

Continuous fuzzing via OSS-Fuzz integration (free for OSS security tools).

| Fuzz target | Property |
|---|---|
| `scan_input` | Never panics on any UTF-8 input |
| `scan_input` | Never allocates >100MB |
| `scan_output` | Never panics |
| `scan_output` | Bounded latency (<100ms even adversarial) |
| `normalize_unicode` | Output is valid UTF-8 |
| `decode_encoded` | Bounded recursion depth |
| `pattern_scan` | Bounded latency on adversarial wordlist + input |

Initial fuzz dictionary seeded with corpus attack strings.

### 11.5 Integration tests

| Test | Coverage |
|---|---|
| Full pipeline with default scanner | All detectors fire correctly |
| Full pipeline with custom builder | Configurations compose |
| Allow/Flag/Block decision boundaries | Threshold logic |
| Verdict structure for each decision | All fields populated correctly |
| Concurrent scans (rayon-based) | Thread safety |
| Long input (1MB+) | Latency stays bounded |
| Repeated calls (1M sequential) | No memory leak (Valgrind / ASAN) |
| Empty input, only whitespace, unicode-only input | Edge cases handled |

### 11.6 Corpus tests (the credibility tests)

Test against external datasets — these are the numbers we publish:

| Corpus | Source | License | Use |
|---|---|---|---|
| JailbreakBench | github.com/JailbreakBench/jailbreakbench | MIT | Detection rate on academic-standard jailbreaks |
| garak probes | github.com/NVIDIA/garak | Apache 2.0 | Wide attack surface coverage |
| ACL LLMSec 2025 bypasses | arXiv 2504.11168 (cited samples) | Cite + redistribute under fair use | Our hero feature: 100% catch claim |
| Curated benign inputs | We curate | MIT | False-positive measurement |
| HarmBench | github.com/centerforaisafety/HarmBench | MIT | Behavioral commitment violation tests |

For each, the test suite reports:
- Detection rate (% flagged or blocked)
- False positive rate on benign set
- Per-category breakdown (Unicode, encoding, instruction-override, etc.)
- p50 / p99 latency on the corpus
- Comparison vs. published numbers (Lakera 74.6%, Azure 42.98%, etc.)

These numbers go in `benchmarks.md` and are regenerated on every release.

### 11.7 Regression tests

Every reported bypass becomes a permanent test case. Workflow:

1. Bug report comes in with a bypassing input
2. New test added to `tests/regression/` with the input + expected verdict
3. Fix applied
4. Test now passes
5. Test permanently runs in CI; never removed

By v1.0 we should have hundreds of regression tests, each named after the issue/CVE.

### 11.8 Cross-language consistency tests

Critical: Rust, Python, WASM must produce identical verdicts for identical inputs. Otherwise our cross-language story is a lie.

```python
# tests/cross_language/test_consistency.py
TEST_INPUTS = load_test_corpus()

for input in TEST_INPUTS:
    rust_verdict = run_rust_cli(input)
    py_verdict = sieve.Scanner().scan_input(input.system, input.user)
    wasm_verdict = run_wasm_node(input)

    assert rust_verdict.decision == py_verdict.decision == wasm_verdict.decision
    assert abs(rust_verdict.score - py_verdict.score) < 0.001
    assert abs(rust_verdict.score - wasm_verdict.score) < 0.001
    assert canonical_findings(rust_verdict) == canonical_findings(py_verdict) == canonical_findings(wasm_verdict)
```

Runs on every commit.

### 11.9 Performance regression tests (criterion)

CI fails if any benchmark regresses >10% vs. previous release.

| Benchmark | Threshold |
|---|---|
| `scan_input_small` (100B input) | <1ms p99 |
| `scan_input_medium` (1KB input) | <5ms p99 |
| `scan_input_large` (10KB input) | <20ms p99 |
| `scan_output_with_canary` | <1ms p99 |
| `unicode_normalize` | <500µs p99 |
| `pattern_scan_10kb` | <1ms p99 |

Results published as flame graphs + markdown table in repo.

### 11.10 Memory tests

- No memory leaks (Valgrind nightly, ASAN on every commit)
- Bounded peak allocation per scan (<10MB)
- 1M sequential scans → no allocator growth (`heaptrack` periodic)

### 11.11 WASM-specific tests

- Bundle size budget: <2MB compressed (fail build if exceeded)
- Cold-start latency in Cloudflare Workers (real wrangler-based test in CI)
- Cold-start in Vercel Edge runtime (integration test)
- Functional parity with native Rust (cross-language test suite)
- Streaming-compatible: scan partial outputs

### 11.12 Real-LLM integration tests (opt-in, nightly)

Gated on `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_URL` secrets. Run nightly only.

For each provider:
- 100 known attack inputs → measure catch rate
- 100 benign inputs → measure FPR
- 50 system-prompt-override attempts → measure context-aware detection rate
- Canary leak rate with and without sieve protection

This is what fuels the launch blog post numbers.

### 11.13 Platform matrix

CI runs on:
| OS | Arch | Rust | Python |
|---|---|---|---|
| Ubuntu 22.04 | x86_64 | stable / MSRV / nightly | 3.9, 3.10, 3.11, 3.12 |
| Ubuntu 22.04 | aarch64 | stable | 3.11 |
| macOS 13 | x86_64 | stable | 3.11 |
| macOS 14 | aarch64 | stable | 3.11 |
| Windows 2022 | x86_64 | stable | 3.11 |
| WASM | wasm32-unknown-unknown | stable | N/A |

### 11.14 Soak / stability tests

Pre-release only:
- 24h continuous scan loop with random inputs → no crashes, no memory growth
- Stress test: 1000 concurrent scan threads for 1h → no panics, bounded latency

### 11.15 Coverage targets

- `sieve-core` lines: ≥90%
- `sieve-core` branches: ≥85%
- Public API: 100% (every function called by a test)
- Bindings (sieve-py, sieve-wasm): ≥80%

Tracked via Codecov + reported on every PR.

### 11.16 Adversarial / red-team tests

Automated probes inspired by garak — run against the library, not an LLM:

- **Bypass attempts** with each Unicode trick variant (zero-width, tags, homoglyphs, combining chars, RTL overrides, math alphanumerics)
- **Encoding combinations** (base64-of-base64, base64-of-hex, etc.)
- **Wordlist evasion** (deliberate misspellings, l33t speak, Unicode-substituted letters)
- **Heuristic gaming** (high-entropy benign inputs that shouldn't trip the scorer)
- **Canary leak forgery** (model outputs strings similar to canaries without actual hijack)
- **Commitment bypass** (output that technically meets commitment but violates spirit)

Targets: catch rate ≥95% on the bypass set, FPR ≤2% on benign set.

### 11.17 Documentation tests

- Every code block in README is executable via `rustdoc --test` or doctest equivalents
- Every example in `examples/` directory runs in CI
- API docs build cleanly with no broken links
- `mdbook` for the long-form user guide; built and link-checked in CI

## 12. Roadmap

### v0.1 — "Vendor-Neutral Core" (target: 4 weeks)
- Core Rust crate with all v0.1 detectors
- Python binding (pyo3 + maturin) + contrib wrappers (openai, anthropic)
- WASM binding (wasm-bindgen) + `sieve-guard-nextjs` helpers
- BYO-ONNX classifier interface (no bundled weights)
- Heuristic context analyzer
- Deterministic commitment checks
- Full test pyramid up through corpus tests
- Benchmark suite with public numbers vs. JailbreakBench/garak/ACL'25
- README with honest scope
- `sieve-corpus` repo bootstrapped with ~5,000 patterns

### v0.2 — "Agentic + Multi-Turn" (target: 8 weeks post-v0.1)
- Tool-call linter with declarative invariants
- Provenance-aware RAG scanning + auto-spotlighting
- Conversation state tracker (multi-turn arcs)
- Piggyback LLM context analyzer (generic `LlmCallable` trait)
- Node binding (napi-rs)
- Go binding (cgo + cbindgen)
- More Python contrib: LiteLLM, LangChain, LlamaIndex
- TOML config file support

### v0.3 — "Classifier + Differential" (target: 16 weeks post-v0.1)
- Bundled reference ONNX classifier (opt-in feature, no default model)
- Semantic commitment checks (LLM-judge optional)
- Differential testing (opt-in per-call)
- Streaming output scanning
- CLI tool (`sieve scan file.txt`)
- HTTP sidecar mode
- Swift/Kotlin bindings (uniffi)

### v0.4+ — "Open-ended"
- PII detection (sister project, separate crate)
- Custom rule DSL
- Browser extension (catch injection in UI before it hits backend)

### v1.0 — when:
- Real production adopters at 25+ orgs
- Test coverage ≥90%
- API stable (no breaking changes for 3 months)
- Cross-binding consistency verified
- Independent security audit completed

## 13. Threat model — what we catch, what we don't

### What this library catches with high confidence
- Known jailbreak phrase patterns (~5,000 curated)
- Unicode smuggling (zero-width, homoglyphs, tags, math alphanumerics)
- Base64/hex/rot13-encoded payloads (one level of nesting)
- Goal hijacking via canary token leakage in output
- Deterministic behavioral commitment violations (language, persona, refusal keywords)
- High-entropy instruction overrides
- (v0.2) Tool-call argument anomalies vs declared invariants
- (v0.2) Cross-turn risk accumulation

### What this library does NOT catch
- **Novel paraphrased jailbreaks** not in the pattern corpus
- **Adaptive adversarial attacks** (gradient-optimized, RL-driven). Industry-wide unsolved.
- **Semantic attacks** that achieve injection via plausible-sounding natural language without recognizable patterns
- **Multi-turn social engineering** beyond what the conversation tracker handles
- **Indirect injection from RAG** — we *flag* with provenance; we cannot *stop* it. The model can still be persuaded by retrieved content.
- **Behavioral drift from commitments** that require semantic understanding (handled in v0.3 via optional LLM judge)
- **Side-channel attacks** (timing, prompt-length-based information leakage)
- **Generic content moderation** (toxicity, hate, NSFW) — out of scope, use Llama Guard

The README leads with this list. Honesty is the project's reputational moat.

## 14. Success metrics

| Metric | 3 months | 12 months |
|---|---|---|
| GitHub stars (main repo) | 500 | 3,000 |
| Crates.io downloads | 5,000 | 100,000 |
| PyPI downloads | 20,000 | 500,000 |
| npm downloads (`sieve-guard-wasm` + `sieve-guard-nextjs`) | 5,000 | 100,000 |
| Production adopters (named, with permission) | 3 | 25 |
| External contributors (>1 merged PR) | 2 | 15 |
| HN front page hits | ≥1 | — |
| Reported & fixed bypasses | — | ≥10 |
| Corpus repo PRs (`sieve-corpus`) | 5 | 100 |
| Coverage % (sieve-core) | ≥85% | ≥90% |

## 15. Launch plan

### Phase 1 — Build (week 1–3)
- Cargo workspace scaffold
- Implement v0.1 detectors with unit + property tests
- Python binding (pyo3 + maturin)
- WASM binding (wasm-bindgen)
- Optional contrib wrappers for OpenAI, Anthropic, Vercel AI SDK
- README draft (the marketing artifact)

### Phase 2 — Validate (week 4)
- Run full corpus suite; generate benchmark numbers
- Run cross-language consistency tests
- Run live-LLM integration tests with API keys
- Cut v0.1.0-rc1; publish to crates.io / PyPI / npm under pre-release tags
- Internal red-team pass

### Phase 3 — Launch (week 5)
- Blog post: "Why your prompt injection defense doesn't catch zero-width characters" (cites ACL 2025)
- Show HN post leading with the side-by-side Unicode bypass demo
- Cross-post: /r/rust, /r/MachineLearning, /r/LocalLLaMA, Lobsters
- Tweet thread with the comparison screenshots
- v0.1.0 final tag

### Phase 4 — Sustain (month 2+)
- 24-72h issue response SLA
- Weekly `sieve-corpus` curation
- Patch releases for reported bypasses
- v0.2 development in parallel

## 16. Open questions

| # | Question | Default |
|---|---|---|
| 1 | **Name** | `sieve` (working). Alternatives: `shibboleth`, `prompt-sieve`, `latch`, `untangle`. |
| 2 | Aho-Corasick wordlist source | Mix curated + license-audited public (LLM Guard MIT + Rebuff Apache + garak Apache + JailbreakBench MIT) |
| 3 | Homoglyph map source | TR39 confusables, Latin/Cyrillic/Greek subset for v0.1 |
| 4 | Telemetry | **Zero, ever.** Document as feature. |
| 5 | Wordlist update mechanism | Bundle in crate, no remote fetch. Separate `sieve-corpus` repo for community updates. |
| 6 | Versioning | Pre-1.0 SemVer with experimental disclaimer until v1.0 |
| 7 | Async core | Sync core, async orchestrator/middleware only |
| 8 | Canary scheme | Random 16-byte tokens base64-encoded; pluggable in v0.2 |
| 9 | Wordlist size budget | <500KB for builtin set; users add custom files |
| 10 | Optional features (Cargo) | `ort` (ONNX), `commitments-llm` (LLM-judge), `contrib-*` | 

## 17. Appendix: research references

- `research/LANDSCAPE.md` — full competitive landscape
- arXiv 2504.11168 — ACL LLMSec 2025 Unicode bypass paper
- arXiv 2505.13028 — Palit independent benchmark
- JailbreakBench (NeurIPS 2024)
- garak (NVIDIA)
- TR39 Unicode confusables
- OWASP LLM Top 10 (2025)
- Microsoft Spotlighting technique (Build 2025)
