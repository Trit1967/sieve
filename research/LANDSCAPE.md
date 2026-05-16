# Prompt Injection Defense / LLM Input Filtering — Competitive Landscape
> Research date: 2026-05-16 | Scope: build/no-build decision + positioning for a Rust-native library

---

## Comparison Table

| Tool | Approach | Language/Runtime | License | Standout Strength | Standout Weakness |
|------|----------|-----------------|---------|-------------------|-------------------|
| **Rebuff** | Heuristic + vector DB + LLM-as-judge + canary tokens | Python (TS client) | Apache 2.0 | Multi-layer; canary token leak detection | Prototype-grade; F1 ~0.66–0.70; acquired/absorbed by Palo Alto |
| **LLM Guard** | 20+ scanner pipeline (regex, classifiers, transformers) | Python | MIT | Most comprehensive OSS coverage; good PII + output scanning | High latency (order-of-magnitude slower than Lakera); no FFI |
| **NeMo Guardrails** | Programmable Colang rules + optional LLM-as-judge | Python | Other (NVIDIA custom) | Conversation flow control; production-grade for dialog systems | Not a security classifier — more of a policy engine; complex setup |
| **Guardrails AI** | Validator framework (plug-in model) | Python | Apache 2.0 | Huge validator ecosystem; output validation strong | Not injection-specific; overhead per call; Python-only |
| **Vigil LLM** | YARA rules + vector similarity + transformer + canary | Python + REST | Apache 2.0 | Multi-signal with configurable thresholds | Small community; last meaningful update 2024; no FFI |
| **Llama Guard 3/4** | Fine-tuned LLM classifier (8B / 12B) | Python + model weights | Llama custom | Strong recall; multilingual (8 langs); open weights | ~200–500ms inference; 8B+ model weight requirement; not embeddable |
| **garak (NVIDIA)** | Red-team / vulnerability scanner | Python | Apache 2.0 | 7,800+ stars; widest attack-surface coverage | Evaluation tool, not a runtime defense |
| **JailbreakBench** | NeurIPS 2024 benchmark dataset + eval harness | Python | MIT | Standardized jailbreak eval; 593 stars | No runtime component |
| **HarmBench** | Standardized red-team eval framework | Jupyter/Python | MIT | 948 stars; academic standard | Offline eval only |
| **Lakera Guard** | Proprietary trained classifiers (cloud API) | REST API | Commercial (acquired by Cisco, May 2025) | Sub-50ms; 98%+ claimed detection; 100+ languages | Vendor lock-in; Cisco acquisition trajectory unclear; FPR 0.14 with context |
| **Azure Prompt Shields** | Microsoft's proprietary classifiers | REST API (Azure) | Commercial | Azure-native integration; spotlighting for indirect injection | F1 only 42.98% on GuardionAI benchmark; $0.38/1K text records; bypassed by emoji/Unicode attacks |
| **AWS Bedrock Guardrails** | Configurable policy engine + AWS classifiers | AWS SDK | Commercial | Deep Bedrock ecosystem integration | $0.15/1K text units per policy; Bedrock-only; limited external use |
| **Robust Intelligence / Cisco AI Defense** | Algorithmic red-team + AI firewall | Commercial (acquired by Cisco, Oct 2024) | Commercial | Enterprise-grade; AI firewall concept; Talos + Splunk threat intel | Fully absorbed into Cisco; no standalone product; opaque roadmap |
| **HiddenLayer** | Model scanning + runtime detection | Commercial | Commercial (~$500/mo+) | Full ML lifecycle coverage (supply chain + runtime) | Enterprise pricing; overkill for inference-layer-only use |
| **CalypsoAI** | LLM inference firewall (test-defend-observe) | Commercial (acquired by F5, Sep 2025 for $180M) | Commercial | Strong DLP + auditability; model-agnostic | F5 acquisition; enterprise-only pricing |
| **Protect AI Layer** | Posture + runtime + red-team platform | Commercial (acquired by Palo Alto, Jul 2025 for ~$500M) | Commercial | Now part of Prisma AIRS; broadest enterprise posture | Absorbed into PANW; OSS tools now under PANW umbrella |
| **Prompt Security** | Inline LLM proxy/firewall | Commercial | Commercial | Real-time bidirectional scanning; policy engine | Pricing opaque; small team |

---

## Open Source Tools

### Rebuff (Protect AI → Palo Alto Networks)
- **Approach**: Four-layer hybrid — heuristic scanner, vector-DB similarity against known attacks (embeddings), OpenAI LLM-as-judge, canary word detection. The canary system injects a token into the system prompt and checks if the model's response leaks it (indicating goal hijacking).
- **Language/Runtime**: Python SDK + TypeScript client; requires OpenAI API + Pinecone vector DB. No FFI.
- **Latency**: Inherits OpenAI round-trip (~200–800ms) for LLM-judge layer.
- **License**: Apache 2.0 (GitHub: protectai/rebuff, 1,481 stars).
- **Detection**: Direct prompt injection, goal hijacking, canary leakage.
- **Published benchmarks**: F1 ~0.697 on OpenAI Moderation; 0.662 on WildGuard; drops to 0.525 on GA Jailbreak Bench with 0.825 FPR on adversarial sets.
- **Honest gaps**: Explicitly marked "prototype stage." Requires external API keys (OpenAI, Pinecone). High latency. The LLM-judge approach is expensive at scale. Absorbed into Palo Alto's Prisma AIRS — independent OSS maintenance is questionable going forward.
- **Traction**: 1,481 stars. Now effectively orphaned under PANW.

---

### LLM Guard (originally Protect AI / Laiyer)
- **Approach**: Pipeline of 20+ scanners, each targeting one threat class. Scanners are modular: some are regex/heuristic, some use HuggingFace transformer classifiers (e.g., `deberta-v3-base-prompt-injection`), some are LLM-as-judge. Covers both input and output.
- **Language/Runtime**: Python-only. REST API available via self-hosted deployment. No official FFI.
- **Latency**: Reported as "order-of-magnitude higher than Lakera" in independent benchmarks (TrueFoundry, 2025). Running all scanners simultaneously: ~1–5 seconds per request depending on which are enabled. Can be reduced by disabling heavier scanners.
- **License**: MIT (GitHub: protectai/llm-guard, 2,954 stars).
- **Detection**: Prompt injection, jailbreak, PII (via NER), toxic content, ban topics, sensitive info leakage, code detection, regex patterns, language detection, relevance, reading time, gibberish.
- **Published benchmarks**: Not disclosed by maintainer. Third-party: high recall but latency is the primary production blocker.
- **Honest gaps**: Python-only; significant latency overhead; absorbed by Palo Alto, maintenance trajectory unclear. False-positive tuning is manual and time-consuming. Scanner ordering matters for performance but is non-obvious.
- **Traction**: 2,954 stars; also now under Palo Alto umbrella.

---

### NVIDIA NeMo Guardrails
- **Approach**: Colang domain-specific language defines dialog flows and safety policies. Calls an LLM to decide if a flow is triggered (LLM-as-judge at the policy level). Not a classifier in the traditional sense — it's a conversation orchestration layer with safety rails embedded. Does not do vector similarity or regex injection detection natively.
- **Language/Runtime**: Python. Requires access to an LLM backend (OpenAI, vLLM, etc.). No FFI.
- **Latency**: Adds a full LLM round-trip per policy check. Not suitable for sub-100ms requirements.
- **License**: NVIDIA custom open license (non-Apache; some restrictions on commercial redistribution).
- **Detection**: Hallucination, off-topic responses, jailbreak (via LLM judgment), conversation flow violations. Indirect injection via input rails available but requires custom Colang definitions.
- **Published benchmarks**: None disclosed. Community notes that the jailbreak detection is "asking the LLM if the prompt will break the LLM" — not independently validated.
- **Honest gaps**: HN discussion: "probably fair to call this stuff 'not battle tested'." Requires deep Colang expertise for complex policies. Not a drop-in classifier. Heavy runtime dependency (full LLM required). NVIDIA's custom license is a friction point.
- **Traction**: 6,133 stars, 680 forks. Strong NVIDIA ecosystem adoption.

---

### Guardrails AI
- **Approach**: Validator plugin framework — you compose validators (HuggingFace models, custom functions, LLM calls) that run against LLM inputs/outputs. Not injection-specific; it's a general output validation framework. Validators can catch injection patterns but require manual composition.
- **Language/Runtime**: Python SDK. No FFI.
- **Latency**: Depends on validators used. Lightweight validators: <50ms. LLM-as-judge validators: 200ms+.
- **License**: Apache 2.0 (GitHub: guardrails-ai/guardrails, 6,868 stars — highest in OSS space).
- **Detection**: Whatever validators you compose. Built-in: PII, toxicity, relevance, format validation, regex. Injection-specific validators are community-contributed.
- **Honest gaps**: Not a security product per se — it's a validation framework that can be used for security. Injection defense requires finding and composing the right validators. Python-only. High stars reflect broad appeal, not injection-specific credibility.
- **Traction**: 6,868 stars. Active maintained; not PANW-absorbed. Most general OSS tool in space.

---

### Vigil LLM
- **Approach**: Multi-signal with configurable alarm thresholds. Scanners: (1) vector similarity against known injection patterns in a local vector DB, (2) YARA rules for pattern matching, (3) HuggingFace transformer classifier, (4) prompt-response similarity (canary-style), (5) canary token detection. Default: flag if 3+ scanners fire simultaneously (reduces false positives).
- **Language/Runtime**: Python library + REST API (FastAPI). No FFI.
- **Latency**: Local inference with small transformer: ~50–200ms depending on hardware.
- **License**: Apache 2.0 (GitHub: deadbits/vigil-llm, 479 stars).
- **Detection**: Prompt injection, jailbreak, goal hijacking, canary leakage. Most configurable OSS option.
- **Honest gaps**: Small community; last significant update early 2024. Not production-hardened; no published benchmark performance. REST API only for non-Python callers. Requires local vector DB setup.
- **Traction**: 479 stars. Niche but technically interesting.

---

### Meta Llama Guard 3 / 4
- **Approach**: Fine-tuned LLM (Llama-3.1-8B base) specifically for content safety classification. Performs multi-class classification over MLCommons hazard taxonomy. Input: conversation turns → output: safe/unsafe + violated category. Not prompt-injection-specific; broader content safety.
- **Language/Runtime**: Requires running an 8B–12B model. Python inference (vLLM, HuggingFace). C/C++ via llama.cpp (unofficial Rust: candle, mistral.rs).
- **Latency**: 200–500ms on GPU; higher on CPU. Not suitable for synchronous filtering in latency-sensitive paths.
- **License**: Llama custom license (open weights, some commercial restrictions).
- **Detection**: Violence, hate, sexual content, criminal planning, jailbreaks (indirect). Supports 8 languages. Does NOT natively detect prompt injection in the technical sense (system prompt override).
- **Published benchmarks**: Outperforms GPT-4 on MLCommons benchmarks; lower FPR than prior versions.
- **Honest gaps**: Designed for content moderation, not injection detection specifically. Inference cost is high. Running 8B model in critical path is a significant infrastructure decision.
- **Traction**: Available on HuggingFace; used widely by Meta ecosystem adopters.

---

## Benchmark / Research Tools

### garak (NVIDIA)
- **What it is**: LLM vulnerability scanner / red-team framework. 7,822 stars. Tests a target LLM against attack probes across many categories.
- **Approach**: Probe generators (jailbreak attempts, prompt injection, encoding attacks, etc.) + detectors that evaluate output.
- **Use case**: Evaluation and CI/CD safety testing, not runtime defense. Python, Apache 2.0.
- **Key finding**: Useful for measuring how well a defense works, but is not a defense itself.

### JailbreakBench (NeurIPS 2024)
- **What it is**: Standardized dataset + eval harness for jailbreak attacks. 593 stars. Accepted at NeurIPS 2024 Datasets & Benchmarks Track.
- **Key finding**: Provides attack strings and judges. No runtime component. The reference benchmark for academic jailbreak research.

### HarmBench
- **What it is**: Standardized automated red-teaming evaluation framework. 948 stars.
- **Key finding**: Covers 400 harmful behaviors across 18 functional categories. Academic standard. Jupyter/Python. Offline only.

### GuardionAI Leaderboard (Dec 2025)
- **Key published numbers**: ModernGuard (GuardionAI proprietary) F1 = 86.33%; Azure Prompt Shield F1 = 42.98%. Tests 30 attack categories including Crescendo, TAP, zero-shot. Most other tools not on this leaderboard.
- **Critical note**: Published by GuardionAI to promote their own product. Numbers for Azure Prompt Shield seem low and should be independently verified.

### Palit Benchmark (arXiv 2505.13028, 2025)
- **Key finding**: Lakera Guard achieved 74.6% accuracy with precision 0.94 but FPR 0.14 when context was added. ProtectAI LLM Guard: order-of-magnitude higher latency.

### Bypass Research (arXiv 2504.11168, 2025 — ACL LLMSec Workshop)
- **Key finding**: Character injection + adversarial ML methods achieve up to **100% evasion** against six major guardrail systems including Azure Prompt Shield and Meta Prompt Guard. Emoji smuggling, zero-width characters, Unicode tags, and homoglyphs bypass all tested classifiers while remaining readable to the target LLM. This is the most important research finding for positioning: **no existing system is robust against adaptive adversarial attacks**.

---

## Commercial / Cloud Tools

### Lakera Guard (Acquired by Cisco, May 2025)
- **Approach**: Proprietary trained classifier ensemble. Closed-source model. REST API.
- **Latency**: Sub-50ms (published); validated in independent benchmarks.
- **Pricing**: Free tier: 10K calls/month. Pro: contact sales. Enterprise: custom. Now folded into Cisco AI Defense.
- **Detection**: Direct injection, indirect injection, jailbreak, system prompt extraction, PII, toxic content. 100+ languages.
- **Published benchmarks**: Claims 98%+ detection; independent Palit benchmark: 74.6% accuracy (FPR 0.14 with context). GuardionAI did not include them in their leaderboard.
- **Honest gaps**: Cisco acquisition creates uncertainty — Lakera's standalone API may be wound down in favor of Cisco AI Defense bundle. FPR rises significantly when context documents are included. Vendor lock-in.
- **Traction**: Dominant OSS-adjacent commercial solution pre-acquisition. Significant enterprise adoption.

### Microsoft Prompt Shields (Azure AI Content Safety)
- **Approach**: Microsoft proprietary classifiers. Spotlighting technique (announced Build 2025) separates trusted vs. untrusted input segments to improve indirect injection detection.
- **Latency**: Not published; REST API to Azure region.
- **Pricing**: $0.38 per 1,000 text records (Standard tier, pay-as-you-go). Free: 5,000 records/month.
- **Detection**: Direct injection, indirect injection (documents/emails/web), jailbreak.
- **Published benchmarks**: GuardionAI F1 = 42.98% — worst of named tools. ACL 2025 research shows full bypass via emoji/Unicode.
- **Honest gaps**: Low independent benchmark performance. Azure-only (unless using REST, but billing tied to Azure). Spotlighting is promising but unvalidated externally. Bypass vulnerability publicly documented.
- **Traction**: Default choice for Azure AI customers; major adoption by default ecosystem lock-in.

### AWS Bedrock Guardrails
- **Approach**: Configurable policy engine on top of AWS classifiers. Supports: content filters, denied topics, sensitive info redaction, grounding checks, and prompt attack detection.
- **Latency**: Not published for guardrail layer specifically.
- **Pricing**: $0.15 per 1,000 text units per policy type. Charged regardless of block outcome.
- **Detection**: Prompt attack (jailbreak + injection) in Standard tier. Content filtering, topic denial.
- **Honest gaps**: Bedrock-only — no external use. Policy-based rather than semantic. Limited transparency on classifier internals. Per-policy pricing compounds quickly.
- **Traction**: Default for AWS Bedrock customers; captive audience.

### Robust Intelligence / Cisco AI Defense
- **Approach**: Algorithmic red-teaming + AI firewall. Now deeply integrated into Cisco AI Defense with Talos + Splunk threat intelligence.
- **Acquired**: Cisco, October 2024.
- **Detection**: Full enterprise scope — model risk, prompt injection, data poisoning, adversarial inputs.
- **Honest gaps**: No longer a standalone product. Pricing is enterprise contract. Opaque roadmap post-acquisition.
- **Traction**: Enterprise security teams; Cisco's existing security customer base is the distribution channel.

### HiddenLayer
- **Approach**: Full ML lifecycle security — model scanning, supply chain risk, runtime detection, attack simulation.
- **Pricing**: ~$500/month+ (enterprise custom). Available on AWS + Azure Marketplace.
- **Detection**: Model extraction, adversarial inputs, evasion attacks, data poisoning, prompt injection.
- **Honest gaps**: Targets ML Ops teams, not application developers. Overkill for inference-layer-only filtering.
- **Traction**: Crunchbase shows VC-backed; enterprise customer base. Not primarily a prompt injection tool.

### CalypsoAI (Acquired by F5, September 2025 for ~$180M)
- **Approach**: Inline LLM proxy (test-defend-observe model). Real-time bidirectional prompt + response scanning. Strong DLP and auditability.
- **Detection**: Prompt injection, data leakage, PII, policy violations, agentic workflow monitoring.
- **Honest gaps**: F5 acquisition — trajectory toward ADC/WAF integration, not standalone AI security. Enterprise pricing, no self-hosted option.
- **Traction**: Government and finance sector customers; F5's network customer base is distribution.

### Protect AI Layer / Prisma AIRS (Palo Alto Networks, Acquired July 2025 for ~$500M)
- **Approach**: AI security posture management + runtime protection + red-teaming. LLM Guard and Rebuff are now Palo Alto products.
- **Detection**: End-to-end — model scanning, posture, runtime.
- **Honest gaps**: Enterprise-only bundle. All OSS tools now under PANW; unclear whether community editions survive.
- **Traction**: Palo Alto's Prisma customer base; $500M acquisition signals market validation.

---

## Critical Questions Answered

### Is there an existing Rust-native solution?
**Effectively no.** GitHub search for `prompt+injection+rust` returns:
- `techlab-innov/llmtrace` (49 stars): Rust proxy, prompt injection + PII, OpenAI-compatible. Most serious contender but minimal stars and unclear maintenance.
- `0xkaz/nanoguard` (1 star): "Nano-fast Rust guardrails proxy. CPU-only, offline-first, OpenAI-compatible. Filters prompt injection and PII in microseconds."
- `giorgiozoppi/cerberus-llm` (0 stars): Async Rust LLM security scanner.
- `pauljsymonds/oxideshield` (0 stars): Rust prompt injection/jailbreak guards.
- `mirseo/string-formatter` (10 stars): Rule-based injection blocker in Rust.

None has meaningful adoption, documentation, or production credibility. **The Rust space is empty.**

### Do any OSS tools offer good FFI to non-Python languages?
No. Every major OSS tool (LLM Guard, Vigil, NeMo Guardrails, Guardrails AI, Rebuff) is Python-only with no official FFI. The only cross-language access is via REST API (self-hosted), which adds network overhead and operational complexity. This is a genuine gap.

### What's the honest state-of-the-art detection rate against modern jailbreaks?
**Discouraging.** The most rigorous 2025 academic finding (arXiv 2504.11168, ACL LLMSec 2025):
- Adaptive attacks (gradient descent, RL, random search, human-guided) achieve **>90% evasion** against most published defenses.
- Defenses that report "near-zero attack success" against static attacks collapse against adaptive attacks.
- Emoji smuggling, zero-width characters, Unicode tags bypass ALL tested classifiers.
- Best independent benchmark (Palit 2025): Lakera Guard ~74.6% accuracy. GuardionAI's own tool claims 86.33% F1 — but this is self-reported.
- The honest answer: **70–86% detection against known/static attacks; <50% against adaptive adversarial attacks.** No tool publishes adaptive attack numbers.

### What's the price-per-call for commercial APIs at scale?
| Service | Price | Notes |
|---------|-------|-------|
| Lakera Guard | ~$0.001–0.005/call (estimated from tier structure) | Now Cisco; pricing may change |
| Azure Prompt Shields | $0.38/1,000 text records ≈ $0.00038/call | Per text record, not per character |
| AWS Bedrock Guardrails | $0.15/1,000 text units/policy | Per 1K chars; multiple policies multiply cost |
| Others | Contact sales | No public pricing |

At 1M calls/day, Azure = ~$380/day ($139K/year). AWS depends heavily on text volume and policy count.

---

## Gaps in the Market

This section is the most strategically important.

### 1. No Rust-native library with real adoption
Every tool in this space requires Python or a REST API hop. For teams building in Rust, Go, C++, or any compiled language, the only options are: (a) shell out to Python, (b) spin up a sidecar REST service (LLM Guard's REST mode), or (c) call a cloud API (latency + cost + privacy concerns). A Rust library that compiles directly into any language via FFI/WASM or as a native crate is **entirely unoccupied**.

### 2. No offline-first, zero-network-dependency option at production quality
All commercial tools require network calls. OSS tools with local inference (LLM Guard + HuggingFace models) have Python deps and high latency. A compiled Rust library with bundled ONNX or quantized classifier weights that runs 100% offline and deterministically would serve: air-gapped environments, edge/IoT, gaming backends, and privacy-sensitive deployments. No production-quality tool does this today.

### 3. The latency tier between "regex-only" and "LLM-as-judge" is poorly served
Current tools are either:
- Fast but weak: regex/heuristic (< 5ms, high FPR/FNR)
- Accurate but slow: LLM-as-judge (200–800ms, requires API call)
- Middle ground poorly covered: fine-tuned small transformer classifier (50–200ms, good accuracy, Python-only)

A Rust library running ONNX-exported fine-tuned classifiers (e.g., DeBERTa-small, DistilBERT-based injection classifier) could hit **10–30ms** latency with **good detection** — better than the current middle ground.

### 4. No tool is robust against Unicode/encoding evasion
The ACL 2025 bypass paper showed emoji smuggling and zero-width characters defeat all tested classifiers. No tool has published a fix. A Rust library could normalize Unicode (NFKC + zero-width stripping + homoglyph mapping) before classification as a first layer — something Python tools can do but have not prioritized. Rust's strong Unicode handling (the `unicode-normalization` crate is best-in-class) is a genuine differentiator.

### 5. Multi-language ecosystem (FFI) gap
All commercial APIs are REST. All OSS is Python. Teams using Node.js, Go, Java, C#, or Rust have no good native library. A Rust library with C FFI exports (or WASM) would cover all these ecosystems in one build target.

### 6. M&A vacuum in the OSS space
Rebuff → Palo Alto. LLM Guard → Palo Alto. Lakera → Cisco. CalypsoAI → F5. Robust Intelligence → Cisco. The open source options are all now under enterprise vendor control. **Community trust in the OSS alternatives is at a low.** A genuinely independent, well-licensed Rust library has a trust positioning advantage right now.

---

## Recommendation

### Build: Yes — with a specific, narrow scope

**Don't** try to build a comprehensive platform or compete with Cisco AI Defense on enterprise features. That's a $500M acquisition price vs. an OSS library.

**Do** build a Rust-native, offline-first, zero-network-dependency injection detection library targeting:

1. **Compiled language teams** (Rust, C, C++, Go via CGo, Node via NAPI) who currently have no native option.
2. **Latency-sensitive paths** where a 400ms cloud API call is unacceptable — game backends, real-time agent systems, edge deployments, CLI tools.
3. **Privacy/compliance-constrained deployments** — air-gapped, on-prem, regulated industries (healthcare, finance, defense) where sending prompts to a cloud classifier is a compliance problem.

**Positioning statement (draft):** *"The first production-quality, offline Rust library for LLM prompt injection detection. Embeds directly into your service with zero network calls, sub-30ms latency, and C FFI for polyglot use."*

### Technical architecture to differentiate
- **Layer 1**: Unicode normalization pass (NFKC + zero-width strip + homoglyph map) — catches the bypass vectors that defeat all cloud tools.
- **Layer 2**: High-throughput heuristic/regex scanner (Aho-Corasick, hand-tuned patterns). <1ms.
- **Layer 3**: Bundled ONNX classifier (fine-tuned DeBERTa-small or similar, ~40MB). Target: 10–30ms on CPU.
- **Layer 4**: Optional canary token tracker (stateless, hash-based) for detecting goal hijacking.
- **FFI surface**: C ABI exports (`detect_injection(const char*, size_t) -> Score`) + WASM target for browser/edge.

### What to be honest about
- Against adaptive adversarial attacks (gradient-descent optimized), even the best systems are <50% effective. A Rust library won't solve this — neither does anyone else. The positioning should be "defense in depth, first layer" not "complete protection."
- The fine-tuned classifier layer requires Python tooling to train and export; the Rust library consumes pre-exported ONNX weights.
- This is a **library**, not a product. Monetization (if any) would be through support contracts, a hosted cloud variant, or integration with enterprise security tooling — not the OSS library itself.

### Market timing
The M&A vacuum (all OSS tools absorbed by PANW/Cisco/F5) creates an unusual window where the community needs a credible, independent alternative. **Build now.**

---

*Sources: GitHub API (direct); WebSearch results from Lakera, Microsoft Learn, AWS, GuardionAI, arXiv, ACL Anthology, TrueFoundry, PaloAltoNetworks press releases, F5/CalypsoAI acquisition announcements, eesel.ai, appsecsanta.com, aiflowreview.com, Capterra, Futurepedia, SiliconANGLE, CNBC, Orrick, guardion.ai.*
