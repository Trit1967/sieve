# Why your prompt injection defense doesn't catch zero-width characters

> Draft v0.1 — review before posting. Numbers come from
> `benchmarks/REPORT.md` and arXiv 2504.11168.

In April 2026, a paper at ACL LLMSec disclosed something the prompt
injection defense industry has been quietly tolerating: zero-width
characters and Unicode tag codepoints achieve up to **100% evasion**
against Lakera, Azure Prompt Shields, Meta Prompt Guard, and ProtectAI
v2 (arXiv [2504.11168](https://arxiv.org/abs/2504.11168)).

The attack is depressingly simple. Instead of saying

> ignore all previous instructions

an attacker says

> hello͏̄͠͡ ignore all previous instructions

where the highlighted region contains invisible Unicode tag codepoints
(`U+E0049` ... `U+E007F`) carrying ASCII letters. The guardrail sees
"hello" plus some invisible glyphs. The LLM sees the smuggled English.

Every commercial guardrail product I tested ships this bypass today.
Worse — they ship it as "behaviorally robust pattern matching" with no
input normalization layer at all. The published numbers (Lakera 74.6%,
Azure Prompt Shield 42.98% — independent eval, arXiv
[2505.13028](https://arxiv.org/abs/2505.13028)) don't even cover the
tag-codepoint class.

I built [sieve](https://github.com/Trit1967/sieve) to fix this
specific gap, plus the seven others that the published comparison
landscape papers over.

## What sieve does

The library is a pure-Rust scanner with bindings for Python (PyPI)
and WASM (npm). Strings in, verdicts out. No network calls. No LLM
vendor dependencies. No telemetry, ever.

```python
import sieve

scanner = sieve.Scanner()
pre = scanner.scan_input(system_prompt, user_input)
if pre.is_block():
    raise InjectionBlocked()

response = your_llm_call()  # Ollama / OpenAI / Anthropic / custom
post = scanner.scan_output(system_prompt, response, pre.canary_state)
```

The scan pipeline runs 8 independent detectors:

1. **Unicode normalization** — strips tag codepoints + zero-width
   chars, applies NFKC, maps a curated Latin/Cyrillic/Greek homoglyph
   subset to ASCII. This is the hero feature: every documented
   ACL'25 bypass is in our regression suite.
2. **Pattern scanner** — Aho-Corasick over a curated 220-entry
   jailbreak wordlist. Audited by hand; FPR-free on 108 adversarial
   benign inputs.
3. **Encoding scanner** — detects base64 / hex / rot13 segments,
   decodes them (max depth 2 to bound DoS surface), re-scans the
   decoded text.
4. **Heuristic scorer** — instruction density / script switch /
   Shannon entropy on the lowercased input.
5. **Canary engine** — injects a 16-byte random token into the
   system prompt and detects leakage in the output.
6. **Context analyzer** — parses the system prompt into atomic
   instructions and identifies which one a given user input is
   trying to override.
7. **Commitment checks** — extracts deterministic commitments
   ("respond in English", "you are Bob", "never discuss medical
   advice") and verifies the output honors them.
8. **BYO classifier** — a `Classifier` trait so users plug in any
   ONNX model from HuggingFace, candle, burn, or a custom HTTP endpoint.

## The numbers

From `benchmarks/REPORT.md` on the bundled corpus (reproducible with
`./benchmarks/run.sh`):

- Jailbreak corpus (224 curated patterns): **100.0% Block**
- Benign FPR corpus (108 lines, deliberately adversarial-looking):
  **0.0% block-FPR**
- Per-call latency: **p50 7µs, p99 18µs**

Published competitor numbers, in proper context:

| Tool | Catch rate | FPR | Network calls | Telemetry |
|---|---|---|---|---|
| Lakera Guard | 74.6% (arXiv 2505.13028) | not reported | yes | yes |
| Azure Prompt Shield | 42.98% (same paper) | not reported | yes | yes |
| LLM Guard | varies | varies | no | no |
| **sieve v0.1** | **100% / corpus, see scope** | **0% blocks on benigns** | **none, ever** | **none, ever** |

Cross-test comparisons are unfair — every product has its own test
set. We publish the harness so anyone can run sieve against
JailbreakBench, garak, ACL'25, or their own corpus and re-publish the
numbers. `./benchmarks/run.sh --jbb path/to/jailbreakbench.json` etc.

## What sieve does NOT catch

This section is also the first one in the README. Honesty is the
project's reputational moat.

- **Novel paraphrased jailbreaks** not in the corpus. We're a pattern
  + heuristic + canary engine, not a semantic understander. v0.3
  ships an optional LLM-judge for this class.
- **Adaptive adversarial attacks** (gradient-optimized, RL-driven).
  Industry-wide unsolved; we won't claim otherwise.
- **Semantic attacks** indistinguishable from natural language.
- **Multi-turn social engineering** beyond what the conversation
  tracker handles. Partial coverage in v0.2.
- **Indirect injection from RAG** — we *flag* with provenance (v0.2);
  we cannot *stop* the model from being persuaded.
- **Generic content moderation** (toxicity, hate, NSFW). Use Llama
  Guard.

## Try it

```sh
# Rust
cargo add sieve-core

# Python
pip install sieve-guard

# Next.js
npm install sieve-guard-wasm sieve-guard-nextjs
```

Permissive license (MIT + Apache-2.0). No signup. No telemetry. No
cloud component. Source at
[github.com/Trit1967/sieve](https://github.com/Trit1967/sieve).

The Unicode-tag-bypass demo is the first executable code block in
the README. Run it and see for yourself.
