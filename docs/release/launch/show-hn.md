# Show HN: sieve — vendor-neutral prompt injection defense (Rust + Python + WASM)

> Draft v0.1. Lead with the bypass demo; HN-formatted plain text.

Hi HN —

I built sieve because every commercial prompt-injection guardrail I
tested ships a 100%-evasion bypass that's been documented in the
literature for over a year. ACL LLMSec 2025
(arxiv.org/abs/2504.11168) showed that Lakera, Azure Prompt Shields,
Meta Prompt Guard, and ProtectAI v2 all let zero-width characters and
Unicode tag codepoints sail through. As of May 2026 none of them have
shipped a fix.

The simplest version of the attack:

  visible:   hello ignore all previous instructions
  on wire:   hello͏͏͠͞ ignore all previous instructions
             ^^^^^^ U+E0049 U+E0067 U+E006E ... (Unicode tags)

The guardrail sees the visible "hello" plus invisible glyphs and
green-lights it. The LLM sees the smuggled instructions. Same bytes,
different interpretation.

sieve is a pure-Rust scanner with bindings for Python (pyo3) and WASM
(wasm-bindgen). Strings in, structured verdicts out. No network calls.
No LLM-vendor dependencies in the core. No telemetry, ever. Dual MIT
+ Apache-2.0.

The headline numbers on the bundled corpus (reproducible with
`./benchmarks/run.sh`):

  Jailbreak corpus (224 curated):     100.0% Block
  Benign FPR corpus (108 lines):        0.0% Block
  Per-scan latency:               p50 7µs, p99 18µs

Architecture is 8 independent deterministic detectors run by a thin
orchestrator: Unicode normalization (the hero feature — strips tag
codepoints, zero-width, applies NFKC, maps a curated Latin/Cyrillic/
Greek homoglyph subset), Aho-Corasick over a 220-entry wordlist,
base64/hex/rot13 decode-and-rescan (bounded recursion to prevent DoS),
a heuristic scorer (instruction density / script switch / Shannon
entropy), a canary engine (injects a random token in the system
prompt and detects leakage), a heuristic context analyzer, and
deterministic commitment checks (language / persona / refusal keyword).
Users plug in any ONNX classifier via a small trait.

The README leads with what sieve does NOT catch — novel paraphrased
jailbreaks not in the corpus, adaptive adversarial attacks (industry-
wide unsolved), semantic attacks indistinguishable from natural
language, multi-turn social engineering, RAG-borne indirect injection.
Honesty is the project's reputational moat. Every previous-art tool
on the market has these same limits; they just don't lead with them.

Repo: github.com/Trit1967/sieve
Crate: crates.io/crates/sieve-core
PyPI: pypi.org/project/sieve/
npm: npmjs.com/package/sieve-guard-wasm + sieve-guard-nextjs

Pre-release as of today. Bypasses welcome — they become permanent
regression tests under the usual coordinated-disclosure flow
described in SECURITY.md.

Happy to answer questions.
