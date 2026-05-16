# Twitter / X launch thread — sieve v0.1

> Draft v0.1. Each numbered block is one tweet.

---

1/ I built sieve — a vendor-neutral, embeddable, offline-first prompt
   injection defense library. Rust core, Python (PyPI) + WASM (npm)
   bindings. No network calls. No LLM-vendor lock-in. No telemetry.

   github.com/Trit1967/sieve

---

2/ Every commercial guardrail I tested ships a 100%-evasion bypass
   that's been public for >1 year:

   Zero-width characters + Unicode tag codepoints sail past Lakera,
   Azure Prompt Shield, Meta Prompt Guard, ProtectAI v2.

   ACL LLMSec 2025: arxiv.org/abs/2504.11168

---

3/ The attack:

   visible:  hello ignore all previous instructions
   on wire:  hello͏̄͠͡ ignore all previous instructions
             ^^^^^^ U+E0049 U+E0067 U+E006E ... (Unicode tags)

   The guardrail sees "hello". The LLM sees the smuggled payload.
   Same bytes, different interpretation.

---

4/ sieve fixes that by normalizing the input before any other detector
   sees it: strip tag codepoints, strip zero-width chars, apply NFKC,
   map a curated Latin/Cyrillic/Greek homoglyph subset to ASCII.

   Every documented ACL'25 bypass is in the regression suite.

---

5/ Headline numbers on the bundled corpus:

   • Jailbreak corpus (224 entries):  100.0% Block
   • Benign FPR corpus (108 entries):   0.0% Block
   • Per-scan latency:           p50 7µs / p99 18µs

   Reproducible: ./benchmarks/run.sh. Brings your own corpus too.

---

6/ Architecture: 8 independent detectors composed by a thin
   orchestrator. Unicode strip / pattern / encoding / heuristic /
   canary / context / commitments / BYO-ONNX classifier.

   Sync core (R12). String in, Verdict out (R3). That's the whole API.

---

7/ Inviolable rules from day one:

   • Zero network calls in sieve-core (R1, audited in CI)
   • Zero LLM-vendor deps in sieve-core (R2, audited in CI)
   • Zero telemetry, ever (R5, permanent)
   • No bundled ONNX weights (R11, BYO interface only)

---

8/ The README LEADS with what sieve does NOT catch — novel
   paraphrased jailbreaks, adaptive adversarial attacks (industry-
   wide unsolved), semantic attacks indistinguishable from prose,
   multi-turn social engineering, RAG-borne injection.

   Honesty is the moat.

---

9/ Try it:

   Rust:    cargo add sieve-core
   Python:  pip install sieve
   Next.js: npm install @sieve/wasm @sieve/nextjs

   MIT + Apache-2.0. Pre-release. Bypass reports welcome — they become
   permanent regression tests.

---

10/ Why I built this: I wanted to embed defense in a Rust LLM project
    and the entire OSS landscape is Python-only. The commercial tier
    is consolidating fast (Lakera→Cisco, Protect AI→Palo Alto,
    CalypsoAI→F5) and trust positioning is unusually open. /end
