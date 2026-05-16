# sieve

Vendor-neutral, embeddable, offline-first prompt injection defense.

Strings in. Verdicts out. No network calls. No LLM-vendor lock-in. No
telemetry. Ever.

```rust
use sieve_core::{Scanner, Decision};

let scanner = Scanner::default();
let verdict = scanner.scan_input(&system_prompt, &user_input);

if verdict.decision == Decision::Block {
    return Err("prompt injection blocked");
}
```

> **Status: pre-release.** v0.1 is under active construction; do not
> deploy in production yet.

## Who this is for

- **Rust LLM-app developers** — first-class native option, no Python sidecar.
- **Python teams** (FastAPI / Django / LangChain / LlamaIndex / raw scripts).
- **Next.js teams** — works in both Node and Edge runtimes via WASM.
- **Privacy-constrained teams** (healthcare / finance / gov) — 100% offline.
- **Open-source LLM projects** (Ollama / vLLM / llama.cpp wrappers).

## What you get in v0.1

- 8 deterministic detectors: Unicode strip / homoglyph map, curated
  pattern wordlist, encoding payload scanner, heuristic scorer,
  canary engine, context analyzer, commitment checks, BYO-ONNX trait.
- Single-shot `scan_input` / `scan_output` API across Rust, Python, WASM.
- Cross-language verdict consistency (same input → same JSON).
- Reproducible benchmarks: 100% detection on the curated jailbreak
  set, 0% block-FPR on the curated benign set, p99 latency < 20µs.

## What you do NOT get

See [What this does NOT catch](./scope.md). Read it before deploying.
