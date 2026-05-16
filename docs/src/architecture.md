# Architecture

See [ARCHITECTURE.md](https://github.com/Trit1967/sieve/blob/main/ARCHITECTURE.md)
in the repo root for the layered design (L1 SDK middleware → L6
telemetry), the data flow diagram per LLM call, and the cross-language
binding strategy.

In one sentence: pure-Rust core, FFI in bindings only, every detector
is independent and emits structured findings into a single aggregator.
