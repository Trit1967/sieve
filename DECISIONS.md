# Architecture Decision Records

Decisions made before / during sieve v0.1 implementation. New ADRs append to the bottom.

---

## ADR-0001 — Project name: `sieve` (provisional, pending availability check)

**Status:** Provisional. Final name lock requires verifying availability on crates.io, PyPI, and npm before the v0.1.0-rc1 publish.

**Context:** IMPLEMENTATION_PROMPT.md §11 lists `sieve` as working title with alternatives (`shibboleth`, `prompt-sieve`, `latch`, `untangle`).

**Decision:** Use `sieve` as the package name throughout the codebase. If crates.io/PyPI/npm conflicts surface during the release-prep phase, do a global rename via a single atomic commit; nothing else couples to the name.

**Consequences:**
- Rust crate: `sieve-core` (publishable as `sieve` on crates.io)
- Python: `sieve` on PyPI with extras `[openai]`, `[anthropic]`
- npm: `@sieve/wasm`, `@sieve/nextjs`

---

## ADR-0002 — Async stance: sync core, async only in middleware

**Status:** Locked.

**Decision:** `sieve-core` is fully synchronous. No `tokio`, no `async-std`, no `async fn` in core. Async appears only in contrib middleware wrappers (Python `contrib.openai`, JS `@sieve/nextjs`), which the user already brought their own runtime for via the LLM SDK.

**Rationale:**
- Scanning is CPU-bound (Aho-Corasick, Unicode normalization, regex).
- Sync core keeps it embeddable from any host (Edge runtimes, WASM, blocking Python frames, FFI).
- No runtime coupling means no version-skew hell with downstream tokio/smol/async-std users.

**Verification:** `cargo tree -p sieve-core` must show zero async runtime crates.

---

## ADR-0003 — MSRV: stable Rust minus two

**Status:** Locked.

**Decision:** Target MSRV is `stable - 2` minor versions at the time of each release. CI tests against `stable`, MSRV, and `nightly` on Ubuntu x86_64.

**Rationale:** Standard ecosystem practice. Wide enough to cover most users' toolchains, tight enough to allow recent stdlib features.

---

## ADR-0004 — WASM build profile: `opt-level = "z"`, `lto = true`, no `wee_alloc`

**Status:** Locked for v0.1.

**Decision:**
- `[profile.release]` for `sieve-wasm`: `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true`.
- Do NOT pull in `wee_alloc` — it's unmaintained and the default `dlmalloc` is fine for our footprint.
- Default features only on the WASM build (no `ort`, no `commitments-llm`).

**Rationale:** Target is <2MB compressed. `wee_alloc` saves ~10KB but is a maintenance liability. We can revisit if size budget becomes tight.

**Verification:** CI fails if compressed WASM bundle > 2MB.

---

## ADR-0005 — Canary token format: random 16-byte base64

**Status:** Locked for v0.1; pluggable in v0.2.

**Decision:** Default canary = 16 random bytes from a CSPRNG (`getrandom`), URL-safe base64 encoded (no padding). Yields a 22-character ASCII token.

**Rationale:**
- Random tokens are simple, leak-detectable by exact substring + fuzzy match, and impossible for an attacker to predict.
- Format-constrained tokens (e.g., "always start replies with 'PURPLE-ELEPHANT-42'") leak more reliably but signal their presence to an attacker who sees the system prompt.
- Pluggable canary schemes (v0.2) let users opt into format constraints when they trust the system prompt is private.

**Verification:** Property test — two canaries from independent `Canary::new()` calls are never equal across 1M iterations.

---

## ADR-0006 — Telemetry: zero, ever, no exceptions

**Status:** Locked, immutable.

**Decision:** `sieve-core` and all first-party bindings perform zero network operations. No "anonymous usage analytics," no remote rule updates, no version-check pings, no crash reports.

The only "telemetry" is `scanner.metrics()` — a struct of in-process counters the user can read and export themselves wherever they want. We never touch that data.

**Verification:**
- `cargo deny check bans` rejects `reqwest`, `hyper`, `ureq`, `surf`, `isahc` in `sieve-core`'s dep graph.
- CI greps the source for `std::net`, `reqwest`, `tokio::net` and fails if found in core.

---

## ADR-0007 — Homoglyph map: TR39 confusables, Latin/Cyrillic/Greek subset only (v0.1)

**Status:** Locked for v0.1.

**Decision:** Build `confusables.bin` at compile time via a `build.rs` that parses the Unicode TR39 confusables.txt. Subset to the Latin-Cyrillic-Greek script triangle — the most-exploited homoglyph attack surface and the smallest that covers documented bypasses.

**Rationale:**
- Full TR39 is large (~1MB) and includes scripts the v0.1 corpus doesn't exercise.
- Latin/Cyrillic/Greek covers the published 100%-bypass attacks (ACL'25).
- v0.2 can opt into the full table behind a feature flag.

---

## ADR-0008 — Wordlist seed for v0.1: ~50–100 curated patterns

**Status:** Locked for v0.1 Phase 3.

**Decision:** Phase 3 ships PatternScanner with a 50–100 entry hand-curated `jailbreaks.txt`. Phase 14 expands to ~5,000 via merge of JailbreakBench (MIT) + garak probes (Apache) + LLM Guard wordlist (MIT, credited) + Rebuff vector DB corpus (Apache, credited).

A `provenance.txt` next to `jailbreaks.txt` records the source + license for each batch. No upstream attribution is dropped.

---

## ADR-0009 — `unwrap()` discipline

**Status:** Locked.

**Decision:** `sieve-core/src` is clippy-gated with `unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"`. Tests (`#[cfg(test)]` blocks and `tests/`) are exempt.

The compile-time wordlist load via `include_bytes!` + `build.rs` is the only place we accept compile-time invariants; runtime IO uses `Result` everywhere.

---

## ADR-0010 — Build verifies cross-language consistency on every commit

**Status:** Locked for Phase 17 onwards.

**Decision:** A `sieve-cli` test-only binary in `sieve-core` reads JSON `{system, user}` from stdin and emits a canonicalized `Verdict` JSON. The Python and WASM bindings run the same corpus through their native API; CI asserts byte-equal canonical output (with `score` tolerance < 0.001).

**Rationale:** "Strings in, verdicts out, same everywhere" is the headline architectural promise. Untested = lie.

---

## ADR-0011 — Open question deferrals (documented, not yet resolved)

Resolve before the named phase ships:

| # | Open question | Defer to |
|---|---|---|
| 1 | Whether to publish a separate `sieve-corpus` repo at v0.1 or stub it | Phase 14 |
| 2 | Final ONNX feature gating (`ort` v2 API stability for `sieve-core`) | Phase 9 |
| 3 | Vercel AI SDK middleware signature — `v3.x` API as of 2026-05 | Phase 13 |
| 4 | Whether `@sieve/nextjs` re-exports `@sieve/wasm` or peer-depends on it | Phase 13 |

These are tracked but do not block v0.1 scaffolding.
