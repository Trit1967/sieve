# sieve

Vendor-neutral, embeddable, offline-first prompt injection defense.

Strings in. Verdicts out. No network calls. No LLM-vendor lock-in. No
telemetry.

```rust
use sieve_core::{Decision, Scanner};

let scanner = Scanner::default();
let verdict = scanner.scan_input(system_prompt, user_input);

if verdict.decision == Decision::Block {
    return Err("prompt injection blocked");
}
```

## Use It As A Library

Sieve is not an app server, proxy, database, queue, callback loop, or agent
framework. It is a set of small scanning APIs that return structured verdicts.

```rust
let verdict = scanner.scan_input(system_prompt, user_input);
```

```python
verdict = scanner.scan_input(system_prompt, user_input)
```

```typescript
const verdict = await sieveCheck(systemPrompt, userInput);
```

## Boundaries To Scan

Scan every untrusted boundary before it enters model context:

```typescript
await sieveCheckTurn(state, messages);
await sieveCheckToolCall("search", JSON.stringify(args));
await sieveCheckToolResult("fetch_url", fetchedPage);
await sieveCheckRetrievedDocument("rag_chunk", chunk, sourceId);
```

## What You Get In v0.3

- Rust core with Python, WASM, and Next.js bindings.
- Direct input and output scanning.
- Canary instrumentation for output leak detection.
- Structured agent, tool, and RAG boundary scanning.
- Unicode, encoding, curated-pattern, heuristic, semantic, slot, spotlight,
  anomaly, and differential detectors.
- Offline deterministic defaults.
- Optional BYO classifier and SDK wrappers.

## What You Do Not Get

Sieve is not a formal proof against adaptive attackers, arbitrary paraphrase,
side channels, or every future agent attack shape.

Read [What this does NOT catch](./scope.md) before using it as a blocking
control.
