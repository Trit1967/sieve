# sieve examples

Working examples for each supported runtime.

| Example | Path | What it shows |
|---|---|---|
| Rust basic | [`rust-basic/`](rust-basic/) | The minimum: `Scanner::default()` + a benign, an injection, a Unicode bypass, and a canary leak. Runs with `cargo run -p rust-basic`. |
| Python FastAPI | [`python-fastapi/`](python-fastapi/) | `sieve.contrib.openai.wrap()` integrated into a FastAPI chat endpoint with structured error responses. |
| Python LangChain | [`python-langchain/`](python-langchain/) | Vendor-neutral primary API (`scan_input` + `scan_output`) used directly inside a LangChain pipeline. No contrib wrapper needed. |
| Next.js + Vercel AI SDK | [`nextjs-vercel-ai/`](nextjs-vercel-ai/) | `sieveMiddleware()` wrapping `@ai-sdk/openai` inside a Next.js App Router POST handler. |
| Next.js Edge runtime | [`nextjs-edge-runtime/`](nextjs-edge-runtime/) | Stateless `sieveCheck()` from Next.js Edge middleware (`runtime: 'edge'`). Sub-50ms cold start with the WASM bundle. |

Each example is intentionally short — they're the smallest thing that
exercises the relevant API surface, not a production starter. See
the [main README](../README.md) for the full feature list and
[ARCHITECTURE.md](../ARCHITECTURE.md) for the layered design.
