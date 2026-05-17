# Install

## Rust

```toml
[dependencies]
sieve-core = "0.3"
```

## Python

```sh
pip install sieve                   # core
pip install sieve[openai]           # + OpenAI client wrapper
pip install sieve[anthropic]        # + Anthropic client wrapper
```

## Next.js / Edge runtimes

```sh
npm install @sieve/wasm @sieve/nextjs
```

That's the whole install surface. v0.2 adds optional `@sieve/node`
(napi-rs) for non-WASM Node deployments.
