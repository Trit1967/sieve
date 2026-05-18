# Install

## Rust

```toml
[dependencies]
sieve-core = "0.3"
```

## Python

```sh
pip install sieve-guard             # core
pip install sieve-guard[openai]           # + OpenAI client wrapper
pip install sieve-guard[anthropic]        # + Anthropic client wrapper
```

## Next.js / Edge runtimes

```sh
npm install sieve-guard-wasm sieve-guard-nextjs
```

That's the whole install surface. A future Node-native package can be added
separately if WASM is not the right runtime for a deployment.
