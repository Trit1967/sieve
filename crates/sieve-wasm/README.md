# @sieve/wasm

WebAssembly build of [sieve](https://github.com/Trit1967/sieve), the
vendor-neutral prompt injection defense library.

```bash
npm install @sieve/wasm
```

```typescript
import init, { Scanner } from '@sieve/wasm';
await init();

const scanner = new Scanner();

const pre = scanner.scanInput(systemPrompt, userInput);
if (pre.decision === 'Block') return new Response('blocked', { status: 400 });

const response = await yourLlmCall(systemPrompt, userInput);
const post = scanner.scanOutput(systemPrompt, response, pre.canary_state);

console.log(post.decision, post.findings);
```

Works in:

- Browsers (modern, WASM-capable)
- Cloudflare Workers
- Vercel Edge Runtime
- Deno
- Node.js (`require('@sieve/wasm')`)

See the [main repository](https://github.com/Trit1967/sieve) for the full
API contract, what this does NOT catch, and the benchmark report.
