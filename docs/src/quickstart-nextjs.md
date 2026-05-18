# Quickstart (Next.js)

```sh
npm install sieve-guard-wasm sieve-guard-nextjs
```

Enable WebAssembly in `next.config.mjs`:

```javascript
const nextConfig = {
  webpack(config) {
    config.experiments = {
      ...config.experiments,
      asyncWebAssembly: true,
    };
    return config;
  },
};

export default nextConfig;
```

## Edge middleware (stateless input-only scan)

```typescript
// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import { applySievePolicy, sieveCheck } from "sieve-guard-nextjs";

export const config = { runtime: "edge", matcher: ["/api/chat/:path*"] };

export async function middleware(req: NextRequest) {
  const { message } = await req.clone().json();
  const verdict = await sieveCheck("You are helpful.", message);
  const policy = await applySievePolicy("public_app", verdict);
  if (policy.safe_to_auto_block) {
    return NextResponse.json({ error: "blocked", policy }, { status: 400 });
  }
  return NextResponse.next();
}
```

## OpenAI SDK wrapper (Node runtime)

```typescript
import OpenAI from "openai";
import { wrapOpenAI } from "sieve-guard-nextjs/openai";

const client = wrapOpenAI(new OpenAI());
const resp = await client.chat.completions.create({ ... });
console.log(resp.sieve.decision);
```

## Vercel AI SDK middleware

```typescript
import { openai } from "@ai-sdk/openai";
import { sieveMiddleware } from "sieve-guard-nextjs/ai-sdk";

const protectedModel = sieveMiddleware(openai("gpt-4o"));
```

See [`examples/nextjs-edge-runtime`](https://github.com/Trit1967/sieve/tree/main/examples/nextjs-edge-runtime)
and [`examples/nextjs-vercel-ai`](https://github.com/Trit1967/sieve/tree/main/examples/nextjs-vercel-ai).
