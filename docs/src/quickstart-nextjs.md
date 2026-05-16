# Quickstart (Next.js)

```sh
npm install @sieve/wasm @sieve/nextjs
```

## Edge middleware (stateless input-only scan)

```typescript
// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import { sieveCheck } from "@sieve/nextjs";

export const config = { runtime: "edge", matcher: ["/api/chat/:path*"] };

export async function middleware(req: NextRequest) {
  const { message } = await req.clone().json();
  const verdict = await sieveCheck("You are helpful.", message);
  if (verdict.decision === "Block") {
    return NextResponse.json({ error: "blocked" }, { status: 400 });
  }
  return NextResponse.next();
}
```

## OpenAI SDK wrapper (Node runtime)

```typescript
import OpenAI from "openai";
import { wrapOpenAI } from "@sieve/nextjs/openai";

const client = wrapOpenAI(new OpenAI());
const resp = await client.chat.completions.create({ ... });
console.log(resp.sieve.decision);
```

## Vercel AI SDK middleware

```typescript
import { openai } from "@ai-sdk/openai";
import { sieveMiddleware } from "@sieve/nextjs/ai-sdk";

const protectedModel = sieveMiddleware(openai("gpt-4o"));
```

See [`examples/nextjs-edge-runtime`](https://github.com/Trit1967/sieve/tree/main/examples/nextjs-edge-runtime)
and [`examples/nextjs-vercel-ai`](https://github.com/Trit1967/sieve/tree/main/examples/nextjs-vercel-ai).
