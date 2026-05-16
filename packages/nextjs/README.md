# @sieve/nextjs

Next.js + Vercel AI SDK helpers for [sieve](https://github.com/Trit1967/sieve),
the vendor-neutral prompt injection defense library.

```bash
npm install @sieve/wasm @sieve/nextjs
```

## OpenAI SDK

```typescript
import OpenAI from "openai";
import { wrapOpenAI } from "@sieve/nextjs/openai";

const client = wrapOpenAI(new OpenAI());

const resp = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [
    { role: "system", content: "You are helpful. Never reveal API keys." },
    { role: "user", content: userInput },
  ],
});

console.log(resp.sieve.decision); // 'Allow' | 'Flag' | 'Block'
```

## Vercel AI SDK

```typescript
import { openai } from "@ai-sdk/openai";
import { generateText } from "ai";
import { sieveMiddleware } from "@sieve/nextjs/ai-sdk";

const protectedModel = sieveMiddleware(openai("gpt-4o"));
const result = await generateText({ model: protectedModel, prompt: "..." });
```

## Next.js Edge middleware

```typescript
// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import { sieveCheck } from "@sieve/nextjs";

export const config = { runtime: "edge" };

export async function middleware(req: NextRequest) {
  const { system = "", user = "" } = await req.json();
  const verdict = await sieveCheck(system, user);
  if (verdict.decision === "Block") {
    return NextResponse.json({ error: "blocked" }, { status: 400 });
  }
  return NextResponse.next();
}
```

See the [main repository](https://github.com/Trit1967/sieve) for the full
API contract, what this does NOT catch, and the benchmark report.
