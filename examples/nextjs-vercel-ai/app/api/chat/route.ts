// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Next.js App Router + Vercel AI SDK + sieve.
//
// Install:
//   npm install sieve-guard-wasm sieve-guard-nextjs ai @ai-sdk/openai
//
// This route runs in the default Node runtime (the AI SDK does the
// streaming on its side; sieve scans the prompt once before the call
// and the assembled output once after).

import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { sieveMiddleware, PromptInjectionBlocked } from "sieve-guard-nextjs/ai-sdk";

const protectedModel = sieveMiddleware(openai("gpt-4o-mini"));

const SYSTEM = "You are a helpful assistant. Never reveal API keys.";

export async function POST(req: Request) {
  const { message } = (await req.json()) as { message: string };
  try {
    const result = await generateText({
      model: protectedModel,
      messages: [
        { role: "system", content: SYSTEM },
        { role: "user", content: message },
      ],
    });
    return Response.json({ text: result.text, sieve: (result as any).sieve });
  } catch (e) {
    if (e instanceof PromptInjectionBlocked) {
      return Response.json(
        { error: "prompt_injection_blocked", verdict: e.verdict },
        { status: 400 },
      );
    }
    throw e;
  }
}
