// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Vercel AI SDK middleware (`@sieve/nextjs/ai-sdk`).
//
// Usage:
//   import { openai } from '@ai-sdk/openai';
//   import { sieveMiddleware } from '@sieve/nextjs/ai-sdk';
//
//   const protectedModel = sieveMiddleware(openai('gpt-4o'));
//   const result = await generateText({ model: protectedModel, prompt: '...' });
//
// The middleware wraps any object that quacks like a v3.x AI-SDK
// `LanguageModelV1`: it intercepts `doGenerate` / `doStream`, runs
// `sieveCheck` on the inbound messages, and aborts with
// {@link PromptInjectionBlocked} if the verdict is Block.

import {
  sieveCheck,
  sieveCheckOutput,
  PromptInjectionBlocked,
  type CanaryState,
} from "./index.js";

interface PromptPart {
  type?: string;
  role?: string;
  content?: unknown;
  text?: string;
}

interface DoGenerateOptions {
  prompt?: PromptPart[] | { messages?: PromptPart[] };
  [key: string]: unknown;
}

interface DoGenerateResult {
  text?: string;
  content?: Array<{ type?: string; text?: string }>;
  [key: string]: unknown;
}

interface LanguageModelLike {
  doGenerate: (options: DoGenerateOptions) => Promise<DoGenerateResult>;
  doStream?: (options: DoGenerateOptions) => Promise<unknown>;
  [key: string]: unknown;
}

function flattenPrompt(prompt: DoGenerateOptions["prompt"]): {
  system: string;
  user: string;
} {
  const parts: PromptPart[] = Array.isArray(prompt)
    ? prompt
    : ((prompt as { messages?: PromptPart[] } | undefined)?.messages ?? []);
  let system = "";
  let user = "";
  for (const p of parts) {
    const role = p.role ?? p.type ?? "";
    const text =
      typeof p.content === "string"
        ? p.content
        : Array.isArray(p.content)
          ? (p.content as PromptPart[]).map((c) => c.text ?? "").join("")
          : (p.text ?? "");
    if (role === "system") system = text;
    else if (role === "user") user = text;
  }
  return { system, user };
}

function generatedText(result: DoGenerateResult): string {
  if (typeof result.text === "string") return result.text;
  if (Array.isArray(result.content)) {
    return result.content
      .filter((c) => c.type === "text" || !c.type)
      .map((c) => c.text ?? "")
      .join("");
  }
  return "";
}

/**
 * Wrap a Vercel AI SDK language model so inbound prompts are scanned
 * before the call and outputs are scanned after. Returns a new model
 * object preserving every original method.
 */
export function sieveMiddleware<M extends LanguageModelLike>(model: M): M {
  const original = model.doGenerate.bind(model);
  const wrapped = {
    ...model,
    doGenerate: async (options: DoGenerateOptions): Promise<DoGenerateResult> => {
      const { system, user } = flattenPrompt(options.prompt);
      const pre = await sieveCheck(system, user);
      if (pre.decision === "Block") {
        throw new PromptInjectionBlocked(pre);
      }
      const result = await original(options);
      const post = await sieveCheckOutput(system, generatedText(result), pre.canary_state);
      (result as { sieve?: unknown }).sieve = post;
      if (post.decision === "Block") {
        throw new PromptInjectionBlocked(post);
      }
      return result;
    },
  } as M;

  if (typeof model.doStream === "function") {
    const originalStream = model.doStream.bind(model);
    wrapped.doStream = async (options: DoGenerateOptions): Promise<unknown> => {
      // Streaming: pre-flight scan only in v0.1; post-flight on stream
      // chunks lands with the streaming scanner in v0.3.
      const { system, user } = flattenPrompt(options.prompt);
      const pre = await sieveCheck(system, user);
      if (pre.decision === "Block") {
        throw new PromptInjectionBlocked(pre);
      }
      return originalStream(options);
    };
  }

  return wrapped;
}

export { PromptInjectionBlocked };
export type { CanaryState };
