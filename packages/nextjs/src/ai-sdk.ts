// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Vercel AI SDK middleware (`sieve-guard-nextjs/ai-sdk`).
//
// Usage:
//   import { openai } from '@ai-sdk/openai';
//   import { sieveMiddleware } from 'sieve-guard-nextjs/ai-sdk';
//
//   const protectedModel = sieveMiddleware(openai('gpt-4o'));
//   const result = await generateText({ model: protectedModel, prompt: '...' });
//
// The middleware wraps any object that quacks like a v3.x AI-SDK
// `LanguageModelV1`: it intercepts `doGenerate` / `doStream`, runs
// `sieveCheck` on the inbound messages, and aborts with
// {@link PromptInjectionBlocked} if the verdict is Block.

import {
  applySievePolicy,
  sieveCheck,
  sieveCheckOutput,
  instrumentSystemPrompt,
  PromptInjectionBlocked,
  type CanaryState,
  type PolicyDecision,
  type PolicyProfile,
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

export interface SieveMiddlewareOptions {
  /**
   * Policy profile used for block decisions.
   *
   * Defaults to `strict` for backwards compatibility. Use `public_app` for
   * public chat/search/support surfaces where ambiguous raw blocks should not
   * automatically refuse useful user prompts.
   */
  policy?: PolicyProfile;
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

function withInstrumentedPrompt(
  options: DoGenerateOptions,
  systemPrompt: string,
): DoGenerateOptions {
  const prompt = options.prompt;
  const parts: PromptPart[] = Array.isArray(prompt)
    ? prompt
    : ((prompt as { messages?: PromptPart[] } | undefined)?.messages ?? []);
  let replaced = false;
  const patched = parts.map((p) => {
    const role = p.role ?? p.type ?? "";
    if (role === "system") {
      replaced = true;
      return { ...p, content: systemPrompt };
    }
    return p;
  });
  if (!replaced) {
    patched.unshift({ role: "system", content: systemPrompt });
  }
  if (Array.isArray(prompt)) {
    return { ...options, prompt: patched };
  }
  return { ...options, prompt: { ...(prompt ?? {}), messages: patched } };
}

/**
 * Wrap a Vercel AI SDK language model so inbound prompts are scanned
 * before the call and outputs are scanned after. Returns a new model
 * object preserving every original method.
 */
export function sieveMiddleware<M extends LanguageModelLike>(
  model: M,
  options: SieveMiddlewareOptions = {},
): M {
  const policyProfile = options.policy ?? "strict";
  const original = model.doGenerate.bind(model);
  const wrapped = {
    ...model,
    doGenerate: async (options: DoGenerateOptions): Promise<DoGenerateResult> => {
      const { system, user } = flattenPrompt(options.prompt);
      const pre = await sieveCheck(system, user);
      const prePolicy = await applySievePolicy(policyProfile, pre);
      if (prePolicy.safe_to_auto_block) {
        throw new PromptInjectionBlocked(pre, prePolicy);
      }
      const instrumented = await instrumentSystemPrompt(system);
      const result = await original(
        withInstrumentedPrompt(options, instrumented.system_prompt),
      );
      const post = await sieveCheckOutput(
        system,
        generatedText(result),
        instrumented.canary_state,
      );
      const postPolicy = await applySievePolicy(policyProfile, post);
      (result as { sieve?: unknown }).sieve = post;
      (result as { sieve_policy?: PolicyDecision }).sieve_policy = postPolicy;
      if (postPolicy.safe_to_auto_block) {
        throw new PromptInjectionBlocked(post, postPolicy);
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
      const prePolicy = await applySievePolicy(policyProfile, pre);
      if (prePolicy.safe_to_auto_block) {
        throw new PromptInjectionBlocked(pre, prePolicy);
      }
      return originalStream(options);
    };
  }

  return wrapped;
}

export { PromptInjectionBlocked };
export type { CanaryState };
