// SPDX-License-Identifier: MIT OR Apache-2.0
//
// OpenAI SDK wrapper (`@sieve/nextjs/openai`).
//
// Usage:
//   import OpenAI from 'openai';
//   import { wrapOpenAI } from '@sieve/nextjs/openai';
//
//   const client = wrapOpenAI(new OpenAI());
//   const resp = await client.chat.completions.create({ ... });
//   console.log(resp.sieve.decision);

import {
  sieveCheck,
  sieveCheckOutput,
  instrumentSystemPrompt,
  PromptInjectionBlocked,
  type Verdict,
} from "./index.js";

interface MessagePart {
  text?: string;
  [key: string]: unknown;
}

interface Message {
  role?: string;
  content?: string | MessagePart[];
  [key: string]: unknown;
}

interface CreateArgs {
  messages?: Message[];
  [key: string]: unknown;
}

interface ChatCompletion {
  choices?: Array<{
    message?: { content?: string | null };
  }>;
  [key: string]: unknown;
}

function extractMessages(args: CreateArgs): { system: string; user: string } {
  const messages = args.messages ?? [];
  let system = "";
  let user = "";
  for (const m of messages) {
    const content = typeof m.content === "string"
      ? m.content
      : Array.isArray(m.content)
        ? m.content.map((p) => p.text ?? "").join("")
        : "";
    if (m.role === "system") system = content;
    else if (m.role === "user") user = content;
  }
  return { system, user };
}

function responseText(resp: ChatCompletion): string {
  return resp.choices?.[0]?.message?.content ?? "";
}

function withInstrumentedSystem(args: CreateArgs, systemPrompt: string): CreateArgs {
  const messages = args.messages ?? [];
  let replaced = false;
  const patched = messages.map((m) => {
    if (m.role === "system") {
      replaced = true;
      return { ...m, content: systemPrompt };
    }
    return m;
  });
  if (!replaced) {
    patched.unshift({ role: "system", content: systemPrompt });
  }
  return { ...args, messages: patched };
}

/**
 * Wrap an OpenAI client so every `chat.completions.create` call is
 * scanned in and out. Returns the same client (mutated in place).
 *
 * - Pre-flight scan runs before the LLM call. A `"Block"` verdict
 *   throws {@link PromptInjectionBlocked} without making the LLM call.
 * - Post-flight scan runs on the assistant message. A `"Block"` verdict
 *   throws {@link PromptInjectionBlocked} after the LLM has been
 *   called — the response is still attached to the error via
 *   `error.verdict`.
 * - Successful responses carry the post-flight verdict on `resp.sieve`.
 */
export function wrapOpenAI<T extends {
  chat: { completions: { create: (...args: any[]) => Promise<any> } };
}>(client: T): T {
  const original = client.chat.completions.create.bind(client.chat.completions);
  client.chat.completions.create = async (args: CreateArgs): Promise<any> => {
    const { system, user } = extractMessages(args);
    const pre = await sieveCheck(system, user);
    if (pre.decision === "Block") {
      throw new PromptInjectionBlocked(pre);
    }
    const instrumented = await instrumentSystemPrompt(system);
    const resp: ChatCompletion = await original(
      withInstrumentedSystem(args, instrumented.system_prompt),
    );
    const text = responseText(resp);
    const post = await sieveCheckOutput(system, text, instrumented.canary_state);
    (resp as { sieve?: Verdict }).sieve = post;
    if (post.decision === "Block") {
      throw new PromptInjectionBlocked(post);
    }
    return resp;
  };
  return client;
}

export { PromptInjectionBlocked };
