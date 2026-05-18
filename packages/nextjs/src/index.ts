// SPDX-License-Identifier: MIT OR Apache-2.0
//
// sieve-guard-nextjs — Next.js / Vercel AI SDK helpers on top of sieve-guard-wasm.
//
// Sub-exports:
//   import { wrapOpenAI }       from 'sieve-guard-nextjs/openai';
//   import { sieveMiddleware }  from 'sieve-guard-nextjs/ai-sdk';
//
// This root module exposes the lower-level primitives that both
// sub-exports build on: `sieveCheck()` (a stateless input-only scan
// safe for Next.js middleware running on the Edge runtime) and the
// re-exported `Scanner` / `Verdict` shapes for users who want to drive
// the scanner themselves.

import * as sieveWasm from "sieve-guard-wasm";

let initialized: Promise<void> | null = null;
type ScannerHandle = InstanceType<typeof sieveWasm.Scanner>;
let scanner: ScannerHandle | null = null;

/** Internal: ensure the wasm module is loaded exactly once. */
async function getScanner(): Promise<ScannerHandle> {
  if (!initialized) {
    initialized = (async () => {
      const maybeInit = (sieveWasm as { default?: () => Promise<unknown> }).default;
      if (typeof maybeInit === "function") {
        await maybeInit();
      }
    })();
  }
  await initialized;
  if (!scanner) {
    scanner = new sieveWasm.Scanner();
  }
  return scanner;
}

/** Verdict-shaped object returned by the WASM core. */
export interface Verdict {
  decision: "Allow" | "Flag" | "Block";
  score: number;
  findings: Finding[];
  normalized_input: string | null;
  canary_state: CanaryState;
  canaries_leaked: CanaryLeak[];
  commitments_violated: CommitmentViolation[];
  latency_us: number;
}

export interface Finding {
  detector: string;
  severity: "Info" | "Warn" | "Block";
  message: string;
  matched_span: [number, number] | null;
  score: number;
  category: string;
}

export interface CanaryState {
  canaries: string[];
}

export interface CanaryLeak {
  canary: string;
  matched_span: [number, number];
  exact: boolean;
}

export interface CommitmentViolation {
  kind: string;
  expected: string;
  observed: string;
  confidence: number;
}

export interface InstrumentedPrompt {
  system_prompt: string;
  canary_state: CanaryState;
}

export type MessageRole = "system" | "developer" | "user" | "assistant" | "tool";

export interface ChatMessage {
  role: MessageRole;
  content: string;
  name?: string;
}

export interface ConversationState {
  turns_seen: number;
  prior_flags: number;
  prior_blocks: number;
  authority_claims: number;
  persona_shift_attempts: number;
  fake_memory_claims: number;
}

export interface TurnScanResult {
  verdict: Verdict;
  state: ConversationState;
}

export type DocumentSourceKind =
  | "rag_chunk"
  | "web_page"
  | "email"
  | "pdf"
  | "ocr"
  | "code_review"
  | "issue_comment"
  | "tool_output"
  | "other";

/**
 * Stateless input-only scan.
 *
 * Designed for use from Next.js Edge middleware where you only have the
 * request body and want to short-circuit obvious injection attempts
 * before they reach your route handler.
 *
 * For the full input+output pipeline, use {@link wrapOpenAI} or
 * {@link sieveMiddleware}.
 */
export async function sieveCheck(
  systemPrompt: string,
  userInput: string,
): Promise<Verdict> {
  const s = await getScanner();
  return s.scanInput(systemPrompt, userInput) as Verdict;
}

/** Convenience: instrument a system prompt with a fresh canary. */
export async function instrumentSystemPrompt(
  systemPrompt: string,
): Promise<InstrumentedPrompt> {
  const s = await getScanner();
  return s.instrumentSystemPrompt(systemPrompt) as InstrumentedPrompt;
}

/** Convenience: scan an output given the canary state from a prior input scan. */
export async function sieveCheckOutput(
  systemPrompt: string,
  output: string,
  canaryState: CanaryState,
): Promise<Verdict> {
  const s = await getScanner();
  return s.scanOutput(systemPrompt, output, canaryState) as Verdict;
}

/** Scan a role-separated chat transcript without flattening trust boundaries. */
export async function sieveCheckMessages(messages: ChatMessage[]): Promise<Verdict> {
  const s = await getScanner();
  return s.scanMessages(messages) as Verdict;
}

/** Scan a tool/function call name and raw JSON argument payload. */
export async function sieveCheckToolCall(
  name: string,
  argumentsJson: string,
): Promise<Verdict> {
  const s = await getScanner();
  return s.scanToolCall(name, argumentsJson) as Verdict;
}

/** Scan untrusted tool/function output before adding it to model context. */
export async function sieveCheckToolResult(
  name: string,
  content: string,
): Promise<Verdict> {
  const s = await getScanner();
  return s.scanToolResult(name, content) as Verdict;
}

/** Scan untrusted retrieved content before adding it to a RAG prompt. */
export async function sieveCheckRetrievedDocument(
  sourceKind: DocumentSourceKind,
  content: string,
  sourceId?: string,
): Promise<Verdict> {
  const s = await getScanner();
  return s.scanRetrievedDocument(sourceKind, content, sourceId) as Verdict;
}

/** Create an empty caller-owned conversation state object. */
export function createConversationState(): ConversationState {
  const maybeNewState = (sieveWasm as {
    newConversationState?: () => ConversationState;
  }).newConversationState;
  if (typeof maybeNewState === "function") {
    return maybeNewState();
  }
  return {
    turns_seen: 0,
    prior_flags: 0,
    prior_blocks: 0,
    authority_claims: 0,
    persona_shift_attempts: 0,
    fake_memory_claims: 0,
  };
}

/** Scan one structured conversation turn and return the updated state. */
export async function sieveCheckTurn(
  state: ConversationState,
  messages: ChatMessage[],
): Promise<TurnScanResult> {
  const s = await getScanner();
  return s.scanTurn(state, messages) as TurnScanResult;
}

/** Thrown by SDK wrappers when a verdict's decision is `"Block"`. */
export class PromptInjectionBlocked extends Error {
  readonly verdict: Verdict;
  constructor(verdict: Verdict) {
    super(`prompt injection blocked: ${verdict.findings.length} finding(s)`);
    this.name = "PromptInjectionBlocked";
    this.verdict = verdict;
  }
}

export const SIEVE_NEXTJS_VERSION = "0.3.0";
