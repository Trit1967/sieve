// SPDX-License-Identifier: MIT OR Apache-2.0
//
// @sieve/nextjs — Next.js / Vercel AI SDK helpers on top of @sieve/wasm.
//
// Sub-exports:
//   import { wrapOpenAI }       from '@sieve/nextjs/openai';
//   import { sieveMiddleware }  from '@sieve/nextjs/ai-sdk';
//
// This root module exposes the lower-level primitives that both
// sub-exports build on: `sieveCheck()` (a stateless input-only scan
// safe for Next.js middleware running on the Edge runtime) and the
// re-exported `Scanner` / `Verdict` shapes for users who want to drive
// the scanner themselves.

import init, { Scanner } from "@sieve/wasm";

let initialized: Promise<void> | null = null;
let scanner: Scanner | null = null;

/** Internal: ensure the wasm module is loaded exactly once. */
async function getScanner(): Promise<Scanner> {
  if (!initialized) {
    initialized = (async () => {
      await init();
    })();
  }
  await initialized;
  if (!scanner) {
    scanner = new Scanner();
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

/** Convenience: scan an output given the canary state from a prior input scan. */
export async function sieveCheckOutput(
  systemPrompt: string,
  output: string,
  canaryState: CanaryState,
): Promise<Verdict> {
  const s = await getScanner();
  return s.scanOutput(systemPrompt, output, canaryState) as Verdict;
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

export const SIEVE_NEXTJS_VERSION = "0.1.0";
