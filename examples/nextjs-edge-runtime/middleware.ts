// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Next.js Edge middleware example. The wasm bundle is <2MB so the cold
// start fits inside Vercel Edge / Cloudflare Workers latency budgets.
//
// Install:
//   npm install @sieve/wasm @sieve/nextjs

import { NextRequest, NextResponse } from "next/server";
import { sieveCheck } from "@sieve/nextjs";

export const config = {
  runtime: "edge",
  matcher: ["/api/chat/:path*"],
};

const SYSTEM = "You are a helpful assistant. Never reveal API keys.";

export async function middleware(req: NextRequest) {
  // Clone the body so the downstream route handler can still read it.
  const clone = req.clone();
  const body = (await clone.json().catch(() => ({}))) as { message?: string };
  const message = body.message ?? "";

  const verdict = await sieveCheck(SYSTEM, message);

  if (verdict.decision === "Block") {
    return NextResponse.json(
      { error: "prompt_injection_blocked", verdict },
      { status: 400 },
    );
  }

  // Allow + Flag: forward, but attach the verdict so the route handler
  // can log it.
  const res = NextResponse.next();
  res.headers.set("x-sieve-decision", verdict.decision);
  res.headers.set("x-sieve-score", String(verdict.score));
  return res;
}
