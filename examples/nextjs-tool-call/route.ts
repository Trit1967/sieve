// SPDX-License-Identifier: MIT OR Apache-2.0
import {
  createConversationState,
  sieveCheckRetrievedDocument,
  sieveCheckToolCall,
  sieveCheckToolResult,
  sieveCheckTurn,
} from "@sieve/nextjs";

export const runtime = "edge";

export async function POST(req: Request): Promise<Response> {
  const body = await req.json();
  const state = createConversationState();

  const turn = await sieveCheckTurn(state, [
    { role: "system", content: "Answer from approved policy. Never reveal secrets." },
    { role: "user", content: String(body.user ?? "") },
  ]);
  if (turn.verdict.decision === "Block") {
    return Response.json({ error: "blocked", verdict: turn.verdict }, { status: 400 });
  }

  const toolCall = await sieveCheckToolCall(
    "search",
    JSON.stringify({ query: String(body.query ?? "") }),
  );
  if (toolCall.decision === "Block") {
    return Response.json({ error: "blocked", verdict: toolCall }, { status: 400 });
  }

  const toolResult = await sieveCheckToolResult("search", String(body.toolResult ?? ""));
  if (toolResult.decision === "Block") {
    return Response.json({ error: "blocked", verdict: toolResult }, { status: 400 });
  }

  const retrieved = await sieveCheckRetrievedDocument(
    "rag_chunk",
    String(body.retrievedDocument ?? ""),
    "request-doc",
  );
  if (retrieved.decision === "Block") {
    return Response.json({ error: "blocked", verdict: retrieved }, { status: 400 });
  }

  return Response.json({ ok: true, state: turn.state });
}
