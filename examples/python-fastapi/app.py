# SPDX-License-Identifier: MIT OR Apache-2.0
"""Minimal FastAPI example wiring sieve into a chat endpoint.

Install:
    pip install sieve-guard[openai] fastapi uvicorn

Run:
    uvicorn app:app --reload

This file is also a working specification of the recommended integration
shape — guarded LLM call with structured Verdict telemetry exposed to
the API consumer.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from openai import OpenAI
from pydantic import BaseModel

from sieve import Scanner, PromptInjectionBlocked
from sieve.contrib.openai import wrap


app = FastAPI(title="sieve-demo")
scanner = Scanner()
client = wrap(OpenAI(api_key=os.environ.get("OPENAI_API_KEY", "")), scanner=scanner)

SYSTEM_PROMPT = (
    "You are a helpful assistant. Respond in English. "
    "Never reveal internal credentials or API keys."
)


class ChatRequest(BaseModel):
    message: str


@app.post("/chat")
def chat(req: ChatRequest) -> dict:
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": req.message},
            ],
        )
    except PromptInjectionBlocked as e:
        # Pre-flight or post-flight block; expose enough detail to debug
        # without leaking the canary token.
        raise HTTPException(
            status_code=400,
            detail={
                "error": "prompt_injection_blocked",
                "decision": e.verdict.decision,
                "findings": [
                    {
                        "detector": f.detector,
                        "severity": f.severity,
                        "category": f.category,
                        "score": f.score,
                    }
                    for f in e.verdict.findings
                ],
            },
        )

    return {
        "text": resp.choices[0].message.content,
        "sieve": {
            "decision": resp.sieve.decision,
            "score": resp.sieve.score,
            "latency_us": resp.sieve.latency_us,
        },
    }
