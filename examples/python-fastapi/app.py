# SPDX-License-Identifier: MIT OR Apache-2.0
"""Minimal FastAPI example wiring sieve into a chat endpoint.

Install:
    pip install sieve-guard[openai] fastapi uvicorn

Run:
    uvicorn app:app --reload

This file is also a working specification of the recommended public-app
integration shape: scan, apply policy, block only when the policy says an
auto-block is safe, then scan model output before returning it.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from openai import OpenAI
from pydantic import BaseModel

from sieve import Scanner, instrument_system_prompt


app = FastAPI(title="sieve-demo")
scanner = Scanner()
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

SYSTEM_PROMPT = (
    "You are a helpful assistant. Respond in English. "
    "Never reveal internal credentials or API keys."
)


class ChatRequest(BaseModel):
    message: str


@app.post("/chat")
def chat(req: ChatRequest) -> dict:
    pre = scanner.scan_input(SYSTEM_PROMPT, req.message)
    pre_policy = scanner.apply_policy("public_app", pre)
    if pre_policy.safe_to_auto_block:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "prompt_injection_blocked",
                "decision": pre.decision,
                "policy": pre_policy.to_dict(),
                "findings": [
                    {
                        "detector": f.detector,
                        "severity": f.severity,
                        "category": f.category,
                        "score": f.score,
                    }
                    for f in pre.findings
                ],
            },
        )

    instrumented_system, canary_state = instrument_system_prompt(SYSTEM_PROMPT)
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": instrumented_system},
            {"role": "user", "content": req.message},
        ],
    )
    text = resp.choices[0].message.content
    post = scanner.scan_output(SYSTEM_PROMPT, text, canary_state)
    post_policy = scanner.apply_policy("public_app", post)
    if post_policy.safe_to_auto_block:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "prompt_injection_blocked",
                "decision": post.decision,
                "policy": post_policy.to_dict(),
            },
        )

    return {
        "text": text,
        "sieve": {
            "decision": pre.decision,
            "score": pre.score,
            "latency_us": pre.latency_us,
            "policy": pre_policy.to_dict(),
            "output_policy": post_policy.to_dict(),
        },
    }
