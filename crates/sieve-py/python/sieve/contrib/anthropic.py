# SPDX-License-Identifier: MIT OR Apache-2.0
"""Anthropic SDK convenience wrapper.

Installed via ``pip install sieve-guard[anthropic]``. Same flow as
``sieve.contrib.openai.wrap`` but adapted to the Anthropic SDK's
``client.messages.create`` shape (which uses a top-level ``system``
parameter and a ``messages`` array of user/assistant turns).
"""

from __future__ import annotations

from typing import Any, Literal
from sieve import Scanner, PromptInjectionBlocked

PolicyProfile = Literal["strict", "public_app", "monitor"]


def _extract(kwargs: dict[str, Any]) -> tuple[str, str]:
    system = kwargs.get("system", "") or ""
    if isinstance(system, list):
        system = "\n".join(
            (p.get("text", "") if isinstance(p, dict) else getattr(p, "text", ""))
            for p in system
        )
    messages = kwargs.get("messages", []) or []
    user = ""
    for m in messages:
        role = m.get("role") if isinstance(m, dict) else getattr(m, "role", None)
        content = m.get("content") if isinstance(m, dict) else getattr(m, "content", "")
        if not isinstance(content, str):
            try:
                content = "".join(
                    p.get("text", "") if isinstance(p, dict) else getattr(p, "text", "")
                    for p in content
                )
            except (TypeError, AttributeError):
                content = ""
        if role == "user":
            user = content
    return system, user


def _response_text(resp: Any) -> str:
    try:
        blocks = resp.content if hasattr(resp, "content") else resp["content"]
        parts = []
        for b in blocks:
            if isinstance(b, dict):
                if b.get("type") == "text":
                    parts.append(b.get("text", ""))
            else:
                if getattr(b, "type", "") == "text":
                    parts.append(getattr(b, "text", ""))
        return "".join(parts)
    except (AttributeError, KeyError, IndexError, TypeError):
        return ""


def _should_block(scanner: Scanner, policy: PolicyProfile, verdict: Any) -> tuple[bool, Any]:
    decision = scanner.apply_policy(policy, verdict)
    return decision.safe_to_auto_block, decision


def wrap(
    client: Any,
    scanner: Scanner | None = None,
    policy: PolicyProfile = "strict",
) -> Any:
    if scanner is None:
        scanner = Scanner()
    original = client.messages.create

    def patched(**kwargs: Any) -> Any:
        system, user = _extract(kwargs)
        pre = scanner.scan_input(system, user)
        blocked, pre_policy = _should_block(scanner, policy, pre)
        if blocked:
            raise PromptInjectionBlocked(pre, pre_policy)
        resp = original(**kwargs)
        text = _response_text(resp)
        post = scanner.scan_output(system, text, pre.canary_state)
        _, post_policy = _should_block(scanner, policy, post)
        try:
            setattr(resp, "sieve", post)
            setattr(resp, "sieve_policy", post_policy)
        except (AttributeError, TypeError):
            try:
                resp.__dict__["sieve"] = post  # type: ignore[attr-defined]
                resp.__dict__["sieve_policy"] = post_policy  # type: ignore[attr-defined]
            except (AttributeError, TypeError):
                pass
        if post_policy.safe_to_auto_block:
            raise PromptInjectionBlocked(post, post_policy)
        return resp

    client.messages.create = patched
    return client


__all__ = ["wrap"]
