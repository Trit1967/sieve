# SPDX-License-Identifier: MIT OR Apache-2.0
"""OpenAI SDK convenience wrapper.

Installed via ``pip install sieve[openai]``. The wrapper monkey-patches
``client.chat.completions.create`` to:

1. Call ``scanner.scan_input(system, user)`` on the messages.
2. Raise ``PromptInjectionBlocked`` if the verdict blocks.
3. Forward the request to the underlying client.
4. Call ``scanner.scan_output(system, response_text, canary_state)``.
5. Attach the verdict to the response as ``.sieve``.

The wrapper performs ZERO network I/O of its own (R1). All network calls
happen inside the OpenAI client the user supplied — sieve only sees the
strings that flow through.
"""

from __future__ import annotations

from typing import Any
from sieve import Scanner, PromptInjectionBlocked


def _extract_messages(kwargs: dict[str, Any]) -> tuple[str, str]:
    """Return (system_prompt, last_user_message) from a `messages` kwarg.

    Falls back to empty strings if the kwarg shape isn't recognized — the
    scanner is robust to empty inputs and will simply emit no findings.
    """
    messages = kwargs.get("messages", []) or []
    system = ""
    user = ""
    for m in messages:
        role = m.get("role") if isinstance(m, dict) else getattr(m, "role", None)
        content = m.get("content") if isinstance(m, dict) else getattr(m, "content", "")
        if not isinstance(content, str):
            # Multi-part content (image+text) — flatten the text parts.
            try:
                content = "".join(
                    p.get("text", "") if isinstance(p, dict) else getattr(p, "text", "")
                    for p in content
                )
            except (TypeError, AttributeError):
                content = ""
        if role == "system":
            system = content
        elif role == "user":
            user = content
    return system, user


def _response_text(resp: Any) -> str:
    try:
        choices = resp.choices if hasattr(resp, "choices") else resp["choices"]
        first = choices[0]
        msg = first.message if hasattr(first, "message") else first["message"]
        content = msg.content if hasattr(msg, "content") else msg["content"]
        return content or ""
    except (AttributeError, KeyError, IndexError, TypeError):
        return ""


def wrap(client: Any, scanner: Scanner | None = None) -> Any:
    """Wrap an OpenAI client. Returns the same client with
    ``chat.completions.create`` monkey-patched in place.

    Args:
        client: An instance of ``openai.OpenAI`` (or anything implementing
            ``client.chat.completions.create(**kwargs)``).
        scanner: Optional pre-built ``sieve.Scanner``. If omitted, a default
            scanner is constructed.

    Returns:
        The same client (mutated). The patched method:
        - sets ``resp.sieve`` on success to the post-flight ``Verdict``.
        - raises ``PromptInjectionBlocked`` on a Block verdict.
    """
    if scanner is None:
        scanner = Scanner()
    original = client.chat.completions.create

    def patched(**kwargs: Any) -> Any:
        system, user = _extract_messages(kwargs)
        pre = scanner.scan_input(system, user)
        if pre.is_block():
            raise PromptInjectionBlocked(pre)
        resp = original(**kwargs)
        text = _response_text(resp)
        post = scanner.scan_output(system, text, pre.canary_state)
        try:
            setattr(resp, "sieve", post)
        except (AttributeError, TypeError):
            # Frozen / pydantic models: stash on a mutable attribute the
            # caller can still see.
            try:
                resp.__dict__["sieve"] = post  # type: ignore[attr-defined]
            except (AttributeError, TypeError):
                pass
        if post.is_block():
            raise PromptInjectionBlocked(post)
        return resp

    client.chat.completions.create = patched
    return client


__all__ = ["wrap"]
