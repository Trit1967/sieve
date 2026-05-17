# SPDX-License-Identifier: MIT OR Apache-2.0
"""sieve — vendor-neutral prompt injection defense.

Pure-string API on top of the pyo3-backed core. ``Scanner.scan_input`` and
``Scanner.scan_output`` mirror the Rust API one-to-one (ADR-0010).

Contrib wrappers for the OpenAI and Anthropic SDKs live in
``sieve.contrib`` and are installed via package extras::

    pip install sieve              # core only
    pip install sieve[openai]      # + OpenAI wrapper
    pip install sieve[anthropic]   # + Anthropic wrapper
"""

from ._native import (
    Scanner,
    Verdict,
    Finding,
    CanaryState,
    CanaryLeak,
    CommitmentViolation,
    instrument_system_prompt,
    __version__,
)


class PromptInjectionBlocked(Exception):
    """Raised by contrib wrappers when a verdict's decision is ``Block``."""

    def __init__(self, verdict: Verdict) -> None:
        super().__init__(
            f"prompt injection blocked: {len(verdict.findings)} finding(s)"
        )
        self.verdict = verdict


__all__ = [
    "Scanner",
    "Verdict",
    "Finding",
    "CanaryState",
    "CanaryLeak",
    "CommitmentViolation",
    "instrument_system_prompt",
    "PromptInjectionBlocked",
    "__version__",
]
