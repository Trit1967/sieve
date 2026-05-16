# Commitments

Sieve extracts deterministic commitments from the system prompt and
verifies them against the model output. v0.1 ships three kinds:

| Commitment | System-prompt trigger | Output check |
|---|---|---|
| `Language` | "respond in English" / "speak French" | Stopword-frequency language detection (top-9 languages). |
| `Persona` | "You are Bob" | Output's first-person self-identification ("I am X") must match. |
| `RefusalKeyword` | "never discuss medical advice" | Output must not contain the forbidden phrase. |

Violations become `CommitmentViolation` entries in the output verdict
and contribute findings of `Severity::Block` (for `refusal_keyword`) or
`Severity::Warn` (for `language` / `persona`).

The semantic / LLM-judge half of commitment verification (for
commitments that can't be checked deterministically) is v0.3 work.
