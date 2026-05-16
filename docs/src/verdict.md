# The verdict schema

Every `scan_input` and `scan_output` call returns a `Verdict`:

```json
{
  "decision": "Allow" | "Flag" | "Block",
  "score": 0.0,
  "findings": [
    {
      "detector": "unicode" | "patterns" | "encoding" | "heuristics" | "context" | "canary" | "commitments" | "<custom-classifier-name>",
      "severity": "Info" | "Warn" | "Block",
      "message": "human-readable explanation",
      "matched_span": [start, end] | null,
      "score": 0.0,
      "category": "UnicodeSmuggling" | "KnownPattern" | ...
    }
  ],
  "normalized_input": "post-Unicode-strip text",
  "canary_state": { "canaries": ["..."] },
  "canaries_leaked": [],
  "commitments_violated": [],
  "latency_us": 1234
}
```

## Decision rules

- **Block**: at least one finding has `severity: "Block"`.
- **Flag**: aggregate score ≥ 0.5 but no Block finding.
- **Allow**: everything else.

The aggregate `score` is the max of all `findings[*].score`, clamped to
`[0.0, 1.0]`.

## Categories cheat sheet

| Category | Source |
|---|---|
| `UnicodeSmuggling` | Tag codepoints, zero-width, homoglyphs, NFKC drift. |
| `KnownPattern` | Curated jailbreak corpus match. |
| `EncodingPayload` | base64 / hex / rot13-encoded jailbreak. |
| `InstructionDensity` | Heuristic scorer or context analyzer hit. |
| `LanguageSwitch` | Multiple Unicode scripts in one input. |
| `HighEntropy` | Repetition / low Shannon entropy. |
| `CanaryLeak` | Output side: model leaked the injected canary. |
| `CommitmentViolation` | Output side: language / persona / refusal-keyword drift. |
| `ToolCallAnomaly`, `ConversationDrift` | Reserved for v0.2 — tool-call linter + conversation tracker. |
