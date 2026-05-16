# What this does NOT catch

Honesty is the project's reputational moat. v0.1 ships these limits
explicitly:

| Out of scope | Why |
|---|---|
| Novel paraphrased jailbreaks not in the corpus | We're a pattern + heuristic + canary engine, not a semantic understander. v0.3 adds an optional LLM-judge for this. |
| Adaptive adversarial attacks (gradient-optimized, RL-driven) | Industry-wide unsolved (sub-50% catch everywhere as of 2026). We won't claim otherwise. |
| Semantic attacks that read as natural language | Same. v0.3 LLM-judge is the path forward. |
| Multi-turn social engineering | Partial coverage via conversation tracker in v0.2; not in v0.1. |
| Indirect injection from RAG content | We *flag* (with provenance in v0.2); we cannot *stop* the model from being persuaded. |
| PII detection | Adjacent problem; deferred to v0.4 or a sister crate. |
| Generic content moderation (toxicity, hate, NSFW) | Out of scope. Use Llama Guard or similar. |
| Side-channel attacks (timing, length-based leakage) | Out of scope. |

If you're reading this list thinking "wait, that's a lot of things you
don't catch" — yes. Every prompt-injection library on the market has
these limits. Most don't lead with them. We do.
