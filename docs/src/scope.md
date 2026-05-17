# What this does NOT catch

Honesty is the project's reputational moat. v0.3 ships these limits
explicitly:

| Out of scope | Why |
|---|---|
| Novel paraphrased jailbreaks not in the corpus | Structural scorers help, but adaptive natural language remains a real miss class. |
| Adaptive adversarial attacks (gradient-optimized, RL-driven) | Not solved here. Do not treat this library as a formal guarantee. |
| Semantic attacks that read as natural language | Same. Optional LLM-judge hooks can help, but they are not enabled by default. |
| Multi-turn social engineering | Partial single-turn coverage; durable conversation state is still future work. |
| Indirect injection from RAG content | We *flag* (with provenance in v0.2); we cannot *stop* the model from being persuaded. |
| PII detection | Adjacent problem; deferred to v0.4 or a sister crate. |
| Generic content moderation (toxicity, hate, NSFW) | Out of scope. Use Llama Guard or similar. |
| Side-channel attacks (timing, length-based leakage) | Out of scope. |

If you're reading this list thinking "wait, that's a lot of things you
don't catch" — yes. Every prompt-injection library on the market has
these limits. Most don't lead with them. We do.
