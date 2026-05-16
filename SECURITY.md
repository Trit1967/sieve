# Security policy

`sieve` is a prompt-injection defense library. Bypasses are inevitable. We treat them as bugs, not embarrassments — every published bypass becomes a permanent regression test.

## Reporting a bypass

**Do not open a public issue with a working bypass.** Coordinate disclosure first.

1. Email: security@sieve.dev (placeholder — replace with real address before v0.1.0-rc1).
2. Subject: `[sieve bypass] <one-line summary>`.
3. Body should include:
   - Input(s) that bypass detection.
   - System prompt context (if relevant).
   - Affected version(s).
   - Your preferred attribution (name + handle, or "anonymous").
   - PGP key if you want an encrypted reply.

We will respond within 72 hours.

## What we will do

1. Reproduce and confirm.
2. Add a regression test under `crates/sieve-core/tests/regression/<issue-id>.rs`.
3. Implement a fix.
4. Cut a patch release.
5. Credit you in the release notes (unless you ask us not to).

## What we will NOT do

- Pay bug bounties (we're an OSS project — for now).
- Quietly fix and hope nobody notices. Every fix is publicly documented.
- Mark a bypass as "not a bug" because we deem the input "obvious." All inputs are fair game.

## What's out of scope

These are documented limits, not bypasses (see README + PRD §13):

- Novel paraphrased jailbreaks not in the corpus.
- Adaptive adversarial attacks (gradient-based, RL-driven).
- Semantic attacks indistinguishable from natural language.
- Indirect injection from RAG content (we flag, we cannot stop).
- Generic content moderation (toxicity, hate, NSFW).
- Side-channel timing attacks.

If you report one of these we will close the issue with a pointer here. Not because it isn't real — because it's outside what this library promises to catch.

## Supply chain

- All dependencies audited via `cargo deny check`.
- No build script downloads — every byte we ship comes from a versioned source.
- Reproducible builds for the Python wheel and WASM bundle.
- GPG-signed release tags.
