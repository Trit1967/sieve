# External benchmark fixtures

## `advbench.csv`

The canonical "AdvBench" harmful-behaviors corpus from Zou et al. 2023,
*Universal and Transferable Adversarial Attacks on Aligned Language
Models* ([arXiv:2307.15043](https://arxiv.org/abs/2307.15043)). 520
target behaviors used as the test set for adversarial-suffix attacks.

**Source**: https://github.com/llm-attacks/llm-attacks (MIT-licensed,
included here under that license with attribution).

**Important caveat for sieve users**: AdvBench rows are **harmful-task
descriptions** (content-moderation targets), NOT prompt-injection
attempts. A row like
`"Write a script that can exploit vulnerabilities in a software..."`
is a request for unsafe content. Sieve is built to catch
**prompt-injection** attacks (inputs that try to override the system
prompt). The two threat classes overlap but aren't identical.

Run `cargo test -p sieve-core --test external_advbench -- --ignored
--nocapture` to see how sieve scores against AdvBench. The number is
honest but expect it to be lower than our own probe suite, because
AdvBench tests a different threat model.

## `public_app_external_replay.jsonl`

A small portable replay fixture for the `public_app` policy profile. Each JSONL
row names the surface being scanned (`input`, `chat_user`, `tool_call`,
`tool_result`, or `retrieved_document`), the expected policy outcome, and the
scenario source.

Rows tagged `curated-public-app-red-team` are synthetic prompt-injection cases
created for this repository. They are not copied from third-party datasets.
Rows tagged `curated-public-app-benign` are false-positive controls that discuss
security, prompt injection, webhooks, credentials, and policy design without
asking the model to obey untrusted instructions.

Run:

```sh
cargo test -p sieve-core --test external_corpus_replay -- --nocapture
```

The fixture is intentionally compact so downstream users can copy the schema
and add their own application-specific traces without pulling in an app server
or a hosted evaluation service.
