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

Replay a local corpus with the same schema:

```sh
SIEVE_REPLAY_CORPUS=/path/to/public-app-corpus.jsonl \
  cargo test -p sieve-core --test external_corpus_replay -- --nocapture
```

On PowerShell:

```powershell
$env:SIEVE_REPLAY_CORPUS = "C:\path\to\public-app-corpus.jsonl"
cargo test -p sieve-core --test external_corpus_replay -- --nocapture
Remove-Item Env:\SIEVE_REPLAY_CORPUS
```

The fixture is intentionally compact so downstream users can copy the schema
and add their own application-specific traces without pulling in an app server
or a hosted evaluation service.

## `public_app_replay.schema.json`

JSON Schema for a single JSONL row. Use it in editors or CI validators when
maintaining an application-specific replay corpus. The Rust replay test also
enforces the same critical invariants at runtime:

- row IDs must be unique and non-empty.
- `retrieved_document` rows must include `source_kind`.
- `attack` rows must use `expected: "auto_block"`.
- `benign` rows must use `expected: "not_hard_block"`.
- unknown fields are rejected.

## `public_app_replay_template.jsonl`

A tiny copyable starter corpus with two attack rows and two benign rows. Replace
the `source` labels and `text` fields with traces from your own public app, then
run it with `SIEVE_REPLAY_CORPUS` or `scripts/public_app_replay_report.py
--corpus`.

Validate corpus shape without running the replay gates:

```sh
python scripts/validate_public_app_replay_corpus.py \
  crates/sieve-core/tests/fixtures/public_app_replay_template.jsonl
```
