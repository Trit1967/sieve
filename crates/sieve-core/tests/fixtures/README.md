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
