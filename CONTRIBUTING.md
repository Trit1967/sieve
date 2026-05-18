# Contributing to sieve

Thanks for considering a contribution. This project is security-adjacent, so the bar on correctness is higher than typical — please read this before opening a PR.

## Ground rules

1. **No network calls in `sieve-core`.** Period. (See ADR-0006.)
2. **No LLM-vendor dependencies in core.** SDK wrappers live in `contrib/` subpackages.
3. **No `unwrap()` / `expect()` / `panic!()` in production paths.** Tests are exempt.
4. **No telemetry, ever.** This is permanent.
5. **No emojis in code or docs.**
6. **One logical change per commit.** Atomic, conventional-commit format.

## Setup

```sh
# Rust
rustup toolchain install stable
rustup component add clippy rustfmt llvm-tools-preview

# Python
py -m pip install maturin pytest

# Node
npm install -g pnpm
```

## Workflow

1. Fork + branch from `main`.
2. Read `docs/project/PRD.md`, `docs/project/ARCHITECTURE.md`, `research/goals/IMPLEMENTATION_PROMPT.md`, and `docs/project/DECISIONS.md`.
3. If your change adds a new detector, file a design issue first.
4. Run the quality gates locally:
   ```sh
   cargo fmt --check
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all-features
   cargo deny check
   ```
5. Open PR with a description that ties the change to a phase from research/goals/IMPLEMENTATION_PROMPT.md (or explains why it's outside the phase plan).

## Reporting bypasses

If you found an input that defeats sieve, do not open a public PR/issue first. See [SECURITY.md](SECURITY.md) for the disclosure workflow.

Every fixed bypass becomes a permanent regression test in `crates/sieve-core/tests/regression/`.

## Adding patterns to the wordlist

`crates/sieve-core/src/data/jailbreaks.txt` ships with the crate. Adding patterns:

- One pattern per line.
- ASCII-fold + lowercase normalization is applied at load time.
- Cite the source in `crates/sieve-core/src/data/provenance.txt`.
- Run `cargo test --test corpus -- --include-ignored` to verify FPR doesn't regress on the curated benign set.

## Testing

| Layer | When it runs |
|---|---|
| Unit | every commit |
| Property (proptest) | every commit, 1000+ cases |
| Integration | every commit |
| Fuzz (cargo-fuzz) | weekly + on-demand |
| Corpus (JailbreakBench / garak / ACL'25 / benign) | every commit |
| Cross-language consistency | every commit |
| Performance regression (criterion) | every commit; fail >10% regression |
| Real-LLM (gated on secrets) | nightly, `main` only |

## License

By contributing you agree your work is dual-licensed under MIT + Apache-2.0.
