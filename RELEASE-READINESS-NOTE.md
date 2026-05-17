# Release Readiness Note

Generated during the GitHub-library readiness pass.

## Completed

- Aligned Python and Next.js package versions to `0.3.0`.
- Updated README and docs away from stale v0.1 wording where it affected public trust.
- Added explicit scanner operating modes:
  - `strict`: historical aggressive blocking.
  - `balanced`: high-confidence blocks, ambiguous block findings become flags.
  - `monitor`: never returns `Block`.
- Exposed mode selection through the Rust builder, Python `Scanner(mode)`, and WASM `new Scanner(mode)`.
- Kept default mode as `strict` to preserve existing detection behavior.
- Expanded the canary wrapper plumbing regression suite to 1000 cases.
- Renamed the CI job to make the 1000-case canary plumbing gate visible.
- Preserved and verified the canary instrumentation API added in the previous pass.

## Local Verification

Passing:

```powershell
$cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
& $cargo fmt --all -- --check
& $cargo test -q
& $cargo test -q -p sieve-core --test adversarial_500 -- --nocapture
cd packages\nextjs
npm test -- --run
npm run typecheck
npm run build
cd ..\..
$py = if (Test-Path .venv\Scripts\python.exe) { '.venv\Scripts\python.exe' } else { 'python' }
& $py -m maturin develop --manifest-path crates/sieve-py/Cargo.toml
& $py -m pytest crates/sieve-py/python/sieve/tests/test_basic.py -q
& $py -m maturin build --manifest-path crates/sieve-py/Cargo.toml
& $cargo package -q -p sieve-core --allow-dirty
& $cargo build -q -p sieve-wasm --target wasm32-unknown-unknown
```

Observed highlights:

- Rust workspace tests: `218` core tests plus integration suites passed.
- Adversarial harness: `2893 / 2894` attacks caught, `22 / 626` benign stress probes false-blocked in strict mode.
- Next.js tests: `1004` passed, including `1000` canary-plumbing regression cases.
- Python smoke tests: `11` passed.
- Python wheel dry-run built `sieve-0.3.0-cp39-abi3-win_amd64.whl`.
- Next.js package build produced ESM, CJS, and DTS outputs.
- `sieve-core` crate package dry-run passed.
- `sieve-wasm` lower-level Rust build for `wasm32-unknown-unknown` passed after installing that target.
- Full `wasm-pack build crates/sieve-wasm --release --target web` passed.
- Full `wasm-pack build crates/sieve-wasm --release --target bundler` passed.
- Clean sample install smoke passed using local `@sieve/wasm` and `@sieve/nextjs` artifacts.
- The sample smoke caught and drove fixes for two package-shape issues:
  - `@sieve/nextjs` ESM exports pointed to `.mjs` files that the build does not emit.
  - `@sieve/nextjs` assumed a default WASM init export; it now tolerates wasm-pack targets that do not provide one.
  - WASM scanner timing used `std::time::Instant`; `latency_us` is now `0` on `wasm32` instead of panicking.

## GitHub Actions Status

- The current local changes are not yet pushed, so GitHub Actions has not run on this exact tree.
- GitHub reported no workflow runs or combined statuses for local base commit `aa44db5f6d909876237d271941d6f4802054eeab`.
- CI now includes an explicit sample-install smoke job in addition to the 1000-case canary-plumbing job.
- To run remote CI on this exact tree, push these changes to a branch and open a PR against `main`.

## Next Recommended Work

- Add a full balanced-mode adversarial/FPR harness before changing the default mode from `strict`.
