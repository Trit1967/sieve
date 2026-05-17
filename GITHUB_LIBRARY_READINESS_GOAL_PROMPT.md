# GitHub Library Readiness Goal Prompt

You are working in the `sieve` repository. Treat this as an OSS security/devtool library, not an app. The goal is to make the project installable, trustworthy, and release-ready as a GitHub library.

## Objective

Turn `sieve` into a credible public GitHub library with consistent packaging, honest documentation, visible CI gates, usable integration examples, safer default behavior, and reproducible release dry-runs.

## Current Assessment

The repo already has a serious shape:

- Rust core library.
- Python binding.
- WASM binding.
- Next.js helpers.
- Adversarial harness.
- Canary plumbing regression tests.

But it is not yet release-polished. The largest risks are OSS trust and integration quality, not raw detector count.

## Required Work

### 1. Fix Version And Documentation Drift

- Align Rust workspace, Python package, WASM package, Next.js package, README, changelog, and release docs around the same current version.
- Remove stale v0.1 claims where the code has moved to v0.3 behavior.
- Update the README's "What this does NOT catch" section so it matches measured current behavior.
- Keep limitations blunt and specific.

Acceptance criteria:

- `Cargo.toml`, `crates/sieve-py/pyproject.toml`, `packages/nextjs/package.json`, WASM package metadata, README, and CHANGELOG do not contradict each other.
- README clearly says this is pre-release or release-ready, but not both.

### 2. Wire Canary Plumbing Regression Into CI

- Ensure the 500-case canary-plumbing regression suite runs in GitHub Actions.
- Make the CI job name explicit enough that a reviewer sees canary wrapper plumbing is protected.
- Preserve existing Rust, Python, WASM, Next.js, benchmark, and consistency jobs.

Acceptance criteria:

- CI runs the 500-case suite.
- CI fails if wrapper calls do not send the instrumented system prompt or use matching canary state for output scanning.

### 3. Add Operating Modes

Add library-level operating modes:

- `strict`: aggressive blocking for high-risk environments.
- `balanced`: block only high-confidence findings, flag ambiguous cases.
- `monitor`: never block; return findings and scores only.

Implement modes in the core API first, then expose them through Python/WASM/Next.js if practical.

Acceptance criteria:

- Default mode is documented and intentional.
- Mode behavior is tested.
- `monitor` mode never returns `Decision::Block`.
- `balanced` mode reduces benign false-blocks compared with `strict`.

### 4. Reduce False Positives

Use the adversarial harness false-block examples as regression targets. Current known false-block themes include:

- Benign roleplay.
- Developer/debug wording.
- API policy questions.
- Benign base64 decode questions.
- Creative writing involving words like "forget."

Do not lower recall blindly. Tune severity and mode behavior so common benign developer requests are not hard-blocked by default.

Acceptance criteria:

- Add regression tests for known false-block examples.
- `strict` may still block some ambiguous cases.
- `balanced` should flag or allow most benign examples without dropping below the project's catch-rate floor.

### 5. Improve Integration-First Examples

Update README and examples so a new user can copy-paste a working integration quickly.

Include:

- Rust minimal scanner.
- Python FastAPI/OpenAI wrapper.
- Next.js route handler.
- Vercel AI SDK middleware.
- Scan-only/monitor-mode example.
- Output scanning with canary state.

Acceptance criteria:

- Examples compile or are covered by smoke tests where practical.
- The canary examples send the instrumented prompt to the model, not only synthetic test output.

### 6. Avoid Soundness Overclaims

Do not claim formal prompt-injection soundness. Position the library as:

> Offline prompt-injection detection and output-leak protection with measurable regression tests.

Document:

- What is verified.
- What is inferred.
- What remains unsolved.
- False-positive and false-negative tradeoffs.

Acceptance criteria:

- README, docs, launch copy, and package descriptions do not imply guaranteed protection.
- Any benchmark claims include corpus size and measurement context.

### 7. Run Release Dry-Runs

Perform clean install/build checks for every public surface:

- Rust crate build and tests.
- Python wheel build and import test.
- WASM package build.
- Next.js package build, typecheck, and tests.
- Example app install where feasible.

Acceptance criteria:

- Dry-run commands and outputs are recorded in a release-readiness note.
- Any blocker is either fixed or listed with owner, severity, and next action.

## Verification Commands

Run at minimum:

```powershell
$cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
& $cargo fmt --all -- --check
& $cargo test -q
& $cargo test -q -p sieve-core --test adversarial_500 -- --nocapture
cd packages\nextjs
npm test -- --run
npm run typecheck
cd ..\..
$py = if (Test-Path .venv\Scripts\python.exe) { '.venv\Scripts\python.exe' } else { 'python' }
& $py -m pytest crates/sieve-py/python/sieve/tests/test_basic.py -q
```

Add package build commands during the release dry-run phase.

## Success Definition

The project is ready for a credible GitHub-library release when:

- Version and docs are internally consistent.
- Canary wrapper plumbing is protected by CI.
- Operating modes are implemented and documented.
- Known false-positive classes are tested and improved.
- README is integration-first and honest.
- Release dry-runs pass or have documented blockers.
- No copy claims formal soundness or guaranteed prompt-injection prevention.
