# Improvement Goal Prompt

Improve `sieve` by turning canary protection from an exposed core primitive into behavior that actually works in first-party wrappers.

Primary finding:

- `Scanner::scan_input()` returns `canary_state`, but the Python and Next.js OpenAI wrappers forward the original system prompt to the provider. In wrapper usage, the model usually never sees the generated canary, so `scan_output()` can only detect synthetic leaks, not real system-prompt leakage.

Target outcome:

- Expose an explicit `instrument_system_prompt` API through Python and WASM/Next.js.
- Patch first-party wrappers so successful pre-flight scans send the instrumented system prompt to the provider.
- Use the same returned `canary_state` for post-flight output scanning.
- Preserve the original caller request shape as much as practical.
- Add a deterministic 500-case regression suite proving wrapper calls send an instrumented system prompt and scan the output with matching canary state.

Success criterion:

- The 500-case regression suite must pass at least 99% of cases.
- Existing Rust, Python, and Next.js smoke tests should continue to pass.
- If any case is intentionally allowed to fail, document why and keep the measured pass rate at or above 99%.

Non-goals:

- Do not claim formal prompt-injection soundness.
- Do not add network calls, telemetry, or vendor dependencies to `sieve-core`.
- Do not broaden into unrelated detector tuning unless needed to keep existing tests passing.
