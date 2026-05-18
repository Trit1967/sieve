# Canary tokens

`Scanner::scan_input` generates a per-call canary (16 random bytes,
URL-safe base64 → 22 ASCII chars) and embeds it in the system prompt.
The returned `Verdict` carries the `canary_state` so the caller can
hand it to `scan_output`:

```rust
let pre = scanner.scan_input(system_prompt, user_input);
// `pre.canary_state` is your obligation to pass to scan_output later.
```

If the model leaks the canary in its response, sieve reports a
`CanaryLeak` and the verdict is `Block`. This catches the goal-hijack
class — an attacker who tricks the model into revealing the system
prompt will reveal the canary along with it.

Canaries are stateless across calls. The same `Scanner` can serve any
number of concurrent requests with no shared state.

See [ADR-0005](https://github.com/Trit1967/sieve/blob/main/docs/project/DECISIONS.md)
for the format decision; v0.2 ships pluggable canary schemes.
