# Public App Policy

The raw scanner is intentionally strict. That is useful at internal trust
boundaries, but a public chat box should not blindly refuse every ambiguous
`Block` verdict. Use the `public_app` policy profile for public-facing inputs.

The policy layer keeps the raw verdict intact and adds an app-facing decision:

```text
scan input -> raw Verdict -> apply public_app policy -> app action
```

`public_app` only marks `safe_to_auto_block` for high-confidence cases such as
direct secret exfiltration, canary leaks, tool-boundary injection, RAG document
injection, role-boundary smuggling, and actionable encoded payloads. Ambiguous
roleplay, documentation, education, debugging, and policy questions are logged
or reviewed instead of hard-blocked.

## Rust

```rust
use sieve_core::{apply_policy, PolicyProfile, RecommendedAction, Scanner};

let scanner = Scanner::default();
let verdict = scanner.scan_input(system_prompt, user_input);
let policy = apply_policy(PolicyProfile::PublicApp, &verdict);

if policy.safe_to_auto_block {
    return Err("prompt injection blocked");
}

log::debug!("sieve action={:?} verdict={:?}", policy.recommended_action, verdict);
```

## Python

```python
import sieve

scanner = sieve.Scanner()
verdict = scanner.scan_input(system_prompt, user_input)
policy = scanner.apply_policy("public_app", verdict)

if policy.safe_to_auto_block:
    raise sieve.PromptInjectionBlocked(verdict)

print(policy.recommended_action, policy.confidence)
```

## Next.js

```typescript
import { applySievePolicy, sieveCheck } from "sieve-guard-nextjs";

const verdict = await sieveCheck(systemPrompt, userInput);
const policy = await applySievePolicy("public_app", verdict);

if (policy.safe_to_auto_block) {
  return Response.json({ error: "blocked", verdict, policy }, { status: 400 });
}
```

Wrapper helpers also accept the same profile:

```python
client = wrap(OpenAI(), policy="public_app")
```

```typescript
const client = wrapOpenAI(new OpenAI(), { policy: "public_app" });
const model = sieveMiddleware(openai("gpt-4o"), { policy: "public_app" });
```

## Profiles

| Profile | Use case | Auto-block behavior |
| --- | --- | --- |
| `strict` | Internal tools, tests, high-risk boundaries | Raw `Block` is safe to block |
| `public_app` | Public chat, search, support, content tools | Only high-confidence attacks are safe to block |
| `monitor` | Shadow rollout and telemetry-only trials | Never auto-blocks |

## Scenario Gate

The checked-in `public_app_policy_1000` suite currently runs 1620 generated
public-app scenarios plus 101 realistic benign public-app prompts:

- 600 benign public-app prompts: 0 hard-blocked.
- 101 realistic benign public-app prompts: 0 hard-blocked.
- 1020 high-confidence attacks: 1012 auto-blocked, 99.2%.
- Monitor policy: 0 hard-blocks across the same 1620 scenarios.

Run it locally:

```sh
cargo test -p sieve-core --test public_app_policy_1000 -- --nocapture
```
