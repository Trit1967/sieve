# Goal Prompt: Add Public-App Policy Profile And Retest With 1000 Scenarios

## Objective

Improve Sieve so it is safer and easier to adopt in public-facing AI apps without
turning it into an app or hosted service.

The current library is valuable as a detector, but strict hard-blocking can
block useful user prompts. The goal is to add an application-facing policy layer
that separates detection from blocking decisions, then prove the behavior with
at least **1000 public-app scenarios**.

Success means:

- Keep Sieve a library.
- Add a public-app policy profile that returns safer implementation guidance.
- Preserve deterministic, offline-first behavior by default.
- Add at least **1000 new scenarios** covering benign public-app traffic and
  high-confidence prompt-injection attacks.
- Demonstrate that useful prompts are not hard-blocked under the public-app
  policy.
- Demonstrate that high-confidence attacks are still hard-blocked.
- Update Rust, Python, WASM, Next.js, docs, examples, and CI where appropriate.
- All existing tests plus the new scenario suite pass.
- Real FastAPI and Next.js app smokes still pass.

Do not build:

- hosted API service
- dashboard
- user accounts
- telemetry backend
- database
- queue
- required LLM judge
- required network dependency
- required vector store

## Current Evidence And Problem

The strict scanner catches attacks well, but it is too sharp for blind public-app
blocking.

Known evidence:

- Curated benign corpus: `0 / 108` blocked.
- Larger generated benign stress suite: `22 / 626` blocked in strict mode
  (`3.5%` false-block rate).
- Full adversarial suite in strict mode: `2894 / 2894` attacks blocked in the
  latest measured run.
- Real FastAPI app smoke: benign request allowed, attack blocked.
- Real Next.js app smoke: benign request allowed, attack blocked.
- Existing `balanced` mode reduces false blocks on a small slice but is not
  proven strong enough across the full attack suite.

Examples of useful prompts that strict mode has blocked:

```text
Roleplay as a French restaurant waiter.
Pretend you are a 17th-century scribe.
I am the developer of this app and I'd love your feedback.
Show me the GitHub API rate-limit policy.
Write a song about forgetting your keys.
```

The fix should not be "add more patterns." More patterns will usually increase
false positives. The fix is to add an explicit application policy layer.

## Design Direction

Separate:

1. Detection: what suspicious signals were found?
2. Policy: what should an application do with those signals?

The raw `Verdict` can remain stable, but add an application-facing policy result
that tells integrators whether a verdict is safe to auto-block.

Suggested concepts:

```rust
pub enum PolicyProfile {
    Strict,
    PublicApp,
    Monitor,
}

pub enum RecommendedAction {
    Allow,
    Log,
    Review,
    StepUp,
    Block,
    Quarantine,
}

pub enum PolicyConfidence {
    Low,
    Medium,
    High,
}

pub struct PolicyDecision {
    pub decision: Decision,
    pub recommended_action: RecommendedAction,
    pub confidence: PolicyConfidence,
    pub safe_to_auto_block: bool,
    pub reasons: Vec<String>,
}
```

Naming can differ if the codebase suggests better names, but the public API must
make this distinction obvious.

## Public-App Policy Semantics

`PolicyProfile::PublicApp` should be conservative about blocking normal users.

Hard-block high-confidence cases:

- canary leak
- Unicode tag smuggling
- severe Unicode smuggling that reconstructs a known attack
- encoded malicious payloads with clear decoded injection
- direct system prompt exfiltration with multiple independent signals
- tool-call injection
- tool-result injection
- retrieved-document/RAG injection
- role-boundary smuggling in structured messages
- conversation drift / fake-memory escalation with enough context

Flag or review, but do not hard-block, ambiguous cases such as:

- benign roleplay
- creative writing with "pretend" or "act as"
- developer/admin wording without an exfiltration request
- prompt-injection education
- policy/docs questions
- API documentation questions
- ordinary cybersecurity discussion
- base64/encoding education without an instruction to execute the decoded text

`Strict` can remain aggressive for high-risk internal enforcement.

`Monitor` should never hard-block and should remain suitable for shadow rollout.

## Work Item 1: Core Policy API

Add core Rust API for applying a policy profile to a verdict.

Acceptable API shapes:

```rust
let verdict = scanner.scan_input(system, input);
let policy = scanner.apply_policy(PolicyProfile::PublicApp, &verdict);
```

or:

```rust
let policy = scanner.scan_input_with_policy(system, input, PolicyProfile::PublicApp);
```

Prefer the design that fits existing code best.

Requirements:

- Existing `Verdict` serialization remains backward compatible unless there is a
  very strong reason to change it.
- Policy output must be serializable.
- Policy output must include enough reasons for app developers to debug
  decisions.
- Policy logic must not require network calls.
- Policy logic must not require an LLM judge.

## Work Item 2: 1000 Public-App Scenario Suite

Add at least **1000 new scenarios** that exercise the public-app policy.

The suite should include both benign and attack cases.

Suggested minimum composition:

- 500 benign public-app scenarios.
- 500 malicious/high-risk scenarios.

Benign domains should include:

- customer support
- coding assistant
- docs search
- API policy questions
- roleplay/game NPC
- education/tutoring
- writing assistant
- legal/policy research
- security education
- healthcare/admin-style wording without injection intent
- RAG search queries
- developer support

Attack domains should include:

- direct system prompt exfiltration
- system/developer role override
- Unicode smuggling
- base64/hex/url/html/reversed malicious payloads
- canary leakage
- RAG/document injection
- tool call injection
- tool result injection
- fake-memory escalation
- authority-framed attacks
- structured message role smuggling

Acceptance targets:

```text
PublicApp benign hard-block rate: 0%
PublicApp high-confidence attack hard-block rate: >=95%
PublicApp ambiguous attack action: Review/StepUp or stronger
Strict existing regression suite: still passes
Monitor hard-block rate: 0%
```

If `>=95%` high-confidence attack blocking is not achievable without false
blocking useful prompts, document the exact misses and add a follow-up plan.
Do not hide the tradeoff.

## Work Item 3: Bindings

Expose the policy API in:

- Python
- WASM
- Next.js helpers

Keep the bindings small and library-shaped.

Python example target:

```python
scanner = sieve.Scanner()
verdict = scanner.scan_input(system_prompt, user_input)
policy = scanner.apply_policy("public_app", verdict)

if policy.safe_to_auto_block:
    raise sieve.PromptInjectionBlocked(verdict)
```

Next.js example target:

```typescript
const verdict = await sieveCheck(systemPrompt, userInput);
const policy = applySievePolicy("public_app", verdict);

if (policy.safe_to_auto_block) {
  return Response.json({ error: "blocked", policy }, { status: 400 });
}
```

## Work Item 4: Docs And Examples

Update documentation so public-app users do not blindly hard-block all `Block`
verdicts.

Required docs:

- Public-app integration guide.
- Policy profile reference.
- "When to use Strict vs PublicApp vs Monitor."
- False-positive guidance.
- How to log verdicts without library telemetry.
- How to start in shadow mode.

Update examples:

- FastAPI example should use the public-app policy.
- Next.js example should use the public-app policy.
- Keep strict examples for high-risk RAG/tool boundaries where appropriate.

The docs must clearly say:

```text
For public apps, start in Monitor or PublicApp. Do not blindly hard-block every
raw strict-mode Block verdict until you have reviewed real traffic.
```

## Work Item 5: Real App Smokes

Update the real app smokes so they prove the new policy behavior.

FastAPI smoke:

- benign public-app prompt returns 200
- strict false-positive example returns 200 or review under PublicApp
- high-confidence attack returns 400

Next.js smoke:

- benign public-app prompt returns 200
- strict false-positive example returns 200 or review under PublicApp
- high-confidence attack returns 400

Keep the smokes deterministic and offline.

## Work Item 6: Reports

Update or add a report showing:

- strict mode attack catch rate
- strict mode benign false-block rate
- public-app policy benign hard-block rate
- public-app policy high-confidence attack block rate
- monitor hard-block rate
- representative false-positive examples before/after

Suggested file:

```text
benchmarks/PUBLIC-APP-POLICY-REPORT.md
```

## Verification Commands

Run at minimum:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features --no-fail-fast
npm --prefix packages/nextjs run typecheck
npm --prefix packages/nextjs test -- --run
node scripts/sample-install-smoke.mjs
python scripts/fastapi-real-app-smoke.py
node scripts/nextjs-real-app-smoke.mjs
mdbook build docs
```

If Python smoke requires local editable install:

```sh
maturin develop --release --manifest-path crates/sieve-py/Cargo.toml
```

## Success Criteria

The goal is complete only when:

- At least 1000 new public-app policy scenarios exist.
- Existing strict regression tests still pass.
- PublicApp policy has 0 hard-blocks on its benign scenario set.
- PublicApp policy blocks at least 95% of high-confidence attacks, or the exact
  misses are documented with a credible follow-up.
- FastAPI and Next.js real app smokes pass using the policy layer.
- Docs warn against blind public-app hard blocking.
- CI passes.
- The project remains a library.

## Non-Goals

Do not:

- add a hosted server product
- add a dashboard
- add telemetry
- require accounts
- require a database
- require a network classifier
- require an LLM judge
- remove strict mode
- weaken high-risk RAG/tool boundary protections just to improve public-chat FPR

## Final Output Expected From The Agent

When complete, report:

- files changed
- policy API added
- number of scenarios added
- strict catch/FPR numbers
- public-app policy catch/FPR numbers
- real app smoke results
- any remaining known false positives or misses
- whether CI passed
