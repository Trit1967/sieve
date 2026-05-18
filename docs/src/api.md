# Public API

The public API surface is intentionally tiny.

## Rust (`sieve_core`)

```rust
pub struct Scanner { /* ... */ }
impl Scanner {
    pub fn default() -> Self;
    pub fn new() -> Self;
    pub fn builder() -> ScannerBuilder;
    pub fn scan_input(&self, system_prompt: &str, user_input: &str) -> Verdict;
    pub fn scan_output(&self, system_prompt: &str, output: &str, canary_state: &CanaryState) -> Verdict;
    pub fn apply_policy(&self, profile: PolicyProfile, verdict: &Verdict) -> PolicyDecision;
}

pub struct Verdict {
    pub decision: Decision,
    pub score: f32,
    pub findings: Vec<Finding>,
    pub normalized_input: Option<String>,
    pub canary_state: CanaryState,
    pub canaries_leaked: Vec<CanaryLeak>,
    pub commitments_violated: Vec<CommitmentViolation>,
    pub latency_us: u64,
}

pub enum Decision { Allow, Flag, Block }
pub enum PolicyProfile { Strict, PublicApp, Monitor }
pub enum RecommendedAction { Allow, Log, Review, StepUp, Block, Quarantine }
pub enum PolicyConfidence { Low, Medium, High }
pub struct PolicyDecision {
    pub profile: PolicyProfile,
    pub decision: Decision,
    pub recommended_action: RecommendedAction,
    pub confidence: PolicyConfidence,
    pub safe_to_auto_block: bool,
    pub reasons: Vec<String>,
}
pub enum Severity { Info, Warn, Block }
pub enum Category {
    UnicodeSmuggling, KnownPattern, EncodingPayload, InstructionDensity,
    LanguageSwitch, HighEntropy, CanaryLeak, CommitmentViolation,
    ToolCallAnomaly, ConversationDrift,
}
```

`ScannerBuilder` lets you toggle individual detectors and plug in a
custom `Classifier` (the BYO-ONNX seam).

## Python (`sieve`)

Mirror of the Rust API. `decision`, `severity`, and `category` are
PascalCase string literals so Python users never see a Rust import.

`Scanner.apply_policy("public_app", verdict)` returns a `PolicyDecision`
with `recommended_action`, `confidence`, and `safe_to_auto_block`.

## TypeScript (`sieve-guard-wasm` / `sieve-guard-nextjs`)

```typescript
class Scanner {
  constructor();
  scanInput(systemPrompt: string, userInput: string): Verdict;
  scanOutput(systemPrompt: string, output: string, canaryState: CanaryState | string): Verdict;
  applyPolicy(profile: "strict" | "public_app" | "monitor", verdict: Verdict): PolicyDecision;
}

async function applySievePolicy(
  profile: "strict" | "public_app" | "monitor",
  verdict: Verdict,
): Promise<PolicyDecision>;
```

The verdict shape is byte-identical across all three bindings — see
[ADR-0010](https://github.com/Trit1967/sieve/blob/main/docs/project/DECISIONS.md).
