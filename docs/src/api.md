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

## TypeScript (`@sieve/wasm` / `@sieve/nextjs`)

```typescript
class Scanner {
  constructor();
  scanInput(systemPrompt: string, userInput: string): Verdict;
  scanOutput(systemPrompt: string, output: string, canaryState: CanaryState | string): Verdict;
}
```

The verdict shape is byte-identical across all three bindings — see
[ADR-0010](https://github.com/Trit1967/sieve/blob/main/DECISIONS.md).
