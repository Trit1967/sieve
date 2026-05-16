# BYO classifier

Sieve does NOT bundle ML weights ([R11](https://github.com/Trit1967/sieve/blob/main/PRD.md)).
Users plug in their own model via the `Classifier` trait:

```rust
use sieve_core::classifier::{Classifier, ClassificationResult};

#[derive(Debug)]
struct MyClassifier { /* ... */ }

impl Classifier for MyClassifier {
    fn classify(&self, input: &str) -> ClassificationResult {
        ClassificationResult {
            score: my_inference(input),
            label: "INJECTION".into(),
            metadata: Default::default(),
        }
    }
    fn name(&self) -> &'static str { "my-classifier" }
}

let scanner = sieve_core::Scanner::builder()
    .with_classifier(MyClassifier::load("model.onnx")?)
    .build()?;
```

The trait is `Send + Sync + Debug + object-safe` so any inference
backend works — `ort`, `candle`, `burn`, a remote HTTP endpoint (only
from user code, never from `sieve-core` itself).

Documented compatible models (no weights bundled, no auto-download):

- `deepset/deberta-v3-base-injection`
- `protectai/deberta-v3-base-prompt-injection-v2`

v0.2 ships an `ort`-backed reference implementation behind the `onnx`
feature once `ort` 2.0 stabilizes.
