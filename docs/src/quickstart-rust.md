# Quickstart (Rust)

```rust
use sieve_core::{Scanner, Decision};

let scanner = Scanner::default();

let pre = scanner.scan_input(&system_prompt, &user_input);
if pre.decision == Decision::Block {
    return Err("prompt injection blocked".into());
}

let response: String = your_llm_call(&system_prompt, &user_input).await?;

let post = scanner.scan_output(&system_prompt, &response, &pre.canary_state);
if post.decision == Decision::Block {
    return Err("model output blocked".into());
}
```

The example crate at [`examples/rust-basic`](https://github.com/Trit1967/sieve/tree/main/examples/rust-basic)
runs each of the four scanner-side cases (benign, direct injection,
Unicode-tag smuggling, canary-leak detection).
