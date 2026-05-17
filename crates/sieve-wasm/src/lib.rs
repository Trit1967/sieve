// SPDX-License-Identifier: MIT OR Apache-2.0
//! `WebAssembly` binding for sieve via wasm-bindgen.
//!
//! Published to npm as `@sieve/wasm`. The bundle is consumed directly from
//! browser code, Cloudflare Workers, Vercel Edge runtime, Deno, and Node.
//! Size budget: <2MB compressed (enforced in CI per ADR-0004).
//!
//! API contract mirrors `sieve_core::Scanner` 1:1 (ADR-0010 / R8 / R3).
//! `Verdict` and friends are returned as plain JS objects via
//! `serde_wasm_bindgen` so consumers see the canonical schema directly.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![warn(clippy::pedantic, missing_docs, rust_2018_idioms)]
#![allow(clippy::module_name_repetitions)]

use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::*;

use sieve_core::{
    inject_system_prompt, CanaryState as CoreCanaryState, Scanner as CoreScanner,
    ScannerMode as CoreScannerMode,
};

/// Scanner handle exposed to JavaScript.
#[wasm_bindgen]
pub struct Scanner {
    inner: CoreScanner,
}

#[wasm_bindgen]
impl Scanner {
    /// Construct a default scanner.
    ///
    /// The default scanner enables every detector in strict mode.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(mode: Option<String>) -> Result<Self, JsError> {
        let mode = mode
            .as_deref()
            .map(|m| {
                CoreScannerMode::parse(m)
                    .ok_or_else(|| JsError::new("mode must be strict|balanced|monitor"))
            })
            .transpose()?
            .unwrap_or(CoreScannerMode::Strict);
        let inner = CoreScanner::builder()
            .with_mode(mode)
            .build()
            .map_err(|e| JsError::new(&format!("scanner build: {e}")))?;
        Ok(Self { inner })
    }

    /// Run the input-side pipeline.
    ///
    /// Returns a JS object matching the `Verdict` schema.
    ///
    /// # Errors
    /// Returns a `JsError` only if serialization of the verdict fails (which
    /// is a bug — verdicts are always JSON-serializable per Phase 1).
    #[wasm_bindgen(js_name = scanInput)]
    pub fn scan_input(&self, system_prompt: &str, user_input: &str) -> Result<JsValue, JsError> {
        let v = self.inner.scan_input(system_prompt, user_input);
        // Preserve maps as plain JS objects (default behavior); the canonical
        // serializer matches the JSON wire format produced by the Rust core.
        v.serialize(&Serializer::json_compatible())
            .map_err(|e| JsError::new(&format!("verdict serialize: {e}")))
    }

    /// Instrument a system prompt with a fresh canary.
    ///
    /// Returns `{ system_prompt, canary_state }`. Wrappers should send the
    /// returned `system_prompt` to the model and pass the returned
    /// `canary_state` to `scanOutput`.
    ///
    /// # Errors
    /// Returns a `JsError` if canary generation or serialization fails.
    #[wasm_bindgen(js_name = instrumentSystemPrompt)]
    pub fn instrument_system_prompt(&self, system_prompt: &str) -> Result<JsValue, JsError> {
        let (instrumented, canary_state) = inject_system_prompt(system_prompt)
            .map_err(|e| JsError::new(&format!("canary instrument: {e}")))?;
        let out = serde_json::json!({
            "system_prompt": instrumented,
            "canary_state": canary_state,
        });
        out.serialize(&Serializer::json_compatible())
            .map_err(|e| JsError::new(&format!("instrument serialize: {e}")))
    }

    /// Run the output-side pipeline.
    ///
    /// `canary_state` is the value carried over from the prior `scanInput`
    /// call. It can be passed as either a `CanaryState` JS object or its
    /// JSON-serialized string (useful when shuttling state through Edge
    /// runtimes that flatten objects across worker boundaries).
    ///
    /// # Errors
    /// Returns a `JsError` if `canary_state` cannot be deserialized, or if
    /// the resulting verdict cannot be serialized.
    #[wasm_bindgen(js_name = scanOutput)]
    pub fn scan_output(
        &self,
        system_prompt: &str,
        output: &str,
        canary_state: JsValue,
    ) -> Result<JsValue, JsError> {
        let cs: CoreCanaryState = if canary_state.is_string() {
            let s: String = serde_wasm_bindgen::from_value(canary_state)
                .map_err(|e| JsError::new(&format!("canary_state string: {e}")))?;
            serde_json::from_str(&s)
                .map_err(|e| JsError::new(&format!("canary_state json: {e}")))?
        } else {
            serde_wasm_bindgen::from_value(canary_state)
                .map_err(|e| JsError::new(&format!("canary_state object: {e}")))?
        };
        let v = self.inner.scan_output(system_prompt, output, &cs);
        v.serialize(&Serializer::json_compatible())
            .map_err(|e| JsError::new(&format!("verdict serialize: {e}")))
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self {
            inner: CoreScanner::default(),
        }
    }
}

/// Crate version, exported as a top-level JS constant.
#[wasm_bindgen(js_name = SIEVE_WASM_VERSION)]
#[must_use]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// Re-export Serialize so the closure above can call it.
use serde::Serialize as _;
