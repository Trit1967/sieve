// SPDX-License-Identifier: MIT OR Apache-2.0
//! `WebAssembly` binding for sieve via wasm-bindgen.
//!
//! Published to npm as `sieve-guard-wasm`. The bundle is consumed directly from
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
    apply_policy as core_apply_policy, inject_system_prompt, CanaryState as CoreCanaryState,
    ChatMessage as CoreChatMessage, ConversationState as CoreConversationState,
    DocumentSourceKind as CoreDocumentSourceKind, MessageRole as CoreMessageRole,
    PolicyDecision as CorePolicyDecision, PolicyProfile as CorePolicyProfile,
    RetrievedDocument as CoreRetrievedDocument, Scanner as CoreScanner,
    ScannerMode as CoreScannerMode, ToolCall as CoreToolCall, ToolResult as CoreToolResult,
    Verdict as CoreVerdict,
};

#[derive(Deserialize)]
struct JsChatMessage {
    role: String,
    content: String,
    #[serde(default)]
    name: Option<String>,
}

fn parse_message_role(role: &str) -> Result<CoreMessageRole, JsError> {
    match role.trim().to_ascii_lowercase().as_str() {
        "system" => Ok(CoreMessageRole::System),
        "developer" => Ok(CoreMessageRole::Developer),
        "user" => Ok(CoreMessageRole::User),
        "assistant" => Ok(CoreMessageRole::Assistant),
        "tool" => Ok(CoreMessageRole::Tool),
        _ => Err(JsError::new(
            "role must be system|developer|user|assistant|tool",
        )),
    }
}

fn parse_document_source_kind(kind: &str) -> Result<CoreDocumentSourceKind, JsError> {
    match kind.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "rag_chunk" | "rag" => Ok(CoreDocumentSourceKind::RagChunk),
        "web_page" | "web" | "page" => Ok(CoreDocumentSourceKind::WebPage),
        "email" => Ok(CoreDocumentSourceKind::Email),
        "pdf" => Ok(CoreDocumentSourceKind::Pdf),
        "ocr" => Ok(CoreDocumentSourceKind::Ocr),
        "code_review" => Ok(CoreDocumentSourceKind::CodeReview),
        "issue_comment" | "github_comment" => Ok(CoreDocumentSourceKind::IssueComment),
        "tool_output" | "tool_result" => Ok(CoreDocumentSourceKind::ToolOutput),
        "other" | "document" => Ok(CoreDocumentSourceKind::Other),
        _ => Err(JsError::new(
            "sourceKind must be rag_chunk|web_page|email|pdf|ocr|code_review|issue_comment|tool_output|other",
        )),
    }
}

fn parse_policy_profile(profile: &str) -> Result<CorePolicyProfile, JsError> {
    CorePolicyProfile::parse(profile)
        .ok_or_else(|| JsError::new("profile must be strict|public_app|monitor"))
}

fn borrowed_chat_messages(messages: &[JsChatMessage]) -> Result<Vec<CoreChatMessage<'_>>, JsError> {
    messages
        .iter()
        .map(|message| {
            Ok(CoreChatMessage {
                role: parse_message_role(&message.role)?,
                content: &message.content,
                name: message.name.as_deref(),
            })
        })
        .collect()
}

fn serialize_verdict(verdict: &sieve_core::Verdict) -> Result<JsValue, JsError> {
    verdict
        .serialize(&Serializer::json_compatible())
        .map_err(|e| JsError::new(&format!("verdict serialize: {e}")))
}

fn serialize_policy_decision(policy: &CorePolicyDecision) -> Result<JsValue, JsError> {
    policy
        .serialize(&Serializer::json_compatible())
        .map_err(|e| JsError::new(&format!("policy serialize: {e}")))
}

/// Scanner handle exposed to JavaScript.
#[wasm_bindgen]
#[derive(Default)]
pub struct Scanner {
    inner: CoreScanner,
}

#[wasm_bindgen]
impl Scanner {
    /// Construct a default scanner.
    ///
    /// The default scanner enables every detector in strict mode.
    ///
    /// # Errors
    /// Returns a `JsError` if `mode` is not `strict`, `balanced`, or `monitor`,
    /// or if scanner construction fails.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::needless_pass_by_value)]
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
        serialize_verdict(&v)
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
        serialize_verdict(&v)
    }

    /// Scan a role-separated message list without collapsing trust boundaries.
    ///
    /// `messages` must be an array of `{ role, content, name? }` objects.
    ///
    /// # Errors
    /// Returns a `JsError` if messages cannot be deserialized, a role is
    /// invalid, or the verdict cannot be serialized.
    #[wasm_bindgen(js_name = scanMessages)]
    pub fn scan_messages(&self, messages: JsValue) -> Result<JsValue, JsError> {
        let owned: Vec<JsChatMessage> = serde_wasm_bindgen::from_value(messages)
            .map_err(|e| JsError::new(&format!("messages: {e}")))?;
        let borrowed = borrowed_chat_messages(&owned)?;
        let verdict = self.inner.scan_messages(&borrowed);
        serialize_verdict(&verdict)
    }

    /// Scan a structured tool call name and raw JSON arguments.
    ///
    /// # Errors
    /// Returns a `JsError` if the verdict cannot be serialized.
    #[wasm_bindgen(js_name = scanToolCall)]
    pub fn scan_tool_call(&self, name: &str, arguments_json: &str) -> Result<JsValue, JsError> {
        let verdict = self.inner.scan_tool_call(&CoreToolCall {
            name,
            arguments_json,
        });
        serialize_verdict(&verdict)
    }

    /// Scan untrusted tool output/result content.
    ///
    /// # Errors
    /// Returns a `JsError` if the verdict cannot be serialized.
    #[wasm_bindgen(js_name = scanToolResult)]
    pub fn scan_tool_result(&self, name: &str, content: &str) -> Result<JsValue, JsError> {
        let verdict = self
            .inner
            .scan_tool_result(&CoreToolResult { name, content });
        serialize_verdict(&verdict)
    }

    /// Scan untrusted retrieved content such as RAG chunks, web pages, emails,
    /// PDF/OCR text, and issue comments.
    ///
    /// # Errors
    /// Returns a `JsError` if the source kind is invalid or the verdict cannot
    /// be serialized.
    #[wasm_bindgen(js_name = scanRetrievedDocument)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn scan_retrieved_document(
        &self,
        source_kind: &str,
        content: &str,
        source_id: Option<String>,
    ) -> Result<JsValue, JsError> {
        let kind = parse_document_source_kind(source_kind)?;
        let verdict = self.inner.scan_retrieved_document(&CoreRetrievedDocument {
            source_kind: kind,
            source_id: source_id.as_deref(),
            content,
        });
        serialize_verdict(&verdict)
    }

    /// Scan a turn and return `{ verdict, state }` with updated caller-owned
    /// conversation state.
    ///
    /// # Errors
    /// Returns a `JsError` if state or messages cannot be deserialized, a role
    /// is invalid, or the output cannot be serialized.
    #[wasm_bindgen(js_name = scanTurn)]
    pub fn scan_turn(&self, state: JsValue, messages: JsValue) -> Result<JsValue, JsError> {
        let mut state: CoreConversationState = serde_wasm_bindgen::from_value(state)
            .map_err(|e| JsError::new(&format!("conversation state: {e}")))?;
        let owned: Vec<JsChatMessage> = serde_wasm_bindgen::from_value(messages)
            .map_err(|e| JsError::new(&format!("messages: {e}")))?;
        let borrowed = borrowed_chat_messages(&owned)?;
        let verdict = self.inner.scan_turn(&mut state, &borrowed);
        let out = serde_json::json!({
            "verdict": verdict,
            "state": state,
        });
        out.serialize(&Serializer::json_compatible())
            .map_err(|e| JsError::new(&format!("turn serialize: {e}")))
    }

    /// Apply an application policy profile to a raw verdict.
    ///
    /// Use `public_app` for public-facing chat and search inputs where
    /// ambiguous scanner blocks should be reviewed or logged instead of
    /// blindly refused.
    ///
    /// # Errors
    /// Returns a `JsError` if the policy profile is invalid, the verdict
    /// cannot be deserialized, or the policy decision cannot be serialized.
    #[wasm_bindgen(js_name = applyPolicy)]
    pub fn apply_policy(&self, profile: &str, verdict: JsValue) -> Result<JsValue, JsError> {
        let profile = parse_policy_profile(profile)?;
        let verdict: CoreVerdict = serde_wasm_bindgen::from_value(verdict)
            .map_err(|e| JsError::new(&format!("verdict: {e}")))?;
        let policy = core_apply_policy(profile, &verdict);
        serialize_policy_decision(&policy)
    }
}

/// Crate version, exported as a top-level JS constant.
#[wasm_bindgen(js_name = SIEVE_WASM_VERSION)]
#[must_use]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Return an empty caller-owned conversation state object.
///
/// # Errors
/// Returns a `JsError` if serialization fails.
#[wasm_bindgen(js_name = newConversationState)]
pub fn new_conversation_state() -> Result<JsValue, JsError> {
    CoreConversationState::new()
        .serialize(&Serializer::json_compatible())
        .map_err(|e| JsError::new(&format!("conversation state serialize: {e}")))
}

// Re-export traits so helper serializers and `JsChatMessage` derive work.
use serde::{Deserialize, Serialize as _};
