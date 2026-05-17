// SPDX-License-Identifier: MIT OR Apache-2.0
//! Python binding for sieve via pyo3.
//!
//! The crate is built as a `cdylib` and shipped as
//! `sieve._native` inside the `sieve` Python package. The pure-Python
//! layer in `python/sieve/__init__.py` re-exports the native types and
//! adds contrib wrappers (see `python/sieve/contrib/`).
//!
//! Per ADR-0010, the bindings reflect the core Verdict schema 1:1 and the
//! cross-language consistency test suite checks byte-equal canonical JSON
//! between Rust, Python, and WASM verdicts on every commit.

// pyo3 0.22: `PyRuntimeError::new_err` already returns `PyErr`, but the
// inference path through `map_err` makes clippy flag the closure body as a
// useless conversion. Allowing the lint at module level keeps the call
// sites readable.
#![allow(clippy::useless_conversion)]

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
use pyo3::wrap_pyfunction;

use sieve_core::{
    inject_system_prompt, CanaryLeak as CoreCanaryLeak, CanaryState as CoreCanaryState,
    Category as CoreCategory, ChatMessage as CoreChatMessage,
    CommitmentViolation as CoreCommitmentViolation, ConversationState as CoreConversationState,
    Decision as CoreDecision, DocumentSourceKind as CoreDocumentSourceKind, Finding as CoreFinding,
    MessageRole as CoreMessageRole, RetrievedDocument as CoreRetrievedDocument,
    Scanner as CoreScanner, ScannerMode as CoreScannerMode, Severity as CoreSeverity,
    ToolCall as CoreToolCall, ToolResult as CoreToolResult, Verdict as CoreVerdict,
};

// ---- Decision / Severity / Category ------------------------------------

fn decision_str(d: CoreDecision) -> &'static str {
    match d {
        CoreDecision::Allow => "Allow",
        CoreDecision::Flag => "Flag",
        CoreDecision::Block => "Block",
    }
}

fn severity_str(s: CoreSeverity) -> &'static str {
    match s {
        CoreSeverity::Info => "Info",
        CoreSeverity::Warn => "Warn",
        CoreSeverity::Block => "Block",
    }
}

#[allow(clippy::needless_pass_by_value)]
fn category_str(c: CoreCategory) -> &'static str {
    match c {
        CoreCategory::UnicodeSmuggling => "UnicodeSmuggling",
        CoreCategory::KnownPattern => "KnownPattern",
        CoreCategory::EncodingPayload => "EncodingPayload",
        CoreCategory::InstructionDensity => "InstructionDensity",
        CoreCategory::LanguageSwitch => "LanguageSwitch",
        CoreCategory::HighEntropy => "HighEntropy",
        CoreCategory::CanaryLeak => "CanaryLeak",
        CoreCategory::CommitmentViolation => "CommitmentViolation",
        CoreCategory::ToolCallAnomaly => "ToolCallAnomaly",
        CoreCategory::ConversationDrift => "ConversationDrift",
        _ => "Unknown",
    }
}

fn parse_message_role(role: &str) -> PyResult<CoreMessageRole> {
    match role.trim().to_ascii_lowercase().as_str() {
        "system" => Ok(CoreMessageRole::System),
        "developer" => Ok(CoreMessageRole::Developer),
        "user" => Ok(CoreMessageRole::User),
        "assistant" => Ok(CoreMessageRole::Assistant),
        "tool" => Ok(CoreMessageRole::Tool),
        _ => Err(PyValueError::new_err(
            "role must be system|developer|user|assistant|tool",
        )),
    }
}

fn parse_document_source_kind(kind: &str) -> PyResult<CoreDocumentSourceKind> {
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
        _ => Err(PyValueError::new_err(
            "source_kind must be rag_chunk|web_page|email|pdf|ocr|code_review|issue_comment|tool_output|other",
        )),
    }
}

struct OwnedChatMessage {
    role: CoreMessageRole,
    content: String,
    name: Option<String>,
}

fn parse_chat_messages(messages: &Bound<'_, PyAny>) -> PyResult<Vec<OwnedChatMessage>> {
    let mut out = Vec::new();
    for item in messages.try_iter()? {
        let item = item?;
        let role = item.get_item("role")?.extract::<String>()?;
        let content = item.get_item("content")?.extract::<String>()?;
        let name = match item.get_item("name") {
            Ok(value) if !value.is_none() => Some(value.extract::<String>()?),
            _ => None,
        };
        out.push(OwnedChatMessage {
            role: parse_message_role(&role)?,
            content,
            name,
        });
    }
    Ok(out)
}

fn borrowed_chat_messages(messages: &[OwnedChatMessage]) -> Vec<CoreChatMessage<'_>> {
    messages
        .iter()
        .map(|message| CoreChatMessage {
            role: message.role,
            content: &message.content,
            name: message.name.as_deref(),
        })
        .collect()
}

// ---- Finding -----------------------------------------------------------

#[pyclass(name = "Finding", module = "sieve._native", frozen)]
#[derive(Clone)]
struct Finding {
    inner: CoreFinding,
}

#[pymethods]
impl Finding {
    #[getter]
    fn detector(&self) -> &str {
        &self.inner.detector
    }
    #[getter]
    fn severity(&self) -> &'static str {
        severity_str(self.inner.severity)
    }
    #[getter]
    fn message(&self) -> &str {
        &self.inner.message
    }
    #[getter]
    fn matched_span(&self) -> Option<(usize, usize)> {
        self.inner.matched_span
    }
    #[getter]
    fn score(&self) -> f32 {
        self.inner.score
    }
    #[getter]
    fn category(&self) -> &'static str {
        category_str(self.inner.category)
    }
    fn __repr__(&self) -> String {
        format!(
            "Finding(detector='{}', severity='{}', category='{}', score={:.3})",
            self.inner.detector,
            severity_str(self.inner.severity),
            category_str(self.inner.category),
            self.inner.score,
        )
    }
}

// ---- CanaryState / CanaryLeak / CommitmentViolation --------------------

#[pyclass(name = "CanaryState", module = "sieve._native")]
#[derive(Clone)]
struct CanaryState {
    inner: CoreCanaryState,
}

#[pymethods]
impl CanaryState {
    #[new]
    #[pyo3(signature = (canaries=Vec::new()))]
    fn new(canaries: Vec<String>) -> Self {
        Self {
            inner: CoreCanaryState { canaries },
        }
    }
    #[getter]
    fn canaries(&self) -> Vec<String> {
        self.inner.canaries.clone()
    }
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("serialize: {e}")))
    }
    #[staticmethod]
    fn from_json(s: &str) -> PyResult<Self> {
        serde_json::from_str::<CoreCanaryState>(s)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("deserialize: {e}")))
    }
}

#[pyclass(name = "CanaryLeak", module = "sieve._native", frozen)]
#[derive(Clone)]
struct CanaryLeak {
    inner: CoreCanaryLeak,
}

#[pymethods]
impl CanaryLeak {
    #[getter]
    fn canary(&self) -> &str {
        &self.inner.canary
    }
    #[getter]
    fn matched_span(&self) -> (usize, usize) {
        self.inner.matched_span
    }
    #[getter]
    fn exact(&self) -> bool {
        self.inner.exact
    }
}

#[pyclass(name = "CommitmentViolation", module = "sieve._native", frozen)]
#[derive(Clone)]
struct CommitmentViolation {
    inner: CoreCommitmentViolation,
}

#[pymethods]
impl CommitmentViolation {
    #[getter]
    fn kind(&self) -> &str {
        &self.inner.kind
    }
    #[getter]
    fn expected(&self) -> &str {
        &self.inner.expected
    }
    #[getter]
    fn observed(&self) -> &str {
        &self.inner.observed
    }
    #[getter]
    fn confidence(&self) -> f32 {
        self.inner.confidence
    }
}

// ---- ConversationState -------------------------------------------------

#[pyclass(name = "ConversationState", module = "sieve._native")]
#[derive(Clone)]
struct ConversationState {
    inner: CoreConversationState,
}

#[pymethods]
impl ConversationState {
    #[new]
    #[pyo3(signature = (
        turns_seen=0,
        prior_flags=0,
        prior_blocks=0,
        authority_claims=0,
        persona_shift_attempts=0,
        fake_memory_claims=0
    ))]
    fn new(
        turns_seen: u32,
        prior_flags: u32,
        prior_blocks: u32,
        authority_claims: u32,
        persona_shift_attempts: u32,
        fake_memory_claims: u32,
    ) -> Self {
        Self {
            inner: CoreConversationState {
                turns_seen,
                prior_flags,
                prior_blocks,
                authority_claims,
                persona_shift_attempts,
                fake_memory_claims,
            },
        }
    }

    #[getter]
    fn turns_seen(&self) -> u32 {
        self.inner.turns_seen
    }

    #[getter]
    fn prior_flags(&self) -> u32 {
        self.inner.prior_flags
    }

    #[getter]
    fn prior_blocks(&self) -> u32 {
        self.inner.prior_blocks
    }

    #[getter]
    fn authority_claims(&self) -> u32 {
        self.inner.authority_claims
    }

    #[getter]
    fn persona_shift_attempts(&self) -> u32 {
        self.inner.persona_shift_attempts
    }

    #[getter]
    fn fake_memory_claims(&self) -> u32 {
        self.inner.fake_memory_claims
    }

    fn reset(&mut self) {
        self.inner.reset();
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("serialize: {e}")))
    }

    #[staticmethod]
    fn from_json(s: &str) -> PyResult<Self> {
        serde_json::from_str::<CoreConversationState>(s)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(format!("deserialize: {e}")))
    }

    fn __repr__(&self) -> String {
        format!(
            "ConversationState(turns_seen={}, prior_flags={}, prior_blocks={})",
            self.inner.turns_seen, self.inner.prior_flags, self.inner.prior_blocks,
        )
    }
}

// ---- Verdict -----------------------------------------------------------

#[pyclass(name = "Verdict", module = "sieve._native", frozen)]
struct Verdict {
    inner: CoreVerdict,
}

#[pymethods]
impl Verdict {
    #[getter]
    fn decision(&self) -> &'static str {
        decision_str(self.inner.decision)
    }
    #[getter]
    fn score(&self) -> f32 {
        self.inner.score
    }
    #[getter]
    fn findings(&self) -> Vec<Finding> {
        self.inner
            .findings
            .iter()
            .map(|f| Finding { inner: f.clone() })
            .collect()
    }
    #[getter]
    fn normalized_input(&self) -> Option<&str> {
        self.inner.normalized_input.as_deref()
    }
    #[getter]
    fn canary_state(&self) -> CanaryState {
        CanaryState {
            inner: self.inner.canary_state.clone(),
        }
    }
    #[getter]
    fn canaries_leaked(&self) -> Vec<CanaryLeak> {
        self.inner
            .canaries_leaked
            .iter()
            .map(|l| CanaryLeak { inner: l.clone() })
            .collect()
    }
    #[getter]
    fn commitments_violated(&self) -> Vec<CommitmentViolation> {
        self.inner
            .commitments_violated
            .iter()
            .map(|v| CommitmentViolation { inner: v.clone() })
            .collect()
    }
    #[getter]
    fn latency_us(&self) -> u64 {
        self.inner.latency_us
    }

    fn is_allow(&self) -> bool {
        self.inner.is_allow()
    }
    fn is_flag(&self) -> bool {
        self.inner.is_flag()
    }
    fn is_block(&self) -> bool {
        self.inner.is_block()
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyRuntimeError::new_err(format!("serialize: {e}")))
    }
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = self.to_json()?;
        let json_mod = py.import("json")?;
        let obj = json_mod.call_method1("loads", (s,))?;
        obj.extract()
    }
    fn __repr__(&self) -> String {
        format!(
            "Verdict(decision='{}', score={:.3}, findings={}, latency_us={})",
            decision_str(self.inner.decision),
            self.inner.score,
            self.inner.findings.len(),
            self.inner.latency_us,
        )
    }
}

// ---- Scanner -----------------------------------------------------------

#[pyclass(name = "Scanner", module = "sieve._native")]
struct Scanner {
    inner: CoreScanner,
}

#[pymethods]
impl Scanner {
    #[new]
    #[pyo3(signature = (mode=None))]
    fn new(mode: Option<&str>) -> PyResult<Self> {
        let mode = mode
            .map(|m| {
                CoreScannerMode::parse(m)
                    .ok_or_else(|| PyValueError::new_err("mode must be strict|balanced|monitor"))
            })
            .transpose()?
            .unwrap_or(CoreScannerMode::Strict);
        let inner = CoreScanner::builder()
            .with_mode(mode)
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("scanner build: {e}")))?;
        Ok(Self { inner })
    }

    fn scan_input(&self, system_prompt: &str, user_input: &str) -> Verdict {
        Verdict {
            inner: self.inner.scan_input(system_prompt, user_input),
        }
    }

    fn scan_output(
        &self,
        system_prompt: &str,
        output: &str,
        canary_state: &CanaryState,
    ) -> Verdict {
        Verdict {
            inner: self
                .inner
                .scan_output(system_prompt, output, &canary_state.inner),
        }
    }

    fn scan_messages(&self, messages: &Bound<'_, PyAny>) -> PyResult<Verdict> {
        let owned = parse_chat_messages(messages)?;
        let borrowed = borrowed_chat_messages(&owned);
        Ok(Verdict {
            inner: self.inner.scan_messages(&borrowed),
        })
    }

    fn scan_tool_call(&self, name: &str, arguments_json: &str) -> Verdict {
        Verdict {
            inner: self.inner.scan_tool_call(&CoreToolCall {
                name,
                arguments_json,
            }),
        }
    }

    fn scan_tool_result(&self, name: &str, content: &str) -> Verdict {
        Verdict {
            inner: self
                .inner
                .scan_tool_result(&CoreToolResult { name, content }),
        }
    }

    #[pyo3(signature = (source_kind, content, source_id=None))]
    fn scan_retrieved_document(
        &self,
        source_kind: &str,
        content: &str,
        source_id: Option<&str>,
    ) -> PyResult<Verdict> {
        Ok(Verdict {
            inner: self.inner.scan_retrieved_document(&CoreRetrievedDocument {
                source_kind: parse_document_source_kind(source_kind)?,
                source_id,
                content,
            }),
        })
    }

    fn scan_turn(
        &self,
        mut state: PyRefMut<'_, ConversationState>,
        messages: &Bound<'_, PyAny>,
    ) -> PyResult<Verdict> {
        let owned = parse_chat_messages(messages)?;
        let borrowed = borrowed_chat_messages(&owned);
        Ok(Verdict {
            inner: self.inner.scan_turn(&mut state.inner, &borrowed),
        })
    }

    fn __repr__(&self) -> String {
        "Scanner(default)".into()
    }
}

/// Instrument a system prompt with a fresh canary.
///
/// Returns `(instrumented_system_prompt, canary_state)`. Contrib wrappers send
/// the instrumented prompt to the model and reuse the canary state for
/// post-flight scanning.
#[pyfunction]
fn instrument_system_prompt(system_prompt: &str) -> PyResult<(String, CanaryState)> {
    inject_system_prompt(system_prompt)
        .map(|(instrumented, inner)| (instrumented, CanaryState { inner }))
        .map_err(|e| PyRuntimeError::new_err(format!("canary instrument: {e}")))
}

// ---- Module init -------------------------------------------------------

#[pymodule]
fn _native(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Scanner>()?;
    m.add_class::<Verdict>()?;
    m.add_class::<Finding>()?;
    m.add_class::<CanaryState>()?;
    m.add_class::<CanaryLeak>()?;
    m.add_class::<CommitmentViolation>()?;
    m.add_class::<ConversationState>()?;
    m.add_function(wrap_pyfunction!(instrument_system_prompt, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
