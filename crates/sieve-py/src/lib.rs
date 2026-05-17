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
use pyo3::types::PyDict;
use pyo3::wrap_pyfunction;

use sieve_core::{
    inject_system_prompt, CanaryLeak as CoreCanaryLeak, CanaryState as CoreCanaryState,
    Category as CoreCategory, CommitmentViolation as CoreCommitmentViolation,
    Decision as CoreDecision, Finding as CoreFinding, Scanner as CoreScanner,
    ScannerMode as CoreScannerMode, Severity as CoreSeverity, Verdict as CoreVerdict,
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
    m.add_function(wrap_pyfunction!(instrument_system_prompt, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
