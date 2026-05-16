#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Reproducible benchmark runner for sieve.
#
# Usage:
#   ./benchmarks/run.sh                      # runs bundled corpora only
#   ./benchmarks/run.sh --jbb path/to.json   # adds JailbreakBench corpus
#   ./benchmarks/run.sh --garak path/        # adds garak probe dump
#   ./benchmarks/run.sh --acl path/to.txt    # adds ACL'25 bypass samples
#
# Writes benchmarks/REPORT.md with per-corpus detection rate, FPR, and
# p50/p99 latency. Re-runs deterministic given the same inputs.

set -euo pipefail

cd "$(dirname "$0")/.."

echo "[bench] building sieve-bench (release)"
# Workspace builds share a target/ dir at the workspace root regardless
# of --manifest-path, so the binary lands at ./target/release/sieve-bench
# (or .exe on Windows). Resolve both.
cargo build --release -p sieve-bench

BIN="./target/release/sieve-bench"
if [ ! -x "$BIN" ] && [ -x "${BIN}.exe" ]; then
  BIN="${BIN}.exe"
fi

echo "[bench] running bundled corpus (jailbreaks.txt + benign.txt)"
"$BIN" \
  --jailbreaks crates/sieve-core/src/data/jailbreaks.txt \
  --benign    crates/sieve-core/src/data/benign.txt \
  --output    benchmarks/REPORT.md \
  "$@"

echo "[bench] wrote benchmarks/REPORT.md"
