#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Cross-language consistency harness for sieve.
#
# For each input in benchmarks/consistency/cases/*.txt, run scan_input
# from each of the three bindings (Rust CLI, Python module, WASM via
# Node) and assert identical Decision strings.
#
# Prerequisites (handled by the .github/workflows/consistency.yml job):
#   - ./target/release/sieve-bench built (Rust reference)
#   - `sieve` Python package importable (maturin develop --release)
#   - crates/sieve-wasm/pkg/ produced by wasm-pack build --target nodejs

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SYSTEM="You are a helpful assistant."
CASES_DIR="benchmarks/consistency/cases"

if [ ! -d "$CASES_DIR" ]; then
  echo "no cases directory $CASES_DIR — nothing to check" >&2
  exit 0
fi

mismatches=0
total=0

for case_file in "$CASES_DIR"/*.txt; do
  echo "=== $(basename "$case_file") ==="
  while IFS= read -r line; do
    # skip blanks + comments
    case "$line" in
      ''|'#'*) continue ;;
    esac
    total=$((total + 1))

    rust_out=$(printf '%s\n' "$line" | python3 - <<PY
import json, sys
print(json.dumps({"system": "$SYSTEM", "user": sys.stdin.read().rstrip("\n")}))
PY
)
    # Rust: use sieve-bench in single-line mode via a one-shot file.
    tmp=$(mktemp)
    printf '%s\n' "$line" > "$tmp"
    rust_decision=$(./target/release/sieve-bench --jailbreaks "$tmp" --output /tmp/_r.md > /dev/null && \
      grep -E '\| Jailbreaks \(curated\) \|' /tmp/_r.md | awk -F'|' '{ if ($4 > 0) print "Block"; else if ($5 > 0) print "Flag"; else print "Allow" }')
    rm -f "$tmp"

    py_decision=$(python3 - <<PY
import sieve
s = sieve.Scanner()
v = s.scan_input("$SYSTEM", """$line""")
print(v.decision)
PY
)

    wasm_decision=$(node -e "
const { Scanner } = require('${REPO_ROOT}/crates/sieve-wasm/pkg/sieve_wasm.js');
const s = new Scanner();
const line = process.argv[1];
const v = s.scanInput('${SYSTEM}', line);
console.log(v.decision);
" "$line")

    if [ "$rust_decision" = "$py_decision" ] && [ "$py_decision" = "$wasm_decision" ]; then
      echo "ok   rust=$rust_decision py=$py_decision wasm=$wasm_decision  :: $line"
    else
      echo "MISS rust=$rust_decision py=$py_decision wasm=$wasm_decision  :: $line"
      mismatches=$((mismatches + 1))
    fi
  done < "$case_file"
done

echo ""
echo "=== summary ==="
echo "  total cases: $total"
echo "  mismatches:  $mismatches"

if [ "$mismatches" -gt 0 ]; then
  echo "FAIL: $mismatches mismatches across $total cases" >&2
  exit 1
fi
echo "OK: all $total cases agreed across Rust / Python / WASM"
