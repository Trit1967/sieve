#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Validate a public-app replay JSONL corpus without external dependencies."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_KEYS = {"id", "kind", "surface", "expected", "source_kind", "source", "text", "notes"}
REQUIRED_KEYS = {"id", "kind", "surface", "expected", "source", "text", "notes"}
KINDS = {"attack", "benign"}
SURFACES = {"input", "chat_user", "tool_call", "tool_result", "retrieved_document"}
EXPECTED = {"auto_block", "not_hard_block"}
SOURCE_KINDS = {
    "rag_chunk",
    "web_page",
    "email",
    "pdf",
    "ocr",
    "code_review",
    "issue_comment",
    "tool_output",
    "other",
}


def resolve_path(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def validate_row(row: Any, line_no: int, ids: set[str]) -> list[str]:
    errors: list[str] = []
    prefix = f"line {line_no}"
    if not isinstance(row, dict):
        return [f"{prefix}: row must be a JSON object"]

    keys = set(row)
    missing = REQUIRED_KEYS - keys
    unknown = keys - ALLOWED_KEYS
    if missing:
        errors.append(f"{prefix}: missing required fields: {', '.join(sorted(missing))}")
    if unknown:
        errors.append(f"{prefix}: unknown fields: {', '.join(sorted(unknown))}")

    for field in REQUIRED_KEYS:
        value = row.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{prefix}: {field} must be a non-empty string")

    case_id = row.get("id")
    if isinstance(case_id, str) and case_id:
        if case_id in ids:
            errors.append(f"{prefix}: duplicate id {case_id!r}")
        ids.add(case_id)

    kind = row.get("kind")
    surface = row.get("surface")
    expected = row.get("expected")
    source_kind = row.get("source_kind")

    if isinstance(kind, str) and kind not in KINDS:
        errors.append(f"{prefix}: kind must be one of {sorted(KINDS)}, got {kind!r}")
    if isinstance(surface, str) and surface not in SURFACES:
        errors.append(f"{prefix}: surface must be one of {sorted(SURFACES)}, got {surface!r}")
    if isinstance(expected, str) and expected not in EXPECTED:
        errors.append(f"{prefix}: expected must be one of {sorted(EXPECTED)}, got {expected!r}")

    if source_kind is not None:
        if not isinstance(source_kind, str) or source_kind not in SOURCE_KINDS:
            errors.append(
                f"{prefix}: source_kind must be one of {sorted(SOURCE_KINDS)}, got {source_kind!r}"
            )
    if surface == "retrieved_document" and source_kind is None:
        errors.append(f"{prefix}: retrieved_document rows must set source_kind")
    if kind == "attack" and expected != "auto_block":
        errors.append(f"{prefix}: attack rows must use expected='auto_block'")
    if kind == "benign" and expected != "not_hard_block":
        errors.append(f"{prefix}: benign rows must use expected='not_hard_block'")

    return errors


def validate_corpus(path: Path) -> tuple[int, int, list[str]]:
    errors: list[str] = []
    ids: set[str] = set()
    rows = 0
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            rows += 1
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError as exc:
                errors.append(f"line {line_no}: invalid JSON: {exc.msg}")
                continue
            errors.extend(validate_row(row, line_no, ids))
    if rows == 0:
        errors.append("corpus is empty")
    return rows, len(ids), errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, help="Public-app replay JSONL corpus path.")
    args = parser.parse_args()

    path = resolve_path(args.corpus)
    if not path.exists():
        parser.error(f"corpus path does not exist: {path}")

    rows, unique_ids, errors = validate_corpus(path)
    if errors:
        print(f"FAIL: {path}", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"OK: {path} ({rows} rows, {unique_ids} unique ids)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
