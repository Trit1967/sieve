#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run the public-app replay gates and print a Markdown report."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def cargo_cmd() -> str:
    path_entries = os.environ.get("PATH", "").split(os.pathsep)
    names = ["cargo.exe", "cargo"] if os.name == "nt" else ["cargo"]
    for entry in path_entries:
        for name in names:
            candidate = Path(entry) / name
            if candidate.exists():
                return str(candidate)
    fallback = Path.home() / ".cargo" / "bin" / ("cargo.exe" if os.name == "nt" else "cargo")
    return str(fallback)


CARGO = cargo_cmd()
COMMANDS = [
    [
        CARGO,
        "test",
        "-p",
        "sieve-core",
        "--test",
        "public_app_policy_1000",
        "--",
        "--nocapture",
    ],
    [
        CARGO,
        "test",
        "-p",
        "sieve-core",
        "--test",
        "external_corpus_replay",
        "--",
        "--nocapture",
    ],
    [
        CARGO,
        "test",
        "-p",
        "sieve-core",
        "--test",
        "mutation_fuzz_public_app",
        "--",
        "--nocapture",
    ],
]


def validate_corpus(corpus: Path | None) -> int:
    if corpus is None:
        return 0
    validator = ROOT / "scripts" / "validate_public_app_replay_corpus.py"
    proc = subprocess.run(
        [sys.executable, str(validator), str(corpus)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.stdout:
        print(proc.stdout, file=sys.stderr, end="")
    return proc.returncode


def run_command(command: list[str], corpus: Path | None) -> tuple[int, str]:
    env = os.environ.copy()
    if corpus is not None and "external_corpus_replay" in command:
        env["SIEVE_REPLAY_CORPUS"] = str(corpus)
    proc = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return proc.returncode, proc.stdout


def interesting_lines(output: str) -> list[str]:
    keep = []
    prefixes = (
        "===",
        "attack auto-blocks:",
        "benign hard-blocks:",
        "auto-blocks:",
        "hard-blocks:",
        "test result:",
    )
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefixes):
            keep.append(stripped)
    return keep


def build_report(results: list[tuple[list[str], int, str]], corpus: Path | None) -> str:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    lines = [
        "# Public App Replay Report",
        "",
        f"Generated: {now}",
    ]
    if corpus is not None:
        lines.extend(["", f"Custom corpus: `{corpus}`"])
    lines.extend([
        "",
        "| Gate | Status |",
        "| --- | --- |",
    ])
    for command, code, _ in results:
        name = command[command.index("--test") + 1]
        status = "PASS" if code == 0 else f"FAIL ({code})"
        lines.append(f"| `{name}` | {status} |")

    lines.append("")
    for command, _, output in results:
        name = command[command.index("--test") + 1]
        lines.append(f"## `{name}`")
        lines.append("")
        summary = interesting_lines(output)
        if summary:
            lines.extend(f"- {line}" for line in summary)
        else:
            lines.append("- No summary lines emitted.")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        help="Optional JSONL corpus path for external_corpus_replay.",
    )
    parser.add_argument("--out", type=Path, help="Optional Markdown output path.")
    args = parser.parse_args()
    corpus = None
    if args.corpus:
        corpus = args.corpus if args.corpus.is_absolute() else ROOT / args.corpus
        if not corpus.exists():
            parser.error(f"--corpus path does not exist: {corpus}")
        validation_code = validate_corpus(corpus)
        if validation_code != 0:
            return validation_code

    results = []
    for command in COMMANDS:
        print(f"running: {' '.join(command)}", file=sys.stderr)
        results.append((command, *run_command(command, corpus)))

    report = build_report(results, corpus)
    if args.out:
        out = args.out if args.out.is_absolute() else ROOT / args.out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report + "\n", encoding="utf-8")
    print(report)

    return 0 if all(code == 0 for _, code, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
