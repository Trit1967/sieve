// SPDX-License-Identifier: MIT OR Apache-2.0
//! `sieve` — command-line interface for the sieve prompt-injection
//! defense library. Reads input from stdin (or `--input <file>`) and
//! prints a JSON verdict.
//!
//! ```text
//! sieve scan [--system <file_or_text>] [--input <file>] [--output text|json]
//! sieve check < input.txt
//! sieve --version
//! sieve --help
//! ```
//!
//! Exit codes:
//!   0 — Allow
//!   1 — Flag
//!   2 — Block
//!   3 — error (invalid args, IO failure, etc.)

use std::io::{self, Read, Write};
use std::process::ExitCode;

use serde_json::json;
use sieve_core::{Decision, Scanner, Verdict};

const HELP: &str = "\
sieve — vendor-neutral prompt-injection defense, CLI

USAGE:
    sieve scan [OPTIONS]
    sieve check [OPTIONS]    (alias for `scan`)
    sieve --version
    sieve --help

OPTIONS:
    --system <text-or-@file>   System prompt. Prefix with @ to read from a file.
                               If omitted, uses a generic placeholder.
    --input <file>             Read user input from a file. If omitted, reads
                               from stdin.
    --output <text|json>       Output format. Default: json.
    -h, --help                 Show this help.
    -V, --version              Show version.

EXIT CODES:
    0   Allow
    1   Flag
    2   Block
    3   Error
";

const DEFAULT_SYSTEM: &str = "You are a helpful assistant.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{HELP}");
        return ExitCode::from(3);
    }

    match args[0].as_str() {
        "-h" | "--help" => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        "-V" | "--version" => {
            println!("sieve {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "scan" | "check" => match run_scan(&args[1..]) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("sieve: error: {e}");
                ExitCode::from(3)
            }
        },
        unknown => {
            eprintln!("sieve: unknown subcommand '{unknown}'\n\n{HELP}");
            ExitCode::from(3)
        }
    }
}

fn run_scan(args: &[String]) -> io::Result<ExitCode> {
    let opts = parse_scan_args(args)?;
    let system_prompt = resolve_system(opts.system.as_deref())?;
    let user_input = resolve_input(opts.input.as_deref())?;

    let scanner = Scanner::default();
    let verdict = scanner.scan_input(&system_prompt, &user_input);

    print_verdict(&verdict, opts.output_json)?;

    Ok(exit_code_for(verdict.decision))
}

struct ScanOpts {
    system: Option<String>,
    input: Option<String>,
    output_json: bool,
}

fn parse_scan_args(args: &[String]) -> io::Result<ScanOpts> {
    let mut system = None;
    let mut input = None;
    let mut output_json = true;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--system" => {
                i += 1;
                system = Some(
                    args.get(i)
                        .ok_or_else(|| io::Error::other("--system needs an argument"))?
                        .clone(),
                );
            }
            "--input" => {
                i += 1;
                input = Some(
                    args.get(i)
                        .ok_or_else(|| io::Error::other("--input needs an argument"))?
                        .clone(),
                );
            }
            "--output" => {
                i += 1;
                let fmt = args
                    .get(i)
                    .ok_or_else(|| io::Error::other("--output needs an argument"))?;
                match fmt.as_str() {
                    "json" => output_json = true,
                    "text" => output_json = false,
                    other => {
                        return Err(io::Error::other(format!(
                            "--output must be json|text, got '{other}'"
                        )));
                    }
                }
            }
            "-h" | "--help" => {
                println!("{HELP}");
                std::process::exit(0);
            }
            other => {
                return Err(io::Error::other(format!("unknown argument '{other}'")));
            }
        }
        i += 1;
    }
    Ok(ScanOpts {
        system,
        input,
        output_json,
    })
}

fn resolve_system(arg: Option<&str>) -> io::Result<String> {
    match arg {
        None => Ok(DEFAULT_SYSTEM.into()),
        Some(s) if s.starts_with('@') => std::fs::read_to_string(&s[1..]),
        Some(s) => Ok(s.into()),
    }
}

fn resolve_input(arg: Option<&str>) -> io::Result<String> {
    if let Some(path) = arg {
        std::fs::read_to_string(path)
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    }
}

fn print_verdict(verdict: &Verdict, json: bool) -> io::Result<()> {
    if json {
        let findings: Vec<_> = verdict
            .findings
            .iter()
            .map(|f| {
                json!({
                    "detector": f.detector,
                    "severity": format!("{:?}", f.severity),
                    "score": f.score,
                    "category": format!("{:?}", f.category),
                    "message": f.message,
                    "matched_span": f.matched_span,
                })
            })
            .collect();
        let out = json!({
            "decision": match verdict.decision {
                Decision::Allow => "allow",
                Decision::Flag  => "flag",
                Decision::Block => "block",
            },
            "score": verdict.score,
            "latency_us": verdict.latency_us,
            "findings": findings,
        });
        let mut stdout = io::stdout().lock();
        serde_json::to_writer_pretty(&mut stdout, &out)?;
        writeln!(stdout)?;
    } else {
        let mut stdout = io::stdout().lock();
        writeln!(
            stdout,
            "decision: {:?}\nscore: {:.2}\nlatency_us: {}\nfindings: {}",
            verdict.decision,
            verdict.score,
            verdict.latency_us,
            verdict.findings.len()
        )?;
        for f in &verdict.findings {
            writeln!(
                stdout,
                "  [{}] {:?} {:.2} — {}",
                f.detector, f.severity, f.score, f.message
            )?;
        }
    }
    Ok(())
}

fn exit_code_for(d: Decision) -> ExitCode {
    match d {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Flag => ExitCode::from(1),
        Decision::Block => ExitCode::from(2),
    }
}
