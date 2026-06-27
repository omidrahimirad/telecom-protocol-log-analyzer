"""Command-line interface for the telecom protocol log analyzer."""

from __future__ import annotations

import argparse
from pathlib import Path

from telecom_log_analyzer.analyzer import analyze_directory, analyze_file
from telecom_log_analyzer.generator import generate_log
from telecom_log_analyzer.parser import TelecomLogParser
from telecom_log_analyzer.protocol_reference import explain_message, known_messages
from telecom_log_analyzer.report import render_json, render_markdown, render_terminal, write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="telecom-log-analyzer",
        description="Analyze simplified 4G/5G RRC, NAS, and NGAP troubleshooting logs.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze one log file and print a report.")
    analyze.add_argument("log_file", type=Path)
    analyze.add_argument("--format", choices=["terminal", "json", "markdown"], default="terminal")
    analyze.add_argument("--timeout", type=int, default=10, help="Timeout threshold in seconds.")

    analyze_dir = subparsers.add_parser(
        "analyze-dir", help="Analyze every .log/.jsonl/.txt in a directory."
    )
    analyze_dir.add_argument("directory", type=Path)
    analyze_dir.add_argument("--timeout", type=int, default=10)

    export = subparsers.add_parser("export", help="Export analysis report to JSON or Markdown.")
    export.add_argument("log_file", type=Path)
    export.add_argument("--format", choices=["json", "markdown"], required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--timeout", type=int, default=10)

    validate = subparsers.add_parser(
        "validate-log", help="Validate log format and show parse warnings."
    )
    validate.add_argument("log_file", type=Path)

    explain = subparsers.add_parser("explain-message", help="Explain a protocol message name.")
    explain.add_argument("message", nargs="?")
    explain.add_argument("--list", action="store_true", help="List known message names.")

    generate = subparsers.add_parser("generate", help="Generate synthetic simplified logs.")
    generate.add_argument("--scenario", required=True)
    generate.add_argument("--ues", type=int, default=1)
    generate.add_argument("--output", type=Path, required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        report = analyze_file(args.log_file, timeout_seconds=args.timeout)
        if args.format == "json":
            print(render_json(report))
        elif args.format == "markdown":
            print(render_markdown(report))
        else:
            print(render_terminal(report), end="")
        return 1 if report.critical_count else 0

    if args.command == "analyze-dir":
        reports = analyze_directory(args.directory, timeout_seconds=args.timeout)
        for report in reports:
            print(render_terminal(report))
        critical = sum(report.critical_count for report in reports)
        high = sum(report.high_count for report in reports)
        print(f"Directory summary: files={len(reports)} critical={critical} high={high}")
        return 1 if critical else 0

    if args.command == "export":
        report = analyze_file(args.log_file, timeout_seconds=args.timeout)
        write_report(report, args.output, fmt=args.format)
        print(f"Wrote {args.format} report to {args.output}")
        return 0

    if args.command == "validate-log":
        result = TelecomLogParser().parse_file(args.log_file)
        print(f"Valid events: {len(result.events)}")
        print(f"Warnings: {len(result.warnings)}")
        for warning in result.warnings:
            print(f"- line {warning.line_no}: {warning.message}")
        return 1 if result.warnings else 0

    if args.command == "explain-message":
        if args.list:
            for message in known_messages():
                print(message)
            return 0
        if not args.message:
            parser.error("explain-message requires a message name or --list")
        print(f"{args.message}: {explain_message(args.message)}")
        return 0

    if args.command == "generate":
        generate_log(args.scenario, args.ues, args.output)
        print(f"Generated {args.ues} UE scenario(s) at {args.output}")
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2
