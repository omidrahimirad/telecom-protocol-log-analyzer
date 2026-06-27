"""Command-line interface for the telecom protocol log analyzer."""

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

from telecom_log_analyzer.analyzer import analyze_directory, analyze_file, parse_input_file
from telecom_log_analyzer.generator import generate_log
from telecom_log_analyzer.knowledge_base import load_cause_catalog
from telecom_log_analyzer.models import AnalysisReport, Severity
from telecom_log_analyzer.parser import TelecomLogParser
from telecom_log_analyzer.protocol_reference import explain_message, known_messages
from telecom_log_analyzer.report import (
    render_html,
    render_json,
    render_markdown,
    render_terminal,
    write_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="telecom-log-analyzer",
        description="Analyze simplified 4G/5G RRC, NAS, and NGAP troubleshooting logs.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze one log file and print a report.")
    analyze.add_argument("log_file", type=Path)
    analyze.add_argument("--format", choices=["terminal", "json", "markdown"], default="terminal")
    analyze.add_argument(
        "--output-format",
        choices=["terminal", "json", "markdown", "html"],
        help="Preferred report format. Supersedes --format when provided.",
    )
    analyze.add_argument("--output", type=Path, help="Write report to a file instead of stdout.")
    analyze.add_argument(
        "--input-format",
        choices=["auto", "simplified", "jsonl", "tshark-json"],
        default="auto",
    )
    analyze.add_argument("--timer-profile", choices=["lab", "field"], default="field")
    analyze.add_argument("--timer-config", type=Path)
    analyze.add_argument("--min-severity", choices=[severity.value for severity in Severity])
    analyze.add_argument(
        "--show-timeline",
        action="store_true",
        help="Kept for compatibility; timeline is shown in terminal/Markdown reports.",
    )
    analyze.add_argument("--show-normalized-events", action="store_true")
    analyze.add_argument("--timeout", type=int, default=10, help="Timeout threshold in seconds.")

    analyze_dir = subparsers.add_parser(
        "analyze-dir", help="Analyze every .log/.jsonl/.txt in a directory."
    )
    analyze_dir.add_argument("directory", type=Path)
    analyze_dir.add_argument("--timeout", type=int, default=10)
    analyze_dir.add_argument("--timer-profile", choices=["lab", "field"], default="field")
    analyze_dir.add_argument("--timer-config", type=Path)

    export = subparsers.add_parser("export", help="Export analysis report to JSON or Markdown.")
    export.add_argument("log_file", type=Path)
    export.add_argument("--format", choices=["json", "markdown", "html"], required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--timeout", type=int, default=10)
    export.add_argument(
        "--input-format", choices=["auto", "simplified", "jsonl", "tshark-json"], default="auto"
    )
    export.add_argument("--timer-profile", choices=["lab", "field"], default="field")
    export.add_argument("--timer-config", type=Path)

    validate = subparsers.add_parser(
        "validate-log", help="Validate log format and show parse warnings."
    )
    validate.add_argument("log_file", type=Path)
    validate.add_argument(
        "--input-format", choices=["auto", "simplified", "jsonl", "tshark-json"], default="auto"
    )

    explain = subparsers.add_parser("explain-message", help="Explain a protocol message name.")
    explain.add_argument("message", nargs="?")
    explain.add_argument("--list", action="store_true", help="List known message names.")

    generate = subparsers.add_parser("generate", help="Generate synthetic simplified logs.")
    generate.add_argument("--scenario", required=True)
    generate.add_argument("--ues", type=int, default=1)
    generate.add_argument("--output", type=Path, required=True)

    convert = subparsers.add_parser("convert", help="Convert decoded input to normalized JSONL.")
    convert.add_argument("log_file", type=Path)
    convert.add_argument(
        "--input-format", choices=["auto", "simplified", "jsonl", "tshark-json"], default="auto"
    )
    convert.add_argument("--to", choices=["normalized-jsonl"], required=True)
    convert.add_argument("--output", type=Path)

    summarize = subparsers.add_parser("summarize", help="Print a compact analysis summary.")
    summarize.add_argument("log_file", type=Path)
    summarize.add_argument(
        "--input-format", choices=["auto", "simplified", "jsonl", "tshark-json"], default="auto"
    )
    summarize.add_argument("--timer-profile", choices=["lab", "field"], default="field")
    summarize.add_argument("--timer-config", type=Path)

    subparsers.add_parser("list-cause-codes", help="List normalized cause-code catalog entries.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        report = analyze_file(
            args.log_file,
            timeout_seconds=args.timeout,
            input_format=args.input_format,
            timer_profile=args.timer_profile,
            timer_config=args.timer_config,
        )
        if args.min_severity:
            report = filter_by_min_severity(report, Severity(args.min_severity))
        output_format = args.output_format or args.format
        rendered = render_report(report, output_format)
        if args.show_normalized_events:
            rendered += "\n" + "\n".join(
                json.dumps(event.to_dict(), sort_keys=True)
                for session in report.sessions
                for event in session.events
            )
        if args.output:
            write_report(
                report,
                args.output,
                fmt="markdown" if output_format == "terminal" else output_format,
            )
        else:
            print(rendered, end="" if rendered.endswith("\n") else "\n")
        return 1 if report.critical_count else 0

    if args.command == "analyze-dir":
        reports = analyze_directory(
            args.directory,
            timeout_seconds=args.timeout,
            timer_profile=args.timer_profile,
            timer_config=args.timer_config,
        )
        for report in reports:
            print(render_terminal(report))
        critical = sum(report.critical_count for report in reports)
        high = sum(report.high_count for report in reports)
        print(f"Directory summary: files={len(reports)} critical={critical} high={high}")
        return 1 if critical else 0

    if args.command == "export":
        report = analyze_file(
            args.log_file,
            timeout_seconds=args.timeout,
            input_format=args.input_format,
            timer_profile=args.timer_profile,
            timer_config=args.timer_config,
        )
        write_report(report, args.output, fmt=args.format)
        print(f"Wrote {args.format} report to {args.output}")
        return 0

    if args.command == "validate-log":
        result = (
            TelecomLogParser().parse_file(args.log_file)
            if args.input_format in {"auto", "simplified", "jsonl"}
            else parse_input_file(args.log_file, input_format=args.input_format)
        )
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

    if args.command == "convert":
        result = parse_input_file(args.log_file, input_format=args.input_format)
        lines = [json.dumps(event.to_dict(), sort_keys=True) for event in result.events]
        text = "\n".join(lines) + ("\n" if lines else "")
        if args.output:
            args.output.write_text(text, encoding="utf-8")
        else:
            print(text, end="")
        return 0 if not result.warnings else 1

    if args.command == "summarize":
        report = analyze_file(
            args.log_file,
            input_format=args.input_format,
            timer_profile=args.timer_profile,
            timer_config=args.timer_config,
        )
        print(
            f"source={report.source} ues={len(report.sessions)} issues={len(report.issues)} "
            f"critical={report.critical_count} high={report.high_count} warnings={len(report.warnings)}"
        )
        return 1 if report.critical_count else 0

    if args.command == "list-cause-codes":
        for entry in load_cause_catalog().to_dict():
            print(
                f"{entry['protocol']} | {entry['normalized_cause']} | "
                f"{entry['domain']} | {entry['severity']}"
            )
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


def render_report(report: AnalysisReport, output_format: str) -> str:
    if output_format == "json":
        return render_json(report)
    if output_format == "markdown":
        return render_markdown(report)
    if output_format == "html":
        return render_html(report)
    return render_terminal(report)


def filter_by_min_severity(report: AnalysisReport, minimum: Severity) -> AnalysisReport:
    rank = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
    issues = [issue for issue in report.issues if rank[issue.severity] >= rank[minimum]]
    return replace(report, issues=issues)
