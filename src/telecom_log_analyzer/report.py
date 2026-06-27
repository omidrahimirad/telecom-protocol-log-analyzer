"""Report rendering for terminal, JSON, and Markdown outputs."""

from __future__ import annotations

import json
from pathlib import Path

from telecom_log_analyzer.models import AnalysisReport, Issue, Session


def render_terminal(report: AnalysisReport) -> str:
    lines = [
        f"Telecom Protocol Log Analysis: {report.source}",
        "=" * 78,
        (
            f"Sessions: {len(report.sessions)} | Events: "
            f"{sum(len(session.events) for session in report.sessions)} | Issues: {len(report.issues)} "
            f"| Critical: {report.critical_count} | High: {report.high_count} | "
            f"Warnings: {len(report.warnings)}"
        ),
        "",
    ]
    if report.warnings:
        lines.append("Warnings")
        for warning in report.warnings:
            lines.append(f"- line {warning.line_no}: {warning.message}")
        lines.append("")

    if report.issues:
        lines.append("Detected Issues")
        lines.append(_table(["Severity", "Issue", "Session", "Layer"], _issue_rows(report.issues)))
        lines.append("")
        for issue in report.issues:
            lines.extend(_terminal_issue_detail(issue))
            lines.append("")
    else:
        lines.append("Detected Issues")
        lines.append("No HIGH or CRITICAL troubleshooting issues detected.")
        lines.append("")

    lines.append("Protocol Flow Checks")
    for session_key, checks in report.flow_checks.items():
        lines.append(f"- {session_key}")
        for check in checks:
            status = "complete" if check["complete"] else "incomplete/abnormal"
            missing = ", ".join(check["missing"]) if check["missing"] else "none"
            abnormal = ", ".join(check["abnormal"]) if check["abnormal"] else "none"
            lines.append(f"  {check['name']}: {status}; missing={missing}; abnormal={abnormal}")
    lines.append("")

    lines.append("Session Timeline")
    for session in report.sessions:
        lines.extend(_terminal_session(session))
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: AnalysisReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def render_markdown(report: AnalysisReport) -> str:
    lines = [
        "# Telecom Protocol Log Analysis Report",
        "",
        f"Source: `{report.source}`",
        "",
        "## Summary",
        "",
        f"- Sessions analyzed: {len(report.sessions)}",
        f"- Events analyzed: {sum(len(session.events) for session in report.sessions)}",
        f"- Issues detected: {len(report.issues)}",
        f"- Critical issues: {report.critical_count}",
        f"- High severity issues: {report.high_count}",
        f"- Parser/session warnings: {len(report.warnings)}",
        "",
    ]

    if report.warnings:
        lines.extend(["## Warnings", ""])
        for warning in report.warnings:
            lines.append(f"- Line {warning.line_no}: {warning.message}")
        lines.append("")

    lines.extend(["## Detected Issues", ""])
    if not report.issues:
        lines.append("No blocking troubleshooting issues were detected by the simplified rule set.")
        lines.append("")
    for index, issue in enumerate(report.issues, start=1):
        lines.extend(
            [
                f"### {index}. {issue.issue_type}",
                "",
                f"- Severity: **{issue.severity.value}**",
                f"- Affected UE/session: `{issue.affected_session}`",
                f"- Failed protocol layer: `{issue.failed_layer}`",
                f"- First suspicious message: {issue.first_suspicious_message}",
                f"- Missing or failed expected message: `{issue.missing_or_failed_expected_message}`",
                "",
                "Probable root cause:",
                "",
                issue.probable_cause,
                "",
                "Evidence lines:",
                "",
            ]
        )
        for event in issue.evidence:
            lines.append(f"- Line {event.line_no}: `{event.raw}`")
        lines.extend(["", "Recommended troubleshooting actions:", ""])
        for action in issue.suggested_actions:
            lines.append(f"- {action}")
        lines.append("")

    lines.extend(["## Protocol Flow Checks", ""])
    if not report.flow_checks:
        lines.append("No protocol flow checks were applicable.")
        lines.append("")
    for session_key, checks in report.flow_checks.items():
        lines.append(f"### {session_key}")
        lines.append("")
        lines.append("| Flow | Status | Missing | Abnormal |")
        lines.append("| --- | --- | --- | --- |")
        for check in checks:
            status = "complete" if check["complete"] else "incomplete/abnormal"
            missing = ", ".join(check["missing"]) if check["missing"] else ""
            abnormal = ", ".join(check["abnormal"]) if check["abnormal"] else ""
            lines.append(f"| {check['name']} | {status} | {missing} | {abnormal} |")
        lines.append("")

    lines.extend(["## UE/Session Timeline", ""])
    for session in report.sessions:
        lines.append(f"### {session.key}")
        lines.append("")
        lines.append("| Time | Layer | Direction | Message | Cause | Cell |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for event in session.events:
            lines.append(
                f"| {event.timestamp_text} | {event.layer} | {event.direction} | "
                f"{event.message} | {event.cause or ''} | {event.cell_id or ''} |"
            )
        lines.append("")

    lines.extend(
        [
            "## Limitations",
            "",
            "- This report is based on simplified text/JSONL logs, not a binary PCAP or full ASN.1 decoder.",
            "- The state machines are intentionally compact and do not implement every 3GPP timer, cause, or vendor extension.",
            "- Findings should be correlated with gNB, AMF, SMF, UPF, UE modem, and RF/KPI data before operational action.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(report: AnalysisReport, output: Path, *, fmt: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        output.write_text(render_json(report), encoding="utf-8")
    elif fmt == "markdown":
        output.write_text(render_markdown(report), encoding="utf-8")
    else:
        msg = f"Unsupported report format: {fmt}"
        raise ValueError(msg)


def _issue_rows(issues: list[Issue]) -> list[list[str]]:
    return [
        [issue.severity.value, issue.issue_type, issue.affected_session, issue.failed_layer]
        for issue in issues
    ]


def _terminal_issue_detail(issue: Issue) -> list[str]:
    lines = [
        f"[{issue.severity.value}] {issue.issue_type} ({issue.affected_session})",
        f"Layer: {issue.failed_layer}",
        f"Suspicious: {issue.first_suspicious_message}",
        f"Expected: {issue.missing_or_failed_expected_message}",
        f"Root cause: {issue.probable_cause}",
        "Evidence:",
    ]
    for event in issue.evidence:
        lines.append(f"  - line {event.line_no}: {event.raw}")
    lines.append("Next steps:")
    for action in issue.suggested_actions:
        lines.append(f"  - {action}")
    return lines


def _terminal_session(session: Session) -> list[str]:
    lines = [f"- {session.key} ({len(session.events)} events)"]
    for event in session.events:
        cause = f" cause={event.cause}" if event.cause else ""
        cell = f" cell={event.cell_id}" if event.cell_id else ""
        lines.append(
            f"  {event.timestamp_text} line={event.line_no} {event.layer} "
            f"{event.direction} {event.message}{cause}{cell}"
        )
    return lines


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]
    header = " | ".join(value.ljust(widths[index]) for index, value in enumerate(headers))
    sep = "-+-".join("-" * width for width in widths)
    body = "\n".join(
        " | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows
    )
    return f"{header}\n{sep}\n{body}"
