from __future__ import annotations

from pathlib import Path

from telecom_log_analyzer.analyzer import analyze_file
from telecom_log_analyzer.report import render_json, render_markdown, render_terminal, write_report


def test_report_renderers_include_required_sections(tmp_path: Path) -> None:
    report = analyze_file(Path("data/samples/registration_auth_failure.log"))

    terminal = render_terminal(report)
    markdown = render_markdown(report)
    json_text = render_json(report)

    assert "Detected Issues" in terminal
    assert "Protocol Flow Checks" in terminal
    assert "Probable root cause" in markdown
    assert "## Protocol Flow Checks" in markdown
    assert "5G_REGISTRATION_AUTHENTICATION_FAILURE" in json_text
    assert "flow_checks" in json_text

    output = tmp_path / "report.md"
    write_report(report, output, fmt="markdown")
    assert output.read_text(encoding="utf-8").startswith("# Telecom Protocol")


def test_report_no_issue_and_unsupported_format(tmp_path: Path) -> None:
    report = analyze_file(Path("data/samples/normal_5g_registration.log"))

    assert "No HIGH or CRITICAL" in render_terminal(report)
    assert "No blocking troubleshooting issues" in render_markdown(report)

    try:
        write_report(report, tmp_path / "bad.txt", fmt="txt")
    except ValueError as exc:
        assert "Unsupported report format" in str(exc)
    else:
        raise AssertionError("Expected unsupported report format to raise")
