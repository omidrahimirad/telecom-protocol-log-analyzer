"""High-level orchestration for telecom log analysis."""

from __future__ import annotations

from pathlib import Path

from telecom_log_analyzer.models import AnalysisReport
from telecom_log_analyzer.parser import TelecomLogParser
from telecom_log_analyzer.rules import RuleEngine
from telecom_log_analyzer.sessionizer import Sessionizer
from telecom_log_analyzer.state_machines import evaluate_session_flows
from telecom_log_analyzer.utils import utc_now


def analyze_file(path: Path, *, strict: bool = False, timeout_seconds: int = 10) -> AnalysisReport:
    parser = TelecomLogParser()
    parse_result = parser.parse_file(path, strict=strict)
    sessionizer = Sessionizer()
    sessions, session_warnings = sessionizer.build_sessions(parse_result.events)
    issues = RuleEngine(timeout_seconds=timeout_seconds).evaluate(sessions)
    flow_checks = {
        session.key: [check.to_dict() for check in evaluate_session_flows(session.events)]
        for session in sessions
    }
    return AnalysisReport(
        source=path,
        sessions=sessions,
        issues=issues,
        warnings=[*parse_result.warnings, *session_warnings],
        generated_at=utc_now(),
        flow_checks=flow_checks,
    )


def analyze_directory(
    path: Path, *, strict: bool = False, timeout_seconds: int = 10
) -> list[AnalysisReport]:
    files = sorted(
        item
        for item in path.iterdir()
        if item.is_file() and item.suffix.lower() in {".log", ".jsonl", ".txt"}
    )
    return [
        analyze_file(file_path, strict=strict, timeout_seconds=timeout_seconds)
        for file_path in files
    ]
