"""High-level orchestration for telecom log analysis."""

from __future__ import annotations

from pathlib import Path

from telecom_log_analyzer.adapters.base import AdapterResult, detect_input_format
from telecom_log_analyzer.adapters.jsonl import JsonlAdapter
from telecom_log_analyzer.adapters.simplified_text import SimplifiedTextAdapter
from telecom_log_analyzer.adapters.tshark_json import TsharkJsonAdapter
from telecom_log_analyzer.correlator import Correlator
from telecom_log_analyzer.models import AnalysisReport
from telecom_log_analyzer.parser import TelecomLogParser
from telecom_log_analyzer.rules import RuleEngine
from telecom_log_analyzer.sessionizer import Sessionizer
from telecom_log_analyzer.state_machines import evaluate_session_flows
from telecom_log_analyzer.timers import load_timer_profile
from telecom_log_analyzer.utils import utc_now


def analyze_file(
    path: Path,
    *,
    strict: bool = False,
    timeout_seconds: int | None = None,
    input_format: str = "auto",
    timer_profile: str = "field",
    timer_config: Path | None = None,
) -> AnalysisReport:
    timer = load_timer_profile(timer_profile, timer_config)
    parse_result = parse_input_file(path, input_format=input_format, strict=strict)
    sessionizer = Sessionizer()
    sessions, session_warnings = sessionizer.build_sessions(parse_result.events)
    issues = RuleEngine(
        timeout_seconds=timeout_seconds,
        timer_profile=timer,
    ).evaluate(sessions)
    flow_checks = {
        session.key: [check.to_dict() for check in evaluate_session_flows(session.events)]
        for session in sessions
    }
    correlation = Correlator().correlate(parse_result.events)
    return AnalysisReport(
        source=path,
        sessions=sessions,
        issues=issues,
        warnings=[*parse_result.warnings, *session_warnings],
        generated_at=utc_now(),
        flow_checks=flow_checks,
        correlation=correlation,
    )


def analyze_directory(
    path: Path,
    *,
    strict: bool = False,
    timeout_seconds: int | None = None,
    input_format: str = "auto",
    timer_profile: str = "field",
    timer_config: Path | None = None,
) -> list[AnalysisReport]:
    files = sorted(
        item
        for item in path.iterdir()
        if item.is_file() and item.suffix.lower() in {".log", ".jsonl", ".txt"}
    )
    return [
        analyze_file(
            file_path,
            strict=strict,
            timeout_seconds=timeout_seconds,
            input_format=input_format,
            timer_profile=timer_profile,
            timer_config=timer_config,
        )
        for file_path in files
    ]


def parse_input_file(
    path: Path, *, input_format: str = "auto", strict: bool = False
) -> AdapterResult:
    selected = detect_input_format(path) if input_format == "auto" else input_format
    if selected == "simplified":
        return SimplifiedTextAdapter().parse_file(path, strict=strict)
    if selected == "jsonl":
        return JsonlAdapter().parse_file(path, strict=strict)
    if selected == "tshark-json":
        return TsharkJsonAdapter().parse_file(path, strict=strict)
    if selected == "auto":
        result = TelecomLogParser().parse_file(path, strict=strict)
        return AdapterResult(events=result.events, warnings=result.warnings)
    msg = f"Unsupported input format: {input_format}"
    raise ValueError(msg)
