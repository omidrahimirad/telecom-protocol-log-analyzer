from __future__ import annotations

from pathlib import Path

from telecom_log_analyzer.analyzer import analyze_file
from telecom_log_analyzer.parser import TelecomLogParser
from telecom_log_analyzer.rules import RuleEngine
from telecom_log_analyzer.sessionizer import Sessionizer

SAMPLES = Path("data/samples")


def test_handover_success_has_no_issues() -> None:
    report = analyze_file(SAMPLES / "handover_success.log")

    assert report.issues == []


def test_handover_failure_detected() -> None:
    report = analyze_file(SAMPLES / "handover_failure_target_cell_unavailable.log")

    assert "HANDOVER_FAILURE" in {issue.issue_type for issue in report.issues}


def test_handover_completion_timeout_detected() -> None:
    result = TelecomLogParser().parse_lines(
        [
            "2026-06-01T10:00:00.000Z | UE=IMSI1 | LAYER=NGAP | DIR=GNB_TO_AMF | MSG=HandoverRequired",
            "2026-06-01T10:00:00.100Z | UE=IMSI1 | LAYER=NGAP | DIR=AMF_TO_GNB | MSG=HandoverRequest",
            "2026-06-01T10:00:00.200Z | UE=IMSI1 | LAYER=NGAP | DIR=GNB_TO_AMF | MSG=HandoverRequestAcknowledge",
            "2026-06-01T10:00:00.300Z | UE=IMSI1 | LAYER=RRC | DIR=GNB_TO_UE | MSG=HandoverCommand",
            "2026-06-01T10:00:20.500Z | UE=IMSI1 | LAYER=NGAP | DIR=GNB_TO_AMF | MSG=HandoverNotify",
        ]
    )
    sessions, _ = Sessionizer().build_sessions(result.events)

    issues = RuleEngine(timeout_seconds=10).evaluate(sessions)

    assert "HANDOVER_EXECUTION_TIMEOUT" in {issue.issue_type for issue in issues}
