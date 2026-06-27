from __future__ import annotations

from pathlib import Path

from telecom_log_analyzer.analyzer import analyze_file
from telecom_log_analyzer.parser import TelecomLogParser
from telecom_log_analyzer.rules import RuleEngine
from telecom_log_analyzer.sessionizer import Sessionizer

SAMPLES = Path("data/samples")


def test_pdu_session_success_has_no_pdu_issues() -> None:
    report = analyze_file(SAMPLES / "pdu_session_setup_success.log")

    assert {issue.issue_type for issue in report.issues} == set()


def test_resource_setup_failure_detected() -> None:
    report = analyze_file(SAMPLES / "pdu_session_resource_setup_failure.log")

    assert "NGAP_PDU_SESSION_RESOURCE_SETUP_FAILURE" in {
        issue.issue_type for issue in report.issues
    }
    assert "PDU_SESSION_ACCEPT_MISSING" in {issue.issue_type for issue in report.issues}


def test_missing_n2_correlation_detected() -> None:
    result = TelecomLogParser().parse_lines(
        [
            "2026-06-01T10:00:00.000Z | UE=IMSI1 | LAYER=RRC | DIR=UE_TO_GNB | MSG=RRCSetupRequest",
            "2026-06-01T10:00:00.100Z | UE=IMSI1 | LAYER=RRC | DIR=GNB_TO_UE | MSG=RRCSetup",
            "2026-06-01T10:00:00.200Z | UE=IMSI1 | LAYER=RRC | DIR=UE_TO_GNB | MSG=RRCSetupComplete",
            "2026-06-01T10:00:01.000Z | UE=IMSI1 | LAYER=NAS | DIR=UE_TO_AMF | MSG=PduSessionEstablishmentRequest | SESSION=5",
        ]
    )
    sessions, _ = Sessionizer().build_sessions(result.events)

    issues = RuleEngine().evaluate(sessions)

    assert "PDU_SESSION_MISSING_N2_CORRELATION" in {issue.issue_type for issue in issues}
