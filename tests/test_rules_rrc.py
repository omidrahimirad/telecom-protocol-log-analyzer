from __future__ import annotations

from pathlib import Path

from telecom_log_analyzer.analyzer import analyze_file

SAMPLES = Path("data/samples")


def test_rrc_setup_timeout_detected() -> None:
    report = analyze_file(SAMPLES / "rrc_setup_timeout.log")
    issue_types = {issue.issue_type for issue in report.issues}

    assert "RRC_SETUP_RESPONSE_MISSING" in issue_types
    assert "REPEATED_INITIAL_ACCESS_ATTEMPTS" in issue_types


def test_rrc_reconfiguration_failure_detected() -> None:
    report = analyze_file(SAMPLES / "rrc_reconfiguration_failure.log")

    assert "RRC_RRCRECONFIGURATIONFAILURE" in {issue.issue_type for issue in report.issues}
