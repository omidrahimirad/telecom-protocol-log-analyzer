from __future__ import annotations

from pathlib import Path

from telecom_log_analyzer.analyzer import analyze_file

SAMPLES = Path("data/samples")


def issue_types(path: str) -> set[str]:
    return {issue.issue_type for issue in analyze_file(SAMPLES / path).issues}


def test_normal_registration_has_no_issues() -> None:
    report = analyze_file(SAMPLES / "normal_5g_registration.log")

    assert report.issues == []
    assert len(report.sessions) == 1


def test_authentication_failure_detected() -> None:
    issues = issue_types("registration_auth_failure.log")

    assert "5G_REGISTRATION_AUTHENTICATION_FAILURE" in issues


def test_registration_reject_detected() -> None:
    report = analyze_file(SAMPLES / "registration_reject_roaming_not_allowed.log")

    assert "5G_REGISTRATION_REJECT" in {issue.issue_type for issue in report.issues}
    assert "roaming-not-allowed" in report.issues[0].probable_cause


def test_security_mode_reject_detected_in_multi_ue_log() -> None:
    issues = issue_types("multi_ue_mixed_failures.log")

    assert "5G_REGISTRATION_SECURITY_MODE_REJECT" in issues
    assert "5G_REGISTRATION_MISSING_AUTHENTICATION_REQUEST" in issues
