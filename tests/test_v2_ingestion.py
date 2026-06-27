from __future__ import annotations

import json
from pathlib import Path

from telecom_log_analyzer.analyzer import analyze_file, parse_input_file
from telecom_log_analyzer.cli import main
from telecom_log_analyzer.knowledge_base import load_cause_catalog
from telecom_log_analyzer.report import render_markdown

FIXTURES = Path("tests/fixtures/tshark")


def test_tshark_json_adapter_extracts_registration_events() -> None:
    result = parse_input_file(
        FIXTURES / "sample_registration.tshark.json", input_format="tshark-json"
    )

    assert len(result.events) == 4
    assert result.warnings == []
    assert result.events[0].layer == "NGAP"
    assert result.events[0].frame_number == 1
    assert result.events[1].imsi == "IMSI001010555123456"
    assert result.events[1].message == "RegistrationRequest"


def test_malformed_tshark_json_produces_warnings_not_crash() -> None:
    result = parse_input_file(
        FIXTURES / "malformed_missing_fields.tshark.json", input_format="tshark-json"
    )

    assert result.events == []
    assert len(result.warnings) == 2


def test_auto_input_format_detects_tshark_json() -> None:
    report = analyze_file(FIXTURES / "sample_registration.tshark.json", input_format="auto")

    assert report.sessions
    assert report.correlation is not None


def test_timer_profile_changes_timeout_behavior() -> None:
    lab = analyze_file(
        FIXTURES / "sample_registration.tshark.json",
        input_format="tshark-json",
        timer_profile="lab",
    )
    field = analyze_file(
        FIXTURES / "sample_registration.tshark.json",
        input_format="tshark-json",
        timer_profile="field",
    )

    assert "5G_REGISTRATION_AUTHENTICATION_TIMEOUT" in {issue.issue_type for issue in lab.issues}
    assert "5G_REGISTRATION_AUTHENTICATION_TIMEOUT" not in {
        issue.issue_type for issue in field.issues
    }


def test_cause_catalog_lookup_and_confidence_fields() -> None:
    catalog = load_cause_catalog()
    entry = catalog.lookup("NAS_5GS", "missing-or-unknown-dnn")

    assert entry is not None
    assert entry.domain.value == "CORE"

    report = analyze_file(Path("data/samples/registration_auth_failure.log"))
    issue = report.issues[0]
    assert issue.confidence > 0.7
    assert issue.recommended_owner
    assert issue.probable_domain.value in {"UE", "CORE", "RAN", "SUBSCRIPTION", "RF", "TRANSPORT"}


def test_markdown_report_contains_domain_owner_confidence() -> None:
    report = analyze_file(Path("data/samples/registration_auth_failure.log"))
    markdown = render_markdown(report)

    assert "Probable domain" in markdown
    assert "Recommended owner" in markdown
    assert "Confidence" in markdown


def test_convert_tshark_to_normalized_jsonl_cli(capsys: object) -> None:
    exit_code = main(
        [
            "convert",
            str(FIXTURES / "sample_registration.tshark.json"),
            "--input-format",
            "tshark-json",
            "--to",
            "normalized-jsonl",
        ]
    )
    captured = capsys.readouterr()
    first_line = captured.out.splitlines()[0]

    assert exit_code == 0
    assert json.loads(first_line)["message"] == "InitialUEMessage"


def test_list_cause_codes_cli(capsys: object) -> None:
    exit_code = main(["list-cause-codes"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "missing or unknown DNN" in captured.out
