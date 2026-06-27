from __future__ import annotations

from pathlib import Path

import pytest

from telecom_log_analyzer.adapters.base import detect_input_format
from telecom_log_analyzer.adapters.tshark_json import TsharkJsonAdapter, guess_message_from_text
from telecom_log_analyzer.cli import main
from telecom_log_analyzer.models import ParseError
from telecom_log_analyzer.timers import load_timer_profile


def test_tshark_adapter_rejects_invalid_root_and_json(tmp_path: Path) -> None:
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{bad", encoding="utf-8")
    non_list = tmp_path / "object.json"
    non_list.write_text("{}", encoding="utf-8")

    with pytest.raises(ParseError, match="Invalid TShark JSON"):
        TsharkJsonAdapter().parse_file(invalid_json)
    with pytest.raises(ParseError, match="root must be a list"):
        TsharkJsonAdapter().parse_file(non_list)


def test_tshark_adapter_skips_non_object_packets(tmp_path: Path) -> None:
    path = tmp_path / "packets.json"
    path.write_text(
        '[123, {"_source": {"layers": {"tcp": {"tcp.port": "38412"}}}}]', encoding="utf-8"
    )

    result = TsharkJsonAdapter().parse_file(path)

    assert result.events == []
    assert len(result.warnings) == 2


def test_detect_input_format_for_json_variants(tmp_path: Path) -> None:
    tshark = tmp_path / "trace.json"
    tshark.write_text('[{"_source": {"layers": {}}}]', encoding="utf-8")
    simple_json = tmp_path / "events.json"
    simple_json.write_text('[{"timestamp": "2026-01-01T00:00:00Z"}]', encoding="utf-8")
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{bad", encoding="utf-8")

    assert detect_input_format(tshark) == "tshark-json"
    assert detect_input_format(simple_json) == "jsonl"
    assert detect_input_format(bad_json) == "simplified"


def test_guess_message_from_text_variants() -> None:
    assert (
        guess_message_from_text("NGAP Handover Request Acknowledge") == "HandoverRequestAcknowledge"
    )
    assert guess_message_from_text("RRC Reconfiguration Failure") == "RRCReconfigurationFailure"
    assert guess_message_from_text("unknown") is None


def test_timer_profile_errors(tmp_path: Path) -> None:
    config = tmp_path / "timers.yaml"
    config.write_text("profiles:\n  bad: []\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unknown timer profile"):
        load_timer_profile("missing", config)
    with pytest.raises(ValueError, match="must be a mapping"):
        load_timer_profile("bad", config)


def test_cli_new_output_and_summary_paths(tmp_path: Path, capsys: object) -> None:
    report = tmp_path / "report.html"
    converted = tmp_path / "events.jsonl"

    analyze_code = main(
        [
            "analyze",
            "tests/fixtures/tshark/sample_registration.tshark.json",
            "--input-format",
            "tshark-json",
            "--output-format",
            "html",
            "--output",
            str(report),
            "--min-severity",
            "MEDIUM",
            "--show-normalized-events",
        ]
    )
    summarize_code = main(
        [
            "summarize",
            "tests/fixtures/tshark/sample_registration.tshark.json",
            "--input-format",
            "tshark-json",
        ]
    )
    export_code = main(
        [
            "export",
            "tests/fixtures/tshark/sample_registration.tshark.json",
            "--input-format",
            "tshark-json",
            "--format",
            "html",
            "--output",
            str(tmp_path / "export.html"),
        ]
    )
    convert_code = main(
        [
            "convert",
            "tests/fixtures/tshark/sample_registration.tshark.json",
            "--input-format",
            "tshark-json",
            "--to",
            "normalized-jsonl",
            "--output",
            str(converted),
        ]
    )
    captured = capsys.readouterr()

    assert analyze_code == 0
    assert summarize_code == 0
    assert export_code == 0
    assert convert_code == 0
    assert report.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert converted.read_text(encoding="utf-8").splitlines()
    assert "source=" in captured.out
