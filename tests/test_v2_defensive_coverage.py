from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from telecom_log_analyzer.adapters.jsonl import JsonlAdapter
from telecom_log_analyzer.adapters.tshark_json import TsharkJsonAdapter, infer_direction
from telecom_log_analyzer.analyzer import parse_input_file
from telecom_log_analyzer.models import LogEvent, ParseError
from telecom_log_analyzer.report import render_terminal
from telecom_log_analyzer.rules import registration_cause_explanation
from telecom_log_analyzer.timers import _load_yaml


def test_jsonl_adapter_invalid_records_and_strict(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text("{bad\n[]\n", encoding="utf-8")

    result = JsonlAdapter().parse_file(path)
    assert result.events == []
    assert len(result.warnings) == 2

    with pytest.raises(ParseError):
        JsonlAdapter().parse_file(path, strict=True)


def test_parse_input_file_rejects_unknown_format(tmp_path: Path) -> None:
    path = tmp_path / "x.log"
    path.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported input format"):
        parse_input_file(path, input_format="pcap")


def test_tshark_missing_layers_and_timestamp_warnings(tmp_path: Path) -> None:
    path = tmp_path / "bad_tshark.json"
    path.write_text(
        '[{"_source": {}}, {"_source": {"layers": {"nas-5gs": {"nas-5gs.message_name": "RegistrationRequest"}}}}]',
        encoding="utf-8",
    )

    result = TsharkJsonAdapter().parse_file(path)

    assert result.events == []
    assert len(result.warnings) == 2


def test_tshark_rrc_packet_and_direction_inference(tmp_path: Path) -> None:
    path = tmp_path / "rrc.json"
    path.write_text(
        """
        [
          {
            "_source": {
              "layers": {
                "frame": {"frame.number": "7", "frame.time_epoch": "1780317602.000"},
                "_ws.col.Info": "Downlink RRC Setup",
                "_ws.col.Source": "gNB",
                "_ws.col.Destination": "UE",
                "nr-rrc": {"nr-rrc.message_name": "RRCSetup", "nr-rrc.c-rnti": "0x1234"}
              }
            }
          }
        ]
        """,
        encoding="utf-8",
    )

    result = TsharkJsonAdapter().parse_file(path)

    assert result.events[0].message == "RRCSetup"
    assert result.events[0].direction == "GNB_TO_UE"
    assert (
        infer_direction("NGAP", {"_ws.col.Info": "Downlink NAS", "_ws.col.Source": "AMF"})
        == "AMF_TO_GNB"
    )
    assert (
        infer_direction("NAS_5GS", {"_ws.col.Info": "Downlink NAS", "_ws.col.Source": "AMF"})
        == "AMF_TO_UE"
    )


def test_model_correlation_key_fallbacks() -> None:
    base = {
        "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "ue_id": "",
        "layer": "NGAP",
        "direction": "UNKNOWN",
        "message": "InitialUEMessage",
        "raw": "raw",
        "line_no": 1,
    }

    assert LogEvent(**base, supi="SUPI-1").correlation_key == "SUPI-1"
    assert LogEvent(**base, imsi="IMSI-1").correlation_key == "IMSI-1"
    assert LogEvent(**base, guti="GUTI-1").correlation_key == "GUTI-1"
    assert LogEvent(**base, five_g_tmsi="TMSI-1").correlation_key == "TMSI-1"
    assert LogEvent(**base, amf_ue_ngap_id="5", ran_ue_ngap_id="9").correlation_key == "NGAP:5/9"
    assert LogEvent(**base, ran_ue_ngap_id="9").correlation_key == "RAN-UE-NGAP-ID:9"
    assert LogEvent(**base, rnti="0x1").correlation_key == "RNTI:0x1"
    assert LogEvent(**base).correlation_key == "UNKNOWN_UE"


def test_registration_cause_explanations_and_bad_yaml(tmp_path: Path) -> None:
    assert "subscriber" in registration_cause_explanation("subscription-not-allowed")
    assert "congestion" in registration_cause_explanation("network-congestion")
    assert "authentication" in registration_cause_explanation("authentication-rejected")
    assert "policy" in registration_cause_explanation("other-cause")

    bad = tmp_path / "bad.yaml"
    bad.write_text("- item\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a mapping"):
        _load_yaml(bad)


def test_terminal_report_warning_lines() -> None:
    from telecom_log_analyzer.analyzer import analyze_file

    report = analyze_file(
        Path("tests/fixtures/tshark/malformed_missing_fields.tshark.json"),
        input_format="tshark-json",
    )
    rendered = render_terminal(report)
    assert "Warnings" in rendered
