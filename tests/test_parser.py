from __future__ import annotations

import pytest

from telecom_log_analyzer.models import ParseError
from telecom_log_analyzer.parser import TelecomLogParser


def test_parse_valid_text_line() -> None:
    line = (
        "2026-06-01T10:15:01.120Z | UE=IMSI001010123456789 | CELL=NR-101 | "
        "LAYER=RRC | DIR=UE_TO_GNB | MSG=RRCSetupRequest | CAUSE=mo-Signalling"
    )

    event = TelecomLogParser().parse_line(line)

    assert event.ue_id == "IMSI001010123456789"
    assert event.cell_id == "NR-101"
    assert event.layer == "RRC"
    assert event.message == "RRCSetupRequest"
    assert event.cause == "mo-Signalling"


def test_parse_jsonl_line() -> None:
    line = (
        '{"timestamp":"2026-06-01T10:15:01.120Z","ue_id":"IMSI001010123456789",'
        '"layer":"NAS","direction":"UE_TO_AMF","message":"RegistrationRequest"}'
    )

    event = TelecomLogParser().parse_line(line)

    assert event.ue_id == "IMSI001010123456789"
    assert event.layer == "NAS"
    assert event.direction == "UE_TO_AMF"
    assert event.message == "RegistrationRequest"


def test_malformed_line_becomes_warning() -> None:
    result = TelecomLogParser().parse_lines(
        [
            "2026-06-01T10:15:01.120Z | UE=IMSI001 | LAYER=NAS | DIR=UE_TO_AMF",
            "not-a-valid-line",
        ]
    )

    assert result.events == []
    assert len(result.warnings) == 2
    assert "Missing required field" in result.warnings[0].message


def test_strict_parser_raises_and_optional_extra_fields() -> None:
    parser = TelecomLogParser()

    event = parser.parse_line(
        "2026-06-01T10:15:01.120Z | UE=IMSI001 | LAYER=NGAP | DIR=AMF_TO_GNB | "
        "MSG=InitialContextSetupRequest | GNB=gNB-1 | VENDOR_CAUSE=test"
    )

    assert event.node_id == "gNB-1"
    assert event.extra == {"VENDOR_CAUSE": "test"}

    with pytest.raises(ParseError):
        parser.parse_lines(["not-a-valid-line"], strict=True)
