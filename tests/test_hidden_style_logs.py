from __future__ import annotations

from pathlib import Path

from telecom_log_analyzer.analyzer import analyze_file
from telecom_log_analyzer.parser import TelecomLogParser


def test_hidden_multi_pdu_same_ue_keeps_evidence_on_correct_session(tmp_path: Path) -> None:
    log = tmp_path / "multi_pdu_same_ue.log"
    log.write_text(
        "\n".join(
            [
                "2026-06-01T12:00:00.000Z | UE=IMSI001010200000001 | CELL=NR-101 | LAYER=RRC | DIR=UE_TO_GNB | MSG=RRCSetupRequest",
                "2026-06-01T12:00:00.050Z | UE=IMSI001010200000001 | CELL=NR-101 | LAYER=RRC | DIR=GNB_TO_UE | MSG=RRCSetup",
                "2026-06-01T12:00:00.100Z | UE=IMSI001010200000001 | CELL=NR-101 | LAYER=RRC | DIR=UE_TO_GNB | MSG=RRCSetupComplete",
                "2026-06-01T12:00:01.000Z | UE=IMSI001010200000001 | CELL=NR-101 | LAYER=NAS | DIR=UE_TO_AMF | MSG=PduSessionEstablishmentRequest | SESSION=10",
                "2026-06-01T12:00:01.100Z | UE=IMSI001010200000001 | CELL=NR-101 | LAYER=NGAP | DIR=AMF_TO_GNB | MSG=PduSessionResourceSetupRequest | SESSION=10",
                "2026-06-01T12:00:01.200Z | UE=IMSI001010200000001 | CELL=NR-101 | LAYER=NGAP | DIR=GNB_TO_AMF | MSG=PduSessionResourceSetupResponse | SESSION=10",
                "2026-06-01T12:00:01.300Z | UE=IMSI001010200000001 | CELL=NR-101 | LAYER=NAS | DIR=AMF_TO_UE | MSG=PduSessionEstablishmentAccept | SESSION=10",
                "2026-06-01T12:00:02.000Z | UE=IMSI001010200000001 | CELL=NR-101 | LAYER=NAS | DIR=UE_TO_AMF | MSG=PduSessionEstablishmentRequest | SESSION=11",
                "2026-06-01T12:00:02.250Z | UE=IMSI001010200000001 | CELL=NR-101 | LAYER=NAS | DIR=AMF_TO_UE | MSG=PduSessionEstablishmentReject | CAUSE=missing-or-unknown-dnn | SESSION=11",
            ]
        ),
        encoding="utf-8",
    )

    report = analyze_file(log)
    pdu_rejects = [
        issue for issue in report.issues if issue.issue_type == "PDU_SESSION_ESTABLISHMENT_REJECT"
    ]

    assert len(pdu_rejects) == 1
    assert pdu_rejects[0].affected_session == "IMSI001010200000001/PDU-11"
    assert [event.session_id for event in pdu_rejects[0].evidence] == ["11", "11"]


def test_hidden_bad_required_values_are_warnings_not_crashes(tmp_path: Path) -> None:
    log = tmp_path / "bad_required_values.log"
    log.write_text(
        "\n".join(
            [
                "2026-06-01T12:05:00.000Z | UE= | CELL=NR-101 | LAYER=NAS | DIR=UE_TO_AMF | MSG=RegistrationRequest",
                "not-a-timestamp | UE=IMSI001010200000002 | LAYER=NAS | DIR=UE_TO_AMF | MSG=RegistrationRequest",
                "2026-06-01T12:05:01.000Z | UE=IMSI001010200000003 | LAYER=FOO | DIR=SIDEWAYS | MSG=RegistrationRequest",
            ]
        ),
        encoding="utf-8",
    )

    result = TelecomLogParser().parse_file(log)

    assert result.events == []
    assert len(result.warnings) == 3
    assert "cannot be empty" in result.warnings[0].message
    assert "Invalid timestamp" in result.warnings[1].message
    assert "Unsupported protocol layer" in result.warnings[2].message


def test_hidden_out_of_order_jsonl_sorts_and_warns(tmp_path: Path) -> None:
    log = tmp_path / "out_of_order.jsonl"
    log.write_text(
        "\n".join(
            [
                '{"timestamp":"2026-06-01T12:10:01.000Z","ue_id":"IMSI001010200000004","layer":"NAS","direction":"AMF_TO_UE","message":"AuthenticationRequest"}',
                '{"timestamp":"2026-06-01T12:10:00.000Z","ue_id":"IMSI001010200000004","layer":"NAS","direction":"UE_TO_AMF","message":"RegistrationRequest"}',
                '{"timestamp":"2026-06-01T12:10:02.000Z","ue_id":"IMSI001010200000004","layer":"NAS","direction":"UE_TO_AMF","message":"AuthenticationResponse"}',
            ]
        ),
        encoding="utf-8",
    )

    report = analyze_file(log)

    assert len(report.warnings) == 1
    assert [event.message for event in report.sessions[0].events] == [
        "RegistrationRequest",
        "AuthenticationRequest",
        "AuthenticationResponse",
    ]
    assert "5G_REGISTRATION_SECURITY_MODE_COMMAND_MISSING" in {
        issue.issue_type for issue in report.issues
    }
    assert "5G registration" in {
        check["name"] for checks in report.flow_checks.values() for check in checks
    }
