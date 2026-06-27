from __future__ import annotations

import json
from pathlib import Path

from telecom_log_analyzer.analyzer import analyze_file


def write_log(tmp_path: Path, name: str, lines: list[str]) -> Path:
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_missing_authentication_request_is_core_domain(tmp_path: Path) -> None:
    path = write_log(
        tmp_path,
        "missing_auth.log",
        [
            "2026-06-01T12:00:00.000Z | UE=IMSI001 | LAYER=NAS | DIR=UE_TO_AMF | MSG=RegistrationRequest",
        ],
    )

    report = analyze_file(path)

    assert report.issues[0].issue_type == "5G_REGISTRATION_MISSING_AUTHENTICATION_REQUEST"
    assert report.issues[0].probable_domain.value == "CORE"
    assert report.issues[0].recommended_owner == "Core Engineer"


def test_session_display_uses_correlation_identity_when_ue_is_unknown(tmp_path: Path) -> None:
    path = tmp_path / "unknown_ue_with_imsi.jsonl"
    path.write_text(
        json.dumps(
            {
                "timestamp": "2026-06-01T12:00:00.000Z",
                "ue_id": "UNKNOWN_UE",
                "imsi": "IMSI001010700000004",
                "layer": "NAS",
                "direction": "UE_TO_AMF",
                "message": "RegistrationRequest",
                "raw": "Uplink NAS: Registration Request",
                "line_no": 1,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    report = analyze_file(path, input_format="jsonl")

    assert report.sessions[0].ue_id == "IMSI001010700000004"
    assert "UE IMSI001010700000004 sent RegistrationRequest" in report.issues[0].probable_cause


def test_handover_release_after_command_is_detected_and_flow_incomplete(tmp_path: Path) -> None:
    path = write_log(
        tmp_path,
        "ho_release.log",
        [
            "2026-06-01T12:04:00.000Z | UE=IMSI001 | LAYER=NGAP | DIR=GNB_TO_AMF | MSG=HandoverRequired | CELL=NR-101",
            "2026-06-01T12:04:00.100Z | UE=IMSI001 | LAYER=NGAP | DIR=AMF_TO_GNB | MSG=HandoverRequest | CELL=NR-202",
            "2026-06-01T12:04:00.200Z | UE=IMSI001 | LAYER=NGAP | DIR=GNB_TO_AMF | MSG=HandoverRequestAcknowledge | CELL=NR-202",
            "2026-06-01T12:04:00.300Z | UE=IMSI001 | LAYER=RRC | DIR=GNB_TO_UE | MSG=HandoverCommand | CELL=NR-101",
            "2026-06-01T12:04:01.300Z | UE=IMSI001 | LAYER=NGAP | DIR=AMF_TO_GNB | MSG=UEContextReleaseCommand | CAUSE=radio-connection-with-ue-lost",
        ],
    )

    report = analyze_file(path)
    issue_types = {issue.issue_type for issue in report.issues}
    handover_check = report.flow_checks["IMSI001"][0]

    assert "HANDOVER_RELEASE_AFTER_COMMAND" in issue_types
    assert not handover_check["complete"]
    assert "HandoverNotify" in handover_check["missing"]
    assert "UEContextReleaseCommand" in handover_check["abnormal"]


def test_context_release_without_handover_does_not_create_handover_flow(tmp_path: Path) -> None:
    path = write_log(
        tmp_path,
        "auth_failure_release.log",
        [
            "2026-06-01T12:04:00.000Z | UE=IMSI001 | LAYER=NAS | DIR=UE_TO_AMF | MSG=RegistrationRequest",
            "2026-06-01T12:04:00.100Z | UE=IMSI001 | LAYER=NAS | DIR=AMF_TO_UE | MSG=AuthenticationRequest",
            "2026-06-01T12:04:00.200Z | UE=IMSI001 | LAYER=NAS | DIR=UE_TO_AMF | MSG=AuthenticationFailure | CAUSE=synch-failure",
            "2026-06-01T12:04:00.300Z | UE=IMSI001 | LAYER=NGAP | DIR=AMF_TO_GNB | MSG=UEContextReleaseCommand | CAUSE=authentication-failure",
        ],
    )

    report = analyze_file(path)
    flow_names = {check["name"] for check in report.flow_checks["IMSI001"]}

    assert "NG-RAN handover" not in flow_names


def test_dnn_failure_domain_is_not_overwritten_by_generic_transport(tmp_path: Path) -> None:
    path = write_log(
        tmp_path,
        "pdu_dnn.log",
        [
            "2026-06-01T12:06:00.000Z | UE=IMSI001 | LAYER=NAS | DIR=UE_TO_AMF | MSG=PduSessionEstablishmentRequest | SESSION=12 | DNN=private | S_NSSAI=1-999999",
            "2026-06-01T12:06:00.200Z | UE=IMSI001 | LAYER=NGAP | DIR=AMF_TO_GNB | MSG=PduSessionResourceSetupRequest | SESSION=12 | DNN=private | S_NSSAI=1-999999",
            "2026-06-01T12:06:00.400Z | UE=IMSI001 | LAYER=NGAP | DIR=GNB_TO_AMF | MSG=PduSessionResourceSetupFailure | SESSION=12 | CAUSE=missing-or-unknown-dnn | DNN=private | S_NSSAI=1-999999",
        ],
    )

    report = analyze_file(path)
    by_type = {issue.issue_type: issue for issue in report.issues}

    assert by_type["NGAP_PDU_SESSION_RESOURCE_SETUP_FAILURE"].probable_domain.value == "CORE"
    assert by_type["PDU_SESSION_ACCEPT_MISSING"].probable_domain.value == "CORE"
