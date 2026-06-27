from __future__ import annotations

from pathlib import Path

import pytest

from telecom_log_analyzer.generator import generate_log
from telecom_log_analyzer.parser import TelecomLogParser
from telecom_log_analyzer.state_machines import PDU_SESSION, REGISTRATION_5G


def test_generator_creates_multi_ue_registration_failure(tmp_path: Path) -> None:
    output = tmp_path / "generated.log"

    generate_log("registration_auth_failure", 2, output)
    result = TelecomLogParser().parse_file(output)

    assert len({event.ue_id for event in result.events}) == 2
    assert "AuthenticationFailure" in {event.message for event in result.events}


@pytest.mark.parametrize(
    "scenario,expected_message",
    [
        ("normal_5g_registration", "RegistrationComplete"),
        ("pdu_session_resource_setup_failure", "PduSessionResourceSetupFailure"),
        ("handover_failure", "HandoverFailure"),
    ],
)
def test_generator_scenarios(tmp_path: Path, scenario: str, expected_message: str) -> None:
    output = tmp_path / f"{scenario}.log"

    generate_log(scenario, 1, output)
    result = TelecomLogParser().parse_file(output)

    assert expected_message in {event.message for event in result.events}


def test_generator_rejects_unknown_scenario(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown scenario"):
        generate_log("unknown", 1, tmp_path / "bad.log")


def test_state_machine_complete_and_abnormal_paths() -> None:
    events = (
        TelecomLogParser()
        .parse_lines(
            [
                "2026-06-01T10:00:00.000Z | UE=IMSI1 | LAYER=NAS | DIR=UE_TO_AMF | MSG=RegistrationRequest",
                "2026-06-01T10:00:00.100Z | UE=IMSI1 | LAYER=NAS | DIR=AMF_TO_UE | MSG=AuthenticationRequest",
                "2026-06-01T10:00:00.200Z | UE=IMSI1 | LAYER=NAS | DIR=UE_TO_AMF | MSG=AuthenticationResponse",
                "2026-06-01T10:00:00.300Z | UE=IMSI1 | LAYER=NAS | DIR=AMF_TO_UE | MSG=SecurityModeCommand",
                "2026-06-01T10:00:00.400Z | UE=IMSI1 | LAYER=NAS | DIR=UE_TO_AMF | MSG=SecurityModeComplete",
                "2026-06-01T10:00:00.500Z | UE=IMSI1 | LAYER=NAS | DIR=AMF_TO_UE | MSG=RegistrationAccept",
                "2026-06-01T10:00:00.600Z | UE=IMSI1 | LAYER=NAS | DIR=UE_TO_AMF | MSG=RegistrationComplete",
            ]
        )
        .events
    )

    check = REGISTRATION_5G.evaluate(events)

    assert check.complete
    assert check.name == "5G registration"
    assert check.missing == []
    assert check.abnormal == []


def test_state_machine_reports_missing_and_abnormal() -> None:
    events = (
        TelecomLogParser()
        .parse_lines(
            [
                "2026-06-01T10:00:00.000Z | UE=IMSI1 | LAYER=NAS | DIR=UE_TO_AMF | MSG=PduSessionEstablishmentRequest",
                "2026-06-01T10:00:00.100Z | UE=IMSI1 | LAYER=NAS | DIR=AMF_TO_UE | MSG=PduSessionEstablishmentReject | CAUSE=missing-dnn",
            ]
        )
        .events
    )

    check = PDU_SESSION.evaluate(events)

    assert not check.complete
    assert check.missing == [
        "PduSessionResourceSetupRequest",
        "PduSessionResourceSetupResponse",
        "PduSessionEstablishmentAccept",
    ]
    assert check.abnormal == ["PduSessionEstablishmentReject"]
