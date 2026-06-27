from __future__ import annotations

from telecom_log_analyzer.parser import TelecomLogParser
from telecom_log_analyzer.sessionizer import Sessionizer


def test_sessionizer_groups_multiple_ues_and_sorts_out_of_order() -> None:
    lines = [
        "2026-06-01T10:00:02.000Z | UE=IMSI2 | LAYER=NAS | DIR=UE_TO_AMF | MSG=RegistrationRequest",
        "2026-06-01T10:00:03.000Z | UE=IMSI1 | LAYER=NAS | DIR=AMF_TO_UE | MSG=AuthenticationRequest",
        "2026-06-01T10:00:01.000Z | UE=IMSI1 | LAYER=NAS | DIR=UE_TO_AMF | MSG=RegistrationRequest",
    ]
    result = TelecomLogParser().parse_lines(lines)

    sessions, warnings = Sessionizer().build_sessions(result.events)

    assert [session.ue_id for session in sessions] == ["IMSI1", "IMSI2"]
    assert [event.message for event in sessions[0].events] == [
        "RegistrationRequest",
        "AuthenticationRequest",
    ]
    assert len(warnings) == 1
    assert "Out-of-order" in warnings[0].message
