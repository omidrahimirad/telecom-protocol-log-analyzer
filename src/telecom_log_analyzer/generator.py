"""Synthetic simplified log generator for demos and tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate_log(scenario: str, ues: int, output: Path) -> None:
    lines: list[str] = []
    base = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
    for index in range(ues):
        ue = f"IMSI00101012345{index:04d}"
        cell = f"NR-{101 + index % 3}"
        offset = timedelta(seconds=index * 2)
        lines.extend(_scenario_lines(scenario, base + offset, ue, cell))
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _scenario_lines(scenario: str, start: datetime, ue: str, cell: str) -> list[str]:
    common_prefix = [
        event(start, ue, cell, "RRC", "UE_TO_GNB", "RRCSetupRequest", "mo-Signalling"),
        event(start + timedelta(milliseconds=80), ue, cell, "RRC", "GNB_TO_UE", "RRCSetup"),
        event(
            start + timedelta(milliseconds=160), ue, cell, "RRC", "UE_TO_GNB", "RRCSetupComplete"
        ),
        event(
            start + timedelta(milliseconds=210), ue, cell, "NGAP", "GNB_TO_AMF", "InitialUEMessage"
        ),
        event(
            start + timedelta(milliseconds=240), ue, cell, "NAS", "UE_TO_AMF", "RegistrationRequest"
        ),
    ]
    if scenario == "registration_auth_failure":
        return [
            *common_prefix,
            event(
                start + timedelta(milliseconds=400),
                ue,
                cell,
                "NAS",
                "AMF_TO_UE",
                "AuthenticationRequest",
            ),
            event(
                start + timedelta(milliseconds=620),
                ue,
                cell,
                "NAS",
                "UE_TO_AMF",
                "AuthenticationFailure",
                "synch-failure",
            ),
        ]
    if scenario == "pdu_session_resource_setup_failure":
        return [
            *successful_registration(start, ue, cell),
            event(
                start + timedelta(seconds=1, milliseconds=400),
                ue,
                cell,
                "NAS",
                "UE_TO_AMF",
                "PduSessionEstablishmentRequest",
                session="10",
            ),
            event(
                start + timedelta(seconds=1, milliseconds=560),
                ue,
                cell,
                "NGAP",
                "AMF_TO_GNB",
                "PduSessionResourceSetupRequest",
                session="10",
            ),
            event(
                start + timedelta(seconds=1, milliseconds=780),
                ue,
                cell,
                "NGAP",
                "GNB_TO_AMF",
                "PduSessionResourceSetupFailure",
                "radio-resources-not-available",
                session="10",
            ),
        ]
    if scenario == "handover_failure":
        return [
            *successful_registration(start, ue, cell),
            event(start + timedelta(seconds=3), ue, cell, "NGAP", "GNB_TO_AMF", "HandoverRequired"),
            event(
                start + timedelta(seconds=3, milliseconds=200),
                ue,
                "NR-202",
                "NGAP",
                "AMF_TO_GNB",
                "HandoverRequest",
            ),
            event(
                start + timedelta(seconds=3, milliseconds=420),
                ue,
                "NR-202",
                "NGAP",
                "GNB_TO_AMF",
                "HandoverFailure",
                "target-cell-not-available",
            ),
        ]
    if scenario != "normal_5g_registration":
        msg = f"Unknown scenario {scenario!r}"
        raise ValueError(msg)
    return successful_registration(start, ue, cell)


def successful_registration(start: datetime, ue: str, cell: str) -> list[str]:
    return [
        event(start, ue, cell, "RRC", "UE_TO_GNB", "RRCSetupRequest", "mo-Signalling"),
        event(start + timedelta(milliseconds=80), ue, cell, "RRC", "GNB_TO_UE", "RRCSetup"),
        event(
            start + timedelta(milliseconds=160), ue, cell, "RRC", "UE_TO_GNB", "RRCSetupComplete"
        ),
        event(
            start + timedelta(milliseconds=220), ue, cell, "NGAP", "GNB_TO_AMF", "InitialUEMessage"
        ),
        event(
            start + timedelta(milliseconds=250), ue, cell, "NAS", "UE_TO_AMF", "RegistrationRequest"
        ),
        event(
            start + timedelta(milliseconds=400),
            ue,
            cell,
            "NAS",
            "AMF_TO_UE",
            "AuthenticationRequest",
        ),
        event(
            start + timedelta(milliseconds=560),
            ue,
            cell,
            "NAS",
            "UE_TO_AMF",
            "AuthenticationResponse",
        ),
        event(
            start + timedelta(milliseconds=720), ue, cell, "NAS", "AMF_TO_UE", "SecurityModeCommand"
        ),
        event(
            start + timedelta(milliseconds=860),
            ue,
            cell,
            "NAS",
            "UE_TO_AMF",
            "SecurityModeComplete",
        ),
        event(
            start + timedelta(seconds=1),
            ue,
            cell,
            "NGAP",
            "AMF_TO_GNB",
            "InitialContextSetupRequest",
        ),
        event(
            start + timedelta(seconds=1, milliseconds=120),
            ue,
            cell,
            "NGAP",
            "GNB_TO_AMF",
            "InitialContextSetupResponse",
        ),
        event(
            start + timedelta(seconds=1, milliseconds=220),
            ue,
            cell,
            "NAS",
            "AMF_TO_UE",
            "RegistrationAccept",
        ),
        event(
            start + timedelta(seconds=1, milliseconds=360),
            ue,
            cell,
            "NAS",
            "UE_TO_AMF",
            "RegistrationComplete",
        ),
    ]


def event(
    timestamp: datetime,
    ue: str,
    cell: str,
    layer: str,
    direction: str,
    message: str,
    cause: str | None = None,
    *,
    session: str | None = None,
) -> str:
    fields = [
        timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        f"UE={ue}",
        f"CELL={cell}",
        f"LAYER={layer}",
        f"DIR={direction}",
        f"MSG={message}",
    ]
    if cause:
        fields.append(f"CAUSE={cause}")
    if session:
        fields.append(f"SESSION={session}")
    return " | ".join(fields)
