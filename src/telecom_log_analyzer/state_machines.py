"""Simplified state-machine helpers for major 4G/5G procedures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from telecom_log_analyzer.models import LogEvent


@dataclass(frozen=True)
class FlowCheck:
    name: str
    expected_sequence: list[str]
    observed: list[str]
    missing: list[str]
    abnormal: list[str]

    @property
    def complete(self) -> bool:
        return not self.missing and not self.abnormal

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "expected_sequence": list(self.expected_sequence),
            "observed": list(self.observed),
            "missing": list(self.missing),
            "abnormal": list(self.abnormal),
            "complete": self.complete,
        }


class OrderedFlowMachine:
    """Check whether expected protocol milestones appeared in order."""

    def __init__(
        self, name: str, expected_sequence: list[str], abnormal_messages: list[str]
    ) -> None:
        self.name = name
        self.expected_sequence = expected_sequence
        self.abnormal_messages = abnormal_messages

    def evaluate(self, events: list[LogEvent]) -> FlowCheck:
        messages = [event.message for event in events]
        index = 0
        observed: list[str] = []
        for message in messages:
            if index < len(self.expected_sequence) and message == self.expected_sequence[index]:
                observed.append(message)
                index += 1
        return FlowCheck(
            name=self.name,
            expected_sequence=list(self.expected_sequence),
            observed=observed,
            missing=self.expected_sequence[index:],
            abnormal=[message for message in messages if message in self.abnormal_messages],
        )


REGISTRATION_5G = OrderedFlowMachine(
    "5G registration",
    [
        "RegistrationRequest",
        "AuthenticationRequest",
        "AuthenticationResponse",
        "SecurityModeCommand",
        "SecurityModeComplete",
        "RegistrationAccept",
        "RegistrationComplete",
    ],
    ["AuthenticationFailure", "SecurityModeReject", "RegistrationReject"],
)

PDU_SESSION = OrderedFlowMachine(
    "PDU session establishment",
    [
        "PduSessionEstablishmentRequest",
        "PduSessionResourceSetupRequest",
        "PduSessionResourceSetupResponse",
        "PduSessionEstablishmentAccept",
    ],
    ["PduSessionEstablishmentReject", "PduSessionResourceSetupFailure"],
)

RRC_SETUP = OrderedFlowMachine(
    "RRC setup",
    ["RRCSetupRequest", "RRCSetup", "RRCSetupComplete"],
    ["RRCReconfigurationFailure", "RadioLinkFailure"],
)

HANDOVER = OrderedFlowMachine(
    "NG-RAN handover",
    ["HandoverRequired", "HandoverRequest", "HandoverRequestAcknowledge", "HandoverCommand"],
    ["HandoverFailure"],
)

FLOW_MACHINES = (REGISTRATION_5G, PDU_SESSION, RRC_SETUP, HANDOVER)


def evaluate_session_flows(events: list[LogEvent]) -> list[FlowCheck]:
    """Return flow checks only for procedures represented in this session."""

    checks: list[FlowCheck] = []
    messages = {event.message for event in events}
    for machine in FLOW_MACHINES:
        relevant = set(machine.expected_sequence) | set(machine.abnormal_messages)
        if messages & relevant:
            checks.append(machine.evaluate(events))
    return checks
