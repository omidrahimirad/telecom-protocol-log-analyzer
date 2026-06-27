"""Short protocol message explanations for CLI users."""

from __future__ import annotations

MESSAGE_REFERENCE: dict[str, str] = {
    "RRCSetupRequest": "UE requests establishment of an RRC connection, typically after random access.",
    "RRCSetup": "gNB provides SRB1 and initial RRC configuration so the UE can complete connection setup.",
    "RRCSetupComplete": "UE confirms RRC setup and can carry the first NAS message toward the core.",
    "RRCReconfiguration": "Network updates radio bearer, measurement, mobility, or DRB configuration.",
    "RRCReconfigurationComplete": "UE accepted and applied the RRC reconfiguration.",
    "RRCReconfigurationFailure": "UE failed to apply RRC configuration, often due to unsupported or invalid radio parameters.",
    "RadioLinkFailure": "Radio link degraded enough that the UE declared RLF or connection failure.",
    "InitialUEMessage": "gNB sends the UE's initial NAS payload to the AMF over NGAP.",
    "DownlinkNASTransport": "AMF sends a NAS message to the UE through the gNB.",
    "UplinkNASTransport": "gNB forwards an uplink NAS message from the UE to the AMF.",
    "RegistrationRequest": "UE starts 5G NAS registration for initial registration, mobility, or periodic update.",
    "AuthenticationRequest": "AMF/AUSF challenges the UE to authenticate the subscriber.",
    "AuthenticationResponse": "UE returns authentication result derived from USIM credentials.",
    "AuthenticationFailure": "UE reports authentication failed, possibly with synchronization or MAC failure details.",
    "SecurityModeCommand": "AMF selects NAS integrity/ciphering algorithms and activates security.",
    "SecurityModeComplete": "UE confirms NAS security mode activation.",
    "SecurityModeReject": "UE rejects selected NAS security mode or context.",
    "RegistrationAccept": "AMF accepts registration and provides allowed NSSAI, GUTI, and registration context.",
    "RegistrationComplete": "UE confirms RegistrationAccept processing.",
    "RegistrationReject": "AMF rejects registration with a NAS cause such as roaming or subscription restriction.",
    "PduSessionEstablishmentRequest": "UE requests a data session for a DNN/S-NSSAI/PDU session ID.",
    "PduSessionEstablishmentAccept": "Network accepts the PDU session and returns session parameters to the UE.",
    "PduSessionEstablishmentReject": "Network rejects the PDU session with a session management cause.",
    "PduSessionResourceSetupRequest": "AMF asks gNB to allocate radio resources for a PDU session.",
    "PduSessionResourceSetupResponse": "gNB confirms radio resources and user-plane tunnel setup.",
    "PduSessionResourceSetupFailure": "gNB could not allocate or configure resources for the PDU session.",
    "HandoverRequired": "Source gNB requests core-assisted handover preparation.",
    "HandoverRequest": "AMF asks target gNB to prepare resources for the incoming UE.",
    "HandoverRequestAcknowledge": "Target gNB accepts handover preparation and returns target configuration.",
    "HandoverCommand": "Network commands the UE to move to the prepared target cell.",
    "HandoverNotify": "Target gNB notifies AMF that UE arrived after handover.",
    "HandoverComplete": "Simplified completion marker for successful handover execution.",
    "HandoverFailure": "Handover preparation or execution failed with a mobility/cell/resource cause.",
}


def explain_message(message_name: str) -> str:
    return MESSAGE_REFERENCE.get(
        message_name,
        "No built-in explanation is available. Check spelling or extend protocol_reference.py.",
    )


def known_messages() -> list[str]:
    return sorted(MESSAGE_REFERENCE)
