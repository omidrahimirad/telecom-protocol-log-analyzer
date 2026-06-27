# Troubleshooting Rules

Rules are deterministic and intentionally explainable. Each finding includes severity, affected UE/session, failed layer, evidence, probable cause, and next troubleshooting steps.

## Registration Rules

`5G_REGISTRATION_MISSING_AUTHENTICATION_REQUEST`

- Trigger: `RegistrationRequest` is present, but no authentication, accept, reject, or failure follows.
- Why it matters: the request may not have reached AMF authentication handling, subscriber lookup may be stuck, or the trace may miss downlink NAS.

`5G_REGISTRATION_AUTHENTICATION_FAILURE`

- Trigger: `AuthenticationFailure` after registration.
- Why it matters: likely USIM/authentication vector mismatch, SQN issue, wrong PLMN profile, or UE-side modem/USIM issue.

`5G_REGISTRATION_SECURITY_MODE_REJECT`

- Trigger: `SecurityModeReject`.
- Why it matters: NAS algorithm negotiation or security context activation failed.

`5G_REGISTRATION_REJECT`

- Trigger: `RegistrationReject`.
- Why it matters: registration was explicitly rejected by core policy or subscriber state. Cause codes such as roaming, subscription, or congestion drive the next checks.

`5G_REGISTRATION_ACCEPT_MISSING`

- Trigger: authentication/security progresses but no `RegistrationAccept` appears.
- Why it matters: AMF may have stalled after security, downlink NAS may be missing, or a release interrupted the procedure.

## PDU Session Rules

`PDU_SESSION_ESTABLISHMENT_REJECT`

- Trigger: `PduSessionEstablishmentReject`.
- Why it matters: DNN/S-NSSAI authorization, SMF policy, subscription, UPF selection, or N4/N3 setup may have failed.

`NGAP_PDU_SESSION_RESOURCE_SETUP_FAILURE`

- Trigger: `PduSessionResourceSetupFailure`.
- Why it matters: the request reached radio resource setup, but gNB or transport resource allocation failed.

`PDU_SESSION_MISSING_N2_CORRELATION`

- Trigger: NAS PDU session request has no matching NGAP resource setup.
- Why it matters: the NAS request may be rejected before resource setup or the trace may lack NGAP data.

`PDU_SESSION_ACCEPT_MISSING`

- Trigger: no NAS accept after PDU session request.
- Why it matters: resource setup or downlink NAS SM delivery did not complete.

## RRC Rules

`RRC_SETUP_RESPONSE_MISSING`

- Trigger: `RRCSetupRequest` without `RRCSetup`.
- Why it matters: initial access may be blocked by RACH instability, overload, admission control, or missing downlink logging.

`RRC_SETUP_COMPLETE_MISSING`

- Trigger: `RRCSetup` without `RRCSetupComplete`.
- Why it matters: UE did not finish SRB1/NAS delivery or uplink capture is incomplete.

`RRC_RRCRECONFIGURATIONFAILURE`

- Trigger: `RRCReconfigurationFailure`.
- Why it matters: UE rejected radio bearer, mobility, measurement, or DRB configuration.

`RRC_RADIOLINKFAILURE`

- Trigger: `RadioLinkFailure`.
- Why it matters: radio conditions or link maintenance failed badly enough to drop the connection.

## Handover Rules

`HANDOVER_PREPARATION_ACK_MISSING`

- Trigger: `HandoverRequired` without `HandoverRequestAcknowledge` or `HandoverFailure`.
- Why it matters: target side did not accept preparation or trace coverage is incomplete.

`HANDOVER_FAILURE`

- Trigger: `HandoverFailure`.
- Why it matters: target cell, admission, neighbor relation, or signaling path blocked mobility.

`HANDOVER_EXECUTION_COMPLETE_MISSING`

- Trigger: `HandoverCommand` without `HandoverNotify` or completion.
- Why it matters: UE may not have reached target cell after command.

`HANDOVER_EXECUTION_TIMEOUT`

- Trigger: completion occurs after configured timeout.
- Why it matters: slow handover execution can affect mobility KPI and user experience.

## Initial Access Rules

`REPEATED_INITIAL_ACCESS_ATTEMPTS`

- Trigger: at least three `RRCSetupRequest` messages from the same UE within 60 seconds.
- Why it matters: repeated access often indicates radio instability, congestion, access barring, or a reject loop.
