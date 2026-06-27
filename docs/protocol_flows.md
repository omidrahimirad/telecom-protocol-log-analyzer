# Simplified Protocol Flows

This project models simplified troubleshooting flows. The message order is inspired by real 4G/5G work, but it is intentionally smaller than complete 3GPP procedures.

## 5G Registration

Typical happy path:

1. UE completes RRC setup.
2. gNB forwards NAS `RegistrationRequest` in `InitialUEMessage`.
3. AMF triggers `AuthenticationRequest`.
4. UE returns `AuthenticationResponse`.
5. AMF sends `SecurityModeCommand`.
6. UE returns `SecurityModeComplete`.
7. AMF accepts registration with `RegistrationAccept`.
8. UE confirms with `RegistrationComplete`.

Troubleshooting focus:

- Missing authentication may indicate AMF routing, subscriber lookup, AUSF/UDM, or trace coverage issue.
- `AuthenticationFailure` often points to USIM/authentication vector/SQN mismatch.
- `RegistrationReject` cause codes frequently map to roaming, subscription, tracking area, congestion, or policy.

## Authentication And Security

Authentication validates the subscriber and USIM-derived credentials. Security mode negotiation activates NAS integrity and ciphering.

Common failure areas:

- USIM profile not provisioned for the test PLMN.
- Wrong subscriber key material in core network.
- SQN resynchronization failure.
- UE capability and AMF algorithm mismatch.
- Capture missing uplink/downlink NAS transport.

## PDU Session Establishment

Typical simplified path:

1. UE sends `PduSessionEstablishmentRequest`.
2. AMF/SMF selects DNN, S-NSSAI, UPF, and policy.
3. AMF sends `PduSessionResourceSetupRequest` to gNB.
4. gNB returns `PduSessionResourceSetupResponse`.
5. Network sends `PduSessionEstablishmentAccept` to UE.

Troubleshooting focus:

- NAS reject indicates session-management policy or subscription issue.
- NGAP resource setup failure points to gNB admission, DRB/QoS mapping, or N3/UPF transport.
- Missing NGAP correlation means the NAS request may not have reached the resource setup stage.

## RRC Setup

Typical simplified path:

1. UE sends `RRCSetupRequest`.
2. gNB sends `RRCSetup`.
3. UE sends `RRCSetupComplete`, often carrying initial NAS.

Troubleshooting focus:

- Missing `RRCSetup` may indicate RACH instability, overload, access barring, or missing downlink capture.
- Missing `RRCSetupComplete` may indicate uplink radio problems, SRB1/RLC problems, UE reset, or capture gap.
- `RRCReconfigurationFailure` suggests unsupported or invalid radio bearer, mobility, measurement, or DRB parameters.

## Handover

Typical simplified NG-RAN handover:

1. Source gNB sends `HandoverRequired`.
2. AMF sends `HandoverRequest` to target gNB.
3. Target gNB returns `HandoverRequestAcknowledge`.
4. Source side sends `HandoverCommand` to UE.
5. Target side reports `HandoverNotify`.

Troubleshooting focus:

- Missing ACK suggests target admission or signaling failure.
- `HandoverFailure` with target-cell cause points to neighbor relation, cell availability, admission, or transport.
- Missing completion after command indicates UE failed target access or the target-side trace is absent.
