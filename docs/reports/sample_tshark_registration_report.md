# Telecom Protocol Log Analysis Report

Source: `tests/fixtures/tshark/sample_registration.tshark.json`

## Summary

- Sessions analyzed: 2
- UEs/traces analyzed: 2
- Procedures observed: 1
- Events analyzed: 4
- Issues detected: 1
- Critical issues: 0
- High severity issues: 1
- Parser/session warnings: 0

## Detected Issues

### 1. 5G_REGISTRATION_SECURITY_MODE_COMMAND_MISSING

- Severity: **HIGH**
- Affected UE/session: `IMSI001010555123456`
- Failed protocol layer: `NAS`
- Last successful step: `AuthenticationRequest`
- First suspicious message: line 4: AuthenticationResponse
- Missing or failed expected message: `SecurityModeCommand`
- Probable domain: `UE`
- Recommended owner: `UE/Modem Engineer`
- Confidence: `0.58`
- Confidence reason: multiple supporting events; finding is based on missing/timeout evidence

Probable root cause:

UE IMSI001010555123456 sent AuthenticationResponse, but no NAS SecurityModeCommand was observed. In a normal initial 5G registration this usually means the AMF did not advance to NAS security activation, the downlink NAS security message is missing from the trace, or authentication result handling failed before algorithm selection.

Evidence lines:

- Line 2: `Uplink NAS: Registration Request`
- Line 3: `Downlink NAS: Authentication Request`
- Line 4: `Uplink NAS: Authentication Response`

Recommended troubleshooting actions:

- Check AMF authentication result handling after AUSF/UDM confirmation.
- Verify downlink NAS transport logging from AMF to gNB.
- Review selected NAS security algorithms and AMF security context allocation.

Suggested troubleshooting commands/checks:

- Collect UE modem NAS/RRC trace around the affected procedure.

False-positive notes:

- Missing-message findings can be caused by trace filtering, incomplete capture points, or decoded-field gaps.

## Protocol Flow Checks

### 101

| Flow | Status | Missing | Abnormal |
| --- | --- | --- | --- |

### IMSI001010555123456

| Flow | Status | Missing | Abnormal |
| --- | --- | --- | --- |
| 5G registration | incomplete/abnormal | SecurityModeCommand, SecurityModeComplete, RegistrationAccept, RegistrationComplete |  |

## UE/Session Timeline

### 101

| Time | Layer | Direction | Message | Cause | Cell |
| --- | --- | --- | --- | --- | --- |
| 2026-06-01T12:40:00Z | NGAP | GNB_TO_AMF | InitialUEMessage |  | NR-101 |

### IMSI001010555123456

| Time | Layer | Direction | Message | Cause | Cell |
| --- | --- | --- | --- | --- | --- |
| 2026-06-01T12:40:00.100000Z | NAS_5GS | UE_TO_AMF | RegistrationRequest |  |  |
| 2026-06-01T12:40:00.300000Z | NAS_5GS | AMF_TO_UE | AuthenticationRequest |  |  |
| 2026-06-01T12:40:03.900000Z | NAS_5GS | UE_TO_AMF | AuthenticationResponse |  |  |

## Limitations

- This report is based on simplified text/JSONL logs, not a binary PCAP or full ASN.1 decoder.
- The state machines are intentionally compact and do not implement every 3GPP timer, cause, or vendor extension.
- Findings should be correlated with gNB, AMF, SMF, UPF, UE modem, and RF/KPI data before operational action.
