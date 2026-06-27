# Limitations And Assumptions

This project intentionally uses simplified logs. It is designed for a GitHub portfolio, learning, and workflow demonstration, not as a production network decoder.

## What It Is

- A deterministic analyzer for readable text or JSONL protocol-event logs.
- A way to demonstrate UE timeline reconstruction and practical troubleshooting logic.
- A compact framework for adding new protocol rules and report formats.

## What It Is Not

- Not a PCAP decoder.
- Not an ASN.1 decoder.
- Not a full NAS/RRC/NGAP binary parser.
- Not fully 3GPP compliant.
- Not a replacement for QXDM, TEMS, Nemo, Wireshark dissectors, vendor EMS/NMS, or commercial core/RAN trace tools.

## Assumptions

- Each input line contains one already-decoded protocol message.
- Required fields are timestamp, UE, layer, direction, and message name.
- Cause, cell, gNB/eNB/node, and PDU session ID are optional.
- Log timestamps are comparable ISO-8601 values.
- Rule results are hypotheses to guide troubleshooting, not final operational conclusions.

## Recommended Real-World Correlation

Before making operational changes, correlate findings with:

- UE modem logs and RF measurements.
- gNB counters, admission logs, RACH/RLC/MAC statistics.
- AMF, AUSF, UDM, SMF, UPF logs.
- Subscriber provisioning and policy data.
- Transport reachability and user-plane tunnel state.
