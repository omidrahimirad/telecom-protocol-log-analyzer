# Real-World Trace Workflow

This tool analyzes already-decoded telecom control-plane events. It does not decode raw PCAP, QXDM, TEMS, Nemo, or vendor proprietary trace formats by itself.

## What This Tool Can Analyze

- Simplified text logs included in this repository.
- Simplified JSONL logs where each line is one decoded event.
- Best-effort Wireshark/TShark JSON exports from decoded captures.
- Lab-oriented traces from Open5GS/UERANSIM workflows after they have been decoded or converted into event records.

## What This Tool Cannot Analyze

- It is not a raw PCAP decoder.
- It is not a full ASN.1 decoder.
- It is not a QXDM, TEMS, Nemo, Wireshark, or vendor OSS replacement.
- It is not fully 3GPP compliant.
- It cannot decode encrypted or ciphered NAS content unless the upstream trace source already exposes decoded fields.

## Capture And Export Example

Capture in a lab environment:

```bash
sudo tcpdump -i any -w 5g_lab_capture.pcapng
```

Export decoded JSON with TShark:

```bash
tshark -r 5g_lab_capture.pcapng -T json > 5g_lab_capture.tshark.json
```

Analyze the decoded JSON:

```bash
uv run python -m telecom_log_analyzer analyze 5g_lab_capture.tshark.json \
  --input-format tshark-json \
  --output-format markdown \
  --output report.md
```

Decoded visibility depends on trace source, keys, protocol layers visible at the capture point, and what Wireshark/TShark can decode.

## Open5GS And UERANSIM Lab Use

For Open5GS/UERANSIM labs, use this tool after collecting AMF/gNB/UE logs or TShark-decoded N2/NAS traces:

1. Start Open5GS and UERANSIM with verbose NAS/NGAP logging.
2. Capture N2 traffic with tcpdump where permitted.
3. Export TShark JSON for decoded NGAP/NAS fields.
4. Run this tool to summarize procedures and flag missing or failed steps.
5. Correlate findings with AMF, SMF, UPF, gNB, and UE logs before assigning root cause.

## How It Complements Existing Tools

Wireshark, QXDM, TEMS, Nemo, and vendor OSS tools remain the primary sources for decoding, RF measurements, modem internals, and network counters. This project complements them by automating procedure-level triage over decoded event streams:

- grouping events by UE and procedure identifiers
- checking expected registration, PDU session, RRC, and handover steps
- surfacing evidence lines and likely ownership domains
- producing Markdown/JSON reports for lab notes and portfolio review
