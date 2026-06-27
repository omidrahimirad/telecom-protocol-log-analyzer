"""Base types and helpers for decoded trace adapters."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from telecom_log_analyzer.models import LogEvent, ParseError, ParseWarning
from telecom_log_analyzer.utils import normalize_key, parse_timestamp

REQUIRED_FIELDS = {"UE", "LAYER", "DIR", "MSG"}
OPTIONAL_FIELDS = {
    "CAUSE",
    "CELL",
    "GNB",
    "ENB",
    "NODE",
    "SESSION",
    "PDU",
    "RAW",
    "SUPI",
    "IMSI",
    "GUTI",
    "FIVE_G_TMSI",
    "RAN_UE_NGAP_ID",
    "AMF_UE_NGAP_ID",
    "RNTI",
    "INTERFACE",
    "PROCEDURE",
    "DNN",
    "S_NSSAI",
    "QFI",
    "NR_CGI",
    "TAI",
    "PLMN",
}
SUPPORTED_LAYERS = {"RRC", "NAS", "NAS_5GS", "NGAP", "S1AP", "X2AP"}
SUPPORTED_DIRECTIONS = {
    "UE_TO_NETWORK",
    "NETWORK_TO_UE",
    "UE_TO_GNB",
    "GNB_TO_UE",
    "UE_TO_AMF",
    "AMF_TO_UE",
    "GNB_TO_AMF",
    "AMF_TO_GNB",
    "UE_TO_ENB",
    "ENB_TO_UE",
    "ENB_TO_MME",
    "MME_TO_ENB",
    "SOURCE_GNB_TO_AMF",
    "AMF_TO_TARGET_GNB",
    "SOURCE_ENB_TO_MME",
    "MME_TO_TARGET_ENB",
    "GNB_TO_GNB",
    "ENB_TO_ENB",
    "UNKNOWN",
}


@dataclass(frozen=True)
class AdapterResult:
    events: list[LogEvent]
    warnings: list[ParseWarning]


class InputAdapter(ABC):
    """Adapter that normalizes already-decoded trace records."""

    @abstractmethod
    def parse_file(self, path: Path, *, strict: bool = False) -> AdapterResult:
        """Parse one file into canonical decoded events."""


def parse_records(
    records: Iterable[tuple[int, str, dict[str, str]]],
    *,
    source_file: Path | None,
    strict: bool = False,
) -> AdapterResult:
    events: list[LogEvent] = []
    warnings: list[ParseWarning] = []
    for line_no, raw, fields in records:
        try:
            events.append(
                event_from_fields(fields, raw=raw, line_no=line_no, source_file=source_file)
            )
        except ParseError as exc:
            warning = ParseWarning(line_no=line_no, message=str(exc), raw_line=raw)
            if strict:
                raise
            warnings.append(warning)
    return AdapterResult(events=events, warnings=warnings)


def event_from_fields(
    fields: dict[str, str],
    *,
    raw: str,
    line_no: int,
    source_file: Path | None,
    raw_fields: dict[str, Any] | None = None,
    packet_number: int | None = None,
    frame_number: int | None = None,
    confidence_notes: list[str] | None = None,
) -> LogEvent:
    normalized = {normalize_key(key): value.strip() for key, value in fields.items()}
    timestamp_text = normalized.pop("TIMESTAMP", None) or normalized.pop("TIME", None)
    if timestamp_text is None:
        raise ParseError("Missing required field: timestamp")

    missing = sorted(REQUIRED_FIELDS - set(normalized))
    if missing:
        raise ParseError(f"Missing required field(s): {', '.join(missing)}")
    empty = sorted(field for field in REQUIRED_FIELDS if not normalized[field].strip())
    if empty:
        raise ParseError(f"Required field(s) cannot be empty: {', '.join(empty)}")

    layer = normalized["LAYER"].upper()
    direction = normalized["DIR"].upper()
    if layer not in SUPPORTED_LAYERS:
        raise ParseError(
            f"Unsupported protocol layer {normalized['LAYER']!r}; expected one of "
            f"{', '.join(sorted(SUPPORTED_LAYERS))}"
        )
    if direction not in SUPPORTED_DIRECTIONS:
        raise ParseError(
            f"Unsupported direction {normalized['DIR']!r}; expected one of the documented directions"
        )
    try:
        timestamp = parse_timestamp(timestamp_text)
    except ValueError as exc:
        raise ParseError(f"Invalid timestamp {timestamp_text!r}: {exc}") from exc

    ue_id = normalized.get("UE") or first_present(
        normalized,
        "SUPI",
        "IMSI",
        "GUTI",
        "FIVE_G_TMSI",
        "RAN_UE_NGAP_ID",
        "RNTI",
    )
    if not ue_id:
        ue_id = "UNKNOWN_UE"

    extra = {
        key: value
        for key, value in normalized.items()
        if key not in REQUIRED_FIELDS and key not in OPTIONAL_FIELDS
    }
    return LogEvent(
        timestamp=timestamp,
        source_file=str(source_file) if source_file else None,
        packet_number=packet_number,
        frame_number=frame_number,
        ue_id=ue_id,
        supi=normalized.get("SUPI"),
        imsi=normalized.get("IMSI") or (ue_id if ue_id.startswith("IMSI") else None),
        guti=normalized.get("GUTI"),
        five_g_tmsi=normalized.get("FIVE_G_TMSI"),
        ran_ue_ngap_id=normalized.get("RAN_UE_NGAP_ID"),
        amf_ue_ngap_id=normalized.get("AMF_UE_NGAP_ID"),
        rnti=normalized.get("RNTI"),
        layer=layer,
        interface=normalized.get("INTERFACE", infer_interface(layer)),
        direction=direction,
        message=normalized["MSG"],
        procedure=normalized.get("PROCEDURE") or infer_procedure(normalized["MSG"]),
        cause=normalized.get("CAUSE"),
        dnn=normalized.get("DNN"),
        s_nssai=normalized.get("S_NSSAI"),
        qfi=normalized.get("QFI"),
        cell_id=normalized.get("CELL"),
        nr_cgi=normalized.get("NR_CGI"),
        tai=normalized.get("TAI"),
        plmn=normalized.get("PLMN"),
        node_id=normalized.get("NODE") or normalized.get("GNB") or normalized.get("ENB"),
        session_id=normalized.get("SESSION") or normalized.get("PDU"),
        raw=raw,
        raw_summary=normalized.get("RAW", raw[:240]),
        raw_fields=raw_fields or {},
        line_no=line_no,
        confidence_notes=confidence_notes or [],
        extra=extra,
    )


def fields_from_pipe_line(line: str) -> dict[str, str]:
    parts = [part.strip() for part in line.split("|")]
    if len(parts) < 2:
        msg = "Line must contain an ISO timestamp followed by pipe-delimited key=value fields"
        raise ParseError(msg)
    fields = {"TIMESTAMP": parts[0]}
    for part in parts[1:]:
        if "=" not in part:
            msg = f"Malformed field {part!r}; expected KEY=VALUE"
            raise ParseError(msg)
        key, value = part.split("=", 1)
        fields[key] = value
    return fields


def detect_input_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return "jsonl"
    if suffix == ".json":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return "simplified"
        if (
            isinstance(payload, list)
            and payload
            and isinstance(payload[0], dict)
            and ("_source" in payload[0] or "_index" in payload[0])
        ):
            return "tshark-json"
        return "jsonl"
    return "simplified"


def infer_interface(layer: str) -> str:
    if layer in {"RRC"}:
        return "Uu"
    if layer in {"NAS", "NAS_5GS"}:
        return "N1"
    if layer == "NGAP":
        return "N2"
    return "unknown"


def infer_procedure(message: str) -> str | None:
    lower = message.lower()
    if "registration" in lower or "authentication" in lower or "securitymode" in lower:
        return "5g_registration"
    if "pdusession" in lower or "pdusessionresource" in lower:
        return "pdu_session_establishment"
    if "handover" in lower:
        return "handover"
    if "uecontextrelease" in lower or "rrcrelease" in lower:
        return "ue_context_release"
    if "rrcsetup" in lower:
        return "rrc_setup"
    return None


def first_present(fields: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = fields.get(key)
        if value:
            return value
    return None
