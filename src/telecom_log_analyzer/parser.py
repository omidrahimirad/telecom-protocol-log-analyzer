"""Parsers for simplified pipe-delimited and JSONL telecom logs."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from telecom_log_analyzer.models import LogEvent, ParseError, ParseResult, ParseWarning
from telecom_log_analyzer.utils import normalize_key, parse_timestamp

REQUIRED_FIELDS = {"UE", "LAYER", "DIR", "MSG"}
OPTIONAL_FIELDS = {"CAUSE", "CELL", "GNB", "ENB", "NODE", "SESSION", "PDU", "RAW"}
SUPPORTED_LAYERS = {"RRC", "NAS", "NGAP", "S1AP", "X2AP"}
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
}


class TelecomLogParser:
    """Parse simplified text or JSONL logs into typed events."""

    def parse_file(self, path: Path, *, strict: bool = False) -> ParseResult:
        return self.parse_lines(path.read_text(encoding="utf-8").splitlines(), strict=strict)

    def parse_lines(self, lines: Iterable[str], *, strict: bool = False) -> ParseResult:
        events: list[LogEvent] = []
        warnings: list[ParseWarning] = []
        for line_no, raw_line in enumerate(lines, start=1):
            raw = raw_line.strip()
            if not raw or raw.startswith("#"):
                continue
            try:
                event = self.parse_line(raw, line_no=line_no)
            except ParseError as exc:
                warning = ParseWarning(line_no=line_no, message=str(exc), raw_line=raw_line)
                if strict:
                    raise
                warnings.append(warning)
                continue
            events.append(event)
        return ParseResult(events=events, warnings=warnings)

    def parse_line(self, line: str, *, line_no: int = 1) -> LogEvent:
        if line.lstrip().startswith("{"):
            return self._parse_json_line(line, line_no=line_no)
        return self._parse_text_line(line, line_no=line_no)

    def _parse_text_line(self, line: str, *, line_no: int) -> LogEvent:
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 2:
            msg = "Line must contain an ISO timestamp followed by pipe-delimited key=value fields"
            raise ParseError(msg)

        fields: dict[str, str] = {}
        for part in parts[1:]:
            if "=" not in part:
                msg = f"Malformed field {part!r}; expected KEY=VALUE"
                raise ParseError(msg)
            key, value = part.split("=", 1)
            fields[normalize_key(key)] = value.strip()

        missing = sorted(REQUIRED_FIELDS - set(fields))
        if missing:
            raise ParseError(f"Missing required field(s): {', '.join(missing)}")
        empty = sorted(field for field in REQUIRED_FIELDS if not fields[field].strip())
        if empty:
            raise ParseError(f"Required field(s) cannot be empty: {', '.join(empty)}")

        return self._event_from_fields(
            timestamp_text=parts[0], fields=fields, raw=line, line_no=line_no
        )

    def _parse_json_line(self, line: str, *, line_no: int) -> LogEvent:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise ParseError("JSONL record must be an object")

        timestamp_text = self._first_present(payload, "timestamp", "time", "ts")
        if timestamp_text is None:
            raise ParseError("Missing required field: timestamp")

        fields: dict[str, str] = {}
        aliases = {
            "ue": "UE",
            "ue_id": "UE",
            "imsi": "UE",
            "supi": "UE",
            "layer": "LAYER",
            "direction": "DIR",
            "dir": "DIR",
            "message": "MSG",
            "msg": "MSG",
            "cause": "CAUSE",
            "cell": "CELL",
            "cell_id": "CELL",
            "gnb": "GNB",
            "node": "NODE",
            "session": "SESSION",
            "session_id": "SESSION",
            "pdu_session_id": "PDU",
        }
        for key, value in payload.items():
            normalized = aliases.get(str(key).lower(), normalize_key(str(key)))
            if value is not None:
                fields[normalized] = str(value)

        missing = sorted(REQUIRED_FIELDS - set(fields))
        if missing:
            raise ParseError(f"Missing required field(s): {', '.join(missing)}")
        empty = sorted(field for field in REQUIRED_FIELDS if not fields[field].strip())
        if empty:
            raise ParseError(f"Required field(s) cannot be empty: {', '.join(empty)}")
        return self._event_from_fields(
            timestamp_text=str(timestamp_text),
            fields=fields,
            raw=line,
            line_no=line_no,
        )

    def _event_from_fields(
        self, *, timestamp_text: str, fields: dict[str, str], raw: str, line_no: int
    ) -> LogEvent:
        extra = {
            key: value
            for key, value in fields.items()
            if key not in REQUIRED_FIELDS and key not in OPTIONAL_FIELDS
        }
        node_id = fields.get("NODE") or fields.get("GNB") or fields.get("ENB")
        session_id = fields.get("SESSION") or fields.get("PDU")
        layer = fields["LAYER"].upper()
        direction = fields["DIR"].upper()
        if layer not in SUPPORTED_LAYERS:
            raise ParseError(
                f"Unsupported protocol layer {fields['LAYER']!r}; expected one of "
                f"{', '.join(sorted(SUPPORTED_LAYERS))}"
            )
        if direction not in SUPPORTED_DIRECTIONS:
            raise ParseError(
                f"Unsupported direction {fields['DIR']!r}; expected one of the documented directions"
            )
        try:
            timestamp = parse_timestamp(timestamp_text)
        except ValueError as exc:
            raise ParseError(f"Invalid timestamp {timestamp_text!r}: {exc}") from exc
        return LogEvent(
            timestamp=timestamp,
            ue_id=fields["UE"],
            layer=layer,
            direction=direction,
            message=fields["MSG"],
            cause=fields.get("CAUSE"),
            cell_id=fields.get("CELL"),
            node_id=node_id,
            session_id=session_id,
            raw=raw,
            line_no=line_no,
            extra=extra,
        )

    @staticmethod
    def _first_present(payload: dict[str, Any], *keys: str) -> Any | None:
        for key in keys:
            if key in payload:
                return payload[key]
        return None
