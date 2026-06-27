"""Adapter for simplified JSONL decoded event logs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from telecom_log_analyzer.adapters.base import AdapterResult, InputAdapter, parse_records
from telecom_log_analyzer.models import ParseError, ParseWarning


class JsonlAdapter(InputAdapter):
    """Parse one decoded event per JSON line."""

    aliases: ClassVar[dict[str, str]] = {
        "timestamp": "TIMESTAMP",
        "time": "TIMESTAMP",
        "ts": "TIMESTAMP",
        "ue": "UE",
        "ue_id": "UE",
        "imsi": "IMSI",
        "supi": "SUPI",
        "layer": "LAYER",
        "protocol": "LAYER",
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

    def parse_file(self, path: Path, *, strict: bool = False) -> AdapterResult:
        return self.parse_lines(
            path.read_text(encoding="utf-8").splitlines(), source_file=path, strict=strict
        )

    def parse_lines(
        self, lines: list[str], *, source_file: Path | None = None, strict: bool = False
    ) -> AdapterResult:
        records: list[tuple[int, str, dict[str, str]]] = []
        warnings: list[ParseWarning] = []
        for line_no, raw_line in enumerate(lines, start=1):
            raw = raw_line.strip()
            if not raw or raw.startswith("#"):
                continue
            try:
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise ParseError("JSONL record must be an object")
                records.append((line_no, raw, self._fields(payload)))
            except (json.JSONDecodeError, ParseError) as exc:
                message = (
                    f"Invalid JSON: {exc.msg}"
                    if isinstance(exc, json.JSONDecodeError)
                    else str(exc)
                )
                if strict:
                    raise ParseError(message) from exc
                warnings.append(ParseWarning(line_no=line_no, message=message, raw_line=raw_line))
        parsed = parse_records(records, source_file=source_file, strict=strict)
        return AdapterResult(events=parsed.events, warnings=[*warnings, *parsed.warnings])

    def _fields(self, payload: dict[str, Any]) -> dict[str, str]:
        fields: dict[str, str] = {}
        for key, value in payload.items():
            if value is None:
                continue
            fields[self.aliases.get(str(key).lower(), str(key).upper())] = str(value)
        return fields
