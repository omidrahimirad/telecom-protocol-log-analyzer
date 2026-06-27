"""Backward-compatible parser facade over decoded trace adapters."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from telecom_log_analyzer.adapters.base import AdapterResult
from telecom_log_analyzer.adapters.jsonl import JsonlAdapter
from telecom_log_analyzer.adapters.simplified_text import SimplifiedTextAdapter
from telecom_log_analyzer.models import LogEvent, ParseError, ParseResult, ParseWarning


class TelecomLogParser:
    """Parse legacy simplified text or JSONL logs into normalized events."""

    def parse_file(self, path: Path, *, strict: bool = False) -> ParseResult:
        if path.suffix.lower() == ".jsonl":
            result = JsonlAdapter().parse_file(path, strict=strict)
        else:
            result = SimplifiedTextAdapter().parse_file(path, strict=strict)
        return ParseResult(events=result.events, warnings=result.warnings)

    def parse_lines(self, lines: Iterable[str], *, strict: bool = False) -> ParseResult:
        normalized_lines = list(lines)
        first = next((line.strip() for line in normalized_lines if line.strip()), "")
        adapter: SimplifiedTextAdapter | JsonlAdapter = (
            JsonlAdapter() if first.startswith("{") else SimplifiedTextAdapter()
        )
        result = adapter.parse_lines(normalized_lines, strict=strict)
        return ParseResult(events=result.events, warnings=result.warnings)

    def parse_line(self, line: str, *, line_no: int = 1) -> LogEvent:
        adapter_result: AdapterResult
        if line.lstrip().startswith("{"):
            adapter_result = JsonlAdapter().parse_lines([line], strict=True)
        else:
            adapter_result = SimplifiedTextAdapter().parse_lines([line], strict=True)
        if not adapter_result.events:
            raise ParseError(f"Unable to parse line {line_no}")
        return adapter_result.events[0]


__all__ = ["LogEvent", "ParseError", "ParseResult", "ParseWarning", "TelecomLogParser"]
