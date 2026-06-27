"""Adapter for pipe-delimited simplified decoded logs."""

from __future__ import annotations

from pathlib import Path

from telecom_log_analyzer.adapters.base import (
    AdapterResult,
    InputAdapter,
    fields_from_pipe_line,
    parse_records,
)
from telecom_log_analyzer.models import ParseError, ParseWarning


class SimplifiedTextAdapter(InputAdapter):
    """Parse the original human-readable KEY=VALUE log format."""

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
                records.append((line_no, raw, fields_from_pipe_line(raw)))
            except ParseError as exc:
                if strict:
                    raise
                warnings.append(ParseWarning(line_no=line_no, message=str(exc), raw_line=raw_line))
        parsed = parse_records(records, source_file=source_file, strict=strict)
        combined = sorted([*warnings, *parsed.warnings], key=lambda warning: warning.line_no)
        return AdapterResult(events=parsed.events, warnings=combined)
