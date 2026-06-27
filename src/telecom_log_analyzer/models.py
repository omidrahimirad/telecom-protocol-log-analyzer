"""Structured models used across parsing, analysis, and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class AnalyzerError(Exception):
    """Base exception for analyzer failures."""


class ParseError(AnalyzerError):
    """Raised when an input log cannot be parsed in strict mode."""


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class ParseWarning:
    """Non-fatal parse or reconstruction warning."""

    line_no: int
    message: str
    raw_line: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"line_no": self.line_no, "message": self.message, "raw_line": self.raw_line}


@dataclass(frozen=True)
class LogEvent:
    """One simplified protocol event extracted from a text or JSONL log."""

    timestamp: datetime
    ue_id: str
    layer: str
    direction: str
    message: str
    raw: str
    line_no: int
    cause: str | None = None
    cell_id: str | None = None
    node_id: str | None = None
    session_id: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def timestamp_text(self) -> str:
        return self.timestamp.isoformat().replace("+00:00", "Z")

    @property
    def session_key(self) -> str:
        if self.session_id:
            return f"{self.ue_id}/PDU-{self.session_id}"
        return self.ue_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp_text,
            "ue_id": self.ue_id,
            "layer": self.layer,
            "direction": self.direction,
            "message": self.message,
            "cause": self.cause,
            "cell_id": self.cell_id,
            "node_id": self.node_id,
            "session_id": self.session_id,
            "line_no": self.line_no,
            "raw": self.raw,
            "extra": dict(self.extra),
        }


@dataclass(frozen=True)
class ParseResult:
    events: list[LogEvent]
    warnings: list[ParseWarning]


@dataclass(frozen=True)
class Session:
    """Chronological event stream for one UE or UE/PDU session view."""

    key: str
    ue_id: str
    events: list[LogEvent]
    session_id: str | None = None

    @property
    def first_seen(self) -> datetime | None:
        return self.events[0].timestamp if self.events else None

    @property
    def last_seen(self) -> datetime | None:
        return self.events[-1].timestamp if self.events else None

    def messages(self) -> list[str]:
        return [event.message for event in self.events]

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "ue_id": self.ue_id,
            "session_id": self.session_id,
            "first_seen": self.first_seen.isoformat().replace("+00:00", "Z")
            if self.first_seen
            else None,
            "last_seen": self.last_seen.isoformat().replace("+00:00", "Z")
            if self.last_seen
            else None,
            "events": [event.to_dict() for event in self.events],
        }


@dataclass(frozen=True)
class Issue:
    """Detected protocol troubleshooting issue."""

    issue_type: str
    affected_session: str
    severity: Severity
    failed_layer: str
    first_suspicious_message: str
    missing_or_failed_expected_message: str
    probable_cause: str
    suggested_actions: list[str]
    evidence: list[LogEvent]

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_type": self.issue_type,
            "affected_session": self.affected_session,
            "severity": self.severity.value,
            "failed_layer": self.failed_layer,
            "first_suspicious_message": self.first_suspicious_message,
            "missing_or_failed_expected_message": self.missing_or_failed_expected_message,
            "probable_cause": self.probable_cause,
            "suggested_actions": list(self.suggested_actions),
            "evidence": [event.to_dict() for event in self.evidence],
        }


@dataclass(frozen=True)
class AnalysisReport:
    """Full analyzer output for a file or directory run."""

    source: Path
    sessions: list[Session]
    issues: list[Issue]
    warnings: list[ParseWarning]
    generated_at: datetime
    flow_checks: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity is Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity is Severity.HIGH)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": str(self.source),
            "generated_at": self.generated_at.isoformat().replace("+00:00", "Z"),
            "summary": {
                "sessions": len(self.sessions),
                "events": sum(len(session.events) for session in self.sessions),
                "issues": len(self.issues),
                "critical": self.critical_count,
                "high": self.high_count,
                "warnings": len(self.warnings),
            },
            "warnings": [warning.to_dict() for warning in self.warnings],
            "flow_checks": self.flow_checks,
            "issues": [issue.to_dict() for issue in self.issues],
            "sessions": [session.to_dict() for session in self.sessions],
        }
