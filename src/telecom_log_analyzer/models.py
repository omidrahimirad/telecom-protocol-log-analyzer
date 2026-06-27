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


class ProbableDomain(str, Enum):
    UE = "UE"
    RAN = "RAN"
    CORE = "CORE"
    SUBSCRIPTION = "SUBSCRIPTION"
    TRANSPORT = "TRANSPORT"
    RF = "RF"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ParseWarning:
    """Non-fatal parse or reconstruction warning."""

    line_no: int
    message: str
    raw_line: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"line_no": self.line_no, "message": self.message, "raw_line": self.raw_line}


@dataclass(frozen=True)
class NormalizedProtocolEvent:
    """Canonical decoded protocol event used by all ingestion adapters."""

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
    source_file: str | None = None
    packet_number: int | None = None
    frame_number: int | None = None
    supi: str | None = None
    imsi: str | None = None
    guti: str | None = None
    five_g_tmsi: str | None = None
    ran_ue_ngap_id: str | None = None
    amf_ue_ngap_id: str | None = None
    rnti: str | None = None
    interface: str = "unknown"
    procedure: str | None = None
    dnn: str | None = None
    s_nssai: str | None = None
    qfi: str | None = None
    nr_cgi: str | None = None
    tai: str | None = None
    plmn: str | None = None
    raw_fields: dict[str, Any] = field(default_factory=dict)
    raw_summary: str = ""
    confidence_notes: list[str] = field(default_factory=list)
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def timestamp_text(self) -> str:
        return self.timestamp.isoformat().replace("+00:00", "Z")

    @property
    def session_key(self) -> str:
        base = self.ue_id or self.correlation_key
        if self.session_id:
            return f"{base}/PDU-{self.session_id}"
        return base

    @property
    def correlation_key(self) -> str:
        if self.supi:
            return self.supi
        if self.imsi:
            return self.imsi
        if self.ue_id:
            return self.ue_id
        if self.guti:
            return self.guti
        if self.five_g_tmsi:
            return self.five_g_tmsi
        if self.amf_ue_ngap_id and self.ran_ue_ngap_id:
            return f"NGAP:{self.amf_ue_ngap_id}/{self.ran_ue_ngap_id}"
        if self.ran_ue_ngap_id:
            return f"RAN-UE-NGAP-ID:{self.ran_ue_ngap_id}"
        if self.rnti:
            return f"RNTI:{self.rnti}"
        return "UNKNOWN_UE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp_text,
            "source_file": self.source_file,
            "packet_number": self.packet_number,
            "frame_number": self.frame_number,
            "ue_id": self.ue_id,
            "supi": self.supi,
            "imsi": self.imsi,
            "guti": self.guti,
            "five_g_tmsi": self.five_g_tmsi,
            "ran_ue_ngap_id": self.ran_ue_ngap_id,
            "amf_ue_ngap_id": self.amf_ue_ngap_id,
            "rnti": self.rnti,
            "protocol": self.layer,
            "layer": self.layer,
            "interface": self.interface,
            "direction": self.direction,
            "message": self.message,
            "procedure": self.procedure,
            "cause": self.cause,
            "dnn": self.dnn,
            "s_nssai": self.s_nssai,
            "qfi": self.qfi,
            "cell_id": self.cell_id,
            "nr_cgi": self.nr_cgi,
            "tai": self.tai,
            "plmn": self.plmn,
            "node_id": self.node_id,
            "session_id": self.session_id,
            "line_no": self.line_no,
            "raw": self.raw,
            "raw_fields": dict(self.raw_fields),
            "raw_summary": self.raw_summary,
            "confidence_notes": list(self.confidence_notes),
            "extra": dict(self.extra),
        }


LogEvent = NormalizedProtocolEvent


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
    last_successful_step: str = "unknown"
    probable_domain: ProbableDomain = ProbableDomain.UNKNOWN
    recommended_owner: str = "Core Engineer"
    confidence: float = 0.5
    confidence_reason: str = "Deterministic rule matched available decoded events."
    suggested_commands: list[str] = field(default_factory=list)
    false_positive_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_type": self.issue_type,
            "affected_session": self.affected_session,
            "severity": self.severity.value,
            "failed_layer": self.failed_layer,
            "first_suspicious_message": self.first_suspicious_message,
            "missing_or_failed_expected_message": self.missing_or_failed_expected_message,
            "probable_cause": self.probable_cause,
            "last_successful_step": self.last_successful_step,
            "probable_domain": self.probable_domain.value,
            "recommended_owner": self.recommended_owner,
            "confidence": self.confidence,
            "confidence_reason": self.confidence_reason,
            "suggested_actions": list(self.suggested_actions),
            "suggested_commands": list(self.suggested_commands),
            "false_positive_notes": list(self.false_positive_notes),
            "evidence": [event.to_dict() for event in self.evidence],
        }


@dataclass(frozen=True)
class CorrelationSummary:
    ue_traces: dict[str, list[int]]
    procedure_traces: dict[str, list[int]]
    pdu_session_traces: dict[str, list[int]]
    mobility_traces: dict[str, list[int]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ue_traces": self.ue_traces,
            "procedure_traces": self.procedure_traces,
            "pdu_session_traces": self.pdu_session_traces,
            "mobility_traces": self.mobility_traces,
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
    correlation: CorrelationSummary | None = None

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
                "ues": len({session.ue_id for session in self.sessions}),
                "procedures": sum(len(checks) for checks in self.flow_checks.values()),
                "events": sum(len(session.events) for session in self.sessions),
                "issues": len(self.issues),
                "critical": self.critical_count,
                "high": self.high_count,
                "warnings": len(self.warnings),
            },
            "warnings": [warning.to_dict() for warning in self.warnings],
            "flow_checks": self.flow_checks,
            "correlation": self.correlation.to_dict() if self.correlation else None,
            "issues": [issue.to_dict() for issue in self.issues],
            "sessions": [session.to_dict() for session in self.sessions],
        }
