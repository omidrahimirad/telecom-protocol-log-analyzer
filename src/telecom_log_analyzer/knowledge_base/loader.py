"""Load and query telecom cause-code knowledge."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from typing import Any

import yaml

from telecom_log_analyzer.models import ProbableDomain, Severity


@dataclass(frozen=True)
class CauseCodeEntry:
    protocol: str
    normalized_cause: str
    aliases: list[str]
    domain: ProbableDomain
    severity: Severity
    explanation: str
    recommended_checks: list[str]
    confidence_hints: str


class CauseCodeCatalog:
    def __init__(self, entries: list[CauseCodeEntry]) -> None:
        self.entries = entries

    def lookup(
        self, protocol: str, cause: str | None, fallback_text: str = ""
    ) -> CauseCodeEntry | None:
        haystack = f"{cause or ''} {fallback_text}".lower()
        protocol_upper = protocol.upper()
        for entry in self.entries:
            protocol_matches = entry.protocol.upper() in {
                protocol_upper,
                protocol_upper.replace("NAS", "NAS_5GS"),
            }
            if not protocol_matches and entry.protocol != "ANY":
                continue
            aliases = [entry.normalized_cause, *entry.aliases]
            if any(alias.lower() in haystack for alias in aliases):
                return entry
        return None

    def to_dict(self) -> list[dict[str, Any]]:
        return [
            {
                "protocol": entry.protocol,
                "normalized_cause": entry.normalized_cause,
                "aliases": entry.aliases,
                "domain": entry.domain.value,
                "severity": entry.severity.value,
                "explanation": entry.explanation,
                "recommended_checks": entry.recommended_checks,
                "confidence_hints": entry.confidence_hints,
            }
            for entry in self.entries
        ]


def load_cause_catalog() -> CauseCodeCatalog:
    with (
        resources.files("telecom_log_analyzer.knowledge_base")
        .joinpath("cause_codes.yaml")
        .open("r", encoding="utf-8") as handle
    ):
        payload = yaml.safe_load(handle) or {}
    entries = []
    for item in payload.get("causes", []):
        entries.append(
            CauseCodeEntry(
                protocol=str(item["protocol"]),
                normalized_cause=str(item["normalized_cause"]),
                aliases=[str(alias) for alias in item.get("aliases", [])],
                domain=ProbableDomain(str(item.get("domain", "UNKNOWN"))),
                severity=Severity(str(item.get("severity", "MEDIUM"))),
                explanation=str(item.get("explanation", "")),
                recommended_checks=[str(check) for check in item.get("recommended_checks", [])],
                confidence_hints=str(item.get("confidence_hints", "")),
            )
        )
    return CauseCodeCatalog(entries)
