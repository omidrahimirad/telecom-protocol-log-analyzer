"""Configurable timer profiles for procedure-aware checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class TimerProfile:
    name: str
    registration_auth_timeout_ms: int = 10000
    security_mode_timeout_ms: int = 10000
    pdu_session_setup_timeout_ms: int = 15000
    handover_completion_timeout_ms: int = 5000

    @property
    def handover_completion_timeout_seconds(self) -> int:
        return max(1, self.handover_completion_timeout_ms // 1000)


def load_timer_profile(profile: str = "field", config_path: Path | None = None) -> TimerProfile:
    payload = _load_yaml(config_path or default_timer_config_path())
    profiles = payload.get("profiles", {}) if isinstance(payload, dict) else {}
    if profile not in profiles:
        available = ", ".join(sorted(profiles)) or "none"
        msg = f"Unknown timer profile {profile!r}; available profiles: {available}"
        raise ValueError(msg)
    data = profiles[profile]
    if not isinstance(data, dict):
        msg = f"Timer profile {profile!r} must be a mapping"
        raise ValueError(msg)
    return TimerProfile(
        name=profile,
        registration_auth_timeout_ms=int(data.get("registration_auth_timeout_ms", 10000)),
        security_mode_timeout_ms=int(data.get("security_mode_timeout_ms", 10000)),
        pdu_session_setup_timeout_ms=int(data.get("pdu_session_setup_timeout_ms", 15000)),
        handover_completion_timeout_ms=int(data.get("handover_completion_timeout_ms", 5000)),
    )


def default_timer_config_path() -> Path:
    root = Path(__file__).resolve().parents[2]
    candidate = root / "config" / "default_timer_profiles.yaml"
    if candidate.exists():
        return candidate
    return Path.cwd() / "config" / "default_timer_profiles.yaml"


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        msg = f"Timer config {path} must contain a mapping"
        raise ValueError(msg)
    return payload
