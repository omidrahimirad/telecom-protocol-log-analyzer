"""Small utility helpers."""

from __future__ import annotations

from datetime import datetime, timezone


def parse_timestamp(value: str) -> datetime:
    """Parse ISO-8601 timestamps including the common trailing Z form."""

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def normalize_key(key: str) -> str:
    return key.strip().upper().replace("-", "_")


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.1f} s"
