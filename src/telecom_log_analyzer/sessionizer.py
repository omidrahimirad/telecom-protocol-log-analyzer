"""UE/session reconstruction from parsed protocol events."""

from __future__ import annotations

from collections import defaultdict

from telecom_log_analyzer.models import LogEvent, ParseWarning, Session


class Sessionizer:
    """Build deterministic chronological sessions for multiple UEs."""

    def build_sessions(self, events: list[LogEvent]) -> tuple[list[Session], list[ParseWarning]]:
        warnings: list[ParseWarning] = []
        per_ue: dict[str, list[LogEvent]] = defaultdict(list)
        last_seen: dict[str, LogEvent] = {}

        for event in events:
            key = event.correlation_key
            previous = last_seen.get(key)
            if previous and event.timestamp < previous.timestamp:
                warnings.append(
                    ParseWarning(
                        line_no=event.line_no,
                        message=f"Out-of-order timestamp for UE trace {key}; timeline was sorted before analysis",
                        raw_line=event.raw,
                    )
                )
            last_seen[key] = event
            per_ue[key].append(event)

        sessions = [
            Session(
                key=trace_key,
                ue_id=ue_events[0].ue_id if ue_events[0].ue_id != "UNKNOWN_UE" else trace_key,
                events=sorted(ue_events, key=lambda item: (item.timestamp, item.line_no)),
            )
            for trace_key, ue_events in sorted(per_ue.items())
        ]
        return sessions, warnings
