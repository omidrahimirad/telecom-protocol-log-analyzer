"""Multi-identifier correlation summaries for normalized events."""

from __future__ import annotations

from collections import defaultdict

from telecom_log_analyzer.models import CorrelationSummary, LogEvent


class Correlator:
    """Build UE, procedure, PDU session, and mobility trace indexes."""

    def correlate(self, events: list[LogEvent]) -> CorrelationSummary:
        ue_traces: dict[str, list[int]] = defaultdict(list)
        procedure_traces: dict[str, list[int]] = defaultdict(list)
        pdu_session_traces: dict[str, list[int]] = defaultdict(list)
        mobility_traces: dict[str, list[int]] = defaultdict(list)

        for event in events:
            line = event.line_no
            ue_traces[event.correlation_key].append(line)
            if event.procedure:
                procedure_traces[f"{event.correlation_key}:{event.procedure}"].append(line)
            if event.session_id:
                pdu_session_traces[f"{event.correlation_key}/PDU-{event.session_id}"].append(line)
            mobility_key = event.nr_cgi or event.cell_id
            if mobility_key:
                mobility_traces[f"{event.correlation_key}@{mobility_key}"].append(line)

        return CorrelationSummary(
            ue_traces=dict(sorted(ue_traces.items())),
            procedure_traces=dict(sorted(procedure_traces.items())),
            pdu_session_traces=dict(sorted(pdu_session_traces.items())),
            mobility_traces=dict(sorted(mobility_traces.items())),
        )
