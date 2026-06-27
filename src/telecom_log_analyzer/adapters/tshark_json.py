"""Best-effort adapter for JSON produced by ``tshark -T json``."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from telecom_log_analyzer.adapters.base import (
    AdapterResult,
    InputAdapter,
    event_from_fields,
    infer_procedure,
)
from telecom_log_analyzer.models import LogEvent, ParseError, ParseWarning


class TsharkJsonAdapter(InputAdapter):
    """Normalize selected decoded Wireshark/TShark fields without raw PCAP decoding."""

    def parse_file(self, path: Path, *, strict: bool = False) -> AdapterResult:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid TShark JSON: {exc.msg}") from exc
        if not isinstance(payload, list):
            raise ParseError("TShark JSON root must be a list of packet objects")

        events: list[LogEvent] = []
        warnings: list[ParseWarning] = []
        for packet_index, packet in enumerate(payload, start=1):
            if not isinstance(packet, dict):
                warnings.append(ParseWarning(packet_index, "Skipping non-object packet"))
                continue
            layers = packet.get("_source", {}).get("layers", {})
            if not isinstance(layers, dict):
                warnings.append(ParseWarning(packet_index, "Packet has no _source.layers object"))
                continue
            flat = flatten(layers)
            try:
                event = self._event_from_packet(
                    flat=flat,
                    layers=layers,
                    packet_number=packet_index,
                    source_file=path,
                )
            except ParseError as exc:
                warning = ParseWarning(packet_index, str(exc), raw_line=json.dumps(packet)[:500])
                if strict:
                    raise
                warnings.append(warning)
                continue
            events.append(event)
        return AdapterResult(events=events, warnings=warnings)

    def _event_from_packet(
        self,
        *,
        flat: dict[str, str],
        layers: dict[str, Any],
        packet_number: int,
        source_file: Path,
    ) -> LogEvent:
        layer = detect_protocol(layers)
        if layer is None:
            raise ParseError(
                "Unsupported TShark packet: no ngap, nas-5gs, nr-rrc, or lte-rrc layer"
            )
        timestamp = first_value(
            flat,
            "frame.frame_time_epoch",
            "frame.time_epoch",
            "frame.frame_time",
            "frame.time",
        )
        if timestamp and re.fullmatch(r"\d+(\.\d+)?", timestamp):
            timestamp = epoch_to_iso(timestamp)
        if not timestamp:
            raise ParseError("Packet missing frame timestamp")
        frame_number_text = first_value(flat, "frame.frame_number", "frame.number")
        frame_number = (
            int(frame_number_text) if frame_number_text and frame_number_text.isdigit() else None
        )
        message = detect_message(flat, layer)
        if not message:
            raise ParseError(f"Could not infer {layer} message name from decoded fields")
        fields = {
            "TIMESTAMP": timestamp,
            "UE": first_value(
                flat,
                "nas-5gs.supi",
                "nas_5gs.supi",
                "nas-5gs.imsi",
                "ngap.ran_ue_ngap_id",
                "ngap.amf_ue_ngap_id",
                "nr-rrc.c-rnti",
                "lte-rrc.c-rnti",
            )
            or "UNKNOWN_UE",
            "LAYER": layer,
            "DIR": infer_direction(layer, flat),
            "MSG": message,
            "CAUSE": first_value(
                flat,
                "nas-5gs.5gsm.cause",
                "nas-5gs.5gmm.cause",
                "ngap.Cause",
                "ngap.cause",
                "nr-rrc.failureCause",
            ),
            "PDU": first_value(
                flat, "nas-5gs.pdu_session_id", "nas-5gs.5gsm.pdu_session_id", "ngap.pDUSessionID"
            ),
            "DNN": first_value(flat, "nas-5gs.dnn", "ngap.dnn"),
            "S_NSSAI": first_value(flat, "nas-5gs.s_nssai", "ngap.s_NSSAI", "ngap.sst"),
            "QFI": first_value(flat, "ngap.qfi", "nas-5gs.qfi"),
            "CELL": first_value(flat, "ngap.nR-CGI", "ngap.nr_cgi", "nr-rrc.cellIdentity"),
            "NR_CGI": first_value(flat, "ngap.nR-CGI", "ngap.nr_cgi"),
            "TAI": first_value(flat, "ngap.tAI", "ngap.tai"),
            "PLMN": first_value(flat, "ngap.pLMNIdentity", "nas-5gs.plmn"),
            "SUPI": first_value(flat, "nas-5gs.supi", "nas_5gs.supi"),
            "IMSI": first_value(flat, "nas-5gs.imsi", "e212.imsi"),
            "GUTI": first_value(flat, "nas-5gs.5g-guti", "nas-5gs.guti"),
            "FIVE_G_TMSI": first_value(flat, "nas-5gs.5g-s-tmsi", "nas-5gs.tmsi"),
            "RAN_UE_NGAP_ID": first_value(flat, "ngap.RAN_UE_NGAP_ID", "ngap.ran_ue_ngap_id"),
            "AMF_UE_NGAP_ID": first_value(flat, "ngap.AMF_UE_NGAP_ID", "ngap.amf_ue_ngap_id"),
            "RNTI": first_value(flat, "nr-rrc.c-rnti", "lte-rrc.c-rnti"),
            "INTERFACE": {"NGAP": "N2", "NAS_5GS": "N1", "RRC": "Uu"}.get(layer, "unknown"),
            "PROCEDURE": infer_procedure(message) or "",
        }
        raw_summary = first_value(flat, "_ws.col.Info", "frame.protocols") or message
        return event_from_fields(
            {key: value for key, value in fields.items() if value is not None},
            raw=raw_summary,
            line_no=packet_number,
            source_file=source_file,
            raw_fields=flat,
            packet_number=packet_number,
            frame_number=frame_number,
            confidence_notes=["best-effort TShark JSON field extraction"],
        )


def flatten(value: Any, prefix: str = "") -> dict[str, str]:
    flattened: dict[str, str] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(flatten(child, child_prefix))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            flattened.update(flatten(child, f"{prefix}.{index}"))
    elif value is not None:
        flattened[prefix] = str(value)
    return flattened


def first_value(flat: dict[str, str], *aliases: str) -> str | None:
    normalized = {key.lower().replace("_", "-"): value for key, value in flat.items()}
    for alias in aliases:
        direct = flat.get(alias)
        if direct:
            return direct
        normalized_alias = alias.lower().replace("_", "-")
        if normalized_alias in normalized:
            return normalized[normalized_alias]
        for key, value in normalized.items():
            if key.endswith(normalized_alias) and value:
                return value
    return None


def detect_protocol(layers: dict[str, Any]) -> str | None:
    lowered = {key.lower() for key in layers}
    if "ngap" in lowered:
        return "NGAP"
    if "nas-5gs" in lowered or "nas_5gs" in lowered:
        return "NAS_5GS"
    if "nr-rrc" in lowered or "lte-rrc" in lowered:
        return "RRC"
    return None


def detect_message(flat: dict[str, str], layer: str) -> str | None:
    explicit = first_value(
        flat,
        "telecom.message",
        "ngap.message_name",
        "nas-5gs.message_name",
        "nr-rrc.message_name",
        "lte-rrc.message_name",
    )
    if explicit:
        return normalize_message_name(explicit)
    info = first_value(flat, "_ws.col.Info") or ""
    guessed = guess_message_from_text(info)
    if guessed:
        return guessed
    if layer == "NGAP":
        return guess_message_from_text(
            " ".join(value for key, value in flat.items() if "ngap" in key.lower())
        )
    if layer == "NAS_5GS":
        return guess_message_from_text(
            " ".join(value for key, value in flat.items() if "nas" in key.lower())
        )
    return guess_message_from_text(
        " ".join(value for key, value in flat.items() if "rrc" in key.lower())
    )


def guess_message_from_text(text: str) -> str | None:
    compact = re.sub(r"[^a-z0-9]+", "", text.lower())
    candidates = {
        "rrcsetuprequest": "RRCSetupRequest",
        "rrcsetupcomplete": "RRCSetupComplete",
        "rrcsetup": "RRCSetup",
        "rrcreconfigurationfailure": "RRCReconfigurationFailure",
        "rrcreconfigurationcomplete": "RRCReconfigurationComplete",
        "rrcreconfiguration": "RRCReconfiguration",
        "registrationrequest": "RegistrationRequest",
        "authenticationrequest": "AuthenticationRequest",
        "authenticationresponse": "AuthenticationResponse",
        "authenticationfailure": "AuthenticationFailure",
        "securitymodecommand": "SecurityModeCommand",
        "securitymodecomplete": "SecurityModeComplete",
        "securitymodereject": "SecurityModeReject",
        "registrationaccept": "RegistrationAccept",
        "registrationcomplete": "RegistrationComplete",
        "registrationreject": "RegistrationReject",
        "initialuemessage": "InitialUEMessage",
        "initialcontextsetuprequest": "InitialContextSetupRequest",
        "initialcontextsetupresponse": "InitialContextSetupResponse",
        "pdusessionestablishmentrequest": "PduSessionEstablishmentRequest",
        "pdusessionestablishmentaccept": "PduSessionEstablishmentAccept",
        "pdusessionestablishmentreject": "PduSessionEstablishmentReject",
        "pdusessionresourcesetuprequest": "PduSessionResourceSetupRequest",
        "pdusessionresourcesetupresponse": "PduSessionResourceSetupResponse",
        "pdusessionresourcesetupfailure": "PduSessionResourceSetupFailure",
        "handoverrequired": "HandoverRequired",
        "handoverrequestacknowledge": "HandoverRequestAcknowledge",
        "handoverrequest": "HandoverRequest",
        "handovercommand": "HandoverCommand",
        "handovernotify": "HandoverNotify",
        "handovercomplete": "HandoverComplete",
        "handoverfailure": "HandoverFailure",
        "uecontextreleasecommand": "UEContextReleaseCommand",
        "uecontextreleasecomplete": "UEContextReleaseComplete",
    }
    for needle, message in candidates.items():
        if needle in compact:
            return message
    return None


def normalize_message_name(value: str) -> str:
    guessed = guess_message_from_text(value)
    return guessed or value.replace(" ", "")


def infer_direction(layer: str, flat: dict[str, str]) -> str:
    source = (first_value(flat, "_ws.col.Source") or "").lower()
    destination = (first_value(flat, "_ws.col.Destination") or "").lower()
    info = (first_value(flat, "_ws.col.Info") or "").lower()
    if layer == "NGAP":
        if "uplink" in info or "gnb" in source:
            return "GNB_TO_AMF"
        if "downlink" in info or "amf" in source:
            return "AMF_TO_GNB"
    if layer == "NAS_5GS":
        if "uplink" in info or "ue" in source:
            return "UE_TO_AMF"
        if "downlink" in info or "amf" in source:
            return "AMF_TO_UE"
    if layer == "RRC":
        if "ue" in source or "uplink" in info:
            return "UE_TO_GNB"
        if "gnb" in source or "downlink" in info:
            return "GNB_TO_UE"
    if destination:
        return "UNKNOWN"
    return "UNKNOWN"


def epoch_to_iso(value: str) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
