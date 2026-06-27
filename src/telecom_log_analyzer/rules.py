"""Telecom troubleshooting rule engine."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta

from telecom_log_analyzer.models import Issue, LogEvent, Session, Severity
from telecom_log_analyzer.utils import format_duration


class RuleEngine:
    """Evaluate deterministic protocol troubleshooting rules."""

    def __init__(self, *, timeout_seconds: int = 10) -> None:
        self.timeout = timedelta(seconds=timeout_seconds)

    def evaluate(self, sessions: Iterable[Session]) -> list[Issue]:
        issues: list[Issue] = []
        for session in sessions:
            issues.extend(self._registration_rules(session))
            issues.extend(self._pdu_session_rules(session))
            issues.extend(self._rrc_rules(session))
            issues.extend(self._handover_rules(session))
            issues.extend(self._access_attempt_rules(session))
        return sorted(
            self._dedupe(issues),
            key=lambda issue: (
                issue.evidence[0].timestamp if issue.evidence else session_sort_floor(),
                issue.affected_session,
                issue.issue_type,
            ),
        )

    def _registration_rules(self, session: Session) -> list[Issue]:
        events = session.events
        issues: list[Issue] = []
        reg_req = first_event(events, "RegistrationRequest")
        if not reg_req:
            return issues

        auth_req = first_event_after(events, "AuthenticationRequest", reg_req)
        auth_resp = (
            first_event_after(events, "AuthenticationResponse", auth_req) if auth_req else None
        )
        auth_fail = first_event_after(events, "AuthenticationFailure", reg_req)
        sec_cmd = first_event_after(events, "SecurityModeCommand", auth_resp or auth_req or reg_req)
        sec_complete = (
            first_event_after(events, "SecurityModeComplete", sec_cmd) if sec_cmd else None
        )
        sec_reject = first_event_after(events, "SecurityModeReject", reg_req)
        reg_accept = first_event_after(events, "RegistrationAccept", reg_req)
        reg_reject = first_event_after(events, "RegistrationReject", reg_req)

        if auth_fail:
            issues.append(
                make_issue(
                    "5G_REGISTRATION_AUTHENTICATION_FAILURE",
                    session,
                    Severity.HIGH,
                    "NAS",
                    auth_fail,
                    "AuthenticationResponse",
                    (
                        f"UE {session.ue_id} returned AuthenticationFailure after NAS authentication. "
                        "This commonly points to USIM authentication vector mismatch, wrong key material "
                        "in AUSF/UDM/HSS, SQN resynchronization problems, or modem-side USIM access errors."
                    ),
                    [
                        "Check AUSF/UDM authentication vectors, SUPI/SUCI provisioning, and USIM profile.",
                        "Inspect modem traces for AUTS/resynchronization details and rejected RAND/AUTN.",
                        "Verify the UE is using the intended test PLMN and subscriber profile.",
                    ],
                    [reg_req, auth_req, auth_fail] if auth_req else [reg_req, auth_fail],
                )
            )

        if sec_reject:
            issues.append(
                make_issue(
                    "5G_REGISTRATION_SECURITY_MODE_REJECT",
                    session,
                    Severity.HIGH,
                    "NAS",
                    sec_reject,
                    "SecurityModeComplete",
                    (
                        f"UE {session.ue_id} rejected NAS Security Mode Command. The likely area is "
                        "NAS algorithm negotiation, integrity/ciphering capability mismatch, or UE/modem "
                        "security context handling."
                    ),
                    [
                        "Compare UE NAS security capabilities against AMF configured algorithms.",
                        "Confirm the selected integrity and ciphering algorithms are supported by the UE.",
                        "Review preceding authentication and security context identifiers.",
                    ],
                    [reg_req, sec_cmd, sec_reject] if sec_cmd else [reg_req, sec_reject],
                )
            )

        if reg_reject:
            cause = reg_reject.cause or "unspecified"
            severity = Severity.CRITICAL if "subscription" in cause.lower() else Severity.HIGH
            issues.append(
                make_issue(
                    "5G_REGISTRATION_REJECT",
                    session,
                    severity,
                    "NAS",
                    reg_reject,
                    "RegistrationAccept",
                    (
                        f"AMF rejected registration for UE {session.ue_id} with cause '{cause}'. "
                        f"{registration_cause_explanation(cause)}"
                    ),
                    [
                        "Map the reject cause to PLMN/subscription policy and AMF registration logs.",
                        "Check roaming restrictions, slice/subscriber profile, and allowed tracking areas.",
                        "Verify the UE is attempting registration on the intended PLMN and RAT.",
                    ],
                    [reg_req, reg_reject],
                )
            )

        if not auth_req and not reg_accept and not reg_reject and not auth_fail:
            issues.append(
                make_issue(
                    "5G_REGISTRATION_MISSING_AUTHENTICATION_REQUEST",
                    session,
                    Severity.MEDIUM,
                    "NAS/NGAP",
                    reg_req,
                    "AuthenticationRequest",
                    (
                        f"UE {session.ue_id} sent RegistrationRequest, but no AuthenticationRequest, "
                        "RegistrationAccept, or RegistrationReject was observed. This suggests the request "
                        "did not progress through AMF authentication handling or the downlink NAS response "
                        "is missing from the capture."
                    ),
                    [
                        "Check NGAP InitialUEMessage and AMF selection/routing for this UE.",
                        "Verify the log source includes downlink NAS transport from AMF to gNB.",
                        "Inspect AMF logs for subscriber lookup, AUSF contact, and overload rejection.",
                    ],
                    [reg_req],
                )
            )

        if auth_req and not auth_resp and not auth_fail and not reg_reject:
            issues.append(
                make_issue(
                    "5G_REGISTRATION_AUTHENTICATION_RESPONSE_TIMEOUT",
                    session,
                    Severity.HIGH,
                    "NAS",
                    auth_req,
                    "AuthenticationResponse",
                    (
                        f"UE {session.ue_id} received AuthenticationRequest, but no "
                        "AuthenticationResponse was observed. This is consistent with USIM access failure, "
                        "UE/modem NAS stack timeout, poor radio conditions before the response, or a capture "
                        "gap on the uplink NAS path."
                    ),
                    [
                        "Check UE modem logs for USIM read/authentication errors.",
                        "Review RRC stability and radio measurements around the authentication challenge.",
                        "Confirm uplink NAS transport is present in the logging point.",
                    ],
                    [reg_req, auth_req],
                )
            )

        if auth_resp and not sec_cmd and not reg_accept and not reg_reject and not sec_reject:
            issues.append(
                make_issue(
                    "5G_REGISTRATION_SECURITY_MODE_COMMAND_MISSING",
                    session,
                    Severity.HIGH,
                    "NAS",
                    auth_resp,
                    "SecurityModeCommand",
                    (
                        f"UE {session.ue_id} sent AuthenticationResponse, but no NAS "
                        "SecurityModeCommand was observed. In a normal initial 5G registration this "
                        "usually means the AMF did not advance to NAS security activation, the downlink "
                        "NAS security message is missing from the trace, or authentication result handling "
                        "failed before algorithm selection."
                    ),
                    [
                        "Check AMF authentication result handling after AUSF/UDM confirmation.",
                        "Verify downlink NAS transport logging from AMF to gNB.",
                        "Review selected NAS security algorithms and AMF security context allocation.",
                    ],
                    [reg_req, auth_req, auth_resp] if auth_req else [reg_req, auth_resp],
                )
            )

        if sec_cmd and not sec_complete and not sec_reject and not reg_reject:
            issues.append(
                make_issue(
                    "5G_REGISTRATION_SECURITY_MODE_COMPLETE_MISSING",
                    session,
                    Severity.HIGH,
                    "NAS",
                    sec_cmd,
                    "SecurityModeComplete",
                    (
                        f"AMF sent SecurityModeCommand to UE {session.ue_id}, but no "
                        "SecurityModeComplete or SecurityModeReject was observed. This points to UE NAS "
                        "security activation timeout, unsupported selected algorithms, radio loss before "
                        "uplink response, or an uplink NAS capture gap."
                    ),
                    [
                        "Compare selected NAS integrity/ciphering algorithms with UE capabilities.",
                        "Check UE modem logs for NAS security activation failure.",
                        "Correlate with RRC/RLC stability during the security mode exchange.",
                    ],
                    [reg_req, sec_cmd],
                )
            )

        if not reg_accept and not reg_reject and not auth_fail and not sec_reject:
            last_reg_event = last_event_in_set(
                events,
                {
                    "RegistrationRequest",
                    "AuthenticationRequest",
                    "AuthenticationResponse",
                    "SecurityModeCommand",
                    "SecurityModeComplete",
                },
            )
            if last_reg_event and last_reg_event.message in {
                "SecurityModeComplete",
            }:
                issues.append(
                    make_issue(
                        "5G_REGISTRATION_ACCEPT_MISSING",
                        session,
                        Severity.HIGH,
                        "NAS",
                        last_reg_event,
                        "RegistrationAccept",
                        (
                            f"Registration signaling for UE {session.ue_id} progressed through "
                            f"{last_reg_event.message}, but no RegistrationAccept was captured. The AMF may "
                            "have stalled after security, subscriber policy may be unresolved, or downlink "
                            "NAS delivery may be missing."
                        ),
                        [
                            "Inspect AMF registration state and subscriber policy decision after security.",
                            "Check NGAP DownlinkNASTransport delivery toward the serving gNB.",
                            "Confirm no UEContextRelease occurred before RegistrationAccept.",
                        ],
                        [reg_req, last_reg_event],
                    )
                )
        return issues

    def _pdu_session_rules(self, session: Session) -> list[Issue]:
        events = session.events
        requests = [event for event in events if event.message == "PduSessionEstablishmentRequest"]
        if not requests:
            return []
        issues: list[Issue] = []
        for request in requests:
            issues.extend(self._pdu_session_procedure_rules(session, request))
        return issues

    def _pdu_session_procedure_rules(self, session: Session, request: LogEvent) -> list[Issue]:
        events = session.events
        affected_session = request.session_key
        accept = first_pdu_event_after(events, "PduSessionEstablishmentAccept", request)
        reject = first_pdu_event_after(events, "PduSessionEstablishmentReject", request)
        setup_request = first_pdu_event_after(events, "PduSessionResourceSetupRequest", request)
        setup_response = first_pdu_event_after(events, "PduSessionResourceSetupResponse", request)
        setup_failure = first_pdu_event_after(events, "PduSessionResourceSetupFailure", request)
        issues: list[Issue] = []

        if reject:
            cause = reject.cause or "unspecified"
            issues.append(
                make_issue(
                    "PDU_SESSION_ESTABLISHMENT_REJECT",
                    session,
                    Severity.HIGH,
                    "NAS",
                    reject,
                    "PduSessionEstablishmentAccept",
                    (
                        f"UE {session.ue_id} requested a PDU session, but SMF/AMF rejected it with "
                        f"cause '{cause}'. This often maps to DNN/S-NSSAI authorization, subscription "
                        "policy, missing UPF route, or session management configuration."
                    ),
                    [
                        "Check DNN, S-NSSAI, SSC mode, and subscriber session policy in UDM/SMF.",
                        "Verify UPF selection and N4 connectivity for the requested slice/DNN.",
                        "Inspect NAS SM cause and SMF logs for policy control failure.",
                    ],
                    [request, reject],
                    affected_session=affected_session,
                )
            )

        if setup_failure:
            cause = setup_failure.cause or "unspecified"
            issues.append(
                make_issue(
                    "NGAP_PDU_SESSION_RESOURCE_SETUP_FAILURE",
                    session,
                    Severity.HIGH,
                    "NGAP",
                    setup_failure,
                    "PduSessionResourceSetupResponse",
                    (
                        f"gNB failed NGAP PDU Session Resource Setup for UE {session.ue_id} with cause "
                        f"'{cause}'. This indicates the NAS SM request reached the network, but radio/N3 "
                        "resource establishment failed before user-plane activation."
                    ),
                    [
                        "Check gNB admission control, DRB configuration, and QoS flow mapping.",
                        "Verify UPF N3 tunnel parameters, TEIDs, transport reachability, and slice mapping.",
                        "Review radio resource availability and cell-specific bearer admission counters.",
                    ],
                    [request, setup_request, setup_failure]
                    if setup_request
                    else [request, setup_failure],
                    affected_session=affected_session,
                )
            )

        if not setup_request and not reject:
            issues.append(
                make_issue(
                    "PDU_SESSION_MISSING_N2_CORRELATION",
                    session,
                    Severity.MEDIUM,
                    "NAS/NGAP",
                    request,
                    "PduSessionResourceSetupRequest",
                    (
                        f"NAS PDU Session Establishment Request from UE {session.ue_id} has no matching "
                        "NGAP PDU Session Resource Setup Request. The request may not have reached SMF, "
                        "N2 correlation may be missing from the trace, or the AMF/SMF rejected it before "
                        "creating radio resource setup."
                    ),
                    [
                        "Check AMF-to-SMF N11 transaction and selected DNN/S-NSSAI.",
                        "Confirm the trace includes NGAP messages for the serving gNB.",
                        "Verify the PDU session ID is consistent between NAS and NGAP records.",
                    ],
                    [request],
                    affected_session=affected_session,
                )
            )

        if not accept and not reject:
            last = setup_failure or setup_response or setup_request or request
            issues.append(
                make_issue(
                    "PDU_SESSION_ACCEPT_MISSING",
                    session,
                    Severity.HIGH if setup_response else Severity.MEDIUM,
                    "NAS/NGAP",
                    last,
                    "PduSessionEstablishmentAccept",
                    (
                        f"PDU session setup for UE {session.ue_id} did not reach "
                        "PduSessionEstablishmentAccept. If NGAP setup succeeded, suspect missing downlink "
                        "NAS SM delivery; otherwise inspect SMF policy, gNB resource admission, and N2/N3 "
                        "transport."
                    ),
                    [
                        "Correlate NAS PDU session ID with NGAP resource setup messages.",
                        "Inspect SMF and AMF logs for session state after resource setup.",
                        "Check whether a UEContextRelease or RRCRelease interrupted the procedure.",
                    ],
                    [request, last] if last is not request else [request],
                    affected_session=affected_session,
                )
            )
        return issues

    def _rrc_rules(self, session: Session) -> list[Issue]:
        events = session.events
        issues: list[Issue] = []
        setup_request = first_event(events, "RRCSetupRequest")
        if setup_request:
            setup = first_event_after(events, "RRCSetup", setup_request)
            complete = first_event_after(events, "RRCSetupComplete", setup or setup_request)
            if not setup:
                issues.append(
                    make_issue(
                        "RRC_SETUP_RESPONSE_MISSING",
                        session,
                        Severity.HIGH,
                        "RRC",
                        setup_request,
                        "RRCSetup",
                        (
                            f"UE {session.ue_id} sent RRCSetupRequest, but no RRCSetup was observed. "
                            "Likely areas are uplink random access instability, gNB admission control, "
                            "overload, or missing downlink RRC capture."
                        ),
                        [
                            "Check PRACH/RACH success counters, uplink coverage, and contention resolution.",
                            "Inspect gNB admission control and cell overload indicators.",
                            "Confirm the log point captures downlink RRC messages for this cell.",
                        ],
                        [setup_request],
                    )
                )
            elif not complete:
                issues.append(
                    make_issue(
                        "RRC_SETUP_COMPLETE_MISSING",
                        session,
                        Severity.HIGH,
                        "RRC",
                        setup,
                        "RRCSetupComplete",
                        (
                            f"gNB sent RRCSetup to UE {session.ue_id}, but RRCSetupComplete is missing. "
                            "This suggests UE failed to complete SRB1/NAS container delivery, lost radio "
                            "link before completion, or uplink RRC logging is incomplete."
                        ),
                        [
                            "Inspect UE radio measurements and uplink scheduling after RRCSetup.",
                            "Check SRB1 setup and MAC/RLC retransmission counters.",
                            "Verify no immediate RRCRelease or cell reselection occurred.",
                        ],
                        [setup_request, setup],
                    )
                )

        for failure_name in ("RRCReconfigurationFailure", "RadioLinkFailure"):
            failure = first_event(events, failure_name)
            if failure:
                cause = failure.cause or "unspecified"
                severity = (
                    Severity.CRITICAL if failure_name == "RadioLinkFailure" else Severity.HIGH
                )
                issues.append(
                    make_issue(
                        f"RRC_{failure_name.upper()}",
                        session,
                        severity,
                        "RRC",
                        failure,
                        "RRCReconfigurationComplete",
                        (
                            f"UE {session.ue_id} reported {failure_name} with cause '{cause}'. This "
                            "points to radio bearer reconfiguration mismatch, unsupported measurement or "
                            "DRB parameters, mobility configuration error, or deteriorated RF conditions."
                        ),
                        [
                            "Compare RRCReconfiguration contents against UE capabilities and band support.",
                            "Review radio measurements, RLC retransmissions, and handover/mobility settings.",
                            "Check whether the failure correlates with a specific cell, PCI, or frequency.",
                        ],
                        [failure],
                    )
                )
        return issues

    def _handover_rules(self, session: Session) -> list[Issue]:
        events = session.events
        required = first_event(events, "HandoverRequired")
        command = first_event(events, "HandoverCommand")
        complete = first_event(events, "HandoverNotify") or first_event(events, "HandoverComplete")
        failure = first_event(events, "HandoverFailure")
        ack = first_event(events, "HandoverRequestAcknowledge")
        issues: list[Issue] = []

        if failure:
            cause = failure.cause or "unspecified"
            issues.append(
                make_issue(
                    "HANDOVER_FAILURE",
                    session,
                    Severity.HIGH,
                    "NGAP/RRC",
                    failure,
                    "HandoverNotify",
                    (
                        f"Handover failed for UE {session.ue_id} with cause '{cause}'. This is often "
                        "caused by target-cell admission failure, Xn/N2 preparation failure, unsupported "
                        "target configuration, or radio conditions degrading during execution."
                    ),
                    [
                        "Inspect source and target cell admission/resource counters.",
                        "Check neighbor relation, target cell availability, and Xn/N2 reachability.",
                        "Review measurement reports and target-cell RSRP/RSRQ/SINR before command.",
                    ],
                    [event for event in (required, ack, command, failure) if event],
                )
            )

        if required and not ack and not failure:
            issues.append(
                make_issue(
                    "HANDOVER_PREPARATION_ACK_MISSING",
                    session,
                    Severity.HIGH,
                    "NGAP",
                    required,
                    "HandoverRequestAcknowledge",
                    (
                        f"Source gNB requested handover for UE {session.ue_id}, but no target-side "
                        "HandoverRequestAcknowledge was captured. Suspect target cell unavailable, "
                        "admission rejection, transport/signaling problem, or missing target-gNB logs."
                    ),
                    [
                        "Check target gNB availability, neighbor relation, and admission logs.",
                        "Validate AMF handover routing and Xn/N2 connectivity.",
                        "Confirm the trace contains both source and target side NGAP records.",
                    ],
                    [required],
                )
            )

        if command and not complete and not failure:
            issues.append(
                make_issue(
                    "HANDOVER_EXECUTION_COMPLETE_MISSING",
                    session,
                    Severity.HIGH,
                    "RRC/NGAP",
                    command,
                    "HandoverNotify",
                    (
                        f"HandoverCommand was sent to UE {session.ue_id}, but no HandoverNotify or "
                        "completion event was observed. The UE may not have accessed the target cell, "
                        "the target cell may be barred/unavailable, or radio conditions may have collapsed "
                        "during execution."
                    ),
                    [
                        "Check UE measurement report and target-cell access attempts.",
                        "Inspect target cell PRACH/RACH and beam/access failure counters.",
                        "Review whether the HandoverCommand contained correct target PCI/ARFCN/cell ID.",
                    ],
                    [command],
                )
            )

        if command and complete:
            duration = complete.timestamp - command.timestamp
            if duration > self.timeout:
                issues.append(
                    make_issue(
                        "HANDOVER_EXECUTION_TIMEOUT",
                        session,
                        Severity.MEDIUM,
                        "RRC/NGAP",
                        command,
                        "HandoverNotify within timeout",
                        (
                            f"Handover execution for UE {session.ue_id} took "
                            f"{format_duration(duration.total_seconds())}, exceeding the configured "
                            f"{format_duration(self.timeout.total_seconds())} threshold. This may indicate "
                            "late target-cell access, weak target coverage, or delayed NGAP notification."
                        ),
                        [
                            "Review target-cell RACH delay and radio measurements during execution.",
                            "Compare timing against field-test KPIs and vendor timer configuration.",
                            "Check whether logging aggregation introduced artificial delay.",
                        ],
                        [command, complete],
                    )
                )
        return issues

    def _access_attempt_rules(self, session: Session) -> list[Issue]:
        attempts = [event for event in session.events if event.message == "RRCSetupRequest"]
        if len(attempts) < 3:
            return []
        window = attempts[-1].timestamp - attempts[0].timestamp
        if window > timedelta(seconds=60):
            return []
        return [
            make_issue(
                "REPEATED_INITIAL_ACCESS_ATTEMPTS",
                session,
                Severity.MEDIUM,
                "RRC/NAS",
                attempts[0],
                "Stable RRC/NAS progression",
                (
                    f"UE {session.ue_id} made {len(attempts)} RRCSetupRequest attempts within "
                    f"{format_duration(window.total_seconds())}. Repeated initial access usually points "
                    "to radio instability, access barring, congestion, or a NAS rejection causing the UE "
                    "to retry attachment/registration."
                ),
                [
                    "Check whether attempts happen on the same cell or after cell reselection.",
                    "Correlate with RACH failures, access barring, overload, or reject causes.",
                    "Inspect UE retry timers and whether the same subscriber is repeatedly rejected.",
                ],
                attempts[:5],
            )
        ]

    @staticmethod
    def _dedupe(issues: list[Issue]) -> list[Issue]:
        seen: set[tuple[str, str, int]] = set()
        unique: list[Issue] = []
        for issue in issues:
            first_line = issue.evidence[0].line_no if issue.evidence else -1
            key = (issue.issue_type, issue.affected_session, first_line)
            if key not in seen:
                unique.append(issue)
                seen.add(key)
        return unique


def make_issue(
    issue_type: str,
    session: Session,
    severity: Severity,
    failed_layer: str,
    suspicious: LogEvent,
    expected: str,
    cause: str,
    actions: list[str],
    evidence: list[LogEvent],
    *,
    affected_session: str | None = None,
) -> Issue:
    return Issue(
        issue_type=issue_type,
        affected_session=affected_session or session.key,
        severity=severity,
        failed_layer=failed_layer,
        first_suspicious_message=f"line {suspicious.line_no}: {suspicious.message}",
        missing_or_failed_expected_message=expected,
        probable_cause=cause,
        suggested_actions=actions,
        evidence=[event for event in evidence if event is not None],
    )


def first_event(events: list[LogEvent], message: str) -> LogEvent | None:
    return next((event for event in events if event.message == message), None)


def first_event_after(
    events: list[LogEvent], message: str, anchor: LogEvent | None
) -> LogEvent | None:
    if anchor is None:
        return first_event(events, message)
    return next(
        (
            event
            for event in events
            if event.message == message
            and (event.timestamp, event.line_no) >= (anchor.timestamp, anchor.line_no)
        ),
        None,
    )


def first_pdu_event_after(
    events: list[LogEvent], message: str, request: LogEvent
) -> LogEvent | None:
    next_request = next(
        (
            event
            for event in events
            if event.message == "PduSessionEstablishmentRequest"
            and (event.timestamp, event.line_no) > (request.timestamp, request.line_no)
        ),
        None,
    )
    for event in events:
        if event.message != message:
            continue
        if (event.timestamp, event.line_no) < (request.timestamp, request.line_no):
            continue
        if next_request and (event.timestamp, event.line_no) >= (
            next_request.timestamp,
            next_request.line_no,
        ):
            continue
        if request.session_id and event.session_id and event.session_id != request.session_id:
            continue
        if request.session_id and event.session_id is None:
            continue
        return event
    return None


def last_event_in_set(events: list[LogEvent], messages: set[str]) -> LogEvent | None:
    for event in reversed(events):
        if event.message in messages:
            return event
    return None


def session_sort_floor() -> object:
    return ""


def registration_cause_explanation(cause: str) -> str:
    normalized = cause.lower()
    if "roaming" in normalized:
        return "The reject cause is consistent with roaming or PLMN policy blocking registration."
    if "subscription" in normalized or "slice" in normalized or "nssai" in normalized:
        return "The reject cause points to subscriber profile, slice authorization, or service entitlement."
    if "congestion" in normalized or "overload" in normalized:
        return "The reject cause points to network congestion or AMF/gNB overload handling."
    if "authentication" in normalized:
        return (
            "The reject cause points to authentication or subscriber identity validation failure."
        )
    return "The reject cause should be correlated with AMF policy and subscriber provisioning."
