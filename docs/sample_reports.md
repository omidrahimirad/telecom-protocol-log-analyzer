# Sample Report Snippets

Generate fresh reports with:

```bash
python -m telecom_log_analyzer export data/samples/registration_auth_failure.log --format markdown --output reports/registration_auth_failure.md
python -m telecom_log_analyzer export data/samples/pdu_session_resource_setup_failure.log --format markdown --output reports/pdu_failure.md
python -m telecom_log_analyzer export data/samples/handover_failure_target_cell_unavailable.log --format markdown --output reports/handover_failure.md
```

Expected issue examples:

- `5G_REGISTRATION_AUTHENTICATION_FAILURE`
- `NGAP_PDU_SESSION_RESOURCE_SETUP_FAILURE`
- `HANDOVER_FAILURE`
- `RRC_SETUP_RESPONSE_MISSING`
- `REPEATED_INITIAL_ACCESS_ATTEMPTS`
