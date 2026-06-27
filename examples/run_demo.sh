#!/usr/bin/env bash
set -euo pipefail

python -m telecom_log_analyzer analyze data/samples/normal_5g_registration.log
python -m telecom_log_analyzer analyze data/samples/registration_auth_failure.log
python -m telecom_log_analyzer export data/samples/handover_failure_target_cell_unavailable.log --format markdown --output reports/handover_failure.md
