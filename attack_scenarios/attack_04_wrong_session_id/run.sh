#!/usr/bin/env bash
set -euo pipefail

echo "=== attack-04 wrong-session-id ==="

python attack_scenarios/attack_04_wrong_session_id/runner.py
