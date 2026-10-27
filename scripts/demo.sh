#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p runtime/agent runtime/web
if [[ ! -f runtime/configuration.yml ]]; then cp examples/configuration.yml runtime/configuration.yml; fi
export PYTHONPATH="$PWD/backend:$PWD"
.venv/bin/python -m acm.cli init --data runtime/web
if [[ ! -f runtime/web/initial-login.txt ]]; then
  .venv/bin/python -m acm.cli create-admin --data runtime/web --bundle runtime/web/initial-login.txt
fi
ACM_CONFIG="$PWD/runtime/configuration.yml" ACM_AGENT_STATE="$PWD/runtime/agent" ACM_DEMO=1 ACM_WRITABLE=1 ACM_ISSUER=https://auth.example.com .venv/bin/uvicorn agent.main:create_app --factory --uds "$PWD/runtime/agent.sock" --no-access-log &
AGENT_PID=$!
trap 'kill "$AGENT_PID" 2>/dev/null || true' EXIT
ACM_DATA="$PWD/runtime/web" ACM_AGENT_SOCKET="$PWD/runtime/agent.sock" ACM_ORIGIN=http://localhost:8098 ACM_SECURE_COOKIE=0 .venv/bin/uvicorn acm.main:create_app --factory --host 127.0.0.1 --port 8098 --no-access-log
