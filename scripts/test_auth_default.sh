#!/usr/bin/env bash
set -euo pipefail
BASE="${PROOFAGENT_URL:-http://localhost:8080}"
# This script expects server WITHOUT DEMO_MODE
code=$(curl -s -o /tmp/na.json -w "%{http_code}" -X POST "$BASE/v1/agents" -H 'Content-Type: application/json' -d '{"name":"x"}')
python3 -c "assert $code==401, open('/tmp/na.json').read(); print('OK unauthenticated create agent rejected')"
