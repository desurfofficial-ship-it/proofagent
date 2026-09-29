#!/usr/bin/env bash
set -euo pipefail
BASE="${PROOFAGENT_URL:-http://localhost:8080}"

echo "== create org A and B =="
OA=$(curl -sf -X POST "$BASE/v1/organizations" -H 'Content-Type: application/json' -d '{"name":"OrgA"}')
OB=$(curl -sf -X POST "$BASE/v1/organizations" -H 'Content-Type: application/json' -d '{"name":"OrgB"}')
KA=$(echo "$OA" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
KB=$(echo "$OB" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")

AA=$(curl -sf -X POST "$BASE/v1/agents" -H "Authorization: Bearer $KA" -H 'Content-Type: application/json' -d '{"name":"A-Bot","principal_id":"a"}')
AID=$(echo "$AA" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")

code=$(curl -s -o /tmp/adv_get.json -w "%{http_code}" -H "Authorization: Bearer $KB" "$BASE/v1/agents/$AID")
python3 -c "import json; d=json.load(open('/tmp/adv_get.json')); assert int('$code') in (403,404), d; print('OK cross-tenant GET blocked', '$code')"

code=$(curl -s -o /tmp/adv_sus.json -w "%{http_code}" -X POST -H "Authorization: Bearer $KB" "$BASE/v1/agents/$AID/suspend")
python3 -c "import json; d=json.load(open('/tmp/adv_sus.json')); assert int('$code') in (403,404), d; print('OK cross-tenant suspend blocked', '$code')"

code=$(curl -s -o /tmp/adv_az.json -w "%{http_code}" -X POST \
  -H "Authorization: Bearer $KB" \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"$AID\",\"action\":{\"tool\":\"calendar.read\"},\"context\":{}}" \
  "$BASE/v1/authorize")
python3 -c "import json; d=json.load(open('/tmp/adv_az.json')); assert int('$code') in (403,401), ( '$code', d); print('OK cross-tenant authorize blocked', '$code')"

echo "ADVERSARIAL PASS"
