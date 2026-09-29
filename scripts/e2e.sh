#!/usr/bin/env bash
set -euo pipefail
BASE="${PROOFAGENT_URL:-http://localhost:8080}"

echo "== health =="
curl -sf "$BASE/health" | tee /tmp/pa_health.json
echo

echo "== create agent =="
AGENT=$(curl -sf -X POST "$BASE/v1/agents" -H 'Content-Type: application/json' \
  -d '{"name":"E2EBot","principal_id":"usr_e2e"}')
AID=$(echo "$AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
echo "agent_id=$AID"

echo "== demo keypair =="
curl -sf -X POST "$BASE/v1/agents/$AID/demo-keypair" >/dev/null

echo "== passport =="
curl -sf -X POST "$BASE/v1/passports" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AID\"}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['passport_id'], d['status'])"

echo "== \$400 DENY =="
D=$(curl -sf -X POST "$BASE/v1/authorize" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AID\",\"action\":{\"type\":\"tool_call\",\"tool\":\"stripe.create_payment\"},\"context\":{\"amount\":400}}")
echo "$D" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['decision']=='DENY', d; print('OK', d['decision'])"

echo "== \$75 REQUIRE_APPROVAL =="
A=$(curl -sf -X POST "$BASE/v1/authorize" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AID\",\"action\":{\"type\":\"tool_call\",\"tool\":\"stripe.create_payment\"},\"context\":{\"amount\":75}}")
echo "$A" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['decision']=='REQUIRE_APPROVAL', d; print('OK', d['decision'])"
AUTH=$(echo "$A" | python3 -c "import sys,json; print(json.load(sys.stdin)['authorization_id'])")

echo "== approve =="
curl -sf -X POST "$BASE/v1/approvals" -H 'Content-Type: application/json' \
  -d "{\"authorization_id\":\"$AUTH\",\"decision\":\"approve\"}" >/dev/null

echo "== receipt =="
R=$(curl -sf -X POST "$BASE/v1/receipts" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AID\",\"authorization_id\":\"$AUTH\",\"action\":{\"type\":\"tool_call\",\"tool\":\"stripe.create_payment\"},\"input_hash\":\"sha256:e2e\",\"result_status\":\"success\",\"result_hash\":\"sha256:e2e\"}")
RID=$(echo "$R" | python3 -c "import sys,json; print(json.load(sys.stdin)['receipt_id'])")
echo "receipt_id=$RID"

echo "== verify =="
curl -sf -X POST "$BASE/v1/verify" -H 'Content-Type: application/json' \
  -d "{\"receipt_id\":\"$RID\"}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['valid'] is True, d; print('OK valid', d['checks'])"

echo "== replay =="
code=$(curl -s -o /tmp/pa_replay.json -w "%{http_code}" -X POST "$BASE/v1/receipts" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AID\",\"authorization_id\":\"$AUTH\",\"action\":{\"type\":\"tool_call\",\"tool\":\"stripe.create_payment\"},\"input_hash\":\"sha256:e2e\",\"result_status\":\"success\",\"result_hash\":\"sha256:e2e\"}")
python3 -c "import json; d=json.load(open('/tmp/pa_replay.json')); assert d.get('error')=='REPLAY_DETECTED', d; print('OK REPLAY_DETECTED http=$code')"

echo "== suspend blocks authorize =="
curl -sf -X POST "$BASE/v1/agents/$AID/suspend" >/dev/null
code=$(curl -s -o /tmp/pa_sus.json -w "%{http_code}" -X POST "$BASE/v1/authorize" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AID\",\"action\":{\"tool\":\"calendar.read\"},\"context\":{}}")
python3 -c "import json; d=json.load(open('/tmp/pa_sus.json')); assert d.get('decision')=='DENY' or d.get('error'); print('OK suspended deny', d)"

echo
echo "=============================="
echo " E2E CANONICAL DEMO: PASSED"
echo "=============================="
