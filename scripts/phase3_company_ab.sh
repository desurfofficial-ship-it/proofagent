#!/usr/bin/env bash
# Phase 3: Company A produces evidence; Company B verifies offline.
export DEMO_MODE="${DEMO_MODE:-1}"
set -euo pipefail
BASE="${PROOFAGENT_URL:-http://localhost:8080}"
WORKDIR="${TMPDIR:-/tmp}/proofagent_phase3"
mkdir -p "$WORKDIR"

echo "======== COMPANY A (producer) ========"
AGENT=$(curl -sf -X POST "$BASE/v1/agents" -H 'Content-Type: application/json' \
  -d '{"name":"CompanyA-Finance","principal_id":"usr_a"}')
AID=$(echo "$AGENT" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
KP=$(curl -sf -X POST "$BASE/v1/agents/$AID/demo-keypair")
PUB=$(echo "$KP" | python3 -c "import sys,json; print(json.load(sys.stdin)['key']['public_key'])")
echo "agent_id=$AID"
echo "public_key=${PUB:0:24}..."

AUTH=$(curl -sf -X POST "$BASE/v1/authorize" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AID\",\"action\":{\"type\":\"tool_call\",\"tool\":\"stripe.create_payment\"},\"context\":{\"amount\":75}}")
DECISION=$(echo "$AUTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['decision'])")
AUTH_ID=$(echo "$AUTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['authorization_id'])")
echo "decision=$DECISION"
if [ "$DECISION" = "REQUIRE_APPROVAL" ]; then
  curl -sf -X POST "$BASE/v1/approvals" -H 'Content-Type: application/json' \
    -d "{\"authorization_id\":\"$AUTH_ID\",\"decision\":\"approve\"}" >/dev/null
  echo "approved by Company A principal"
fi

REC=$(curl -sf -X POST "$BASE/v1/receipts" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AID\",\"authorization_id\":\"$AUTH_ID\",\"action\":{\"type\":\"tool_call\",\"tool\":\"stripe.create_payment\"},\"input_hash\":\"sha256:pay\",\"result_status\":\"success\",\"result_hash\":\"sha256:ok\"}")
RID=$(echo "$REC" | python3 -c "import sys,json; print(json.load(sys.stdin)['receipt_id'])")
echo "$REC" > "$WORKDIR/receipt.json"
echo "receipt_id=$RID written to $WORKDIR/receipt.json"

# Export bundle (what Company A sends to Company B — e.g. email, webhook, shared drive)
curl -sf "$BASE/v1/receipts/$RID/bundle" > "$WORKDIR/bundle.json"
echo "bundle written to $WORKDIR/bundle.json"

echo
echo "======== COMPANY B (verifier) — NO API, offline ========"
# Simulate: Company B only has the bundle file, not Company A's server
if [ -x ./bin/proofagent-verify ]; then
  VERIFY=./bin/proofagent-verify
elif [ -x /tmp/proofagent-verify ]; then
  VERIFY=/tmp/proofagent-verify
else
  go build -o /tmp/proofagent-verify ./cmd/proofagent-verify/
  VERIFY=/tmp/proofagent-verify
fi

echo "--- valid bundle ---"
$VERIFY -bundle "$WORKDIR/bundle.json"

echo "--- tamper detection ---"
python3 - << PY
import json
from pathlib import Path
p = Path("$WORKDIR/bundle.json")
b = json.loads(p.read_text())
b["receipt"]["result"]["status"] = "failed"  # tamper
Path("$WORKDIR/bundle_tampered.json").write_text(json.dumps(b))
print("wrote tampered bundle")
PY
if $VERIFY -bundle "$WORKDIR/bundle_tampered.json"; then
  echo "FAIL: tampered bundle should be invalid"
  exit 1
else
  echo "OK: tampered receipt rejected offline"
fi

echo
echo "=============================================="
echo " PHASE 3 PASS: Company B verified offline"
echo " without Company A dashboard or shared DB"
echo "=============================================="
