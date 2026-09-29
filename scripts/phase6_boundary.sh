#!/usr/bin/env bash
# Phase 6: execution boundary — observed results, not forged claims.
set -euo pipefail
export DEMO_MODE="${DEMO_MODE:-1}"
BASE="${PROOFAGENT_URL:-http://localhost:8080}"

python3 << 'PY'
import os, sys
sys.path.insert(0, "sdk/python")

# crypto may be missing; fall back to demo keys via API
os.environ.setdefault("DEMO_MODE", "1")

from proofagent.client import Client, Agent, ProofAgentError

try:
    from proofagent.boundary import ToolBoundary
    from proofagent import crypto_local
    HAS_CRYPTO = True
    try:
        crypto_local.generate_keypair()
    except Exception:
        HAS_CRYPTO = False
except Exception as e:
    print("import error", e)
    HAS_CRYPTO = False

base = os.environ.get("PROOFAGENT_URL", "http://localhost:8080")

# Always use demo keypair path if no cryptography (server signs observed hashes)
agent = Agent.create(name="BoundaryBot", principal_id="usr_b", base_url=base, client_side_keys=False, with_demo_key=True)
print("agent", agent.agent_id)

payments = {"executed": []}

def stripe_create_payment(amount: float = 0, **kwargs):
    amount = float(amount or kwargs.get("amount") or 0)
    if amount <= 0:
        raise ValueError("amount must be positive")
    payments["executed"].append(amount)
    return {"ok": True, "charged": amount, "provider": "stripe_stub"}

from proofagent.boundary import ToolBoundary
boundary = ToolBoundary(agent, auto_approve=True)
boundary.register("stripe.create_payment", stripe_create_payment)

# DENY path — tool must NOT run
try:
    boundary.run("stripe.create_payment", {"amount": 400})
    print("FAIL: should deny")
    sys.exit(1)
except ProofAgentError as e:
    print("OK deny before execute:", str(e)[:60])
assert payments["executed"] == [], "tool must not run on DENY"

# ALLOW path — tool runs, receipt reflects observed success
obs = boundary.run("stripe.create_payment", {"amount": 25})
print("observed status", obs.result_status, "result", obs.result)
assert obs.result_status == "success"
assert payments["executed"] == [25.0]
assert obs.verification and obs.verification.get("valid") is True
print("OK observed success + valid receipt")

# Error path — tool throws, receipt records error (not forged success)
def broken_tool(amount=0, **kw):
    raise RuntimeError("provider_down")

boundary.register("stripe.create_payment", broken_tool)
obs2 = boundary.run("stripe.create_payment", {"amount": 25})
assert obs2.result_status == "error", obs2
assert "provider_down" in (obs2.error or "")
assert obs2.verification and obs2.verification.get("valid") is True
print("OK observed error captured in receipt (not forged success)")

print("==============================")
print(" PHASE 6 BOUNDARY: PASS")
print("==============================")
PY
