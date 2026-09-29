# Execution boundary (Phase 6)

## Problem

Without a boundary, an agent can claim:

```json
{ "result_status": "success" }
```

even if the tool never ran.

## Model

```
authorize
   ↓
ToolBoundary.run(tool, context)
   ↓
invoke registered function
   ↓
capture return value or exception
   ↓
hash(input) + hash(result)
   ↓
sign ActionReceipt
   ↓
submit + verify
```

## Python

```python
from proofagent import Agent, ToolBoundary

agent = Agent.create(name="Finance", with_demo_key=True)  # or client_side_keys=True
boundary = ToolBoundary(agent, auto_approve=True)

@boundary.tool("stripe.create_payment")
def charge(amount: float, **kwargs):
    return {"charged": amount}

# DENY: tool never runs
# ALLOW: tool runs; receipt.result_status comes from observation
out = boundary.run("stripe.create_payment", {"amount": 25})
assert out.result_status == "success"
assert out.verification["valid"]
```

## Guarantees

| Case | Behavior |
|------|----------|
| Policy DENY | Tool **not** invoked |
| Tool returns | `result_status=success`, hash of real return |
| Tool raises | `result_status=error`, error captured |
| Unregistered tool | Rejected before authorize completes path |

## Limits (honest)

- Boundary is in-process with the agent runtime (trusted decorator/middleware).
- A compromised process can still bypass the decorator; hardware/enclave isolation is out of scope for v0.
- MCP path still uses server demo signing unless client-signed receipts are added to JS.
