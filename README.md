# ProofAgent

**Makes AI actions provable.**

```
Identity → Authority → Policy → Action Receipt → Verification
```

## Quick start

```bash
# API
go run ./services/api
# or
make build && make api

# Python SDK
pip install -e sdk/python
```

```python
from proofagent import Agent
agent = Agent.create(name="FinanceBot")
agent.execute("stripe.create_payment", {"amount": 75}, approve=True)
```

```bash
# TypeScript SDK
cd sdk/typescript && npm i && npm run build

# Docker
docker compose up --build
```

## Canonical demo policy (`pol_demo`)

| Action | Result |
|--------|--------|
| `stripe.create_payment` amount **> 100** | DENY |
| amount **≥ 50** | REQUIRE_APPROVAL |
| amount **< 50** | ALLOW |
| `calendar.read` | ALLOW |

## Repo layout

- `packages/crypto` — frozen canonicalization + Ed25519
- `packages/policy` — deterministic evaluator
- `packages/receipts` — signed Action Receipts
- `services/api` — HTTP API
- `sdk/python` / `sdk/typescript`
- `integrations/mcp` — authorize → execute → receipt middleware

## Docs

- `docs/CRYPTO.md` — frozen signing rules
- Notion: Engineering Kickoff Pack

## License

Proprietary — all rights reserved until otherwise stated.
