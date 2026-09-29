# ProofAgent

**Makes AI actions provable.**

> Who authorized this agent to do this, under which policy, and what exactly happened?

```
Identity → Authority → Policy → Action Receipt → Verification
```

**Version:** 0.1.0

## 60-second start

```bash
go run ./services/api
# open http://localhost:8080/
```

```bash
# Canonical demo (API must be running)
./scripts/e2e.sh
```

## Python

```bash
pip install -e sdk/python
```

```python
from proofagent import Agent

agent = Agent.create(name="FinanceBot")
agent.execute("stripe.create_payment", {"amount": 400})  # raises DENIED
result = agent.execute("stripe.create_payment", {"amount": 75}, approve=True)
assert result["verification"]["valid"]
```

## TypeScript

```bash
cd sdk/typescript && npm i && npm run build
```

```ts
import { Agent } from "@proofagent/sdk";
const agent = await Agent.create({ name: "FinanceBot" });
const result = await agent.execute("stripe.create_payment", { amount: 75 }, { approve: true });
```

## API surface

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/organizations` | Create org + API key |
| POST | `/v1/agents` | Register agent |
| POST | `/v1/agents/{id}/suspend\|revoke\|activate` | Lifecycle |
| POST | `/v1/agents/{id}/keys` | Register Ed25519 public key |
| POST | `/v1/passports` | Issue passport |
| POST | `/v1/policies` | Create policy |
| POST | `/v1/authorize` | ALLOW / DENY / REQUIRE_APPROVAL |
| POST | `/v1/approvals` | Approve high-risk actions |
| POST | `/v1/receipts` | Store signed Action Receipt |
| POST | `/v1/verify` | Independent verification |
| GET | `/` | Dashboard |

Auth: `Authorization: Bearer <api_key>` or `X-API-Key`.  
Set `STRICT_AUTH=1` to require keys (default is open demo mode).

## Demo policy

| Payment amount | Decision |
|----------------|----------|
| > 100 | DENY |
| ≥ 50 | REQUIRE_APPROVAL |
| < 50 | ALLOW |

## Crypto

Frozen rules in [`docs/CRYPTO.md`](docs/CRYPTO.md) — canonical JSON → SHA-256 → Ed25519 over `receipt_hash`.

## License

Proprietary © 2026 ProofAgent / Desurf
