# ProofAgent Architecture (v0)

```
Human / Organization
        │
        ▼
   Agent Passport
        │
        ▼
 Authority / Policy Engine
        │
     ┌──┬──┐
     ▼     ▼
   ALLOW  DENY / REQUIRE_APPROVAL
     │
     ▼
 Tool / API / MCP Server
     │
     ▼
  Action Receipt
     │
     ▼
 Verification API
     │
 ┌───┼───────┐
 ▼   ▼        ▼
Audit  Security  Insurance/Risk (later)
```

## Core primitives

1. **Agent** — the software actor
2. **Authority** — what the agent is permitted to do
3. **Policy** — conditions under which authority may be exercised (ALLOW / DENY / REQUIRE_APPROVAL)
4. **ActionReceipt** — the primary product artifact
5. **Verify()** — independent cryptographic + semantic verification

## Trust boundary

ProofAgent must not rely solely on an agent claiming what it did.

Trusted path:

```
Agent → ProofAgent authorization → Tool execution → ProofAgent observes result → signed receipt
```
