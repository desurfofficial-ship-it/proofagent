# ProofAgent

**Makes AI actions provable.**

Verifiable Agent Authority: Identity → Authority → Policy → Action Receipt → Verification.

## North star

> ProofAgent makes AI actions provable.

The product is **not** another agent identity standard.  
The product is cryptographically verifiable proof that a specific agent, acting for a specific principal, possessed specific authority, was evaluated against a specific policy, and performed a specific action.

## v0 Boundary

- Agent registration + Passport
- Authority / Policy engine (ALLOW / DENY / REQUIRE_APPROVAL)
- Action Receipt generation + Ed25519 signing + hash chain
- Independent verification API
- Python + TypeScript SDKs
- Lightweight MCP middleware
- Minimal dashboard

**Out of scope for v0:** insurance, full MCP gateway, blockchain, proprietary LLM, agent reputation marketplace.

## Source of truth

- Product + Architecture: Notion — *ProofAgent — Agent Trust Fabric v0 Technical Specification*
- Engineering handoff: Notion — *ProofAgent — Engineering Kickoff Pack*
- Cryptographic contract: **frozen** in `docs/CRYPTO.md` and the Kickoff Pack §5

## Repository layout

```
proofagent/
├── services/          # Go services (api, authorization, receipts, verification)
├── sdk/
│   ├── python/
│   └── typescript/
├── integrations/
│   └── mcp/
├── packages/         # Shared schemas, crypto, policy, passport
├── dashboard/
├── infrastructure/
├── docs/
└── tests/
```

## Quick start (coming)

```bash
# once packages/crypto and services are in place
go test ./...
pip install -e sdk/python
```

## License

Proprietary — all rights reserved until otherwise stated.
