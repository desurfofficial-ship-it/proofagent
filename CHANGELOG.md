# Changelog

## 0.1.0 — 2026-09-29

First shippable v0 vertical slice.

### Core
- Agent registration, Ed25519 keys, passports
- Deterministic policy engine (ALLOW / DENY / REQUIRE_APPROVAL)
- Short-lived authorizations + human approvals
- Cryptographically signed Action Receipts (hash chain)
- Independent verification API
- Replay detection

### Clients
- Python SDK (`Agent.execute`)
- TypeScript SDK (`Agent.create` / `execute`)
- MCP middleware (authorize → execute → receipt)
- Browser dashboard at `/`

### Ops
- Docker Compose (API + Postgres)
- GitHub Actions CI
- `scripts/e2e.sh` canonical demo
- `STRICT_AUTH` for API key enforcement
- Postgres schema ready (`infrastructure/schema.sql`)

### Non-goals (deferred)
- Parametric insurance
- Full zero-trust MCP gateway
- Production Postgres dual-write (schema ready)
- Multi-region / Kafka
