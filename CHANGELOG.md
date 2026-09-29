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

## 0.1.3 — 2026-09-29

### Phase 3 — Independent verification
- `cmd/proofagent-verify` offline CLI (no API required)
- `GET /v1/receipts/{id}/bundle` evidence export for Company B
- `scripts/phase3_company_ab.sh` adversarial demo: valid + tamper

## 0.1.4 — 2026-09-29

### Phase 4 — Security hardening
- Auth secure by default: require API key unless `DEMO_MODE=1`
- Tenant isolation on agent get/lifecycle/keys/authorize/approvals/receipts
- demo-keypair only when `DEMO_MODE=1`
- File store never persists demo private keys
- `scripts/adversarial.sh` cross-tenant tests
- CI runs e2e + adversarial

## 0.1.5 — 2026-09-29

### Phase 6 — Execution boundary
- `ToolBoundary`: authorize → invoke tool → observe result → hash → receipt
- DENY prevents tool invocation
- Tool errors recorded as `result_status=error` (not forged success)
- MCP middleware observes tool return/throw
- `scripts/phase6_boundary.sh` + `docs/EXECUTION_BOUNDARY.md`
