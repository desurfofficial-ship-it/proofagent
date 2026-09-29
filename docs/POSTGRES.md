# Postgres path

`infrastructure/schema.sql` is the target schema.

v0 API uses **in-memory** store by default so demos run with zero deps.

When `DATABASE_URL` is set, `/health` reports `memory+postgres_configured`. Full dual-write / Pg-backed store is the next persistence milestone (orgs + agents + receipts tables).

```bash
export DATABASE_URL=postgres://proofagent:proofagent@localhost:5432/proofagent?sslmode=disable
docker compose up -d db
psql "$DATABASE_URL" -f infrastructure/schema.sql
```
