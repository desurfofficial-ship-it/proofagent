# Persistence

## Backends

| Backend | How | Survives restart | Multi-process |
|---------|-----|------------------|---------------|
| **memory** (default) | in-process | No | N/A |
| **file** | `PROOFAGENT_DATA=/var/lib/proofagent` | **Yes** | No (single writer) |
| **postgres** | schema in `infrastructure/schema.sql` | Planned | Yes |

## File store

```bash
export PROOFAGENT_DATA=./data
go run ./services/api
# state written to ./data/state.json (atomic rename)
```

Agents, keys, policies, authorizations, receipts, and passports persist across process restarts.

## Postgres (next)

`infrastructure/schema.sql` is ready. Runtime driver was blocked in the build environment (module proxy 502). When available:

```bash
export DATABASE_URL=postgres://proofagent:proofagent@localhost:5432/proofagent?sslmode=disable
# future: OpenPostgres() implementing the same store.Store interface
```

Atomic consumption target:

```sql
UPDATE authorizations
SET status = 'consumed'
WHERE authorization_id = $1
  AND status IN ('approved', 'pending')
  AND expires_at > NOW()
RETURNING *;
```
