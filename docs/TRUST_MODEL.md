# Trust model (Phase 1)

## Production path (required)

```
Agent generates keypair locally
        ↓
Private key NEVER leaves agent
        ↓
POST /v1/agents/{id}/keys  { public_key }
        ↓
authorize → (approval) → tool runs
        ↓
Agent builds ActionReceipt body
        ↓
Agent signs receipt_hash with private key
        ↓
POST /v1/receipts  { receipt: signed... }
        ↓
ProofAgent verifies signature against registered public key
        ↓
POST /v1/verify  { receipt, public_key }  // independent
```

## Demo path (optional)

`POST /v1/agents/{id}/demo-keypair` returns a private key for local demos only.

Disable with:

```bash
export PROOFAGENT_DEMO=0
```

## Atomic authorization consumption

`ConsumeAuth` transitions `approved|pending → consumed` under a single mutex (memory) / row lock (Postgres next).

Replay after consumption returns `REPLAY_DETECTED`.

## Independent verification

```json
POST /v1/verify
{
  "receipt": { ... },
  "public_key": "<base64 Ed25519>"
}
```

Does not require trusting ProofAgent's key store when `public_key` is supplied by the verifier.
