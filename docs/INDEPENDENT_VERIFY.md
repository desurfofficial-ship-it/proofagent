# Independent verification (Phase 3)

## The demo that matters

```
Company A                         Company B
─────────                         ─────────
authorize + execute               (no API access)
sign receipt
export bundle.json  ───────────►  proofagent-verify -bundle bundle.json
                                  valid: true

                                  (tamper result status)
                                  valid: false
```

Company B needs **only**:
1. The receipt (or evidence bundle)
2. The agent’s public key (or passport containing it)

Company B does **not** need:
- Company A’s dashboard
- Company A’s database
- ProofAgent cloud connectivity

## CLI

```bash
go build -o bin/proofagent-verify ./cmd/proofagent-verify

# From bundle
./bin/proofagent-verify -bundle bundle.json

# From parts
./bin/proofagent-verify -receipt receipt.json -pubkey BASE64_ED25519
```

## Bundle shape

```json
{
  "bundle_version": "0.1",
  "receipt": { "...ActionReceipt..." },
  "public_key": "<base64>",
  "algorithm": "Ed25519"
}
```

## Script

```bash
# API running
./scripts/phase3_company_ab.sh
```
