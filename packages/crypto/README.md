# packages/crypto

Shared cryptographic primitives for ProofAgent.

**Must implement exactly the rules in `docs/CRYPTO.md`.**

## Responsibilities

- Canonical JSON serialization
- SHA-256 hashing with `sha256:` prefix
- Ed25519 sign / verify
- Receipt hash construction
- Chain linkage helpers

## Language targets (v0)

- Go (primary, used by services)
- Python (SDK)
- TypeScript (SDK)

Implementations in different languages **must** produce identical hashes and signatures for the same logical object.
