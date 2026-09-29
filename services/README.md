# services

Go services:

- `api` — HTTP surface, auth, tenancy, routing
- `authorization` — policy evaluation + authorization lifecycle
- `receipts` — canonicalization, hashing, signing, persistence, chain
- `verification` — independent verification API

Start with a single binary that hosts the necessary routes if that accelerates the vertical slice; split later.
