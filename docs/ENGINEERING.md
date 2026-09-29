# Engineering Kickoff Summary

Full ticket list, acceptance criteria, adversarial test matrix, and release gates live in Notion:

**ProofAgent — Engineering Kickoff Pack**

## First PR sequence (from Kickoff Pack)

1. chore: bootstrap monorepo and local infra ✅ (this commit)
2. feat: add organization and API authentication
3. feat: add agent lifecycle
4. feat: add Ed25519 key registry
5. feat: issue signed passports
6. feat: add policy schema and validator
7. feat: add deterministic policy evaluator
8. feat: add authorization lifecycle
9. feat: add approval tokens
10. feat: add canonical action receipts
11. feat: add receipt hash chain
12. feat: add independent verification
13. test: add adversarial receipt and replay suite
14. feat: add Python SDK
15. feat: add TypeScript SDK
16. feat: add MCP middleware
...

## Principle

Build the proof loop first.  
If `authorize → execute → receipt → verify` is not rock-solid, everything else is premature.
