# ProofAgent v0 — Canonicalization & Signing Rules

**Status: FROZEN**  
Any implementation that diverges from these rules is incorrect.

These rules are also recorded in the Engineering Kickoff Pack §5.

## 1. Canonical JSON Serialization

All objects that are hashed or signed **must** be serialized with these exact rules:

1. **UTF-8** encoding only.
2. **Sorted object keys** (lexicographic, Unicode code-point order).
3. **No insignificant whitespace** — compact form (`{"a":1,"b":2}`).
4. **Numbers**:
   - Integers as decimal without leading zeros or `+`.
   - Floats forbidden in v0 signed objects (use integers or strings for amounts if needed).
5. **Null**: explicit `null` is allowed and must be present if the field is defined in the schema.
6. **Omitted vs empty**:
   - Optional fields that are `null` or empty **must be omitted** unless the schema requires them.
   - Empty arrays `[]` and empty objects `{}` are allowed only when the field is required.
7. **String escaping**: standard JSON escaping only.
8. **No trailing commas**.
9. **No Unicode escapes** unless required by JSON (prefer raw UTF-8 characters).

Reference implementation target: produce the same byte sequence as Python’s  
`json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)`.

## 2. Hashing

- Algorithm: **SHA-256**
- Input: the exact canonical JSON bytes of the object **excluding** the `signature` field and the `receipt_hash` field itself.
- Output: lowercase hex string prefixed with `sha256:`  
  Example: `sha256:a3f2...`

## 3. Receipt Hash Construction

1. Create a copy of the receipt object.
2. Remove `signature` and `receipt_hash` (if present).
3. Canonicalize the remaining object.
4. Compute SHA-256 → this becomes `receipt_hash`.
5. Sign the **UTF-8 bytes of the `receipt_hash` string** with Ed25519.
6. Store both `receipt_hash` and `signature`.

## 4. Chain Linkage

- `previous_receipt_hash` = the `receipt_hash` of the immediately prior receipt for the same `agent_id`.
- Genesis receipt uses the constant:  
  `sha256:0000000000000000000000000000000000000000000000000000000000000000`
- Sequence number is **scoped per agent** (starts at 1, increments by 1, no gaps allowed in v0).

## 5. Passport Signing

Same rules as receipts:

- Canonicalize the passport body excluding `signature`.
- Hash → internal `passport_hash` (optional to store).
- Sign the hash (or the canonical bytes) with the issuer/agent key as defined.

## 6. Verification Steps (must be deterministic)

1. Recompute canonical form of the body (excluding signature + receipt_hash).
2. Recompute SHA-256 → must equal stored `receipt_hash`.
3. Verify Ed25519 signature over the `receipt_hash` using the registered public key for that agent/key_id.
4. Check `previous_receipt_hash` matches the prior receipt’s `receipt_hash` for that agent (or genesis constant).
5. Check agent status, key status, authorization status, policy version immutability, and expiration.
6. Return granular check results.

## 7. Forbidden in v0

- Floating-point numbers in signed objects
- Unsorted keys
- Pretty-printed JSON
- Signing the entire pretty-printed document
- Relying on language-specific JSON serializers without the exact rules above

**Never sign ambiguously serialized JSON.**
