package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const HashPrefix = "sha256:"

// GenesisHash is the previous_receipt_hash for the first receipt of an agent.
const GenesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// SHA256Hex returns "sha256:" + lowercase hex of SHA-256(data).
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return HashPrefix + hex.EncodeToString(sum[:])
}

// HashObject canonicalizes v then returns SHA256Hex.
func HashObject(v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return SHA256Hex(b), nil
}

// ReceiptHash computes receipt_hash over the body excluding signature and receipt_hash fields.
// body must be a map or struct that marshals to an object without those fields.
func ReceiptHash(bodyWithoutSigAndHash any) (string, error) {
	return HashObject(bodyWithoutSigAndHash)
}

// ValidateHashPrefix checks format.
func ValidateHashPrefix(h string) error {
	if len(h) != 7+64 || h[:7] != HashPrefix {
		return fmt.Errorf("invalid hash format")
	}
	return nil
}
