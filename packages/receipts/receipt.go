package receipts

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/desurfofficial-ship-it/proofagent/packages/crypto"
)

// Body is the receipt content without receipt_hash and signature.
// Used for hashing per docs/CRYPTO.md.
type Body struct {
	ReceiptVersion      string         `json:"receipt_version"`
	ReceiptID           string         `json:"receipt_id"`
	Sequence            int64          `json:"sequence"`
	Timestamp           string         `json:"timestamp"`
	Principal           map[string]any `json:"principal"`
	Agent               map[string]any `json:"agent"`
	Authority           map[string]any `json:"authority,omitempty"`
	Authorization       map[string]any `json:"authorization"`
	Policy              map[string]any `json:"policy,omitempty"`
	Action              map[string]any `json:"action"`
	Input               map[string]any `json:"input,omitempty"`
	Result              map[string]any `json:"result,omitempty"`
	Approval            map[string]any `json:"approval,omitempty"`
	Security            map[string]any `json:"security,omitempty"`
	PreviousReceiptHash string         `json:"previous_receipt_hash"`
}

// Receipt is Body + hash + signature.
type Receipt struct {
	Body
	ReceiptHash string `json:"receipt_hash"`
	Signature   string `json:"signature"`
}

// Build creates a signed receipt. privateKey signs the receipt_hash string.
func Build(body Body, privateKey ed25519.PrivateKey) (*Receipt, error) {
	if body.ReceiptVersion == "" {
		body.ReceiptVersion = "0.1"
	}
	if body.Timestamp == "" {
		body.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if body.PreviousReceiptHash == "" {
		body.PreviousReceiptHash = crypto.GenesisHash
	}
	hash, err := crypto.HashObject(body)
	if err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}
	sig, err := crypto.SignReceiptHash(privateKey, hash)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return &Receipt{
		Body:        body,
		ReceiptHash: hash,
		Signature:   sig,
	}, nil
}

// VerifyChecks are granular verification results.
type VerifyChecks struct {
	Signature      bool `json:"signature"`
	ReceiptHash    bool `json:"receipt_hash"`
	ChainIntegrity bool `json:"chain_integrity"` // checked if expectedPrev provided
}

// VerifyResult is the independent verification response.
type VerifyResult struct {
	Valid  bool         `json:"valid"`
	Checks VerifyChecks `json:"checks"`
	Error  string       `json:"error,omitempty"`
}

// Verify checks hash and signature. expectedPrev if non-empty must match PreviousReceiptHash.
func Verify(r *Receipt, publicKey ed25519.PublicKey, expectedPrev string) VerifyResult {
	out := VerifyResult{Checks: VerifyChecks{}}
	if r == nil {
		out.Error = "nil_receipt"
		return out
	}
	// Recompute hash over body (without hash/sig)
	computed, err := crypto.HashObject(r.Body)
	if err != nil {
		out.Error = "hash_error"
		return out
	}
	out.Checks.ReceiptHash = computed == r.ReceiptHash
	if err := crypto.VerifyReceiptHash(publicKey, r.ReceiptHash, r.Signature); err == nil {
		out.Checks.Signature = true
	}
	if expectedPrev != "" {
		out.Checks.ChainIntegrity = r.PreviousReceiptHash == expectedPrev
	} else {
		out.Checks.ChainIntegrity = true // not checked
	}
	out.Valid = out.Checks.ReceiptHash && out.Checks.Signature && out.Checks.ChainIntegrity
	if !out.Valid && out.Error == "" {
		out.Error = "verification_failed"
	}
	return out
}
