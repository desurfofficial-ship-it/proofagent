// proofagent-verify: offline independent receipt verification.
// Company B does NOT need Company A's API or dashboard.
//
//	proofagent-verify -receipt receipt.json -pubkey KEY_B64
//	proofagent-verify -bundle bundle.json
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/desurfofficial-ship-it/proofagent/packages/crypto"
	"github.com/desurfofficial-ship-it/proofagent/packages/receipts"
)

func main() {
	receiptPath := flag.String("receipt", "", "path to receipt JSON")
	pubkey := flag.String("pubkey", "", "base64 Ed25519 public key")
	bundlePath := flag.String("bundle", "", "path to evidence bundle (receipt + public_key)")
	expectPrev := flag.String("prev", "", "expected previous_receipt_hash (optional; defaults to receipt field)")
	flag.Parse()

	var rec receipts.Receipt
	var pubB64 string

	if *bundlePath != "" {
		b, err := os.ReadFile(*bundlePath)
		if err != nil {
			fail(err)
		}
		var bundle struct {
			Receipt   receipts.Receipt `json:"receipt"`
			PublicKey string           `json:"public_key"`
			Passport  map[string]any   `json:"passport,omitempty"`
		}
		if err := json.Unmarshal(b, &bundle); err != nil {
			fail(err)
		}
		rec = bundle.Receipt
		pubB64 = bundle.PublicKey
		if pubB64 == "" && bundle.Passport != nil {
			if pk, ok := bundle.Passport["public_key"].(map[string]any); ok {
				if k, ok := pk["key"].(string); ok {
					pubB64 = k
				}
			}
		}
	} else {
		if *receiptPath == "" || *pubkey == "" {
			fmt.Fprintln(os.Stderr, "usage: proofagent-verify -receipt receipt.json -pubkey BASE64")
			fmt.Fprintln(os.Stderr, "   or: proofagent-verify -bundle bundle.json")
			os.Exit(2)
		}
		b, err := os.ReadFile(*receiptPath)
		if err != nil {
			fail(err)
		}
		if err := json.Unmarshal(b, &rec); err != nil {
			fail(err)
		}
		pubB64 = *pubkey
	}

	pub, err := crypto.PublicKeyFromBase64(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fail(fmt.Errorf("invalid public key"))
	}

	prev := *expectPrev
	if prev == "" {
		prev = rec.PreviousReceiptHash
	}
	vr := receipts.Verify(&rec, pub, prev)

	out := map[string]any{
		"valid":  vr.Valid,
		"checks": vr.Checks,
		"receipt_id": rec.ReceiptID,
		"agent_id":   rec.Agent["id"],
		"mode":       "offline_independent",
	}
	if !vr.Valid {
		out["error"] = vr.Error
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	if !vr.Valid {
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
