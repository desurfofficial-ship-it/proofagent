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
	bundlePath := flag.String("bundle", "", "path to evidence bundle v0.1/v0.2")
	expectPrev := flag.String("prev", "", "expected previous_receipt_hash (optional)")
	flag.Parse()

	var rec receipts.Receipt
	var pubB64 string
	var meta map[string]any

	if *bundlePath != "" {
		b, err := os.ReadFile(*bundlePath)
		if err != nil {
			fail(err)
		}
		var bundle map[string]any
		if err := json.Unmarshal(b, &bundle); err != nil {
			fail(err)
		}
		meta = bundle
		rb, _ := json.Marshal(bundle["receipt"])
		if err := json.Unmarshal(rb, &rec); err != nil {
			fail(err)
		}
		if pk, ok := bundle["public_key"].(string); ok {
			pubB64 = pk
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
		"valid":      vr.Valid,
		"checks":     vr.Checks,
		"receipt_id": rec.ReceiptID,
		"agent_id":   rec.Agent["id"],
		"mode":       "offline_independent",
	}
	if !vr.Valid {
		out["error"] = vr.Error
	}
	// Evidence summary from bundle v0.2
	if meta != nil {
		summary := map[string]any{}
		if v, ok := meta["bundle_version"]; ok {
			summary["bundle_version"] = v
		}
		if v, ok := meta["authorization"]; ok {
			summary["authorization"] = v
		}
		if v, ok := meta["policy"]; ok {
			summary["policy"] = v
		}
		if v, ok := meta["approval"]; ok {
			summary["approval"] = v
		}
		if v, ok := meta["chain"]; ok {
			summary["chain"] = v
		}
		if v, ok := meta["agent"]; ok {
			summary["agent"] = v
		}
		out["evidence"] = summary
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
