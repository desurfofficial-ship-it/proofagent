package receipts

import (
	"testing"

	"github.com/desurfofficial-ship-it/proofagent/packages/crypto"
)

func TestBuildAndVerify(t *testing.T) {
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	body := Body{
		ReceiptVersion: "0.1",
		ReceiptID:      "rcpt_1",
		Sequence:       1,
		Timestamp:      "2026-09-29T22:00:00Z",
		Principal:      map[string]any{"id": "usr_1"},
		Agent:          map[string]any{"id": "agt_1", "version": "0.1"},
		Authorization:  map[string]any{"authorization_id": "auth_1", "decision": "ALLOW"},
		Action:         map[string]any{"type": "tool_call", "tool": "calendar.read"},
		Result:         map[string]any{"status": "success", "hash": "sha256:abc"},
		PreviousReceiptHash: crypto.GenesisHash,
	}
	r, err := Build(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	if r.ReceiptHash == "" || r.Signature == "" {
		t.Fatal("missing hash or sig")
	}
	vr := Verify(r, pub, crypto.GenesisHash)
	if !vr.Valid {
		t.Fatalf("verify failed: %+v", vr)
	}
}

func TestTamperDetected(t *testing.T) {
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	body := Body{
		ReceiptID:           "rcpt_2",
		Sequence:            1,
		Principal:           map[string]any{"id": "usr_1"},
		Agent:               map[string]any{"id": "agt_1"},
		Authorization:       map[string]any{"decision": "ALLOW"},
		Action:              map[string]any{"tool": "x"},
		PreviousReceiptHash: crypto.GenesisHash,
	}
	r, err := Build(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	r.Action["tool"] = "tampered"
	vr := Verify(r, pub, crypto.GenesisHash)
	if vr.Valid || vr.Checks.ReceiptHash {
		t.Fatal("tamper should invalidate hash")
	}
}

func TestWrongKey(t *testing.T) {
	_, priv, _ := crypto.GenerateKeyPair()
	pub2, _, _ := crypto.GenerateKeyPair()
	body := Body{
		ReceiptID: "rcpt_3", Sequence: 1,
		Principal: map[string]any{"id": "u"}, Agent: map[string]any{"id": "a"},
		Authorization: map[string]any{"decision": "ALLOW"}, Action: map[string]any{"tool": "t"},
		PreviousReceiptHash: crypto.GenesisHash,
	}
	r, _ := Build(body, priv)
	vr := Verify(r, pub2, crypto.GenesisHash)
	if vr.Valid || vr.Checks.Signature {
		t.Fatal("wrong key should fail signature")
	}
}
