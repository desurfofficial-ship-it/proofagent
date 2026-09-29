package crypto

import (
	"testing"
)

func TestCanonicalJSON_SortedKeys(t *testing.T) {
	obj := map[string]any{
		"z": 1,
		"a": "hello",
		"m": true,
	}
	b, err := CanonicalJSON(obj)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"hello","m":true,"z":1}`
	if string(b) != want {
		t.Fatalf("got %s want %s", b, want)
	}
}

func TestCanonicalJSON_Nested(t *testing.T) {
	obj := map[string]any{
		"b": map[string]any{"y": 2, "x": 1},
		"a": []any{3, 1, 2},
	}
	b, err := CanonicalJSON(obj)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":[3,1,2],"b":{"x":1,"y":2}}`
	if string(b) != want {
		t.Fatalf("got %s want %s", b, want)
	}
}

func TestHashObject_Stable(t *testing.T) {
	obj := map[string]any{"agent_id": "agt_1", "seq": 1}
	h1, err := HashObject(obj)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashObject(obj)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("hash not stable")
	}
	if len(h1) != 7+64 {
		t.Fatalf("unexpected hash length %d", len(h1))
	}
	if h1[:7] != "sha256:" {
		t.Fatal("missing prefix")
	}
}

func TestSignVerifyReceiptHash(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	hash := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sig, err := SignReceiptHash(priv, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceiptHash(pub, hash, sig); err != nil {
		t.Fatal(err)
	}
	// Tamper
	if err := VerifyReceiptHash(pub, hash+"x", sig); err == nil {
		t.Fatal("expected verification failure")
	}
}

func TestGenesisHash(t *testing.T) {
	if GenesisHash != "sha256:0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatal("genesis constant mismatch")
	}
}
