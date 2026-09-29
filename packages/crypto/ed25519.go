package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateKeyPair returns (publicKey, privateKey) for Ed25519.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// SignReceiptHash signs the UTF-8 bytes of the receipt_hash string.
func SignReceiptHash(privateKey ed25519.PrivateKey, receiptHash string) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
	}
	sig := ed25519.Sign(privateKey, []byte(receiptHash))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyReceiptHash verifies signature over the receipt_hash string.
func VerifyReceiptHash(publicKey ed25519.PublicKey, receiptHash, signatureB64 string) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size")
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(publicKey, []byte(receiptHash), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// PublicKeyToBase64 encodes public key.
func PublicKeyToBase64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// PublicKeyFromBase64 decodes public key.
func PublicKeyFromBase64(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}
