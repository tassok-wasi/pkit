package utils

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestGetKeyGenerators(t *testing.T) {
	t.Run("GetRSAKey", func(t *testing.T) {
		bits := 2048
		priv, pub, err := GetRSAKey(bits)
		if err != nil {
			t.Fatalf("GetRSAKey failed: %v", err)
		}
		if priv == nil || pub == nil {
			t.Fatal("Returned RSA keys should not be nil")
		}
		if priv.N.BitLen() < bits-1 || priv.N.BitLen() > bits+1 {
			t.Errorf("Expected RSA key size close to %d, got %d", bits, priv.N.BitLen())
		}
		if !priv.PublicKey.Equal(pub) {
			t.Error("Public key mismatch from generated RSA private key")
		}
	})

	t.Run("GetECDSAKey", func(t *testing.T) {
		curve := elliptic.P256()
		priv, pub, err := GetECDSAKey(curve)
		if err != nil {
			t.Fatalf("GetECDSAKey failed: %v", err)
		}
		if priv == nil || pub == nil {
			t.Fatal("Returned ECDSA keys should not be nil")
		}
		if priv.Curve != curve {
			t.Errorf("Expected curve %v, got %v", curve, priv.Curve)
		}
		if !priv.PublicKey.Equal(pub) {
			t.Error("Public key mismatch from generated ECDSA private key")
		}
	})

	t.Run("GetED25519Key", func(t *testing.T) {
		priv, pub, err := GetED25519Key()
		if err != nil {
			t.Fatalf("GetED25519Key failed: %v", err)
		}
		if len(priv) != ed25519.PrivateKeySize {
			t.Errorf("Expected private key length %d, got %d", ed25519.PrivateKeySize, len(priv))
		}
		if len(pub) != ed25519.PublicKeySize {
			t.Errorf("Expected public key length %d, got %d", ed25519.PublicKeySize, len(pub))
		}
		if !priv.Public().(ed25519.PublicKey).Equal(pub) {
			t.Error("Public key mismatch from generated Ed25519 private key")
		}
	})
}

// randReaderShim helps satisfy crypto/rand reader without global state mutation
type randReaderShim struct{}

func (randReaderShim) Read(b []byte) (int, error) {
	return rand.Reader.Read(b)
}
