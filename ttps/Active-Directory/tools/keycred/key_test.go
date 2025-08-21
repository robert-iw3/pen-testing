package keycred_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/RedTeamPentesting/keycred"
)

func TestMarshalUnmarshalKeyMaterial(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	buffer, err := keycred.MarshalPublicKeyMaterial(&key.PublicKey, false)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	parsedKey, isDer, err := keycred.UnmarshalPublicKeyMaterial(buffer)
	if err != nil {
		t.Fatalf("unmarshal public key: %v", err)
	}

	if isDer {
		t.Fatalf("UnmarshalPublicKeyMaterial claims key is in DER format")
	}

	if !key.PublicKey.Equal(parsedKey) {
		t.Fatalf("key mismatch")
	}
}

func TestDERMarshalUnmarshalKeyMaterial(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	buffer, err := keycred.MarshalPublicKeyMaterial(&key.PublicKey, true)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	parsedKey, isDer, err := keycred.UnmarshalPublicKeyMaterial(buffer)
	if err != nil {
		t.Fatalf("unmarshal public key: %v", err)
	}

	if !isDer {
		t.Fatalf("UnmarshalPublicKeyMaterial claims key is not in DER format")
	}

	if !key.PublicKey.Equal(parsedKey) {
		t.Fatalf("key mismatch")
	}
}
