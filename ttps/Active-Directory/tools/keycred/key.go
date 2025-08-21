package keycred

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
)

// MarshalPublicKeyMaterial serializes an RSA public key in a bcrypt RSA key
// blob
// (https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob)
// or DER representation.
func MarshalPublicKeyMaterial(key *rsa.PublicKey, asDER bool) ([]byte, error) {
	if asDER {
		return x509.MarshalPKCS1PublicKey(key), nil
	}

	modulusBytes := key.N.Bytes()
	exponentBytes := big.NewInt(int64(key.E)).Bytes()

	var buf bytes.Buffer

	err := writeBinary(&buf, binary.LittleEndian,
		uint32(KeyTypeRSAPublic),
		uint32(8*key.Size()),
		uint32(len(exponentBytes)),
		uint32(len(modulusBytes)),
		uint32(0),
		uint32(0),
		exponentBytes,
		modulusBytes,
	)

	return buf.Bytes(), err
}

// UnmarshalPublicKeyMaterial parses binary key material in bcrypt RSA key blob
// (https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob)
// or DER format.
func UnmarshalPublicKeyMaterial(buffer []byte) (key *rsa.PublicKey, isDER bool, err error) {
	if isDerEncoded(buffer) {
		key, err := x509.ParsePKCS1PublicKey(buffer)
		if err != nil {
			return nil, false, fmt.Errorf("parse DER encoded public key: %w", err)
		}

		return key, true, nil
	}

	consumer := newConsumer(buffer, binary.LittleEndian)

	keyType := consumer.Uint32()
	if keyType != KeyTypeRSAPublic {
		return nil, false, fmt.Errorf("unsupported key type: 0x%x", keyType)
	}

	keySize := consumer.Uint32()
	exponentSize := int(consumer.Uint32())
	modulusSize := int(consumer.Uint32())
	prime1Size := int(consumer.Uint32())
	prime2Size := int(consumer.Uint32())

	exponentBytes := consumer.Bytes(exponentSize)
	modulusBytes := consumer.Bytes(modulusSize)
	_ = consumer.Bytes(prime1Size)
	_ = consumer.Bytes(prime2Size)

	exponent := big.NewInt(0)
	exponent.SetBytes(exponentBytes)

	key = &rsa.PublicKey{
		E: int(exponent.Int64()),
		N: big.NewInt(0),
	}

	key.N.SetBytes(modulusBytes)

	if 8*key.Size() != int(keySize) {
		return nil, false, fmt.Errorf("key size mismatch: actual=%d, advertized=%d", 8*key.Size(), keySize)
	}

	return key, false, consumer.Error()
}

func isDerEncoded(buffer []byte) bool {
	return len(buffer) > 0 && buffer[0] == 0x30
}
