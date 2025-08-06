package utils

import (
	"crypto/rand"
	"encoding/base64"
	"log"
)

func GenerateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Error generating random string: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}
