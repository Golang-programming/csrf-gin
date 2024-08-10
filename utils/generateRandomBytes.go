package utils

import (
	"crypto/rand"
	"log"
)

func GenerateRandomBytes(n int) []byte {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)

	if err != nil {
		log.Fatalf("")
		return nil
	}

	return bytes
}
