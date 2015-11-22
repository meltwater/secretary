package main

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/nacl/box"
)

// Generates an NaCL key-pair
func genkey(publicKeyFile string, privateKeyFile string) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	check(err, "Failed to generate key pair")

	pemWrite(publicKey, publicKeyFile, "NACL PUBLIC KEY", 0644)
	pemWrite(privateKey, privateKeyFile, "NACL PRIVATE KEY", 0600)
}

// Decrypts a NaCL box
func decrypt(senderPublicKey *[32]byte, receiverPrivateKey *[32]byte, encrypted []byte) ([]byte, error) {
	if len(encrypted) <= 24 {
		return nil, errors.New("Expected at least 25 bytes of encrypted data")
	}

	var nonce [24]byte
	copy(nonce[:], encrypted)

	plaintext, ok := box.Open(nil, encrypted[24:], &nonce, senderPublicKey, receiverPrivateKey)
	if !ok {
		return nil, errors.New("Failed to decrypt (incorrect keys?)")
	}

	return plaintext, nil
}
