package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

// Generates an NaCL key-pair
func genkey(publicKeyFile string, privateKeyFile string) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	check(err, "Failed to generate key pair")

	pemWrite(publicKey, publicKeyFile, "NACL PUBLIC KEY", 0644)
	pemWrite(privateKey, privateKeyFile, "NACL PRIVATE KEY", 0600)
}

// Encrypts data from stdin and writes to stdout
func encrypt(receiverPublicKeyFile string, senderPrivateKeyFile string) {
	receiverPublicKey := pemRead(receiverPublicKeyFile)
	senderPrivateKey := pemRead(senderPrivateKeyFile)

	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	check(err, "Failed generate random nonce")

	plaintext, err := ioutil.ReadAll(os.Stdin)
	check(err, "Failed to read plaintext data from standard input")

	encrypted := box.Seal(nonce[:], plaintext, &nonce, receiverPublicKey, senderPrivateKey)
	fmt.Printf("ENC[NACL,%s]", base64.StdEncoding.EncodeToString(encrypted))
}

func decryptBox(senderPublicKey *[32]byte, receiverPrivateKey *[32]byte, encrypted []byte) ([]byte, error) {
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

// Decrypts data from stdin and writes to stdout
func decryptStream(senderPublicKey *[32]byte, receiverPrivateKey *[32]byte) {
	envelope, err := ioutil.ReadAll(os.Stdin)
	check(err, "Failed to read encrypted data from standard input")

	encrypted, err := parseEnvelope(string(envelope))
	check(err)

	plaintext, err := decryptBox(senderPublicKey, receiverPrivateKey, encrypted)
	check(err)

	os.Stdout.Write(plaintext)
}

// Decrypts environment variables and writes them to stdout
func decryptEnvironment(senderPublicKey *[32]byte, receiverPrivateKey *[32]byte) {
	for _, item := range os.Environ() {
		keyval := strings.SplitN(item, "=", 2)
		key, value := keyval[0], keyval[1]

		if isEnvelope(value) {
			encrypted, err := parseEnvelope(value)
			check(err)

			plaintext, err := decryptBox(senderPublicKey, receiverPrivateKey, encrypted)
			check(err, "%s: ", key)

			// TODO: needs shell escaping of plaintext value
			fmt.Printf("export %s='%s'\n", key, plaintext)
		}
	}
}

// Decrypts data from stdin and writes to stdout
func decrypt(senderPublicKeyFile string, receiverPrivateKeyFile string, decryptEnv bool) {
	senderPublicKey := pemRead(senderPublicKeyFile)
	receiverPrivateKey := pemRead(receiverPrivateKeyFile)

	if decryptEnv {
		decryptEnvironment(senderPublicKey, receiverPrivateKey)
	} else {
		decryptStream(senderPublicKey, receiverPrivateKey)
	}
}
