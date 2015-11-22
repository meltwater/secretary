package main

import (
	"crypto/rand"
	"encoding/base64"
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

func decryptEnvelope(senderPublicKey *[32]byte, receiverPrivateKey *[32]byte, envelope []byte, msg string) []byte {
	encoded := envelope[9 : len(envelope)-1]
	encrypted := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(encrypted, encoded)
	check(err, "Failed to decode base64 data from standard input")

	var nonce [24]byte
	copy(nonce[:], encrypted)
	plaintext, ok := box.Open(nil, encrypted[24:n], &nonce, senderPublicKey, receiverPrivateKey)
	assert(ok, "Decryption failed (%s)", msg)

	return plaintext
}

// Decrypts data from stdin and writes to stdout
func decryptStream(senderPublicKey *[32]byte, receiverPrivateKey *[32]byte) {
	envelope, err := ioutil.ReadAll(os.Stdin)
	check(err, "Failed to read encrypted data from standard input")

	plaintext := decryptEnvelope(senderPublicKey, receiverPrivateKey, envelope, "incorrect keys?")
	os.Stdout.Write(plaintext)
}

// Decrypts environment variables and writes them to stdout
func decryptEnvironment(senderPublicKey *[32]byte, receiverPrivateKey *[32]byte) {
	for _, item := range os.Environ() {
		keyval := strings.SplitN(item, "=", 2)
		key, value := keyval[0], keyval[1]

		if strings.HasPrefix(value, "ENC[NACL,") && strings.HasSuffix(value, "]") {
			plaintext := decryptEnvelope(senderPublicKey, receiverPrivateKey, []byte(value), key)

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
