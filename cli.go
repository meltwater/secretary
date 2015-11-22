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

// Encrypts data from stdin and writes to stdout
func encryptCommand(receiverPublicKeyFile string, senderPrivateKeyFile string) {
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

// Decrypts data from stdin and writes to stdout
func decryptStream(decryptor Decryptor) {
	envelope, err := ioutil.ReadAll(os.Stdin)
	check(err, "Failed to read encrypted data from standard input")

	plaintext, err := decryptor.Decrypt(string(envelope))
	check(err)

	os.Stdout.Write(plaintext)
}

// Decrypts environment variables and writes them to stdout
func decryptEnvironment(decryptor Decryptor) {
	haserr := false

	for _, item := range os.Environ() {
		keyval := strings.SplitN(item, "=", 2)
		key, value := keyval[0], keyval[1]

		if isEnvelope(value) {
			plaintext, err := decryptor.Decrypt(value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %s\n", key, err)
				haserr = true
				continue
			}

			// TODO: needs shell escaping of plaintext value
			fmt.Printf("export %s='%s'\n", key, plaintext)
		}
	}

	if haserr {
		os.Exit(1)
	}
}
