package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// Encrypts data from stdin and writes to stdout
func encryptCommand(publicKey *[32]byte, privateKey *[32]byte) {
	plaintext, err := ioutil.ReadAll(os.Stdin)
	check(err, "Failed to read plaintext data from standard input")

	envelope, err := encryptEnvelope(publicKey, privateKey, plaintext)
	check(err)

	os.Stdout.WriteString(envelope)
}

// Decrypts data from stdin and writes to stdout
func decryptStream(crypto Crypto) {
	envelope, err := ioutil.ReadAll(os.Stdin)
	check(err, "Failed to read encrypted data from standard input")

	plaintext, err := crypto.Decrypt(string(envelope))
	check(err)

	os.Stdout.Write(plaintext)
}

// Decrypts environment variables and writes them to stdout
func decryptEnvironment(crypto Crypto) {
	haserr := false

	for _, item := range os.Environ() {
		keyval := strings.SplitN(item, "=", 2)
		key, value := keyval[0], keyval[1]

		if isEnvelope(value) {
			plaintext, err := crypto.Decrypt(value)
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
