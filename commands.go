package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

const maxLineLength = 64

// Encrypts data from stdin and writes to stdout
func encryptCommand(input io.Reader, output io.Writer, publicKey *[32]byte, privateKey *[32]byte, wrapLines bool) {
	plaintext, err := ioutil.ReadAll(input)
	check(err, "Failed to read plaintext data from standard input")

	envelope, err := encryptEnvelope(publicKey, privateKey, plaintext)
	check(err)

	if wrapLines {
		for i := 0; i < len(envelope); i += maxLineLength {
			output.Write([]byte(envelope[i:min(i+maxLineLength, len(envelope))]))
			output.Write([]byte("\n"))
		}
	} else {
		output.Write([]byte(envelope))
	}
}

// Decrypts data from stdin and writes to stdout
func decryptStream(input io.Reader, output io.Writer, crypto Crypto) {
	envelope, err := ioutil.ReadAll(input)
	check(err, "Failed to read encrypted data from standard input")

	mangled := stripWhitespace(string(envelope))
	plaintext, err := crypto.Decrypt(mangled)
	check(err)

	output.Write(plaintext)
}

// Decrypts environment variables and writes them to stdout
func decryptEnvironment(input []string, output io.Writer, crypto Crypto) {
	haserr := false

	for _, item := range input {
		keyval := strings.SplitN(item, "=", 2)
		key, value := keyval[0], keyval[1]
		mangled := stripWhitespace(value)

		if isEnvelope(mangled) {
			plaintext, err := crypto.Decrypt(mangled)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %s\n", key, err)
				haserr = true
				continue
			}

			// TODO: needs shell escaping of plaintext value
			fmt.Fprintf(output, "export %s='%s'\n", key, plaintext)
		}
	}

	if haserr {
		os.Exit(1)
	}
}
