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
func encryptCommand(input io.Reader, output io.Writer, crypto EncryptionStrategy, wrapLines bool) {
	plaintext, err := ioutil.ReadAll(input)
	check(err, "Failed to read plaintext data from standard input")

	envelope, err := crypto.Encrypt(plaintext)
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
func decryptStream(input io.Reader, output io.Writer, crypto DecryptionStrategy) {
	payload, err := ioutil.ReadAll(input)
	check(err, "Failed to read encrypted data from standard input")
	result := string(payload)

	envelopes := extractEnvelopes(string(payload))
	if len(envelopes) > 0 {
		for _, envelope := range envelopes {
			plaintext, err := crypto.Decrypt(stripWhitespace(envelope))
			check(err)

			result = strings.Replace(result, envelope, string(plaintext), 1)
		}
	}

	output.Write([]byte(result))
}

// Decrypts environment variables and writes them to stdout
func decryptEnvironment(input []string, output io.Writer, crypto DecryptionStrategy) {
	haserr := false

	for _, item := range input {
		keyval := strings.SplitN(item, "=", 2)
		key, value := keyval[0], keyval[1]
		result := value

		envelopes := extractEnvelopes(value)
		if len(envelopes) > 0 {
			for _, envelope := range envelopes {
				plaintext, err := crypto.Decrypt(stripWhitespace(envelope))
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %s\n", key, err)
					haserr = true
					continue
				}

				result = strings.Replace(result, envelope, string(plaintext), 1)
			}

			fmt.Fprintf(output, "export %s='%s'\n", key, result)
		}
	}

	if haserr {
		os.Exit(1)
	}
}
