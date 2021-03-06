package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
)

const maxLineLength = 64

var shellIdentifierRegexp = regexp.MustCompile("^[A-Za-z_][A-Za-z0-9_]*$")

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
	result, err := decryptEnvelopes(string(payload), crypto)
	check(err, "Failed to decrypt from standard input")
	output.Write([]byte(result))
}

// Decrypts environment variables and writes them to stdout
func decryptEnvironment(input []string, output io.Writer, crypto DecryptionStrategy) (bool, error) {
	ok := true
	var err error

	for _, item := range input {
		keyval := strings.SplitN(item, "=", 2)
		key, value := keyval[0], keyval[1]
		result := value
		decryptedResult, suberr := decryptEnvelopes(result, crypto)
		if suberr != nil {
			ok = false
			err = suberr
			fmt.Fprintf(os.Stderr, "%s: %s\n", key, err)
			continue
		}
		if decryptedResult != result {
			if !shellIdentifierRegexp.Match([]byte(key)) {
				ok = false
				err = fmt.Errorf("the env var '%s' is not a valid shell script identifier. Only alphanumeric characters and underscores are supported, starting with an alphabetic or underscore character", key)
				fmt.Fprintf(os.Stderr, "%s: %s\n", key, err)
			}
			fmt.Fprintf(output, "export %s='%s'\n", key, decryptedResult)
		}
	}

	return ok, err
}

func createExecArgs(args []string, encryptedEnviron []string, crypto DecryptionStrategy) (cmd string, decryptedArgs []string, decryptedEnviron []string, err error) {

	cmd = args[0]
	decryptedArgs = make([]string, len(args))

	decryptedArgs[0] = path.Base(cmd) // By unix convention argv[0] has to be set to basename of command
	for i, arg := range args[1:] {
		decryptedArg, subErr := decryptEnvelopes(arg, crypto)
		if subErr != nil {
			err = fmt.Errorf("Error while decrypting argument: %v", subErr)
		}

		decryptedArgs[i+1] = decryptedArg
	}

	decryptedEnviron = make([]string, len(encryptedEnviron))
	for i, env := range encryptedEnviron {
		decryptedEnv, subErr := decryptEnvelopes(env, crypto)
		if subErr != nil {
			err = fmt.Errorf("Error while decrypting environment variables: %v", subErr)
		}

		decryptedEnviron[i] = decryptedEnv
	}

	return
}
