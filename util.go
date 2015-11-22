package main

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Checked exception thrown on runtime errors
type CommandError struct {
	msg string // description of error
	err error  // inner error
}

func (e *CommandError) Error() string { return e.msg }

// Panics with a message if the given error isn't nil
func check(err error, a ...interface{}) {
	if err != nil {
		var msg string
		if len(a) > 0 {
			msg = fmt.Sprintf("%s (%s)", fmt.Sprintf(a[0].(string), a[1:]...), err)
		} else {
			msg = fmt.Sprintf("%s", err)
		}

		panic(&CommandError{msg, err})
	}
}

// Panics with a message if the given condition isn't true
func assert(condition bool, msg string, a ...interface{}) {
	if !condition {
		panic(&CommandError{fmt.Sprintf(msg, a...), nil})
	}
}

// Min value
func min(a int, b int) int {
	if a <= b {
		return a
	}

	return b
}

// Converts a byte slice to the [32]byte expected by NaCL
func asKey(data []byte) *[32]byte {
	var key [32]byte
	copy(key[:], data[0:32])
	return &key
}

// Serialize a NaCL key to a PEM file
func pemWrite(key *[32]byte, path string, pemType string, fileMode os.FileMode) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: key[:]})
	check(os.MkdirAll(filepath.Dir(path), 0775), "Failed to create directory %s", filepath.Dir(path))
	check(ioutil.WriteFile(path, pemData, fileMode), "Failed to write file %s", path)
}

// Deserialize a PEM file to a NaCL key
func pemRead(path string) *[32]byte {
	pemData, err := ioutil.ReadFile(path)
	check(err, "Failed to read key from %s", path)

	pemBlock, _ := pem.Decode(pemData)
	assert(len(pemBlock.Bytes) == 32, "Expected key %s to be at least 32 bytes", path)
	return asKey(pemBlock.Bytes)
}

func isEnvelope(envelope string) bool {
	return strings.HasPrefix(envelope, "ENC[NACL,") && strings.HasSuffix(envelope, "]")
}

func parseEnvelope(envelope string) ([]byte, error) {
	if !isEnvelope(envelope) {
		return nil, errors.New("Expected ENC[NACL,...] structured string")
	}

	encoded := envelope[9 : len(envelope)-1]
	encrypted := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(encrypted, []byte(encoded))
	if err != nil {
		return nil, err
	}

	return encrypted[0:n], nil
}

func createEnvelope(encrypted []byte) string {
	return fmt.Sprintf("ENC[NACL,%s]", base64.StdEncoding.EncodeToString(encrypted))
}

func ellipsis(input string, maxLength int) string {
	trimmed := strings.TrimSpace(input)
	if len(trimmed) > (maxLength - 3) {
		return fmt.Sprintf("%s...", strings.TrimSpace(trimmed[0:(maxLength-3)]))
	}

	return trimmed
}

func defaults(a ...string) string {
	for _, item := range a {
		if len(item) > 0 {
			return item
		}
	}

	return ""
}
