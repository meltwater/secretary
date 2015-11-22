package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Checked exception thrown on runtime errors
type CommandError struct {
	msg string // description of error
	err error  // inner error
}

func (e *CommandError) Error() string { return e.msg }

// Panics with a message if the given error isn't nil
func check(err error, msg string, a ...interface{}) {
	if err != nil {
		panic(&CommandError{fmt.Sprintf("%s (%s)", fmt.Sprintf(msg, a...), err), err})
	}
}

// Panics with a message if the given condition isn't true
func assert(condition bool, msg string, a ...interface{}) {
	if !condition {
		panic(&CommandError{fmt.Sprintf(msg, a...), nil})
	}
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
