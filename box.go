package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

var envelopeRegexp = regexp.MustCompile("ENC\\[(NACL|KMS),[a-zA-Z0-9+/=\\s]+\\]")

// Converts a byte slice to the [32]byte expected by NaCL
func asKey(data []byte) (*[32]byte, error) {
	if len(data) != 32 {
		return nil, errors.New("Expected a 32 byte key")
	}

	var key [32]byte
	copy(key[:], data[0:32])
	return &key, nil
}

// Converts a byte slice to the [24]byte expected by NaCL
func asNonce(data []byte) (*[24]byte, error) {
	if len(data) != 24 {
		return nil, errors.New("Expected a 24 byte nonce")
	}

	var key [24]byte
	copy(key[:], data[0:24])
	return &key, nil
}

// Encode key to a PEM string
func pemEncode(key *[32]byte, pemType string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: key[:]}))
}

// Decode a PEM string
func pemDecode(encoded string) (*[32]byte, error) {
	mangled := strings.TrimSpace(encoded)

	if !strings.HasPrefix(mangled, "-----BEGIN") {
		mangled = fmt.Sprintf("-----BEGIN KEY-----\n%s\n-----END KEY-----", mangled)
	}

	pemBlock, _ := pem.Decode([]byte(mangled))
	if pemBlock == nil {
		return nil, errors.New("Failed to decode PEM block")
	}

	return asKey(pemBlock.Bytes)
}

// Serialize a NaCL key to a PEM file
func pemWrite(key *[32]byte, path string, pemType string, fileMode os.FileMode) {
	pemData := pemEncode(key, pemType)
	check(os.MkdirAll(filepath.Dir(path), 0775), "Failed to create directory %s", filepath.Dir(path))
	check(ioutil.WriteFile(path, []byte(pemData), fileMode), "Failed to write file %s", path)
}

// Deserialize a PEM file to a NaCL key
func pemRead(path string) *[32]byte {
	encoded, err := ioutil.ReadFile(path)
	check(err, "Failed to read key from %s", path)

	key, err := pemDecode(string(encoded))
	check(err, "Expected key %s to be at least 32 bytes", path)
	return key
}

// Find a key in a candidate list of env variable keys and filenames
// Returns nil if no key is found
func findKey(locations ...string) *[32]byte {
	for _, location := range locations {
		if location == "" {
			continue
		}

		encoded := os.Getenv(location)
		if encoded != "" {
			key, err := pemDecode(encoded)
			check(err, "Failed to decode key in $%s", location)
			return key
		}

		if _, err := os.Stat(location); err == nil {
			return pemRead(location)
		}
	}

	return nil
}

// Find a key in a candidate list of env variable keys and filenames
// Panics if no key is found
func requireKey(name string, locations ...string) *[32]byte {
	key := findKey(locations...)
	assertThat(key != nil, "Failed to find a %s key", name)
	return key
}

func decode(encoded string) ([]byte, error) {
	message := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(message, []byte(encoded))
	if err != nil {
		return nil, err
	}

	return message[0:n], nil
}

func encode(message []byte) string {
	return base64.StdEncoding.EncodeToString(message)
}

func decodeKey(encoded string) (*[32]byte, error) {
	bytes, err := decode(encoded)
	if err != nil {
		return nil, err
	}

	return asKey(bytes)
}

func decodeNonce(encoded string) (*[24]byte, error) {
	bytes, err := decode(encoded)
	if err != nil {
		return nil, err
	}

	return asNonce(bytes)
}

// Generates an NaCL key-pair
func genkey(publicKeyFile string, privateKeyFile string) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	check(err, "Failed to generate key pair")

	pemWrite(publicKey, publicKeyFile, "NACL PUBLIC KEY", 0644)
	pemWrite(privateKey, privateKeyFile, "NACL PRIVATE KEY", 0600)
}

func decryptEnvelopes(input string, decryptor DecryptionStrategy) (output string, err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("%v", r)
			}
		}
	}()

	repl := func(envelope string) string {
		bytes, err := decryptor.Decrypt(envelope)
		if err != nil {
			panic(err)
		}
		return string(bytes)
	}

	output = envelopeRegexp.ReplaceAllStringFunc(input, repl)
	return
}

func extractEnvelopes(payload string) []string {
	return envelopeRegexp.FindAllString(payload, -1)
}

func extractEnvelopeType(envelope string) string {
	submatches := envelopeRegexp.FindStringSubmatch(envelope)
	if submatches != nil {
		return submatches[1]
	}

	return ""
}

func encryptEnvelopeNonce(publicKey *[32]byte, privateKey *[32]byte, plaintext []byte, nonce *[24]byte) (string, error) {
	encrypted := box.Seal(nonce[:], plaintext, nonce, publicKey, privateKey)
	return fmt.Sprintf("ENC[NACL,%s]", encode(encrypted)), nil
}

func encryptEnvelope(publicKey *[32]byte, privateKey *[32]byte, plaintext []byte) (string, error) {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return "", errors.New("Failed generate random nonce")
	}

	return encryptEnvelopeNonce(publicKey, privateKey, plaintext, &nonce)
}

func decryptEnvelopeNonce(publicKey *[32]byte, privateKey *[32]byte, envelope string) ([]byte, *[24]byte, error) {
	if extractEnvelopeType(envelope) != "NACL" {
		return nil, nil, errors.New("Expected ENC[NACL,...] structured string")
	}

	encrypted, err := decode(envelope[9 : len(envelope)-1])
	if err != nil {
		return nil, nil, err
	}

	if len(encrypted) <= 24 {
		return nil, nil, errors.New("Expected at least 25 bytes of encrypted data")
	}

	var nonce [24]byte
	copy(nonce[:], encrypted)

	plaintext, ok := box.Open(nil, encrypted[24:], &nonce, publicKey, privateKey)
	if !ok {
		return nil, nil, errors.New("Failed to decrypt (incorrect keys?)")
	}

	return plaintext, &nonce, nil
}

func decryptEnvelope(publicKey *[32]byte, privateKey *[32]byte, envelope string) ([]byte, error) {
	plaintext, _, err := decryptEnvelopeNonce(publicKey, privateKey, envelope)
	return plaintext, err
}
