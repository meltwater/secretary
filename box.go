package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Generates an NaCL key-pair
func genkey(publicKeyFile string, privateKeyFile string) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	check(err, "Failed to generate key pair")

	pemWrite(publicKey, publicKeyFile, "NACL PUBLIC KEY", 0644)
	pemWrite(privateKey, privateKeyFile, "NACL PRIVATE KEY", 0600)
}

// Decrypts a NaCL box
func decrypt(senderPublicKey *[32]byte, privateKey *[32]byte, encrypted []byte) ([]byte, error) {
	if len(encrypted) <= 24 {
		return nil, errors.New("Expected at least 25 bytes of encrypted data")
	}

	var nonce [24]byte
	copy(nonce[:], encrypted)

	plaintext, ok := box.Open(nil, encrypted[24:], &nonce, senderPublicKey, privateKey)
	if !ok {
		return nil, errors.New("Failed to decrypt (incorrect keys?)")
	}

	return plaintext, nil
}

// Generic decryption mechanism
type Decryptor interface {
	Decrypt(envelope string) ([]byte, error)
}

// Decrypts using in-memory keys
type KeyDecryptor struct {
	PublicKey, PrivateKey *[32]byte
}

func (self *KeyDecryptor) Decrypt(envelope string) ([]byte, error) {
	encrypted, err := parseEnvelope(envelope)
	if err != nil {
		return nil, err
	}

	return decrypt(self.PublicKey, self.PrivateKey, encrypted)
}

func NewKeyDecryptor(publicKey *[32]byte, privateKey *[32]byte) *KeyDecryptor {
	return &KeyDecryptor{PublicKey: publicKey, PrivateKey: privateKey}
}

// Decrypts using the secretary daemon
type RemoteDecryptor struct {
	Url string
}

func NewRemoteDecryptor(url string) *RemoteDecryptor {
	return &RemoteDecryptor{Url: url}
}

func (self *RemoteDecryptor) Decrypt(envelope string) ([]byte, error) {
	response, err := http.PostForm(fmt.Sprintf("%s/v1/decrypt", self.Url), url.Values{"envelope": {envelope}})
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt using daemon (%s)", err))
	}

	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt using daemon (%s)", err))
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt using daemon (HTTP %d Error: %s)", response.StatusCode, ellipsis(string(body), 64)))
	}

	return body, nil
}
