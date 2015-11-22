package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
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

// Encrypt into a NaCL box
func encrypt(publicKey *[32]byte, privateKey *[32]byte, plaintext []byte) ([]byte, error) {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, errors.New("Failed generate random nonce")
	}

	return box.Seal(nonce[:], plaintext, &nonce, publicKey, privateKey), nil
}

// Decrypts a NaCL box
func decrypt(publicKey *[32]byte, privateKey *[32]byte, encrypted []byte) ([]byte, error) {
	if len(encrypted) <= 24 {
		return nil, errors.New("Expected at least 25 bytes of encrypted data")
	}

	var nonce [24]byte
	copy(nonce[:], encrypted)

	plaintext, ok := box.Open(nil, encrypted[24:], &nonce, publicKey, privateKey)
	if !ok {
		return nil, errors.New("Failed to decrypt (incorrect keys?)")
	}

	return plaintext, nil
}

// Generic decryption mechanism
type Crypto interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(envelope string) ([]byte, error)
}

// Decrypts using in-memory keys
type KeyCrypto struct {
	PublicKey, PrivateKey *[32]byte
}

func (self *KeyCrypto) Encrypt(plaintext []byte) (string, error) {
	encrypted, err := encrypt(self.PublicKey, self.PrivateKey, plaintext)
	if err != nil {
		return "", err
	}

	return createEnvelope(encrypted), nil
}

func (self *KeyCrypto) Decrypt(envelope string) ([]byte, error) {
	encrypted, err := parseEnvelope(envelope)
	if err != nil {
		return nil, err
	}

	return decrypt(self.PublicKey, self.PrivateKey, encrypted)
}

func NewKeyCrypto(publicKey *[32]byte, privateKey *[32]byte) *KeyCrypto {
	return &KeyCrypto{PublicKey: publicKey, PrivateKey: privateKey}
}

// Decrypts using the secretary daemon
type RemoteCrypto struct {
	DaemonUrl             string
	PublicKey, PrivateKey *[32]byte
}

func NewRemoteCrypto(url string, publicKey *[32]byte, privateKey *[32]byte) *RemoteCrypto {
	return &RemoteCrypto{DaemonUrl: url, PublicKey: publicKey, PrivateKey: privateKey}
}

func (self *RemoteCrypto) Encrypt(plaintext []byte) (string, error) {
	encrypted, err := encrypt(self.PublicKey, self.PrivateKey, plaintext)
	if err != nil {
		return "", err
	}

	return createEnvelope(encrypted), nil
}

func (self *RemoteCrypto) Decrypt(envelope string) ([]byte, error) {
	response, err := http.PostForm(fmt.Sprintf("%s/v1/decrypt", self.DaemonUrl), url.Values{"envelope": {envelope}})
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt using daemon (%s)", err))
	}

	defer response.Body.Close()
	responseEnvelope, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt using daemon (%s)", err))
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt using daemon (HTTP %d Error: %s)", response.StatusCode, ellipsis(string(responseEnvelope), 64)))
	}

	responseEncrypted, err := parseEnvelope(string(responseEnvelope))
	if err != nil {
		return nil, err
	}

	return decrypt(self.PublicKey, self.PrivateKey, responseEncrypted)
}
