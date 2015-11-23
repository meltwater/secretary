package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Converts a byte slice to the [32]byte expected by NaCL
func asKey(data []byte) (*[32]byte, error) {
	if len(data) != 32 {
		return nil, errors.New("Expected a 32 byte key")
	}

	var key [32]byte
	copy(key[:], data[0:32])
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

func isEnvelope(envelope string) bool {
	return strings.HasPrefix(envelope, "ENC[NACL,") && strings.HasSuffix(envelope, "]")
}

func encryptEnvelope(publicKey *[32]byte, privateKey *[32]byte, plaintext []byte) (string, error) {
	encrypted, err := encrypt(publicKey, privateKey, plaintext)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("ENC[NACL,%s]", encode(encrypted)), nil
}

func decryptEnvelope(publicKey *[32]byte, privateKey *[32]byte, envelope string) ([]byte, error) {
	if !isEnvelope(envelope) {
		return nil, errors.New("Expected ENC[NACL,...] structured string")
	}

	encrypted, err := decode(envelope[9 : len(envelope)-1])
	if err != nil {
		return nil, err
	}

	return decrypt(publicKey, privateKey, encrypted)
}

// Generic decryption mechanism
type Crypto interface {
	Decrypt(envelope string) ([]byte, error)
}

// Decrypts using in-memory keys
type KeyCrypto struct {
	PublicKey, PrivateKey *[32]byte
}

func (self *KeyCrypto) Decrypt(envelope string) ([]byte, error) {
	return decryptEnvelope(self.PublicKey, self.PrivateKey, envelope)
}

func NewKeyCrypto(publicKey *[32]byte, privateKey *[32]byte) *KeyCrypto {
	return &KeyCrypto{PublicKey: publicKey, PrivateKey: privateKey}
}

// Decrypts using the secretary daemon
type RemoteCrypto struct {
	DaemonUrl, AppId, AppVersion, TaskId string
	ConfigKey, MasterKey, PrivateKey     *[32]byte
}

func NewRemoteCrypto(
	daemonUrl string, appId string, appVersion string, taskId string,
	configKey *[32]byte, masterKey *[32]byte, privateKey *[32]byte) *RemoteCrypto {
	return &RemoteCrypto{
		DaemonUrl: daemonUrl, AppId: appId, AppVersion: appVersion, TaskId: taskId,
		ConfigKey: configKey, MasterKey: masterKey, PrivateKey: privateKey}
}

func (self *RemoteCrypto) Decrypt(envelope string) ([]byte, error) {
	// Authenticate with config key and decrypt with service key
	configEnvelope, err := decryptEnvelope(self.ConfigKey, self.PrivateKey, envelope)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt secret parameter using config key and private service key (%s)", err))
	}

	// Encrypt with service key and send to daemon
	serviceEnvelope, err := encryptEnvelope(self.MasterKey, self.PrivateKey, configEnvelope)
	if err != nil {
		return nil, err
	}

	// Envelope is already encrypted with service key
	response, err := httpPostForm(fmt.Sprintf("%s/v1/decrypt", self.DaemonUrl), url.Values{
		"appid":      {self.AppId},
		"appversion": {self.AppVersion},
		"taskid":     {self.TaskId},
		"envelope":   {serviceEnvelope}})
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt using daemon (%s)", err))
	}

	// Decrypt response using application key
	plaintext, err := decryptEnvelope(self.MasterKey, self.PrivateKey, string(response))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt daemon response using master key and private service key (%s)", err))
	}

	return plaintext, nil
}
