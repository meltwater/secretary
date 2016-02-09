package main

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// EncryptionStrategy is a generic encryption mechanism
type EncryptionStrategy interface {
	Encrypt([]byte) (string, error)
}

// DecryptionStrategy is a generic decryption mechanism
type DecryptionStrategy interface {
	Decrypt(envelope string) ([]byte, error)
}

// CompositeDecryptionStrategy multiplexes other decryption strategies {NACL, KMS}
type CompositeDecryptionStrategy struct {
	Strategies map[string]DecryptionStrategy
}

// Decrypt decrypts an envelope
func (k *CompositeDecryptionStrategy) Decrypt(envelope string) ([]byte, error) {
	// Get the type of encryption {NACL, KMS}
	envelopeType := extractEnvelopeType(envelope)
	strategy := k.Strategies[envelopeType]

	if strategy != nil {
		return strategy.Decrypt(envelope)
	}

	return nil, fmt.Errorf("Not configured for decrypting ENC[%s,..] values", envelopeType)
}

// Add a new decryption strategy
func (k *CompositeDecryptionStrategy) Add(envelopeType string, strategy DecryptionStrategy) {
	k.Strategies[envelopeType] = strategy
}

func newCompositeDecryptionStrategy() *CompositeDecryptionStrategy {
	return &CompositeDecryptionStrategy{Strategies: make(map[string]DecryptionStrategy)}
}

// KeyEncryptionStrategy decrypts using in-memory keys
type KeyEncryptionStrategy struct {
	PublicKey, PrivateKey *[32]byte
}

// Encrypt encrypts a buffer and returns an envelope
func (k *KeyEncryptionStrategy) Encrypt(plaintext []byte) (string, error) {
	return encryptEnvelope(k.PublicKey, k.PrivateKey, plaintext)
}

func newKeyEncryptionStrategy(publicKey *[32]byte, privateKey *[32]byte) *KeyEncryptionStrategy {
	return &KeyEncryptionStrategy{PublicKey: publicKey, PrivateKey: privateKey}
}

// KeyDecryptionStrategy decrypts using in-memory keys
type KeyDecryptionStrategy struct {
	PublicKey, PrivateKey *[32]byte
}

// Decrypt decrypts an envelope
func (k *KeyDecryptionStrategy) Decrypt(envelope string) ([]byte, error) {
	return decryptEnvelope(k.PublicKey, k.PrivateKey, envelope)
}

func newKeyDecryptionStrategy(publicKey *[32]byte, privateKey *[32]byte) *KeyDecryptionStrategy {
	return &KeyDecryptionStrategy{PublicKey: publicKey, PrivateKey: privateKey}
}

// DaemonDecryptionStrategy decrypts using the secretary daemon
type DaemonDecryptionStrategy struct {
	DaemonURL, AppID, AppVersion, TaskID string
	MasterKey, DeployKey, ServiceKey     *[32]byte
}

func newDaemonDecryptionStrategy(
	daemonURL string, appID string, appVersion string, taskID string,
	masterKey *[32]byte, deployKey *[32]byte, serviceKey *[32]byte) *DaemonDecryptionStrategy {
	return &DaemonDecryptionStrategy{
		DaemonURL: daemonURL, AppID: appID, AppVersion: appVersion, TaskID: taskID,
		MasterKey: masterKey, DeployKey: deployKey, ServiceKey: serviceKey}
}

// Decrypt decrypts an envelope
func (r *DaemonDecryptionStrategy) Decrypt(envelope string) ([]byte, error) {
	message := DaemonRequest{
		AppID: r.AppID, AppVersion: r.AppVersion, TaskID: r.TaskID,
		RequestedSecret: envelope,
	}
	encoded, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}

	// Encrypt with service key and send to daemon
	if r.ServiceKey != nil {
		encryptedEnvelope, err := encryptEnvelope(r.MasterKey, r.ServiceKey, encoded)
		if err != nil {
			return nil, err
		}

		encoded = []byte(encryptedEnvelope)
	}

	// Encrypt with deploy key and send to daemon
	requestEnvelope, err := encryptEnvelope(r.MasterKey, r.DeployKey, encoded)
	if err != nil {
		return nil, err
	}

	// Envelope is already encrypted with service key
	response, err := httpPostForm(fmt.Sprintf("%s/v1/decrypt", r.DaemonURL), url.Values{
		"appid":      {r.AppID},
		"appversion": {r.AppVersion},
		"taskid":     {r.TaskID},
		"envelope":   {requestEnvelope}})
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt using daemon (%s)", err)
	}

	// Decrypt response using deploy key
	response, err = decryptEnvelope(r.MasterKey, r.DeployKey, string(response))
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt daemon response using deploy key (%s)", err)
	}

	// Decrypt response using service key
	if r.ServiceKey != nil {
		response, err = decryptEnvelope(r.MasterKey, r.ServiceKey, string(response))
		if err != nil {
			return nil, fmt.Errorf("Failed to decrypt daemon response using service key (%s)", err)
		}
	}

	// Unpack response struct
	var parsedResponse DaemonResponse
	err = json.Unmarshal(response, &parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse JSON respons (%s)", err)
	}

	plaintext, err := decode(parsedResponse.PlaintextSecret)
	if err != nil {
		return nil, fmt.Errorf("Failed to base64 decode plaintext secret (%s)", err)
	}

	return plaintext, nil
}
