package main

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// Crypto is a Generic decryption mechanism
type Crypto interface {
	Decrypt(envelope string) ([]byte, error)
}

// KeyCrypto decrypts using in-memory keys
type KeyCrypto struct {
	PublicKey, PrivateKey *[32]byte
}

// Decrypt decrypts an envelope
func (k *KeyCrypto) Decrypt(envelope string) ([]byte, error) {
	return decryptEnvelope(k.PublicKey, k.PrivateKey, envelope)
}

func newKeyCrypto(publicKey *[32]byte, privateKey *[32]byte) *KeyCrypto {
	return &KeyCrypto{PublicKey: publicKey, PrivateKey: privateKey}
}

// RemoteCrypto decrypts using the secretary daemon
type RemoteCrypto struct {
	DaemonURL, AppID, AppVersion, TaskID string
	MasterKey, DeployKey, ServiceKey     *[32]byte
}

func newRemoteCrypto(
	daemonURL string, appID string, appVersion string, taskID string,
	masterKey *[32]byte, deployKey *[32]byte, serviceKey *[32]byte) *RemoteCrypto {
	return &RemoteCrypto{
		DaemonURL: daemonURL, AppID: appID, AppVersion: appVersion, TaskID: taskID,
		MasterKey: masterKey, DeployKey: deployKey, ServiceKey: serviceKey}
}

// Decrypt decrypts an envelope
func (r *RemoteCrypto) Decrypt(envelope string) ([]byte, error) {
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
