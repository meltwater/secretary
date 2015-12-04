package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

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

func newKeyCrypto(publicKey *[32]byte, privateKey *[32]byte) *KeyCrypto {
	return &KeyCrypto{PublicKey: publicKey, PrivateKey: privateKey}
}

// Decrypts using the secretary daemon
type RemoteCrypto struct {
	DaemonUrl, AppId, AppVersion, TaskId        string
	ConfigKey, MasterKey, DeployKey, ServiceKey *[32]byte
}

func newRemoteCrypto(
	daemonUrl string, appId string, appVersion string, taskId string,
	configKey *[32]byte, masterKey *[32]byte, deployKey *[32]byte, serviceKey *[32]byte) *RemoteCrypto {
	return &RemoteCrypto{
		DaemonUrl: daemonUrl, AppId: appId, AppVersion: appVersion, TaskId: taskId,
		ConfigKey: configKey, MasterKey: masterKey, DeployKey: deployKey, ServiceKey: serviceKey}
}

func (self *RemoteCrypto) Decrypt(envelope string) ([]byte, error) {
	// Authenticate with config key and decrypt with deploy key
	requestedSecret, deployNonce, err := decryptEnvelopeNonce(self.ConfigKey, self.DeployKey, envelope)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt secret parameter using config key and deploy key (%s)", err))
	}

	var serviceNonce string
	if self.ServiceKey != nil {
		// Authenticate with config key and decrypt with optional service key
		serviceEnvelope, nonce, err := decryptEnvelopeNonce(self.ConfigKey, self.ServiceKey, string(requestedSecret))
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Failed to decrypt secret parameter using config key and service key (%s)", err))
		}

		requestedSecret = serviceEnvelope
		serviceNonce = encode(nonce[:])
	}

	message := DaemonRequest{
		AppId: self.AppId, AppVersion: self.AppVersion, TaskId: self.TaskId,
		RequestedSecret: string(requestedSecret),
		DeployNonce:     encode(deployNonce[:]), ServiceNonce: serviceNonce}
	encoded, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}

	// Encrypt with service key and send to daemon
	if self.ServiceKey != nil {
		encryptedEnvelope, err := encryptEnvelope(self.MasterKey, self.ServiceKey, encoded)
		if err != nil {
			return nil, err
		}

		encoded = []byte(encryptedEnvelope)
	}

	// Encrypt with deploy key and send to daemon
	requestEnvelope, err := encryptEnvelope(self.MasterKey, self.DeployKey, encoded)
	if err != nil {
		return nil, err
	}

	// Envelope is already encrypted with service key
	response, err := httpPostForm(fmt.Sprintf("%s/v1/decrypt", self.DaemonUrl), url.Values{
		"appid":      {self.AppId},
		"appversion": {self.AppVersion},
		"taskid":     {self.TaskId},
		"envelope":   {requestEnvelope}})
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt using daemon (%s)", err))
	}

	// Decrypt response using deploy key
	response, err = decryptEnvelope(self.MasterKey, self.DeployKey, string(response))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to decrypt daemon response using deploy key (%s)", err))
	}

	// Decrypt response using service key
	if self.ServiceKey != nil {
		response, err = decryptEnvelope(self.MasterKey, self.ServiceKey, string(response))
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Failed to decrypt daemon response using service key (%s)", err))
		}
	}

	// Unpack response struct
	var parsedResponse DaemonResponse
	err = json.Unmarshal(response, &parsedResponse)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to parse JSON request (%s)", err))
	}

	plaintext, err := decode(parsedResponse.PlaintextSecret)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to base64 decode plaintext secret (%s)", err))
	}

	return plaintext, nil
}
