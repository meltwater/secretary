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
	MasterKey, DeployKey, ServiceKey *[32]byte
}

func newRemoteCrypto(
	daemonUrl string, appId string, appVersion string, taskId string,
	masterKey *[32]byte, deployKey *[32]byte, serviceKey *[32]byte) *RemoteCrypto {
	return &RemoteCrypto{
		DaemonUrl: daemonUrl, AppId: appId, AppVersion: appVersion, TaskId: taskId,
		MasterKey: masterKey, DeployKey: deployKey, ServiceKey: serviceKey}
}

func (self *RemoteCrypto) Decrypt(envelope string) ([]byte, error) {
	message := DaemonRequest{
		AppId: self.AppId, AppVersion: self.AppVersion, TaskId: self.TaskId,
		RequestedSecret: envelope,
	}
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
		return nil, errors.New(fmt.Sprintf("Failed to parse JSON respons (%s)", err))
	}

	plaintext, err := decode(parsedResponse.PlaintextSecret)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to base64 decode plaintext secret (%s)", err))
	}

	return plaintext, nil
}
