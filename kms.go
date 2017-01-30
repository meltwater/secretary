package main

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"

	"golang.org/x/crypto/nacl/secretbox"
)

type kmsPayload struct {
	EncryptedDataKey []byte
	Nonce            *[24]byte
	Message          []byte
}

// KmsClient wraps the KMS client to allow mocking
type KmsClient interface {
	GenerateDataKey(keyID string) (*[32]byte, []byte, error)
	Decrypt([]byte) (*[32]byte, error)
}

// KmsClientImpl implements the real KMS client
type KmsClientImpl struct {
	Impl *kms.KMS
}

// KmsFunction is a lambda that operates on the KMS service
type KmsFunction func(*kms.KMS) error

// CallWithRetry executes a function with retry for MissingRegion errors
func (k *KmsClientImpl) CallWithRetry(f KmsFunction) error {
	// Lazy initialize the session
	if k.Impl == nil {
		// Force enable Shared Config to support $AWS_DEFAULT_REGION
		sess, err := session.NewSessionWithOptions(session.Options{
			SharedConfigState: session.SharedConfigEnable,
		})

		if err != nil {
			return err
		}

		k.Impl = kms.New(sess)
	}

	// Invoke the function
	err := f(k.Impl)

	// Attempt to use EC2 meta-data service in case of MissingRegion error
	if err == aws.ErrMissingRegion {
		body, err := httpGet("http://169.254.169.254/2016-06-30/dynamic/instance-identity/document")
		if err == nil {
			var doc ec2metadata.EC2InstanceIdentityDocument
			err := json.Unmarshal(body, &doc)

			if err == nil {
				sess, err := session.NewSessionWithOptions(session.Options{
					Config:            aws.Config{Region: aws.String(doc.Region)},
					SharedConfigState: session.SharedConfigEnable,
				})

				if err == nil {
					k.Impl = kms.New(sess)

					// Retry the function with the new session
					return f(k.Impl)
				}
			}
		}
	}

	return err
}

// GenerateDataKey returns a new symmetric key and its encrypted form
func (k *KmsClientImpl) GenerateDataKey(keyID string) (*[32]byte, []byte, error) {
	var response *kms.GenerateDataKeyOutput
	bytes := int64(32)

	err := k.CallWithRetry(func(impl *kms.KMS) error {
		var ferr error
		response, ferr = impl.GenerateDataKey(&kms.GenerateDataKeyInput{
			KeyId:         &keyID,
			NumberOfBytes: &bytes,
		})
		return ferr
	})

	if err != nil {
		return nil, nil, err
	}

	dataKey, err := asKey(response.Plaintext)
	if err != nil {
		return nil, nil, err
	}

	return dataKey, response.CiphertextBlob, nil
}

// Decrypt a symmetric key
func (k *KmsClientImpl) Decrypt(data []byte) (*[32]byte, error) {
	var response *kms.DecryptOutput

	err := k.CallWithRetry(func(impl *kms.KMS) error {
		var ferr error
		response, ferr = impl.Decrypt(&kms.DecryptInput{
			CiphertextBlob: data,
		})
		return ferr
	})

	if err != nil {
		return nil, err
	}

	return asKey(response.Plaintext)
}

func newKmsClient() *KmsClientImpl {
	return &KmsClientImpl{}
}

// KmsEncryptionStrategy implements envelope encryption using Amazon AWS KMS
type KmsEncryptionStrategy struct {
	Client KmsClient
	KeyID  string
}

// Encrypt a plaintext message and returns a transport envelope
func (k *KmsEncryptionStrategy) Encrypt(plaintext []byte) (string, error) {
	// Generate symmetric data key
	dataKey, encryptedDataKey, err := k.Client.GenerateDataKey(k.KeyID)
	if err != nil {
		return "", err
	}

	// Initialize payload
	payload := &kmsPayload{
		EncryptedDataKey: encryptedDataKey,
		Nonce:            &[24]byte{},
	}

	// Generate nonce
	_, err = io.ReadFull(rand.Reader, payload.Nonce[:])
	if err != nil {
		return "", errors.New("Failed generate random nonce")
	}

	// Encrypt message
	payload.Message = secretbox.Seal(payload.Message, plaintext, payload.Nonce, dataKey)
	buffer := &bytes.Buffer{}
	if err := gob.NewEncoder(buffer).Encode(payload); err != nil {
		return "", err
	}

	return fmt.Sprintf("ENC[KMS,%s]", encode(buffer.Bytes())), nil
}

func newKmsEncryptionStrategy(client KmsClient, keyID string) *KmsEncryptionStrategy {
	return &KmsEncryptionStrategy{Client: client, KeyID: keyID}
}

// KmsDecryptionStrategy implements envelope decryption using Amazon AWS KMS
type KmsDecryptionStrategy struct {
	Client KmsClient
}

// Decrypt a transport envelope
func (k *KmsDecryptionStrategy) Decrypt(envelope string) ([]byte, error) {
	// Extract payload
	encrypted, err := decode(envelope[8 : len(envelope)-1])
	if err != nil {
		return nil, err
	}

	// Decode payload struct
	var payload kmsPayload
	gob.NewDecoder(bytes.NewReader(encrypted)).Decode(&payload)

	// Decrypt key
	dataKey, err := k.Client.Decrypt(payload.EncryptedDataKey)
	if err != nil {
		return nil, err
	}

	// Decrypt message
	var plaintext []byte
	plaintext, ok := secretbox.Open(plaintext, payload.Message, payload.Nonce, dataKey)
	if !ok {
		return nil, fmt.Errorf("Failed to open secretbox")
	}

	return plaintext, nil
}

func newKmsDecryptionStrategy(client KmsClient) *KmsDecryptionStrategy {
	return &KmsDecryptionStrategy{Client: client}
}
