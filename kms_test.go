package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

const mockKmsKey = `Q1PuWtB1E7F1sLpvfBGjL+ZuH+fSCOvMDqTyRQE4GTg=`

type MockKmsClient struct {
}

func (k *MockKmsClient) GenerateDataKey(keyID string) (*[32]byte, []byte, error) {
	if keyID != "123" {
		return nil, nil, errors.New("Expected keyID=123")
	}

	key, err := decode(mockKmsKey)
	if err != nil {
		return nil, nil, err
	}

	dataKey, err := asKey(key)
	if err != nil {
		return nil, nil, err
	}

	return dataKey, []byte(mockKmsKey), nil
}

func (k *MockKmsClient) Decrypt(data []byte) (*[32]byte, error) {
	key, err := decode(string(data))
	if err != nil {
		return nil, err
	}

	dataKey, err := asKey(key)
	if err != nil {
		return nil, err
	}

	return dataKey, nil
}

func newMockKmsClient() *MockKmsClient {
	return &MockKmsClient{}
}

func TestKms(t *testing.T) {
	client := newMockKmsClient()
	encryption := newKmsEncryptionStrategy(client, "123")
	decryption := newKmsDecryptionStrategy(client)

	envelope, err := encryption.Encrypt([]byte("secret"))
	assert.Nil(t, err)

	plaintext, err := decryption.Decrypt(envelope)
	assert.Nil(t, err)
	assert.Equal(t, "secret", string(plaintext))
}

func TestCompositeDecryptionStrategy(t *testing.T) {
	composite := newCompositeDecryptionStrategy()
	composite.Add("KMS", newKmsDecryptionStrategy(newMockKmsClient()))
	composite.Add("NACL", newKeyDecryptionStrategy(
		pemRead("./resources/test/keys/config-public-key.pem"),
		pemRead("./resources/test/keys/master-private-key.pem")))

	{
		plaintext, err := composite.Decrypt("ENC[KMS,RP+BAwEBCmttc1BheWxvYWQB/4IAAQMBEEVuY3J5cHRlZERhdGFLZXkBCgABBU5vbmNlAf+EAAEHTWVzc2FnZQEKAAAAGf+DAQEBCVsyNF11aW50OAH/hAABBgEwAABw/4IBLFExUHVXdEIxRTdGMXNMcHZmQkdqTCtadUgrZlNDT3ZNRHFUeVJRRTRHVGc9ARgr/502fv/vQP+S/5H/k//gOf/gWDNh/53/3in/uf/L/5r/mTxbARYoewY+qb+skiPKwGUnT/2GADtui80vAA==]")
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	{
		plaintext, err := composite.Decrypt("ENC[NACL,fB7RSmpONiUGzaHtd8URiTSKqfBhor6BsJLSQErHH9NSgLTnxNLF60YS8ZT2IQ==]")
		assert.Nil(t, err)
		assert.Equal(t, "secret", string(plaintext))
	}

	{
		plaintext, err := composite.Decrypt("ENC[ACL,fB7RSmpONiUGzaHtd8URiTSKqfBhor6BsJLSQErHH9NSgLTnxNLF60YS8ZT2IQ==]")
		assert.Nil(t, plaintext)
		assert.NotNil(t, err)
		assert.Equal(t, "Not configured for decrypting ENC[,..] values", err.Error())
	}
}

func TestUnsupportedDecryptionStrategy(t *testing.T) {
	composite := newCompositeDecryptionStrategy()

	plaintext, err := composite.Decrypt("ENC[NACL,fB7RSmpONiUGzaHtd8URiTSKqfBhor6BsJLSQErHH9NSgLTnxNLF60YS8ZT2IQ==]")
	assert.Nil(t, plaintext)
	assert.NotNil(t, err)
	assert.Equal(t, "Not configured for decrypting ENC[NACL,..] values", err.Error())
}
