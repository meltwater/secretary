package kms

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKms(t *testing.T) {
	client := NewMockKmsClient()
	encryption := NewKmsEncryptionStrategy(client, "123")
	decryption := NewKmsDecryptionStrategy(client)

	envelope, err := encryption.Encrypt([]byte("secret"))
	assert.Nil(t, err)

	plaintext, err := decryption.Decrypt(envelope)
	assert.Nil(t, err)
	assert.Equal(t, "secret", string(plaintext))
}
