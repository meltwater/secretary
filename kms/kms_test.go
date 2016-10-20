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

func TestUnsupportedDecryptionStrategy(t *testing.T) {
	composite := newCompositeDecryptionStrategy()

	plaintext, err := composite.Decrypt("ENC[NACL,fB7RSmpONiUGzaHtd8URiTSKqfBhor6BsJLSQErHH9NSgLTnxNLF60YS8ZT2IQ==]")
	assert.Nil(t, plaintext)
	assert.NotNil(t, err)
	assert.Equal(t, "Not configured for decrypting ENC[NACL,..] values", err.Error())
}
