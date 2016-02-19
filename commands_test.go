package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptDecryptCommand(t *testing.T) {
	input := bytes.NewBufferString("secret")
	var encrypted, output bytes.Buffer

	configPublicKey := pemRead("./resources/test/keys/config-public-key.pem")
	configPrivateKey := pemRead("./resources/test/keys/config-private-key.pem")
	masterPublicKey := pemRead("./resources/test/keys/master-public-key.pem")
	masterPrivateKey := pemRead("./resources/test/keys/master-private-key.pem")
	encryption := newKeyEncryptionStrategy(masterPublicKey, configPrivateKey)

	encryptCommand(input, &encrypted, encryption, false)

	crypto := newKeyDecryptionStrategy(configPublicKey, masterPrivateKey)
	decryptStream(&encrypted, &output, crypto)

	assert.Equal(t, "secret", output.String())
}

func TestEncryptDecryptCommandSubstrings(t *testing.T) {
	input := bytes.NewBufferString("secret")
	input2 := bytes.NewBufferString("secret2")
	var encrypted, output bytes.Buffer

	configPublicKey := pemRead("./resources/test/keys/config-public-key.pem")
	configPrivateKey := pemRead("./resources/test/keys/config-private-key.pem")
	masterPublicKey := pemRead("./resources/test/keys/master-public-key.pem")
	masterPrivateKey := pemRead("./resources/test/keys/master-private-key.pem")
	encryption := newKeyEncryptionStrategy(masterPublicKey, configPrivateKey)

	encryptCommand(input, &encrypted, encryption, false)
	encrypted.Write([]byte("somepadding"))
	encryptCommand(input2, &encrypted, encryption, false)

	crypto := newKeyDecryptionStrategy(configPublicKey, masterPrivateKey)
	decryptStream(&encrypted, &output, crypto)

	assert.Equal(t, "secretsomepaddingsecret2", output.String())
}

func TestDecryptEnvironmentCommand(t *testing.T) {
	var output bytes.Buffer

	configPublicKey := pemRead("./resources/test/keys/config-public-key.pem")
	configPrivateKey := pemRead("./resources/test/keys/config-private-key.pem")
	masterPublicKey := pemRead("./resources/test/keys/master-public-key.pem")
	masterPrivateKey := pemRead("./resources/test/keys/master-private-key.pem")

	encrypted, err := encryptEnvelope(masterPublicKey, configPrivateKey, []byte("secret"))
	assert.Nil(t, err)

	encrypted2, err := encryptEnvelope(masterPublicKey, configPrivateKey, []byte("secret2"))
	assert.Nil(t, err)

	{
		input := []string{"a=b", fmt.Sprintf("b=%s", encrypted), "c=d", fmt.Sprintf("e=%s", encrypted2), "e.f=d"}

		crypto := newKeyDecryptionStrategy(configPublicKey, masterPrivateKey)
		ok, err := decryptEnvironment(input, &output, crypto)

		assert.True(t, ok)
		assert.Nil(t, err)
		assert.Equal(t, "export b='secret'\nexport e='secret2'\n", output.String())
	}

	{
		input := []string{"a.b=b", fmt.Sprintf("b.c=%s", encrypted)}

		crypto := newKeyDecryptionStrategy(configPublicKey, masterPrivateKey)
		ok, err := decryptEnvironment(input, &output, crypto)

		assert.False(t, ok)
		assert.Equal(t, "The env var 'b.c' is not a valid shell script identifier. Only alphanumeric characters and underscores are supported, starting with an alphabetic or underscore character.", err.Error())
	}
}

func TestDecryptEnvironmentCommandSubstrings(t *testing.T) {
	var output bytes.Buffer

	configPublicKey := pemRead("./resources/test/keys/config-public-key.pem")
	configPrivateKey := pemRead("./resources/test/keys/config-private-key.pem")
	masterPublicKey := pemRead("./resources/test/keys/master-public-key.pem")
	masterPrivateKey := pemRead("./resources/test/keys/master-private-key.pem")

	encrypted, err := encryptEnvelope(masterPublicKey, configPrivateKey, []byte("secret"))
	assert.Nil(t, err)

	encrypted2, err := encryptEnvelope(masterPublicKey, configPrivateKey, []byte("secret2"))
	assert.Nil(t, err)

	input := []string{"a=b", fmt.Sprintf("b=blabla%sblabla%s", encrypted, encrypted2), "c=d"}

	crypto := newKeyDecryptionStrategy(configPublicKey, masterPrivateKey)
	decryptEnvironment(input, &output, crypto)

	assert.Equal(t, "export b='blablasecretblablasecret2'\n", output.String())
}

func TestDecryptEnvironmentCommandSubstringsSpaces(t *testing.T) {
	var output bytes.Buffer

	configPublicKey := pemRead("./resources/test/keys/config-public-key.pem")
	configPrivateKey := pemRead("./resources/test/keys/config-private-key.pem")
	masterPublicKey := pemRead("./resources/test/keys/master-public-key.pem")
	masterPrivateKey := pemRead("./resources/test/keys/master-private-key.pem")

	encrypted, err := encryptEnvelope(masterPublicKey, configPrivateKey, []byte("secret"))
	assert.Nil(t, err)

	encrypted2, err := encryptEnvelope(masterPublicKey, configPrivateKey, []byte("secret2"))
	assert.Nil(t, err)

	input := []string{"a=b", fmt.Sprintf("b=blabla %sb la bla %s", encrypted, encrypted2), "c=d"}

	crypto := newKeyDecryptionStrategy(configPublicKey, masterPrivateKey)
	decryptEnvironment(input, &output, crypto)

	assert.Equal(t, "export b='blabla secretb la bla secret2'\n", output.String())
}
