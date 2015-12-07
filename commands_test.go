package main

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptDecryptCommand(t *testing.T) {
	input := bytes.NewBufferString("secret")
	var encrypted, output bytes.Buffer

	configPublicKey := pemRead("./resources/test/keys/config-public-key.pem")
	configPrivateKey := pemRead("./resources/test/keys/config-private-key.pem")
	masterPublicKey := pemRead("./resources/test/keys/master-public-key.pem")
	masterPrivateKey := pemRead("./resources/test/keys/master-private-key.pem")

	encryptCommand(input, &encrypted, masterPublicKey, configPrivateKey, false)

	crypto := newKeyCrypto(configPublicKey, masterPrivateKey)
	decryptStream(&encrypted, &output, crypto)

	assert.Equal(t, "secret", output.String())
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

	input := []string{"a=b", fmt.Sprintf("b=%s", encrypted), "c=d", fmt.Sprintf("e=%s", encrypted2)}

	crypto := newKeyCrypto(configPublicKey, masterPrivateKey)
	decryptEnvironment(input, &output, crypto)

	assert.Equal(t, "export b='secret'\nexport e='secret2'\n", output.String())
}
