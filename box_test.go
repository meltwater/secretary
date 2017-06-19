package main

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/nacl/box"
)

const privateKey = `Q1PuWtB1E7F1sLpvfBGjL+ZuH+fSCOvMDqTyRQE4GTg=`
const publicKey = `UNlPHu0seDm6He2clMI5QHSaRGrXBdsMiWsamIF85l8=`

func TestAsKey(t *testing.T) {
	buf, err := decode(privateKey)
	assert.Nil(t, err)

	key, err := asKey(buf)
	assert.Nil(t, err)
	assert.Equal(t, buf, key[:])

	_, err = asKey([]byte("abc"))
	assert.NotNil(t, err)

	_, err = asKey(nil)
	assert.NotNil(t, err)
}

func TestAsNonce(t *testing.T) {
	buf, err := decode(`WLWwVUGVX7tTJd84mRioKQflzoTUWMj+PMtrO+c2oxEbnJba3ILzlyqhBKbd2Q==`)
	assert.Nil(t, err)

	nonce, err := asNonce(buf[0:24])
	assert.Nil(t, err)
	assert.Equal(t, buf[0:24], nonce[:])

	_, err = asNonce([]byte("abc"))
	assert.NotNil(t, err)

	_, err = asNonce(nil)
	assert.NotNil(t, err)
}

func TestFindKey(t *testing.T) {
	expected := encode(pemRead("./resources/test/keys/config-public-key.pem")[:])
	assert.Equal(t, expected, encode(findKey("", "RANDOM_ENVVAR_THAT_DOESNT_EXIST", "./resources/test/keys/config-public-key.pem")[:]))
	assert.Nil(t, findKey("", "RANDOM_ENVVAR_THAT_DOESNT_EXIST", "./resources/test/keys/nonexist-public-key.pem"))
}

func TestExtractEnvelopeType(t *testing.T) {
	assert.Equal(t, "", extractEnvelopeType("ENC[NACL,]"))
	assert.Equal(t, "NACL", extractEnvelopeType("ENC[NACL,abc]"))
	assert.Equal(t, "", extractEnvelopeType("ENC[KMS,]"))
	assert.Equal(t, "KMS", extractEnvelopeType("ENC[KMS,abc]"))
	assert.Equal(t, "", extractEnvelopeType("ENC[NACL,"))
	assert.Equal(t, "", extractEnvelopeType("NC[NACL,]"))
	assert.Equal(t, "", extractEnvelopeType("ENC[NACL,abc"))
	assert.Equal(t, "", extractEnvelopeType("ENC[ACL,abc"))
}

func TestEncodeDecode(t *testing.T) {
	publicKey, _, err := box.GenerateKey(rand.Reader)
	encoded := pemEncode(publicKey, "NACL PUBLIC KEY")
	decoded, err := pemDecode(encoded)
	assert.Nil(t, err)
	assert.Equal(t, publicKey, decoded, "Key must be same after encode/decode cycle")
}

func TestDecodeWithoutHeader(t *testing.T) {
	completeKey := `-----BEGIN NACL PUBLIC KEY-----
/1fbWGMTaR+lLQJnEsmxdfwWybKOpPQpyWB3FpNmOF4=
-----END NACL PUBLIC KEY-----`
	strippedKey := `/1fbWGMTaR+lLQJnEsmxdfwWybKOpPQpyWB3FpNmOF4=`

	decoded, err := pemDecode(completeKey)
	assert.Nil(t, err)

	decoded2, err := pemDecode(strippedKey)
	assert.Nil(t, err)
	assert.Equal(t, decoded, decoded2, "Keys must be decode to same value")
}

func TestDecryptEnvelope(t *testing.T) {
	envelope := `ENC[NACL,WLWwVUGVX7tTJd84mRioKQflzoTUWMj+PMtrO+c2oxEbnJba3ILzlyqhBKbd2Q==]`
	privkey, err := pemDecode(privateKey)
	assert.Nil(t, err)

	pubkey, err := pemDecode(publicKey)
	assert.Nil(t, err)

	plaintext, err := decryptEnvelope(pubkey, privkey, envelope)
	assert.Nil(t, err)
	assert.Equal(t, "secret", string(plaintext), "Should decrypt plaintext")
}

func TestEncryptEnvelope(t *testing.T) {
	privkey, err := pemDecode(privateKey)
	assert.Nil(t, err)

	pubkey, err := pemDecode(publicKey)
	assert.Nil(t, err)

	envelope, err := encryptEnvelope(pubkey, privkey, []byte("secret"))
	assert.Nil(t, err)

	plaintext, err := decryptEnvelope(pubkey, privkey, envelope)
	assert.Nil(t, err)
	assert.Equal(t, "secret", string(plaintext), "Should decrypt plaintext")
}

type noopDecryptionStrategyType struct{}

func (noopDecryptionStrategyType) Decrypt(envelope string) ([]byte, error) {
	return []byte(envelope), nil
}

var NoopDecryptionStrategy DecryptionStrategy = noopDecryptionStrategyType{}

func BenchmarkExtractEnvelopes(b *testing.B) {
	for n := 0; n < b.N; n++ {
		decryptEnvelopes("amqp://ENC[NACL,uSr123+/=]:ENC[NACL,pWd123+/=]@rabbit:5672/", NoopDecryptionStrategy)
	}
}
