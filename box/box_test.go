package box

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/nacl/box"
)

const privateKey = `Q1PuWtB1E7F1sLpvfBGjL+ZuH+fSCOvMDqTyRQE4GTg=`
const publicKey = `UNlPHu0seDm6He2clMI5QHSaRGrXBdsMiWsamIF85l8=`

func TestAsKey(t *testing.T) {
	buf, err := Decode(privateKey)
	assert.Nil(t, err)

	key, err := AsKey(buf)
	assert.Nil(t, err)
	assert.Equal(t, buf, key[:])

	_, err = AsKey([]byte("abc"))
	assert.NotNil(t, err)

	_, err = AsKey(nil)
	assert.NotNil(t, err)
}

func TestAsNonce(t *testing.T) {
	buf, err := Decode(`WLWwVUGVX7tTJd84mRioKQflzoTUWMj+PMtrO+c2oxEbnJba3ILzlyqhBKbd2Q==`)
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
	expected := Encode(PemRead("../resources/test/keys/config-public-key.pem")[:])
	assert.Equal(t, expected, Encode(FindKey("", "RANDOM_ENVVAR_THAT_DOESNT_EXIST", "../resources/test/keys/config-public-key.pem")[:]))
	assert.Nil(t, FindKey("", "RANDOM_ENVVAR_THAT_DOESNT_EXIST", "../resources/test/keys/nonexist-public-key.pem"))
}

func TestExtractEnvelopes(t *testing.T) {
	envelopes := ExtractEnvelopes("amqp://ENC[NACL,uSr123+/=]:ENC[NACL,pWd123+/=]@rabbit:5672/")
	assert.Equal(t, 2, len(envelopes))
	assert.Equal(t, []string{"ENC[NACL,uSr123+/=]", "ENC[NACL,pWd123+/=]"}, envelopes)

	envelopes = ExtractEnvelopes("amqp://ENC[NACL,uSr123+/=]:ENC[NACL,pWd123+/=]@rabbit:5672/ENC[NACL,def123+/=]")
	assert.Equal(t, 3, len(envelopes))
	assert.Equal(t, []string{"ENC[NACL,uSr123+/=]", "ENC[NACL,pWd123+/=]", "ENC[NACL,def123+/=]"}, envelopes)

	envelopes = ExtractEnvelopes("amqp://ENC[NACL,]:ENC[NACL,pWd123+/=]@rabbit:5672/")
	assert.Equal(t, 1, len(envelopes))
	assert.Equal(t, []string{"ENC[NACL,pWd123+/=]"}, envelopes)

	envelopes = ExtractEnvelopes("amqp://ENC[NACL,:ENC[NACL,pWd123+/=]@rabbit:5672/")
	assert.Equal(t, 1, len(envelopes))
	assert.Equal(t, []string{"ENC[NACL,pWd123+/=]"}, envelopes)

	envelopes = ExtractEnvelopes("amqp://NC[NACL,]:ENC[NACL,pWd123+/=]@rabbit:5672/")
	assert.Equal(t, 1, len(envelopes))
	assert.Equal(t, []string{"ENC[NACL,pWd123+/=]"}, envelopes)

	envelopes = ExtractEnvelopes("amqp://ENC[NACL,abc:ENC[NACL,pWd123+/=]@rabbit:5672/")
	assert.Equal(t, 1, len(envelopes))
	assert.Equal(t, []string{"ENC[NACL,pWd123+/=]"}, envelopes)
}

func TestExtractEnvelopeType(t *testing.T) {
	assert.Equal(t, "", ExtractEnvelopeType("ENC[NACL,]"))
	assert.Equal(t, "NACL", ExtractEnvelopeType("ENC[NACL,abc]"))
	assert.Equal(t, "", ExtractEnvelopeType("ENC[KMS,]"))
	assert.Equal(t, "KMS", ExtractEnvelopeType("ENC[KMS,abc]"))
	assert.Equal(t, "", ExtractEnvelopeType("ENC[NACL,"))
	assert.Equal(t, "", ExtractEnvelopeType("NC[NACL,]"))
	assert.Equal(t, "", ExtractEnvelopeType("ENC[NACL,abc"))
	assert.Equal(t, "", ExtractEnvelopeType("ENC[ACL,abc"))
}

func TestEncodeDecode(t *testing.T) {
	publicKey, _, err := box.GenerateKey(rand.Reader)
	encoded := PemEncode(publicKey, "NACL PUBLIC KEY")
	decoded, err := PemDecode(encoded)
	assert.Nil(t, err)
	assert.Equal(t, publicKey, decoded, "Key must be same after encode/decode cycle")
}

func TestDecodeWithoutHeader(t *testing.T) {
	completeKey := `-----BEGIN NACL PUBLIC KEY-----
/1fbWGMTaR+lLQJnEsmxdfwWybKOpPQpyWB3FpNmOF4=
-----END NACL PUBLIC KEY-----`
	strippedKey := `/1fbWGMTaR+lLQJnEsmxdfwWybKOpPQpyWB3FpNmOF4=`

	decoded, err := PemDecode(completeKey)
	assert.Nil(t, err)

	decoded2, err := PemDecode(strippedKey)
	assert.Nil(t, err)
	assert.Equal(t, decoded, decoded2, "Keys must be decode to same value")
}

func TestDecryptEnvelope(t *testing.T) {
	envelope := `ENC[NACL,WLWwVUGVX7tTJd84mRioKQflzoTUWMj+PMtrO+c2oxEbnJba3ILzlyqhBKbd2Q==]`
	privkey, err := PemDecode(privateKey)
	assert.Nil(t, err)

	pubkey, err := PemDecode(publicKey)
	assert.Nil(t, err)

	plaintext, err := DecryptEnvelope(pubkey, privkey, envelope)
	assert.Nil(t, err)
	assert.Equal(t, "secret", string(plaintext), "Should decrypt plaintext")
}

func TestEncryptEnvelope(t *testing.T) {
	privkey, err := PemDecode(privateKey)
	assert.Nil(t, err)

	pubkey, err := PemDecode(publicKey)
	assert.Nil(t, err)

	envelope, err := EncryptEnvelope(pubkey, privkey, []byte("secret"))
	assert.Nil(t, err)

	plaintext, err := DecryptEnvelope(pubkey, privkey, envelope)
	assert.Nil(t, err)
	assert.Equal(t, "secret", string(plaintext), "Should decrypt plaintext")
}
