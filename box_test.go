package main

import (
	"crypto/rand"
	a "github.com/stretchr/testify/assert"
	"golang.org/x/crypto/nacl/box"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	publicKey, _, err := box.GenerateKey(rand.Reader)
	encoded := pemEncode(publicKey, "NACL PUBLIC KEY")
	decoded, err := pemDecode(encoded)
	a.Nil(t, err)
	a.Equal(t, publicKey, decoded, "Key must be same after encode/decode cycle")
}

func TestDecodeWithoutHeader(t *testing.T) {
	completeKey := `-----BEGIN NACL PUBLIC KEY-----
/1fbWGMTaR+lLQJnEsmxdfwWybKOpPQpyWB3FpNmOF4=
-----END NACL PUBLIC KEY-----`
	strippedKey := `/1fbWGMTaR+lLQJnEsmxdfwWybKOpPQpyWB3FpNmOF4=`

	decoded, err := pemDecode(completeKey)
	a.Nil(t, err)

	decoded2, err := pemDecode(strippedKey)
	a.Nil(t, err)
	a.Equal(t, decoded, decoded2, "Keys must be decode to same value")
}
