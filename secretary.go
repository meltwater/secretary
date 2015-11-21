package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/nacl/box"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

const insecureSenderPrivateKey = `-----BEGIN NACL PRIVATE KEY-----
CaWsEI/8p6h4814+eRwmaHPAYdlEoWsb2Ln3vtSP+js=
-----END NACL PRIVATE KEY-----`

const insecureSenderPublicKey = `-----BEGIN NACL PUBLIC KEY-----
WzTsRnSSWYLRz7sLTgcr8ApwUYAETBpzdeZkBXH+9Us=
-----END NACL PUBLIC KEY-----`

type CommandError struct {
	msg string // description of error
	err error  // inner error
}

func (e *CommandError) Error() string { return e.msg }

func check(err error, msg string, a ...interface{}) {
	if err != nil {
		panic(&CommandError{fmt.Sprintf("%s (%s)", fmt.Sprintf(msg, a...), err), err})
	}
}

func assert(value bool, msg string, a ...interface{}) {
	if !value {
		panic(&CommandError{fmt.Sprintf(msg, a...), nil})
	}
}

func asKey(data []byte) *[32]byte {
	var key [32]byte
	copy(key[:], data[0:32])
	return &key
}

func pemWrite(data []byte, path string, pemType string, fileMode os.FileMode) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: data})
	check(os.MkdirAll(filepath.Dir(path), 0775), "Failed to create directory %s", filepath.Dir(path))
	check(ioutil.WriteFile(path, pemData, fileMode), "Failed to write file %s", path)
}

func pemRead(path string) *[32]byte {
	pemData, err := ioutil.ReadFile(path)
	check(err, "Failed to read key from %s", path)

	pemBlock, _ := pem.Decode(pemData)
	assert(len(pemBlock.Bytes) == 32, "Expected key %s to be at least 32 bytes", path)
	return asKey(pemBlock.Bytes)
}

func genkey(publicKeyFile string, privateKeyFile string) error {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	check(err, "Failed to generate key pair")

	pemWrite(publicKey[:], publicKeyFile, "NACL PUBLIC KEY", 0644)
	pemWrite(privateKey[:], privateKeyFile, "NACL PRIVATE KEY", 0600)
	return nil
}

func encrypt(receiverPublicKeyFile string, senderPrivateKeyFile string) {
	receiverPublicKey := pemRead(receiverPublicKeyFile)

	var senderPrivateKey *[32]byte
	if len(senderPrivateKeyFile) > 0 {
		senderPrivateKey = pemRead(senderPrivateKeyFile)
	} else {
		pemBlock, _ := pem.Decode([]byte(insecureSenderPrivateKey))
		senderPrivateKey = asKey(pemBlock.Bytes)
	}

	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	check(err, "Failed generate random nonce")

	plaintext, err := ioutil.ReadAll(os.Stdin)
	check(err, "Failed to read plaintext data from standard input")

	encrypted := box.Seal(nonce[:], plaintext, &nonce, receiverPublicKey, senderPrivateKey)
	fmt.Printf("ENC[NACL,%s]", base64.RawStdEncoding.EncodeToString(encrypted))
}

func decrypt(senderPublicKeyFile string, receiverPrivateKeyFile string) {
	var senderPublicKey *[32]byte
	if len(senderPublicKeyFile) > 0 {
		senderPublicKey = pemRead(senderPublicKeyFile)
	} else {
		pemBlock, _ := pem.Decode([]byte(insecureSenderPublicKey))
		senderPublicKey = asKey(pemBlock.Bytes)
	}

	receiverPrivateKey := pemRead(receiverPrivateKeyFile)

	envelope, err := ioutil.ReadAll(os.Stdin)
	check(err, "Failed to read encrypted data from standard input")

	encoded := envelope[9 : len(envelope)-1]
	encrypted := make([]byte, base64.RawStdEncoding.DecodedLen(len(encoded)))
	n, err := base64.RawStdEncoding.Decode(encrypted, encoded)
	check(err, "Failed to decode base64 data from standard input")

	var nonce [24]byte
	copy(nonce[:], encrypted)
	plaintext, ok := box.Open(nil, encrypted[24:n], &nonce, senderPublicKey, receiverPrivateKey)
	assert(ok, "Decryption failed (incorrect keys?)")

	os.Stdout.Write(plaintext)
}

func main() {
	rootCmd := &cobra.Command{Use: "secretary"}
	//rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Verbose output")

	const defaultPublicKeyPath = "./keys/public_key.pem"
	const defaultPrivateKeyPath = "./keys/private_key.pem"

	// Key generation command
	var publicKeyFile, privateKeyFile string
	cmdGenkey := &cobra.Command{
		Use:   "genkey",
		Short: "Generate a public/private key pair",
		Run: func(cmd *cobra.Command, args []string) {
			genkey(publicKeyFile, privateKeyFile)
		},
	}

	cmdGenkey.Flags().StringVarP(&publicKeyFile, "public-key", "", defaultPublicKeyPath, "Public key file")
	cmdGenkey.Flags().StringVarP(&privateKeyFile, "private-key", "", defaultPrivateKeyPath, "Private key file")
	rootCmd.AddCommand(cmdGenkey)

	// Encryption command
	var receiverPublicKeyFile, senderPrivateKeyFile string
	cmdEncrypt := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt data",
		Run: func(cmd *cobra.Command, args []string) {
			encrypt(receiverPublicKeyFile, senderPrivateKeyFile)
		},
	}

	cmdEncrypt.Flags().StringVarP(&receiverPublicKeyFile, "receiver-public-key", "", defaultPublicKeyPath, "Receiver public key file")
	cmdEncrypt.Flags().StringVarP(&senderPrivateKeyFile, "sender-private-key", "", "", "Sender private key file")
	rootCmd.AddCommand(cmdEncrypt)

	// Encryption command
	var senderPublicKeyFile, receiverPrivateKeyFile string
	cmdDecrypt := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt data",
		Run: func(cmd *cobra.Command, args []string) {
			decrypt(senderPublicKeyFile, receiverPrivateKeyFile)
		},
	}

	cmdDecrypt.Flags().StringVarP(&senderPublicKeyFile, "sender-public-key", "", "", "Sender public key file")
	cmdDecrypt.Flags().StringVarP(&receiverPrivateKeyFile, "receiver-private-key", "", defaultPrivateKeyPath, "Receiver private key file")
	rootCmd.AddCommand(cmdDecrypt)

	// Handle checked errors nicely
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case *CommandError:
				fmt.Fprintf(os.Stderr, "%s\n", err)
			default:
				fmt.Fprintf(os.Stderr, "%s\n", errors.Wrap(err, 2).ErrorStack())
			}

			os.Exit(1)
		}
	}()

	rootCmd.Execute()
}
