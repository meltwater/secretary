package main

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
	"os"
)

func main() {
	rootCmd := &cobra.Command{Use: "secretary"}
	//rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Verbose output")

	// Key generation command
	var keyPath string
	cmdGenkey := &cobra.Command{
		Use:   "genkeys",
		Short: "Generate a public/private key pair",
		Run: func(cmd *cobra.Command, args []string) {
			genkey(fmt.Sprintf("%s/master-public-key.pem", keyPath), fmt.Sprintf("%s/master-private-key.pem", keyPath))
			genkey(fmt.Sprintf("%s/config-public-key.pem", keyPath), fmt.Sprintf("%s/config-private-key.pem", keyPath))
		},
	}

	cmdGenkey.Flags().StringVarP(&keyPath, "path", "", "./keys/", "Directory to write keys")
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

	cmdEncrypt.Flags().StringVarP(&receiverPublicKeyFile, "public-key", "", "./keys/master-public-key.pem", "Receiver public key file")
	cmdEncrypt.Flags().StringVarP(&senderPrivateKeyFile, "private-key", "", "./keys/config-private-key.pem", "Sender private key file")
	rootCmd.AddCommand(cmdEncrypt)

	// Decryption command
	var senderPublicKeyFile, receiverPrivateKeyFile string
	var decryptEnv bool
	cmdDecrypt := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt data",
		Run: func(cmd *cobra.Command, args []string) {
			decrypt(senderPublicKeyFile, receiverPrivateKeyFile, decryptEnv)
		},
	}

	cmdDecrypt.Flags().StringVarP(&senderPublicKeyFile, "public-key", "", "./keys/config-public-key.pem", "Sender public key file")
	cmdDecrypt.Flags().StringVarP(&receiverPrivateKeyFile, "private-key", "", "./keys/master-private-key.pem", "Receiver private key file")
	cmdDecrypt.Flags().BoolVarP(&decryptEnv, "decrypt-env", "e", false, "Decrypt environment variables")
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
