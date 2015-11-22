package main

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
	"os"
)

func main() {
	rootCmd := &cobra.Command{Use: "secretary"}

	// Key generation command
	{
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
	}

	// Encryption command
	{
		var publicKeyFile, privateKeyFile string
		cmdEncrypt := &cobra.Command{
			Use:   "encrypt",
			Short: "Encrypt data",
			Run: func(cmd *cobra.Command, args []string) {
				encryptCommand(publicKeyFile, privateKeyFile)
			},
		}

		cmdEncrypt.Flags().StringVarP(&publicKeyFile, "public-key", "", "./keys/master-public-key.pem", "Master public key file")
		cmdEncrypt.Flags().StringVarP(&privateKeyFile, "private-key", "", "./keys/config-private-key.pem", "Config private key file")
		rootCmd.AddCommand(cmdEncrypt)
	}

	// Decryption command
	{
		var publicKeyFile, privateKeyFile, daemonUrl string
		var decryptEnv bool
		cmdDecrypt := &cobra.Command{
			Use:   "decrypt",
			Short: "Decrypt data",
			Run: func(cmd *cobra.Command, args []string) {
				var crypto Crypto

				if len(daemonUrl) > 0 {
					publicKey := pemRead(defaults(publicKeyFile, "./keys/master-public-key.pem"))
					privateKey := pemRead(defaults(privateKeyFile, "./keys/config-private-key.pem"))
					crypto = NewRemoteCrypto(daemonUrl, publicKey, privateKey)
				} else {
					publicKey := pemRead(defaults(publicKeyFile, "./keys/config-public-key.pem"))
					privateKey := pemRead(defaults(privateKeyFile, "./keys/master-private-key.pem"))
					crypto = NewKeyCrypto(publicKey, privateKey)
				}

				if decryptEnv {
					decryptEnvironment(crypto)
				} else {
					decryptStream(crypto)
				}
			},
		}

		cmdDecrypt.Flags().StringVarP(&publicKeyFile, "public-key", "", "", "Config public key file")
		cmdDecrypt.Flags().StringVarP(&privateKeyFile, "private-key", "", "", "Master private key file")
		cmdDecrypt.Flags().StringVarP(&daemonUrl, "daemon-url", "d", "", "URL of secretary daemon, e.g. https://master:8080")

		cmdDecrypt.Flags().BoolVarP(&decryptEnv, "decrypt-env", "e", false, "Decrypt environment variables")
		rootCmd.AddCommand(cmdDecrypt)
	}

	// Daemon command
	{
		var publicKeyFile, privateKeyFile, daemonIp string
		var daemonPort int

		cmdDaemon := &cobra.Command{
			Use:   "daemon",
			Short: "Start the REST service that decrypts secrets",
			Run: func(cmd *cobra.Command, args []string) {
				publicKey := pemRead(publicKeyFile)
				privateKey := pemRead(privateKeyFile)
				crypto := NewKeyCrypto(publicKey, privateKey)
				daemonCommand(daemonIp, daemonPort, crypto)
			},
		}

		cmdDaemon.Flags().StringVarP(&publicKeyFile, "public-key", "", "./keys/config-public-key.pem", "Config public key file")
		cmdDaemon.Flags().StringVarP(&privateKeyFile, "private-key", "", "./keys/master-private-key.pem", "Master private key file")

		cmdDaemon.Flags().StringVarP(&daemonIp, "ip", "i", "0.0.0.0", "Interface to bind to")
		cmdDaemon.Flags().IntVarP(&daemonPort, "port", "p", 8080, "Port to listen on")
		rootCmd.AddCommand(cmdDaemon)
	}

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
