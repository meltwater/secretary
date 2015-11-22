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
		var publicKeyFile, privateKeyFile string
		var decryptEnv bool
		cmdDecrypt := &cobra.Command{
			Use:   "decrypt",
			Short: "Decrypt data",
			Run: func(cmd *cobra.Command, args []string) {
				decryptCommand(publicKeyFile, privateKeyFile, decryptEnv)
			},
		}

		cmdDecrypt.Flags().StringVarP(&publicKeyFile, "public-key", "", "./keys/config-public-key.pem", "Config public key file")
		cmdDecrypt.Flags().StringVarP(&privateKeyFile, "private-key", "", "./keys/master-private-key.pem", "Master private key file")
		cmdDecrypt.Flags().BoolVarP(&decryptEnv, "decrypt-env", "e", false, "Decrypt environment variables")
		rootCmd.AddCommand(cmdDecrypt)
	}

	// Daemon command
	{
		var privateKeyFile, daemonIp string
		var daemonPort int

		cmdDaemon := &cobra.Command{
			Use:   "daemon",
			Short: "Start the REST service that decrypts secrets",
			Run: func(cmd *cobra.Command, args []string) {
				daemonCommand(daemonIp, daemonPort, privateKeyFile)
			},
		}

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
