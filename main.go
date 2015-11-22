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
		var daemonUrl, appId, appVersion, taskId string
		var configKeyFile, masterKeyFile, privateKeyFile string
		var decryptEnv bool
		cmdDecrypt := &cobra.Command{
			Use:   "decrypt",
			Short: "Decrypt data",
			Run: func(cmd *cobra.Command, args []string) {
				var crypto Crypto
				configKey := pemRead(configKeyFile)

				if len(daemonUrl) > 0 {
					masterKey := pemRead(masterKeyFile)
					privateKey := pemRead(defaults(privateKeyFile, "./keys/config-private-key.pem"))
					crypto = NewRemoteCrypto(
						daemonUrl, appId, appVersion, taskId,
						configKey, masterKey, privateKey)
				} else {
					privateKey := pemRead(defaults(privateKeyFile, "./keys/master-private-key.pem"))
					crypto = NewKeyCrypto(configKey, privateKey)
				}

				if decryptEnv {
					decryptEnvironment(crypto)
				} else {
					decryptStream(crypto)
				}
			},
		}

		cmdDecrypt.Flags().StringVarP(&configKeyFile, "config-key", "", "./keys/config-public-key.pem", "Config public key file")
		cmdDecrypt.Flags().StringVarP(&masterKeyFile, "master-key", "", "./keys/master-public-key.pem", "Master public key file")
		cmdDecrypt.Flags().StringVarP(&privateKeyFile, "private-key", "", "", "Private key file")

		cmdDecrypt.Flags().StringVarP(&daemonUrl, "secretary-url", "s", "", "URL of secretary daemon, e.g. https://secretary:8080")
		cmdDecrypt.Flags().StringVarP(&appId, "app-id", "", os.Getenv("MARATHON_APP_ID"), "Marathon app id")
		cmdDecrypt.Flags().StringVarP(&appVersion, "app-version", "", os.Getenv("MARATHON_APP_VERSION"), "Marathon app config version")
		cmdDecrypt.Flags().StringVarP(&taskId, "task-id", "", os.Getenv("MESOS_TASK_ID"), "Mesos task id")

		cmdDecrypt.Flags().BoolVarP(&decryptEnv, "decrypt-env", "e", false, "Decrypt environment variables")
		rootCmd.AddCommand(cmdDecrypt)
	}

	// Daemon command
	{
		var marathonUrl, configKeyFile, masterKeyFile, daemonIp string
		var daemonPort int

		cmdDaemon := &cobra.Command{
			Use:   "daemon",
			Short: "Start the REST service that decrypts secrets",
			Run: func(cmd *cobra.Command, args []string) {
				listenAddress := fmt.Sprintf("%s:%d", daemonIp, daemonPort)
				configKey := pemRead(configKeyFile)
				masterKey := pemRead(masterKeyFile)
				daemonCommand(listenAddress, marathonUrl, configKey, masterKey)
			},
		}

		cmdDaemon.Flags().StringVarP(&marathonUrl, "marathon-url", "", "http://localhost:8080", "URL of Marathon")
		cmdDaemon.Flags().StringVarP(&configKeyFile, "config-key", "", "./keys/config-public-key.pem", "Config public key file")
		cmdDaemon.Flags().StringVarP(&masterKeyFile, "master-key", "", "./keys/master-private-key.pem", "Master private key file")

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
