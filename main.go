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
				if len(args) == 0 {
					args = []string{"master", "config"}
				}

				for _, name := range args {
					genkey(fmt.Sprintf("%s/%s-public-key.pem", keyPath, name), fmt.Sprintf("%s/%s-private-key.pem", keyPath, name))
				}
			},
		}

		cmdGenkey.Flags().StringVarP(&keyPath, "path", "", "./keys/", "Directory to write keys")
		rootCmd.AddCommand(cmdGenkey)
	}

	// Encryption command
	{
		var publicKeyFile, privateKeyFile string
		var wrapLines bool
		cmdEncrypt := &cobra.Command{
			Use:   "encrypt",
			Short: "Encrypt data",
			Run: func(cmd *cobra.Command, args []string) {
				publicKey := requireKey("config public", publicKeyFile, "PUBLIC_KEY", "./keys/master-public-key.pem")
				privateKey := requireKey("deploy private", privateKeyFile, "PRIVATE_KEY", "./keys/config-private-key.pem")
				encryptCommand(os.Stdin, os.Stdout, publicKey, privateKey, wrapLines)
			},
		}

		cmdEncrypt.Flags().StringVarP(&publicKeyFile, "public-key", "", "", "Public key")
		cmdEncrypt.Flags().StringVarP(&privateKeyFile, "private-key", "", "", "Private key")
		cmdEncrypt.Flags().BoolVarP(&wrapLines, "wrap", "w", false, "Wrap long lines")
		rootCmd.AddCommand(cmdEncrypt)
	}

	// Decryption command
	{
		var secretaryURL, appID, appVersion, taskID string
		var configKeyFile, masterKeyFile, deployKeyFile, serviceKeyFile string
		var decryptEnv bool
		cmdDecrypt := &cobra.Command{
			Use:   "decrypt",
			Short: "Decrypt data",
			Run: func(cmd *cobra.Command, args []string) {
				var crypto Crypto
				deployKey := requireKey("deploy private", deployKeyFile, "DEPLOY_PRIVATE_KEY", "./keys/master-private-key.pem")

				if len(secretaryURL) > 0 {
					masterKey := requireKey("master public", masterKeyFile, "MASTER_PUBLIC_KEY", "./keys/master-public-key.pem")
					serviceKey := findKey(serviceKeyFile, "SERVICE_PRIVATE_KEY")
					crypto = newRemoteCrypto(
						secretaryURL, appID, appVersion, taskID,
						masterKey, deployKey, serviceKey)
				} else {
					configKey := requireKey("config public", configKeyFile, "CONFIG_PUBLIC_KEY", "./keys/config-public-key.pem")
					crypto = newKeyCrypto(configKey, deployKey)
				}

				if decryptEnv {
					decryptEnvironment(os.Environ(), os.Stdout, crypto)
				} else {
					decryptStream(os.Stdin, os.Stdout, crypto)
				}
			},
		}

		cmdDecrypt.Flags().StringVarP(&deployKeyFile, "private-key", "", "", "Private key file for use without daemon")

		cmdDecrypt.Flags().StringVarP(&configKeyFile, "config-key", "", "", "Config public key file")
		cmdDecrypt.Flags().StringVarP(&masterKeyFile, "master-key", "", "", "Master public key file")
		cmdDecrypt.Flags().StringVarP(&deployKeyFile, "deploy-key", "", "", "Private deploy key file")
		cmdDecrypt.Flags().StringVarP(&serviceKeyFile, "service-key", "", "", "Private service key file")

		cmdDecrypt.Flags().StringVarP(&secretaryURL, "secretary-url", "s", os.Getenv("SECRETARY_URL"), "URL of secretary daemon, e.g. https://secretary:5070")
		cmdDecrypt.Flags().StringVarP(&appID, "app-id", "", os.Getenv("MARATHON_APP_ID"), "Marathon app id")
		cmdDecrypt.Flags().StringVarP(&appVersion, "app-version", "", os.Getenv("MARATHON_APP_VERSION"), "Marathon app config version")
		cmdDecrypt.Flags().StringVarP(&taskID, "task-id", "", os.Getenv("MESOS_TASK_ID"), "Mesos task id")

		cmdDecrypt.Flags().BoolVarP(&decryptEnv, "decrypt-env", "e", false, "Decrypt environment variables")
		rootCmd.AddCommand(cmdDecrypt)
	}

	// Daemon command
	{
		var marathonURL, configPublicKeyFile, masterPrivateKeyFile, daemonIP string
		var daemonPort int

		cmdDaemon := &cobra.Command{
			Use:   "daemon",
			Short: "Start the REST service that decrypts secrets",
			Run: func(cmd *cobra.Command, args []string) {
				listenAddress := fmt.Sprintf("%s:%d", daemonIP, daemonPort)
				configPublicKey := pemRead(configPublicKeyFile)
				masterKey := pemRead(masterPrivateKeyFile)
				daemonCommand(listenAddress, marathonURL, configPublicKey, masterKey)
			},
		}

		cmdDaemon.Flags().StringVarP(&marathonURL, "marathon-url", "",
			defaults(os.Getenv("MARATHON_URL"), "http://localhost:8080"), "URL of Marathon")
		cmdDaemon.Flags().StringVarP(&configPublicKeyFile, "config-public-key", "", "./keys/config-public-key.pem", "Config public key file")
		cmdDaemon.Flags().StringVarP(&masterPrivateKeyFile, "master-private-key", "", "./keys/master-private-key.pem", "Master private key file")

		cmdDaemon.Flags().StringVarP(&daemonIP, "ip", "i", "0.0.0.0", "Interface to bind to")
		cmdDaemon.Flags().IntVarP(&daemonPort, "port", "p", 5070, "Port to listen on")
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
