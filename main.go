package main

import (
	"fmt"
	"os"

	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
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
		var publicKeyFile, privateKeyFile, awsKmsID string
		var wrapLines bool
		cmdEncrypt := &cobra.Command{
			Use:   "encrypt",
			Short: "Encrypt data",
			Run: func(cmd *cobra.Command, args []string) {
				var crypto EncryptionStrategy

				if len(awsKmsID) > 0 {
					crypto = newKmsEncryptionStrategy(newKmsClient(), awsKmsID)
				} else {
					publicKey := requireKey("config public", publicKeyFile, "PUBLIC_KEY", "./keys/master-public-key.pem")
					privateKey := requireKey("deploy private", privateKeyFile, "PRIVATE_KEY", "./keys/config-private-key.pem")
					crypto = newKeyEncryptionStrategy(publicKey, privateKey)
				}

				encryptCommand(os.Stdin, os.Stdout, crypto, wrapLines)
			},
		}

		cmdEncrypt.Flags().StringVarP(&publicKeyFile, "public-key", "", "", "Public key")
		cmdEncrypt.Flags().StringVarP(&privateKeyFile, "private-key", "", "", "Private key")
		cmdEncrypt.Flags().StringVarP(&awsKmsID, "kms-key-id", "", os.Getenv("KMS_KEY_ID"), "Amazon AWS KMS key id")
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
				var crypto DecryptionStrategy

				if len(secretaryURL) > 0 {
					deployKey := requireKey("deploy private", deployKeyFile, "DEPLOY_PRIVATE_KEY", "./keys/master-private-key.pem")
					masterKey := requireKey("master public", masterKeyFile, "MASTER_PUBLIC_KEY", "./keys/master-public-key.pem")
					serviceKey := findKey(serviceKeyFile, "SERVICE_PRIVATE_KEY")
					crypto = newDaemonDecryptionStrategy(
						secretaryURL, appID, appVersion, taskID,
						masterKey, deployKey, serviceKey)
				} else {
					// Send ENC[KMS,..] and ENC[NACL,...] to separate decryptors
					composite := newCompositeDecryptionStrategy()
					composite.Add("KMS", newKmsDecryptionStrategy(newKmsClient()))

					deployKey := findKey("deploy private", deployKeyFile, "DEPLOY_PRIVATE_KEY", "./keys/master-private-key.pem")
					configKey := findKey("config public", configKeyFile, "CONFIG_PUBLIC_KEY", "./keys/config-public-key.pem")
					if deployKey != nil && configKey != nil {
						composite.Add("NACL", newKeyDecryptionStrategy(configKey, deployKey))
					}

					crypto = composite
				}

				if decryptEnv {
					// err is also printed on stderr, so no need to use it here
					ok, _ := decryptEnvironment(os.Environ(), os.Stdout, crypto)

					if !ok {
						os.Exit(1)
					}
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
		var marathonURL, configKeyFile, masterKeyFile, daemonIP string
		var daemonPort int

		cmdDaemon := &cobra.Command{
			Use:   "daemon",
			Short: "Start the REST service that decrypts secrets",
			Run: func(cmd *cobra.Command, args []string) {
				// Send ENC[KMS,..] and ENC[NACL,...] to separate decryptors
				composite := newCompositeDecryptionStrategy()
				composite.Add("KMS", newKmsDecryptionStrategy(newKmsClient()))

				// NaCL support is optional if configKey isn't given. masterKey is needed to authenticate calling containers
				configKey := findKey("config public", configKeyFile, "CONFIG_PUBLIC_KEY", "./keys/config-public-key.pem")
				masterKey := requireKey("master private", masterKeyFile, "MASTER_PRIVATE_KEY", "./keys/master-private-key.pem")
				if configKey != nil && masterKey != nil {
					composite.Add("NACL", newKeyDecryptionStrategy(configKey, masterKey))
				}

				listenAddress := fmt.Sprintf("%s:%d", daemonIP, daemonPort)
				daemonCommand(listenAddress, marathonURL, masterKey, composite)
			},
		}

		cmdDaemon.Flags().StringVarP(&marathonURL, "marathon-url", "",
			defaults(os.Getenv("MARATHON_URL"), "http://localhost:8080"), "URL of Marathon")
		cmdDaemon.Flags().StringVarP(&configKeyFile, "config-key", "", "", "Config public key file")
		cmdDaemon.Flags().StringVarP(&masterKeyFile, "master-key", "", "", "Master private key file")

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
