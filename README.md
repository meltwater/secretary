# Secretary
Secrets management and distribution for dynamic container environments. 

Uses Marathon as the source of truth about what secrets a service can access and 
how to authenticate each service. Secrets are never stored on disk or visible 
outside the service container.

## System Components

- *config repo* containing environment specific config, public keys and encrypted secrets.
- `secretary` binary embedded into service Docker images and with access to *service-private-key*.
- `secretary daemon` running on master nodes behind a load balancer and with *master-private-key*.

## Key Management
The *master* and *config* key pairs are created once and for each environment using 
`secretary genkeys`. Transfer all the keys to master nodes including the highly 
sensitive *master-private-key*. 

Store *master-public-key* and *config private/public key* in the *config repo* together
with other environment config and encrypted secrets. This enables users with access to the
*config repo* to encrypt secrets and store them in the config.

At service build time generate a service key using `secretary genkeys service`. Each docker
image embeds the *service-private-key* that is `chmod 0600` root-readable and rolled on 
each image build/release. It's read by `secretary` running at container startup which 
then asks secretary-daemon for plaintext secrets. The secrets are injected into the environment
and never written to disk. Service processes should be started as an unprivileged users to 
avoid them later accessing the *service-private-key*.

The *service key* is generated at build/release time and *service-private-key* stored 
in Docker image. The *service-public-key* deployed to Maven/Nexus/Artifactory so it's 
available to e.g. [Lighter](https://github.com/meltwater/lighter) at deployment time.

If the *config-private-key* used for signing encrypted secrets is stored outside *config repo*
then someone else with access to that needs to encrypt every secret.

## Initial Secret Problem?
Secrets are encrypted two times using [NaCL](https://godoc.org/golang.org/x/crypto/nacl/box). 
The inner box is encrypted with the *master-public-key* and the outer level with 
*service-public-key*. The inner box is stored in the *config repo* and the outer box is
automatically created at deployment time.

The *service-public-key* is deployed to Maven and retrieved by [Lighter](https://github.com/meltwater/lighter) 
at deployment time. Lighter uses the *service-public-key* to create the outer encryption box at 
deployment time.

## What is needed to get the secrets?

In the runtime env:

- Outer encryption box from runtime config (through e.g. Marathon API)
- Service private key from Docker image
- Network access to `secretary daemon`

Or with access to the *config repo*:

- Inner box from *config repo*
- Master private key from master nodes

## Examples

```
# Generate master and config key pairs
./secretary genkeys

# Generate an example service key
./secretary genkeys myservice

# One level encryption for writing into deployment config files
echo -n secret | ./secretary encrypt

# Two level deployment encryption for writing into runtime service config
echo -n secret | ./secretary encrypt | ./secretary encrypt --public-key=./keys/myservice-public-key.pem

# Decrypt one level encryption
echo <encrypted> | ./secretary decrypt

# Decrypt two level encryption
echo <encrypted> | ./secretary decrypt --private-key=./keys/myservice-private-key.pem | ./secretary decrypt

# Decrypt two level using daemon. Note that this will only work inside a container deployed 
# with Marathon and with the app config setup like in the example. 
echo <encrypted> | ./secretary decrypt --private-key=./keys/myservice-private-key.pem -s http://secretary:5070
```

# Secretary Daemon with Marathon 
The `secretary daemon` uses Marathon to authenticate a service and validate that it has access
to a given secret. For example

```
{
    "id": "/myproduct/mysubsystem/myservice"
    "env" {
        "CONFIG_PUBLIC_KEY": "WiuMHYfHR/LHEuGb/ifiYvsN8ltAaY2qUnsbfNF/yn4="
        "MASTER_PUBLIC_KEY": "MX+S1xWkxfKlZUvzaEhBLkIVWEkwIrEaD9uKXVC5IGE="
        "DEPLOY_PUBLIC_KEY": "0k+v11LV3SOr+XiFJ/ug0KcPPhwkXnVirmO65nAd1LI="
        "DEPLOY_PRIVATE_KEY": "rEmz7Rt6tUnlC4TKYeNzePYg+p1ePAw4BAtfJAY4zzs="
        "SERVICE_PUBLIC_KEY": "/1fbWGMTaR+lLQJnEsmxdfwWybKOpPQpyWB3FpNmOF4="
        "DATABASE_USERNAME": "myservice"
        "DATABASE_PASSWORD": "ENC[NACL,NVnSkhxA010D2yOWKRFog0jpUvHQzmkmKKHmqAbHAnz8oGbPEFkDfyKHQHGO7w==]"
        "DATABASE_URL": "jdbc:mysql://hostname:3306/schema"
    }
}
```

## Config
Per-environment service config should be stored in a *config repo*. For example as suggested
by [Lighter](https://github.com/meltwater/lighter) when using it to automated Marathon deployments.

The *master-public-key*, *config-public-key* and *config-private-key* should be stored in this
repository for each environment, for example in "./keys/*.pem".

 * Encrypt the plaintext secret with `secretary encrypt`. This defaults to encrypt with 
   *master-public-key* and sign with *config-private-key* and produces an `ENC[NACL, ..]` *envelope*.

## Deployment
[Lighter](https://github.com/meltwater/lighter) automates this part when *service-public-key*
has already been deployed to Maven as part of the software build/release process.

 * Retrieve *service-public-key*
 * Encrypt the *envelope* again using the *service-public-key* and sign with *config-private-key*
 * Deploy app config containing the re-encrypted `DATABASE_PASSWORD` to Marathon

## Container Startup

 * `eval $(secretary decrypt -e -s http://secretary:5070 --private-key=/path/to/myservice-private-key.pem)`
 * *secretary client* running in the container decrypts the first level using *myservice-private-key*
   and authenticates with *config-public-key*.
 * *client* asks the *secretary daemon* for the `DATABASE_PASSWORD` secret to be decrypted. This
   exchange is encrypted/authenticated using *master-public-key* and *myservice-private-key*.
 * *daemon* retrieves `SERVICE_PUBLIC_KEY` from Marathon and uses it to authenticate the service. 
 * *daemon* validates that the service really has access to the given secret by checking the 
   `env` segment of its Marathon config.
 * *daemon* decrypts the secret using *master-private-key* and authenticates with *config-public-key*.
 * *daemon* sends the secret back to the client encrypted with *service-public-key* and signed with *master-private-key*.
 * *client* decrypts the secret using *service-private-key* and authenticates with *master-public-key*.
 * *client* outputs a bash `export DATABASE_PASSWORD=secret` fragment that is sourced into the service environment.

## TODO

* Validate that TaskId corresponds to a running task with the given appid/appversion
* Lighter looks for a type:pem in maven when deploying and send it along in SERVICE_PUBLIC_KEY
* Lighter creates outer box with svc key when deploying. 
* Lighter needs to populate CONFIG_PUBLIC_KEY/MASTER_PUBLIC_KEY
* Needs to declare as insecure service to get autogenerated svckey by lighter. Error if enc envvar present by no key in maven or insecure declared
* Sign/encrypt query parameters in decrypt request to daemon (pack all of them into envelope)
* Setuid secretary-cgi that decrypts the master key to avoid
  giving `secretary daemon` direct access to master private key.
