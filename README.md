# Secretary
[![Travis CI](https://img.shields.io/travis/meltwater/secretary/master.svg)](https://travis-ci.org/meltwater/secretary)
[![Coverage Status](http://codecov.io/github/meltwater/secretary/coverage.svg?branch=master)](http://codecov.io/github/meltwater/secretary?branch=master)

[Secretary](https://en.wikipedia.org/wiki/Secretary#Etymology) solves the problem of
secrets distribution and authorization in highly dynamic container environments.

Secretary uses [Marathon](https://mesosphere.github.io/marathon/) to determine which
service can access what secrets, and how to authenticate that service. This allows for
delegation of secrets management to non-admin users and keeps configuration, secrets
and software versions together throughout the delivery pipeline.

Secretary is conceptually similar to [Puppet agent and server](https://docs.puppetlabs.com/puppet/4.2/reference/architecture.html#communications-and-security)
certificates and [Hiera-Eyaml](https://puppetlabs.com/blog/encrypt-your-data-using-hiera-eyaml) but uses [NaCL](http://nacl.cr.yp.to/) public key
cryptography instead of SSL certificates and PKCS#7 encryption. A key differences with Secretary is however that
plaintext secrets are never stored to disk or otherwise made visible outside the container.

## System Components

- `secretary` executable embedded into service Docker images and with access to
   *deploy-private-key* and the optional *service-private-key*.
- `secretary daemon` running on master nodes behind a load balancer and with
   access to *master-private-key* and the Marathon REST API.
- *config repo* containing environment specific config, public keys and encrypted secrets.

## Encryption
Secretary uses [NaCL](http://nacl.cr.yp.to/) boxes through the golang
[crypto/nacl](https://godoc.org/golang.org/x/crypto/nacl/box) package. Boxes
are encrypted and signed using modern and strong public key cryptography.

Secretary uses 4 distinct key pairs for encrypting secrets and authenticating
service instances.

- *master* key is used to encrypt the secrets stored in the *config repo* and is
  generated for each environment. The *master-public-key* is stored in the
  *config repo* to allow easy configuration updates. The *master-private-key*
  is stored securely on the master nodes where `secretary daemon` runs.

- *config* key pair is used to sign encrypted secrets and control who can create
  encrypted secrets. A key pair is generated for each environment and stored in
  the *config repo* to enable easy configuration updates.

- *deploy* key pair is used to control what service can access what secrets, and
  to authenticate services at runtime. It is generated automatically at deployment
  time for each service, and is part of the Marathon app config. When using
  [Lighter](https://github.com/meltwater/lighter) it will generate this key pair 
  automatically.

  Access to the Marathon REST API should be restricted to avoid reading out the
  *deploy* private keys, and not to mention prevent anyone from starting containers
  with `--privileged --volume=/:/host-root`.

- The optional *service* key pair is used to authenticate Docker images or slave
  nodes. The private key is generated at Docker or VM image build time. It could be
  stored directly in the Docker image or in a VM image and mounted into
  the container.

### Compared to Centralized Systems?
Benefits of using public key cryptography compared to centrally
managed token-based systems like [Vault](https://github.com/hashicorp/vault) or
[KeyWhiz](https://github.com/square/keywhiz)

- Encryption of secrets and modifications to the *config repo* can safely be 
  performed without needing admin access to a central secrets management system.

- It's often desirable to tightly couple deployment of configuration and secrets
  with software deployments in a continuous delivery pipeline. *Configuration as code*
  implies managing configuration and secrets in the same way and using the same pipeline
  as software releases goes though.

  This helps avoid mismatches between what parameters and secrets a specific software
  version expects, and what's actually present in the central secret/config management
  system.

### Initial Secret Problem?
In token-based systems a problem occurs where the token that gives access to secrets
needs to be securely managed. Any holder of a token can use it to request the plaintext
secrets. A token should typically not be checked into source control or it will be
available to anyone with access to the *config repo*.

Secretary mitigates this problem by storing encrypted secrets in the *config repo* and
keeping them encrypted all the way into the runtime environment. Secrets are only ever 
decrypted inside the container at startup and stored in environment variables visible
only to the service.

### What is needed to get the secrets?

In the runtime env:

- Encrypted secret from runtime config
- *Deploy* private key from runtime config
- *Service* private key from Docker image or slave node
- Network access to `secretary daemon`

Or with access to the *config repo*:

- Encrypted secret from *config repo*
- Master private key from master nodes


## Getting Started
The *master* and *config* key pairs are created once and for each environment using
`secretary genkeys`, which defaults to put keys into the ./keys/ directory. Provision
all the keys to each master nodes, including the highly sensitive *master-private-key*.

Store *master-public-key* and *config private/public key* in the *config repo* together
with other environment config and encrypted secrets. This enables users with access to the
*config repo* to encrypt secrets and store them in the config.

Generate a new *deploy* key for each deployment and insert it into the `env` element
of the Marathon app config. [Lighter](https://github.com/meltwater/lighter) will perform 
this step automatically given this config example

*someenv/globals.yml* - stored in the Lighter *config repo*
```
secretary:
  url: 'https://secretary-daemon-loadbalancer:5070'
  master:
    publickey: 'someenv/keys/master-public-key.pem'
```

*someenv/myservice.yml* - stored in the Lighter *config repo*
```
maven:
  groupid: "com.example"
  artifactid: "myservice"
  classifier: "marathon"
  resolve: [1.0.0,2.0.0)
override:
  env:
    DATABASE_USERNAME: "myservice"
    DATABASE_PASSWORD: "ENC[NACL,NVnSkhxA010D2yOWKRFog0jpUvHQzmkmKKHmqAbHAnz8oGbPEFkDfyKHQHGO7w==]"
    DATABASE_URL: "jdbc:mysql://hostname:3306/schema"
```

### Service Key In Docker Image
The service key is optional but adds extra security. It is required by `secretary daemon`
to authenticate a service if its Marathon app *env* defines the *$SERVICE_PUBLIC_KEY* variable.

At build time generate a new *service* key using e.g. `secretary genkeys service` and embed
the *service-private-key* into the Docker image. Ensure it's `chmod 0600` root-only readable
and that a new key is created for each build/release.

The *service-public-key* needs to be available in the Marathon app *env* as *$SERVICE_PUBLIC_KEY*
so that `secretary daemon` can find it when querying Marathon. A solution could be deploying
a template JSON app config to a Maven repository and use [Lighter](https://github.com/meltwater/lighter)
to pull it down at deployment time. For example

*myservice-1.0.0-marathon.json* - deployed to Maven
```
{
  "id": "/myproduct/mysubsystem/myservice"
  "env" {
    "SERVICE_PUBLIC_KEY": "rEmz7Rt6tUnlC4TKYeNzePYg+p1ePAw4BAtfJAY4zzs="
  }
}
```

### Service Key In VM Image
Generate a service key using e.g. `secretary genkeys service` and embed the *service-private-key*
into the VM image. Ensure that the *service-public-key* is available in the Marathon app *env*
as *$SERVICE_PUBLIC_KEY*. A [Lighter](https://github.com/meltwater/lighter) config could look like
like

*someenv/globals.yml* - stored in the Lighter *config repo*
```
variables:
  secretary.service.publickey: "WvDT+V2fB5ZKkbAmHaFh2XqDXC/veVsl1FKSE/HzxC0="
```

*someenv/myservice.yml*
```
override:
  env:
    SERVICE_PUBLIC_KEY: "%{secretary.service.publickey}"
  container:
    volumes:
     - containerPath: "/service/keys"
       hostPath: "/etc/secretary/service-keys"
       mode: "RO"
```

## Runtime Config
An runtime config automatically expanded by Lighter might look like

```
{
    "id": "/myproduct/mysubsystem/myservice"
    ...
    "env" {
        "SECRETARY_URL": "https://secretary-daemon-loadbalancer:5070",
        "MASTER_PUBLIC_KEY": "MX+S1xWkxfKlZUvzaEhBLkIVWEkwIrEaD9uKXVC5IGE=",
        "DEPLOY_PUBLIC_KEY": "0k+v11LV3SOr+XiFJ/ug0KcPPhwkXnVirmO65nAd1LI=",
        "DEPLOY_PRIVATE_KEY": "rEmz7Rt6tUnlC4TKYeNzePYg+p1ePAw4BAtfJAY4zzs=",
        "SERVICE_PUBLIC_KEY": "/1fbWGMTaR+lLQJnEsmxdfwWybKOpPQpyWB3FpNmOF4=",
        "DATABASE_USERNAME": "myservice",
        "DATABASE_PASSWORD": "ENC[NACL,SLXf+O9iG48uyojT0Zg30Q8/uRV8DizuDWMWtgL5PmTU54jxp5cTGrYeLpd86rA=]",
        "DATABASE_URL": "jdbc:mysql://hostname:3306/schema"
    }
    ...
}
```

## Container Startup Sequence
Docker images should embed the `secretary` executable. Call it at container startup to decrypt
environment variables, before starting the actual service.

```
# Decrypt environment variables
eval $(secretary decrypt -e --service-key=/service/keys/service-private-key.pem)

# .. or alternatively decrypt environment variables for setups without a service-private-key
eval $(secretary decrypt -e)

# Start the main application (a Java service in this example)
function launch {
  exec su --preserve-environment unprivileged-service-user -c '$0 "$@"' -- "$@"
}

launch java $JAVA_OPTS -jar /service/lib/standalone.jar $@
```

The complete decryption sequence could be described as

1. *client* asks the *secretary daemon* for the `DATABASE_PASSWORD` secret to be decrypted. This
   exchange is encrypted/authenticated using *master-public-key*, *deploy-private-key* and
   *service-private-key*.
2. *daemon* retrieves `SERVICE_PUBLIC_KEY` and `DEPLOY_PUBLIC_KEY` from Marathon and uses it to
    authenticate the service.
3. *daemon* validates that the service has access to the given secret by checking the
   `env` segment of its Marathon app config.
4. *daemon* decrypts the secret using *master-private-key* and authenticates with *config-public-key*.
5. *daemon* re-encrypts the plaintext secret with *service-public-key* and *deploy-public-key*,
   signed with *master-private-key* before sending it back to the client.
6. *client* decrypts the secret using *deploy-private-key* and *service-private-key*,
   authenticating with *master-public-key*.
7. *client* outputs a sh script `export DATABASE_PASSWORD='secret'` fragment that is sourced into the
   service environment.

## Command Line Usage

```
# Avoid secrets ending up in bash history
set +o history

# Generate master and config key pairs
./secretary genkeys

# Generate example deploy and service key pairs
./secretary genkeys mydeploy myservice

# Generate an example service key
./secretary genkeys myservice

# Encrypt for writing into deployment config files
echo -n secret | ./secretary encrypt

# Decrypt (requires access to master-private-key)
echo <encrypted> | ./secretary decrypt
```

## Secretary Daemon
Deploy several instances of the `secretary daemon` to trusted master nodes and create a
load balancer in front of them to ensure high availability. The daemon defaults to
bind to 5070/tcp. The `secretary daemon` is completely stateless and can be load balanced
easily.

### Systemd and CoreOS/Fleet
Create a [Systemd unit](http://www.freedesktop.org/software/systemd/man/systemd.unit.html) file
in **/etc/systemd/system/secretary.service** with contents like below. Using CoreOS and
[Fleet](https://coreos.com/docs/launching-containers/launching/fleet-unit-files/) then
add the X-Fleet section to schedule the unit on master nodes.

```
[Unit]
Description=Secretary secrets distribution
After=docker.service
Requires=docker.service

[Install]
WantedBy=multi-user.target

[Service]
Environment=IMAGE=meltwater/secretary:latest NAME=secretary

# Allow docker pull to take some time
TimeoutStartSec=600

# Restart on failures
KillMode=none
Restart=always
RestartSec=15

ExecStartPre=-/usr/bin/docker kill ${NAME}
ExecStartPre=-/usr/bin/docker rm ${NAME}
ExecStartPre=-/usr/bin/docker pull ${IMAGE}
ExecStart=/usr/bin/docker run --name=${NAME} \
    -p 5070:5070 \
    -v /etc/secretary/master-keys:/keys \
    -e MARATHON_URL=http://localhost:8080 \
    $IMAGE

ExecStop=/usr/bin/docker stop $NAME

[X-Fleet]
Global=true
MachineMetadata=role=master
```

### Puppet Hiera

Using the [garethr-docker](https://github.com/garethr/garethr-docker) module

```
classes:
  - docker::run_instance

docker::run_instance:
  'secretary':
    image: 'meltwater/secretary:latest'
    ports:
      - '5070:5070'
    volumes:
      - '/etc/secretary/master-keys:/keys'
    env:
      - 'MARATHON_URL=http://localhost:8080'
```
