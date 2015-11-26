# Secretary
[Secretary](https://en.wikipedia.org/wiki/Secretary#Etymology) solves the problem of
secrets distribution, service authentication and secrets authorization in highly 
dynamic container environments. 

It uses Mesosphere [Marathon](https://mesosphere.github.io/marathon/) as the source
of truth of which service can access what secrets and how to authenticate each 
service. Plaintext secrets are never stored on disk or visible outside the container.

## System Components

- *config repo* containing environment specific config, public keys and encrypted secrets.
- `secretary` executable embedded into service Docker images and with access to *
   deploy-private-key* and the optional *service-private-key*.
- `secretary daemon` running on master nodes behind a load balancer and with 
   access to *master-private-key* and the Marathon REST API.


## Encryption
Secretary uses [NaCL](http://nacl.cr.yp.to/) boxes through the golang 
[crypto/nacl](https://godoc.org/golang.org/x/crypto/nacl/box) package. Boxes
are encrypted and signed using modern and strong public key cryptography.

Secretary uses distinct 4 key pairs for encrypting secrets and authenticating 
service instances.

- *master* key is used to encrypt secrets at rest in the *config repo* and is
  generated for each environment. The *master-public-key* is stored in the 
  *config repo* to allow easy configuration updates. The *master-private-key* 
  is stored securely on the data center master nodes where `secretary daemon` runs.

- *config* key pair is used to sign encrypted secrets and control who can create 
  encrypted secrets. A key pair is generated for each environment and stored in 
  the *config repo* to enable easy configuration updates.

- *deploy* key pair is used to control what service can access what secrets and
  to authenticate services at runtime. It should be generated automatically at 
  deployment time like e.g. [Lighter](https://github.com/meltwater/lighter) does, 
  and is part of the Marathon app config.

  Access to the  Marathon REST API should be restricted to avoid reading out the 
  *deploy* private keys, and not to mention prevent anyone from starting containers
  with `--privileged=true --volume=/:/host-root`.

- The optional *service* key pair is used to authenticate Docker images or slave 
  nodes. It could for example be stored inside the Docker image or on the host
  slave nodes and mounted into the service container. 

### Compared to Centralized Systems?
Some benefits of using public key cryptography compared to for example a centrally
managed token-based systems like Vault or KeyWhiz is that 

- Encryption of secrets and modifications to *config repo* can safely be performed 
  by people without needing admin access to a central system. 

- It's often desirable to tightly couple deployment of configuration and secrets
  with software deployments in a continuous delivery pipeline. *Configuration as code*
  implies managing configuration and secrets in the same way and using the same pipeline 
  as software releases goes though.

  This helps avoid mismatches between what parameters and secrets a specific sofware 
  version expects, and what's actually present in the central secret/config management 
  system.

### Initial Secret Problem?
In for example token-based systems a chicken-and-egg kind of problem occurs where 
the token that gives access to secrets needs to be securely managed. Any holder of a
token can use it to request the plaintext secrets. A plaintext token should typically 
not be checked into source control or it will be available to anyone with access to 
the *config repo*. 

Secretary mitigates this problem by encrypting secrets 1 time at rest and an additional
2 times at deployment time. The innermost box is encrypted with the *master-public-key*
and the outer levels with boxes with *service* and *deploy* keys. The inner box is stored
in the *config repo* and the outer boxes are automatically created at deployment time.

Authentication at runtime is performed by `secretary daemon` talking to Marathon and using
both *deploy* and *service* keys to make sure requesting client is actually allowed to 
the secret in question.

### What is needed to get the secrets?

In the runtime env:

- Outermost encryption box from runtime config
- *Deploy* private key from runtime config
- *Service* private key from Docker image or slave node
- Network access to `secretary daemon`

Or with access to the *config repo*:

- Inner box from *config repo*
- Master private key from master nodes


## Getting Started
[Lighter](https://github.com/meltwater/lighter) helps automate deployments to Marathon 
and manage differences between environments. It also automates creation of *deploy* keys
and handle the extra deployment time encryption/signing.

The *master* and *config* key pairs are created once and for each environment using 
`secretary genkeys`, which defaults to put keys into the ./keys/ directory. Provision 
all the keys to each master nodes, including the highly sensitive *master-private-key*. 

Store *master-public-key* and *config private/public key* in the *config repo* together
with other environment config and encrypted secrets. This enables users with access to the
*config repo* to encrypt secrets and store them in the config.

Generate a new *deploy* key for each deployment and encrypt each configured secret once
more. [Lighter](https://github.com/meltwater/lighter) will perform this step automatically 
given this config example

*someenv/globals.yml * - stored in the Lighter *config repo*
```
secretary:
  url: "http://secretary-daemon-loadbalancer:5070"
  master:
    publickey: someenv/keys/master-public-key.pem
  config:
    publickey: someenv/keys/config-public-key.pem
    privatekey: someenv/keys/config-private-key.pem
```

### Service Key In Docker Image
The service key is optional but adds extra security. It is required by `secretary daemon` 
to authenticate a service if its Marathon app *env* defines the *$SERVICE_PUBLIC_KEY* variable.

At build time generate a new *service* key using e.g. `secretary genkeys service` and embed
the *service-private-key* into the Docker image. Ensure it's `chmod 0600` root-only readable 
and that a new key is created for each build/release.

The *service-public-key* needs to be available in the Marathon app *env* as *$SERVICE_PUBLIC_KEY* 
so that `secretary daemon` can find it when querying the Marathon REST API. It could for example
be deployed to Maven/Nexus/Artifactory so it's available in the JSON config template that
[Lighter](https://github.com/meltwater/lighter) pull down at deployment time. For example

*myservice-1.0.0-marathon.json* - deployed to Maven
```
{
  "id": "/myproduct/mysubsystem/myservice"
  "env" {
    "SERVICE_PUBLIC_KEY": "rEmz7Rt6tUnlC4TKYeNzePYg+p1ePAw4BAtfJAY4zzs="
  }
}
```

*someenv/myservice.yml* - stored in the Lighter *config repo*
```
maven:
  groupid: "com.example"
  artifactid: "myservice"
  classifier: "marathon"
  resolve: [1.0.0,2.0.0)
```

### Service Key In VM Image
Generate a service key using e.g. `secretary genkeys service` and embed the *service-private-key*
into the VM image. Ensure that the *service-public-key* is available in the Marathon app *env*
as *$SERVICE_PUBLIC_KEY*. For examle using a [Lighter](https://github.com/meltwater/lighter) config 
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
        "SECRETARY_DAEMON_URL": "http://secretary-daemon-loadbalancer:5070",
        "MASTER_PUBLIC_KEY": "MX+S1xWkxfKlZUvzaEhBLkIVWEkwIrEaD9uKXVC5IGE=",
        "CONFIG_PUBLIC_KEY": "WiuMHYfHR/LHEuGb/ifiYvsN8ltAaY2qUnsbfNF/yn4=",
        "DEPLOY_PUBLIC_KEY": "0k+v11LV3SOr+XiFJ/ug0KcPPhwkXnVirmO65nAd1LI=",
        "DEPLOY_PRIVATE_KEY": "rEmz7Rt6tUnlC4TKYeNzePYg+p1ePAw4BAtfJAY4zzs=",
        "SERVICE_PUBLIC_KEY": "/1fbWGMTaR+lLQJnEsmxdfwWybKOpPQpyWB3FpNmOF4=",
        "DATABASE_USERNAME": "myservice",
        "DATABASE_PASSWORD": "ENC[NACL,NVnSkhxA010D2yOWKRFog0jpUvHQzmkmKKHmqAbHAnz8oGbPEFkDfyKHQHGO7w==]",
        "DATABASE_URL": "jdbc:mysql://hostname:3306/schema"
    }
    ...
}
```

## Container Startup Sequence
Docker images should embed the `secretary` executable. Call it at container startup to decrypt 
environment variables, before starting the actual service (preferably as an unprivileged user).

```
# Decrypt environment variables
eval $(secretary decrypt -e -s "$SECRETARY_DAEMON_URL" --service-key=/service/keys/service-private-key.pem)

# .. or alternatively decrypt environment variables for setups without a service-private-key
eval $(secretary decrypt -e -s "$SECRETARY_DAEMON_URL")

# Start the main application (a Java service in this example)
function launch {
  exec su --preserve-environment unprivileged-service-user -c '$0 "$@"' -- "$@"
}

launch java $JAVA_OPTS -jar /service/lib/standalone.jar $@
```

The complete decryption sequence could be described as

1. *secretary client* running in the container decrypts the outer 2 boxes using *deploy-private-key*
   and *service-private-key*, authenticating with *config-public-key*.
2. *client* asks the *secretary daemon* for the `DATABASE_PASSWORD` secret to be decrypted. This
   exchange is encrypted/authenticated using *master-public-key*, *deploy-private-key* and
   *service-private-key*.
3. *daemon* retrieves `SERVICE_PUBLIC_KEY` and `DEPLOY_PUBLIC_KEY` from Marathon and uses it to 
    authenticate the service. 
4. *daemon* validates that the service has access to the given secret by checking the 
   `env` segment of its Marathon app config.
5. *daemon* decrypts the secret using *master-private-key* and authenticates with *config-public-key*.
6. *daemon* re-encrypts the plaintext secret with *service-public-key* and *deploy-public-key*,
   signed with *master-private-key* before sending it back to the client.
7. *client* decrypts the secret using *deploy-private-key* and *service-private-key*, 
   authenticating with *master-public-key*.
8. *client* outputs a sh script `export DATABASE_PASSWORD='secret'` fragment that is sourced into the
   service environment.

## Command Line Usage

```
# Avoid secrets ending up in bash history
set +o history

# Generate master and config key pairs
./secretary genkeys

# Generate an example service key
./secretary genkeys myservice

# One level encryption for writing into deployment config files
echo -n secret | ./secretary encrypt

# Decrypt one level encryption (if you have access to the master-private-key)
echo <encrypted> | ./secretary decrypt

# Decrypt 2 level runtime encryption (no service key)
echo <encrypted> | ./secretary decrypt --private-key=./keys/deploy-private-key.pem | \
                   ./secretary decrypt

# Decrypt 3 level runtime encryption (with service key)
echo <encrypted> | ./secretary decrypt --private-key=./keys/deploy-private-key.pem | \
                   ./secretary decrypt --private-key=./keys/service-private-key.pem | \
                   ./secretary decrypt
```

## Secretary Daemon 
Deploy several instances of the `secretary daemon` to trusted master nodes and create a
load balancer in front of them to ensure high availability. The deamon defaults to
bind to 5070/tcp.

### Systemd and CoreOS/Fleet
Create a [Systemd unit](http://www.freedesktop.org/software/systemd/man/systemd.unit.html) file 
in **/etc/systemd/system/proxymatic.service** with contents like below. Using CoreOS and
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
Environment=IMAGE=mikljohansson/secretary:latest NAME=secretary

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
    image: 'mikljohansson/secretary:latest'
    ports:
      - '5070:5070'
    volumes:
      - '/etc/secretary/master-keys:/keys'
    env:
      - 'MARATHON_URL=http://localhost:8080'
```

## TODO

* Lighter looks for a type:pem in maven when deploying and send it along in SERVICE_PUBLIC_KEY
* Lighter generates deploy key and sets DEPLOY_PUBLIC_KEY, DEPLOY_PRIVATE_KEY
* Lighter creates inner box with svc key when deploying. 
* Lighter creates outer box with deploy key when deploying. 
* Lighter needs to populate CONFIG_PUBLIC_KEY/MASTER_PUBLIC_KEY
* Needs to declare as insecure service to get autogenerated svckey by lighter. Error if enc envvar present by no key in maven or insecure declared
* Setuid secretary-cgi that decrypts the master key to avoid
  giving `secretary daemon` direct access to master private key.
