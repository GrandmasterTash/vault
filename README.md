# Vault

[Features](#Features) | [Getting Started](#Getting-Started) | [Secrets and Certificates](#Secrets-and-Certificates) | [Nice-to-haves](#Nice-to-haves) | [Running the Tests](#Running-the-Tests) | [Jaeger Tracing](#Jaeger-Tracing) | [Kubernetes](#Kubernetes)

A [Rust](https://www.rust-lang.org/) microservice for **password hashing** and **verification**. As-such it is efficient, scaleable, secure and stable.

Vault APIs uses [gRPC](https://grpc.io/), [MongoDB](https://www.mongodb.com/) for persistence and notifications are sent using [Kafka](https://kafka.apache.org/).

Vault is NOT designed to be an edge service - it is intended to be called from an orchestration service.

## Features
### Supports multiple hashing aglorithms
Vault supports multiple password hashing algorithms:
  - [Argon2](https://en.wikipedia.org/wiki/Argon2)
  - [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
  - [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) (only HMAC SHA256)

### Password policies
Passport policies can be defined or modified on-the-fly without invalidating existing passwords. Policies enforce things like: -
  - Min/max length, number symbols, mixed case, etc.
  - Rotation periods
  - Banned phrases
  - Prohibit re-use last-n passwords
  - Lock-out period

### External Pepper/Secret
Passwords are hashed and stored in a [phc](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md) string, this means the hash is stored with a salt. If you are using the argon algorithm to hash, you can also provide an external secret to combine with the hashes, which isn't stored in the database, giving you an extra layer of protection.

### Migration
Bulk import of existing passwords (either plain-text or in [phc](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md) form).


## Getting Started
To try-out Vault you can build it and spin-up the docker-compose environment with these commands: -

```
docker-compose -f docker-compose-vault.yml build
docker-compose -f docker-compose-vault.yml up -d
```

Check the logs for any errors: -

```
docker logs vault -f
```

If things are working you should see this log entry

```
vault: Vault listening on 0.0.0.0:50011 and using tls
```

Try to use an API: -

```
grpcurl -d '{ "plain_text_password": "Wibbl3!123" }' \
   localhost:50011 grpc.vault.Vault/HashPassword
```

You should see a response with a passwordId field whose value is a UUID. Well done you now have a password!

To verify your password try this: -

```
grpcurl -d '{ "password_id": "<<UUID_FROM_ABOVE>>>", "plain_text_password": "Wibbl3!123" }' \
   localhost:50011 grpc.vault.Vault/ValidatePassword
```

If your password matched you should see and empty response. To confirm - try the wrong password: -

```
grpcurl -d '{ "password_id": "<<UUID_FROM_ABOVE>>>", "plain_text_password": "WRONG" }' \
   localhost:50011 grpc.vault.Vault/ValidatePassword
```

You should see a response stating your password did not match.

For more details on Vault's API refer to [vault.proto](proto/vault.proto)

## Secrets and Certificates
### TLS Certificates
Vault apis are exposed over TLS, so ensure there is a valid cert.pem and key.pem in the [certs](certs) folder.

If you need to create a temporary self-signed certificate try https://github.com/FiloSottile/mkcert as it will deal with the ca side of things too.

```
mkcert -install
mkcert example.com "*.example.com" example.test localhost 127.0.0.1 ::1
```

You can then rename and move the generated certificate and key into the /certs folder and rename and copy the generated ca cert from /etc/ssl/certs/mkcert_development_CA_xxxxx.pem (on Ubuntu for example) into the project certs folder.

The [ca.pem](certs/ca.pem) is used by the integration tests clients. The [cert.pem](cert.pem) and [key.pem](key.pem) are used by the server.

### Mongo Authentication Credentials
The URI to connect to MongoDB can be supplied as an environment variable. However, to avoid putting the MongoDB username and password in this environment variable, use $USERNAME and $PASSWORD tokens instead.

Be careful if/how you escape the '$' though. For example, use this format in a [docker-compose-vault.yml](docker-compose-vault.yml) file: -

```
MONGO_URI: mongodb://$$USERNAME:$$PASSWORD@mongo:27017
```

Use this format in the [.env](.env) file (not deployed at runtime): -

```
MONGO_URI=mongodb://\$USERNAME:\$PASSWORD@localhost:27017
```

And this format in the helm [values.yaml](helm/values.yaml) file: -

```
mongo:
  uri: "mongodb://$USERNAME:$PASSWORD@mongodb.default.svc.cluster.local:27017"
```

Then
edit the secret files [secrets/mongodb_username](secrets/mongodb_username) and [secrets/mongodb_password](secrets/mongodb_password).

These files can be volume mounted at deployment time from a secure source (from a Kubernetes secret for example).

### Pepper
If using the argon hashing algorithm, an external secret can be provided at runtime by mounting your secret pepper into the file [secrets/pepper](secrets/pepper) and it will applied to argon hashed passwords - without being stored in the database.


## Nice-to-haves
- MongoDB and Kafka with tls and Kafka username and password authentication.
- Distributed tracing context propagation across Kafka messages.
- Dynamic trace level switching via an internal API.
- Optional Passport interceptor to validate claims.
- Release builds shouldn't include the internal proto's. Use release/cfg flag to remove them.
- More integration tests required (see TODOs).

## Running the Tests
If you wish to run the tests, first start the docker-compose environement which excludes Vault

```
docker-compose up
```

Then run the unit and integration tests with

```
cargo test
```

## Jaeger Tracing
Distributed tracing can be exported to Jaeger by setting this environment variable: 

```
JAEGER_ENDPOINT=localhost:6831
```

## Kubernetes
A sample [helm](helm) chart is included - before installing you'll need to ensure the secrets and certificates are installed with

```
kubectl create secret tls vault-tls --cert=certs/cert.pem --key=certs/key.pem
kubectl create secret generic vault-secrets --from-literal=pepper=supersecret --from-literal=mongodb_username=root --from-literal=mongodb_password=changeme
```



