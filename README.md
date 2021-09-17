TODO: Integration tests should use a snapshot of the protobuf api NOT the latest generated version.
https://github.com/hyperium/tonic/tree/master/tonic-build

TODO: Helm chart.
TODO: Clippy and audit and gutters.
TODO: Distributed tracing context propagation across Kafka messages.
TODO: Document this file.
TODO: Dynamic trace level switching api?
TODO: AB testing?
Document this is not an externally facing module and should be called by a sign-on orchistrator.
Note: Handy https://github.com/bradleyjkemp/grpc-tools


See vault.proto for API documentation.


Integration Tests
-----------------

Need docker-compose up
Use copy of exported API clients - to catch breaking changes.

Coverage
--------

cargo tarpaulin --ignore-tests --out Lcov

Pepper
------



Healthcheck

grpc_health_probe -addr="[::]:50011" -service="grpc.vault.Vault" -connect-timeout 250ms -rpc-timeout 100m


TLS
You could create a self-signed server certificate and key by running this: -

```
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'
```

And then register the server cert with the ca authority on your machine.


But an easier way is to use https://github.com/FiloSottile/mkcert as it will deal with the ca side of things too.

```
mkcert -install
mkcert example.com "*.example.com" example.test localhost 127.0.0.1 ::1
```

You can then rename and move the certificate and key into the /certs folder and rename and move the ca cert from /etc/ssl/certs/mkcert_development_CA_xxxxx.pem (on Ubuntu for example).

The ca.pem is used by the integration tests clients.
The cert.pem and key.pem are used by the server.
