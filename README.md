
BUG: Underload - blowing through container memory limit. How? Try rate_limiting.
  Argon2 thread bug - need to bump to 3.0.1 and refactor some code.
  Also need a configurable concurrency limit in tower.

TODO: See if tower retry helps with surge overloading an instance (ie. gets us 100% success rate).

TODO: Cant use max_packet_size on jaeger batch - something isn't right when update to 0.15....
TODO: instrument - api:<method> db:<method> + add instrumentation for hashing in other thread.
TODO: rate-limit the hash and verify functions - to avoid too many CPU-bound threads.

TODO: Under heavy load see this.
OpenTelemetry trace error occurred Other(Custom("failed to export batch ExportFailed(ThriftAgentError(ProtocolError { kind: SizeLimit, message: \"jaeger exporter payload size of 71025 bytes over max UDP packet size of 65000 bytes. Try setting a smaller batch size.\" }))"))

TODO: release builds shouldn't include the internal proto's.

MONITORING
----------
TODO: https://tower-rs.github.io/tower/tower/load/index.html

TODO: MongoDB and Kafka tls + Kafka auth.
TODO: Document this file.

Nice to haves
-------------
- Distributed tracing context propagation across Kafka messages.
- Dynamic trace level switching api?
- Passport interceptor to validate claims.
TODO: Interesting https://github.com/uber/prototool#prototool-break-check

Document this is not an externally facing module and should be called by a sign-on orchistrator.
Note: Handy https://github.com/bradleyjkemp/grpc-tools
See vault.proto for API documentation.


Kubernetes
-----------

- cd <vault project root>

SECRETS!!!! https://kubernetes.io/docs/concepts/configuration/secret/

kubectl create secret tls vault-tls --cert=certs/cert.pem --key=certs/key.pem
kubectl create secret generic vault-secrets --from-literal=pepper=supersecret --from-literal=mongodb_username=root --from-literal=mongodb_password=changeme

Health probes in k8s
--------------------
https://github.com/grpc-ecosystem/grpc-health-probe/tree/1329d682b4232c102600b5e7886df8ffdcaf9e26#example-grpc-health-checking-on-kubernetes


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
---
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


Load Testing
------------

Run something like this - be wary of the hashing configuration, it can radically impact performance.

ghz --skipTLS --async \
  --import-paths=/protos \
  --call grpc.vault.Vault/HashPassword \
  --concurrency 50 \
  --connections 50 \
  --total 1000 \
  --rps 10 \
  --timeout 20s \
  -d '{"plain_text_password": "Bibble3!123"}' '[::1]:50011'
