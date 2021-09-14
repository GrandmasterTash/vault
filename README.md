TODO: Add more Kafka notifications.
TODO: Optimise Tests/Kafka connection.
TODO: Document.
TODO: Kafka credentials?
TODO: Pepper via secrets file or env var.
TODO: TLS
TODO: Helm chart.
TODO: Clippy and audit and gutters.
TODO: Join kafka consumer trace to publish trace?
Document this is not an externally facing module and should be called by a sign-on orchistrator.
Note: Handy https://github.com/bradleyjkemp/grpc-tools


See vault.proto for API documentation.




Healthcheck

grpc_health_probe -addr="[::]:50011" -service="grpc.vault.Vault" -connect-timeout 250ms -rpc-timeout 100m