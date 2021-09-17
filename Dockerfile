#
# To build:
#  docker build -t vault .

# cargo chef will cache compiled 3rd party crates making incremental builds much quicker.
FROM rust:1.54.0 AS chef
RUN cargo install cargo-chef
RUN rustup component add rustfmt
WORKDIR vault

# Build a recipe for the chef!
FROM chef AS planner
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./src ./src
COPY ./proto ./proto
COPY ./build.rs ./build.rs
RUN cargo chef prepare  --recipe-path recipe.json

# Build the app from the recipe.
FROM chef AS builder
COPY --from=planner /vault/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./src ./src
COPY ./proto ./proto
COPY ./build.rs ./build.rs
RUN cargo build --release --bin vault

# Copy a grpc probe - this version let's us specify a service name so we can probe readiness and liveliness.
RUN GRPC_HEALTH_PROBE_VERSION=v0.3.1 && \
    wget -qO/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
    chmod +x /bin/grpc_health_probe

# The final image.
FROM gcr.io/distroless/cc-debian10 AS runtime
# Use this to debug.
# FROM debian as runtime
WORKDIR /
COPY --from=builder /lib/x86_64-linux-gnu/libz.so.1 /lib/x86_64-linux-gnu/libz.so.1
COPY --from=builder /vault/target/release/vault .
COPY --from=builder /bin/grpc_health_probe .
CMD ["/vault"]
