FROM rust:1.88-bookworm AS build

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY enclave/Cargo.toml enclave/Cargo.toml
COPY client/Cargo.toml client/Cargo.toml
COPY wallet/Cargo.toml wallet/Cargo.toml
COPY enclave/src enclave/src
COPY client/src client/src
COPY wallet/src wallet/src
RUN cargo build --locked --release -p tinylayer-enclave --features workload --bin tinylayer-workload

FROM debian:bookworm-slim
COPY --from=build /app/target/release/tinylayer-workload /usr/local/bin/tinylayer-workload
COPY LICENSE /usr/share/licenses/tinylayer/LICENSE

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["tinylayer-workload"]
