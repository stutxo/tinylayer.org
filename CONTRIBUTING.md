# Contributing to Tinylayer

Tinylayer is an experimental Bitcoin statechain proof of concept. Changes to
the signer, protocol, transaction construction, or persistence format can
invalidate security assumptions and existing wallet data. Keep changes small,
explicit, and covered by adversarial tests.

## Development setup

Requirements:

- Rust 1.88 or newer.
- A free local TCP port 8080 for the workload binary test.
- Bitcoin Core 28 or newer, `bitcoin-cli`, `curl`, and `jq` for the real
  Regtest flow.
- Docker only when changing or testing the enclave image.

Build the workspace from the repository root:

```bash
cargo build --locked --workspace --all-features
```

## Required checks

Run before submitting a change:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

The workload binary test starts the real workload on `0.0.0.0:8080`. Stop any
local workload or container using that port before running the suite.

For transaction, wallet, or chain-backend changes, also run the real Bitcoin
Core flow described in [`wallet/README.md`](wallet/README.md#automated-regtest-test):

```bash
BITCOIN_DATADIR="$BTC_DIR" KEEP_TMP=1 \
  ./client/scripts/bitcoin-core-regtest.sh
```

This script is the only repository test that uses a real Bitcoin Core node.
The Enclavia transport tests use synthetic attestation; a real Nitro deployment
must be verified separately with the
[`enclave/README.md`](enclave/README.md) runbook.

## Change rules

### Enclave source

[`README.md`](README.md) contains a fully commented copy of the complete
256-line [`enclave/src/lib.rs`](enclave/src/lib.rs). A signer-source change must
update that explanatory copy in the same change, or deliberately revise the
line-count claim and documentation.

Do not add persistence, endpoint authentication, egress, secrets, replicas, or
upgrade behavior without updating the enclave lifecycle and deployment guide.
Those features change the trust boundary rather than merely adding operations.

### Protocol

A protocol-semantic change must coordinate:

- `PROTOCOL_VERSION` and versioned `/v1` routing.
- Capability and authorization hash domain tags.
- Request/response types and strict wire tests.
- `enclave/README.md` HTTP and state-machine documentation.
- Client, wallet, transfer, and compatibility tests.

Do not silently extend strict payloads or reinterpret existing fields under the
same version.

### Bitcoin policy

Transaction changes need positive and negative tests for exact versions,
locktimes, sequences, prevouts, amounts, scripts, sighashes, witnesses, dust,
fees, and mutation resistance. Keep Bitcoin validation in the untrusted client;
the enclave intentionally signs an opaque digest.

### Wallet formats

Wallet state and transfer artifacts currently use `FILE_FORMAT_VERSION = 3`.
Many payload structs reject unknown fields, while some tagged journal variants
do not; do not assume a new field is safely ignored everywhere. A serialized
format change must either preserve exact compatibility or increment the format
version and document migration or the lack of one. Coordinate transfer
encryption domain tags and tests with any format change.

### Dependencies and images

Keep dependency versions and `Cargo.lock` synchronized. The enclave image is
part of the measured trusted computing base, so Dockerfile, base image, runtime
user, port, and dependency changes must be reflected in the deployment guide
and result in a newly recorded PCR policy.

## Security reports

Do not open a public issue for a suspected vulnerability. Follow
[`SECURITY.md`](SECURITY.md) and encrypt sensitive details with the published
reporting key.

## License

By contributing, you agree that your contribution is licensed under the
[MIT License](LICENSE) used by this repository.
