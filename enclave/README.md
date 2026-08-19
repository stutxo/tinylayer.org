# Tinylayer enclave

This directory contains Tinylayer's trusted signer state machine and the
`tinylayer-workload` HTTP process that Enclavia packages into an enclave image.
The application source is [`src/lib.rs`](src/lib.rs); the container definition
is [`Dockerfile`](Dockerfile).

Tinylayer is experimental. The current workload is deliberately fail-stop and
keeps every signing key in process memory. Read [Lifecycle and data
loss](#lifecycle-and-data-loss) before registering or funding a coin.

## Contents

- [How it works](#how-it-works)
- [State machine](#state-machine)
- [Build and run locally](#build-and-run-locally)
- [Deploy to Enclavia](#deploy-to-enclavia)
- [Configure the wallet](#configure-the-wallet)
- [How clients connect](#how-clients-connect)
- [HTTP API](#http-api)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)

## How it works

Production and debug clients use the Enclavia SDK. Local Regtest development
can bypass Enclavia and call the workload directly:

```text
tinylayer-wallet or tinylayer-client
             |
             | production/debug: WSS + Noise + CBOR + attestation
             v
       Enclavia router
             |
             | encrypted tunnel into the measured enclave
             v
    Enclavia in-enclave server
             |
             | HTTP/1.1 to 127.0.0.1:8080
             v
      tinylayer-workload
        GET  /health
        POST /v1
             |
             v
 Arc<Mutex<Signer<21_000>>>
             |
             v
 in-memory map of coin signing states
```

The Enclavia layer authenticates the enclave to the client and encrypts the
channel. It does not authenticate the client to the Tinylayer workload. The
workload has no HTTP credentials, client allowlist, rate limit, or per-client
quota.

For each coin, the enclave holds:

| Value | Purpose |
| --- | --- |
| Enclave secret key | Produces an ordinary BIP340 signature over a client-supplied digest. |
| Authorization commitment | Commits to the current capability and handoff without exposing either preimage. |
| Signature count | Lets clients match live state to the complete recovery history. |
| Latest request and response | Makes one exact lost-response retry idempotent. |

The client holds the other signing key and all Bitcoin policy. The funding
output is a one-leaf P2TR output with this script:

```text
<client_xonly> OP_CHECKSIGVERIFY <enclave_xonly> OP_CHECKSIG
```

The enclave does not parse a transaction, inspect an amount, check a relative delay,
or decide where funds go. It signs an opaque 32-byte digest after checking the
current bearer authorization. The untrusted reference client constructs and
validates the Bitcoin transaction before and after the enclave call.

## State machine

Protocol version 1 is the first Tinylayer protocol and has three operations:

| Operation | Behavior |
| --- | --- |
| `register` | The client chooses a random coin ID and commits to its initial capability. The enclave generates an independent signing key. The first registration for a coin ID wins. |
| `status` | Returns the coin ID, enclave public key, authorization commitment, and signature count. Status is public to anyone who knows the coin ID. |
| `sign` | Verifies the current capability and handoff, signs the supplied digest, rotates authorization to the receiver's capability hash and a fresh handoff, and increments the count atomically. |

Capabilities, handoffs, coin IDs, digests, and hash outputs are all 32 bytes.
The initial handoff is 32 zero bytes.

Authorization uses BIP340-style tagged SHA-256 with fixed field order:

```text
capability_hash =
  tagged_sha256("Tinylayer/Capability/v1", capability)

authorization =
  tagged_sha256("Tinylayer/Authorization/v1",
                coin_id || capability_hash || handoff)
```

All `/v1` state-machine calls share one async mutex. A complete request is
serialized with every other state-machine request and no partially applied
transition is visible. `/health` does not acquire the state lock.

An exact retry of the latest successful `sign` request returns the cached
response without incrementing the counter again. Only that latest request is
retryable. Once another transition succeeds, an older request is stale. The
Enclavia SDK does not automatically resend an in-flight request whose outcome
is unknown; the wallet journals the exact request so the same command can be
rerun safely while the same enclave process and retry cache still exist.

Registration is also idempotent, but a conflicting duplicate does not return
an error: it returns the first registration's live status. A client must verify
the returned coin ID, zero count, and authorization against its prepared
registration, and must check that the newly returned enclave key differs from
the client key, before funding.

## Lifecycle and data loss

The workload has no persistence. It does not read or write Enclavia's `/data`
volume, and it accepts no environment variables or command-line configuration.
Every process boot starts with an empty map.

The following events permanently destroy all enclave signing keys, coin state,
and retry records:

- A process or container crash.
- `enclavia enclave stop`, `restart`, or a stop followed by `start`.
- An image upgrade or rolling replacement.
- Replacing the enclave with a newly created enclave.
- A platform or host failure that restarts the workload.

The same image can produce the same application measurements after a restart,
so attestation and `/health` can both succeed while every previous coin is
unknown. `/health` proves only that the current process answers.

Operational consequences:

- Run exactly one instance. Do not add replicas, load balancing, autoscaling,
  rolling updates, or failover instances.
- Do not provision storage for this version; adding a volume does not make the
  state persistent.
- Do not mark a funded deployment as upgradable. An upgrade loses its state,
  and the reference client pins one PCR set rather than following upgrades.
- Do not set or rotate Enclavia secrets. The workload consumes none, and
  applying a secret change requires a destructive restart.
- Do not stop or replace the process while any funded coin depends on it for a
  future transition.
- `coin fund` finalizes and journals the funding transaction without
  broadcasting it, obtains and durably stores Alice's recovery, and only then
  broadcasts the exact funding bytes. Signer loss before recovery completion
  leaves the selected source funds unbroadcast; signer loss after recovery
  completion leaves Alice with a unilateral recovery.
- After signer loss, owners can only use recoveries already stored by their
  wallets once those transactions become final. The enclave state cannot be
  reconstructed.

The map is capped at 21,000 registrations for the lifetime of one process and
has no deletion operation. Because registration is unauthenticated, an
internet-reachable endpoint can be exhausted by untrusted callers. This proof
of concept is not a hardened public multi-tenant service.

## Build and run locally

### Native workload

Requirements are Rust 1.88 or newer and a free local TCP port 8080. From the
repository root:

```bash
cargo build --locked --release \
  -p tinylayer-enclave \
  --features workload \
  --bin tinylayer-workload

./target/release/tinylayer-workload
```

In another terminal:

```bash
curl --fail-with-body http://127.0.0.1:8080/health
```

The expected body is `ok`. Direct HTTP is unencrypted and unattested. The
wallet permits it only with a loopback URL, `--unsafe-plaintext`, and the
Regtest network.

### Container image

The Docker build context must be the repository root because the Dockerfile
copies all workspace manifests and source directories. Enclavia expects an
amd64 image:

```bash
docker buildx build \
  --platform linux/amd64 \
  --load \
  --file enclave/Dockerfile \
  --tag tinylayer-workload:0.1.0 \
  .
```

Smoke-test the exact image before uploading it:

```bash
docker run --rm \
  --name tinylayer-workload \
  --publish 127.0.0.1:8080:8080 \
  tinylayer-workload:0.1.0
```

Then call `http://127.0.0.1:8080/health` from another terminal. The final image
runs as UID/GID 65532, listens on `0.0.0.0:8080`, and requires no environment
variables, secrets, storage, or outbound network access. It includes the MIT
license notice at `/usr/share/licenses/tinylayer/LICENSE`.

The Rust dependencies are locked, but the Docker base image tags are not
pinned by digest. Record the resulting image ID and deployment measurements;
rebuilding at a later date is not guaranteed to create the same image.

## Deploy to Enclavia

This runbook is written for `enclavia-cli` 0.2.0, matching the Enclavia SDK
version locked by this workspace. Consult the current Enclavia documentation
for account and platform changes:

- [Install the CLI](https://docs.enclavia.io/install.md)
- [Authenticate](https://docs.enclavia.io/auth.md)
- [Deploy](https://docs.enclavia.io/deploy.md)
- [Connect a client](https://docs.enclavia.io/connect.md)

### Prerequisites

- An Enclavia account and permanent account handle.
- Docker with `buildx`, with the daemon running.
- Rust 1.88 or newer and Cargo to install the pinned CLI.
- A C compiler, `pkg-config`, and OpenSSL development headers for the CLI's
  native TLS build; see Enclavia's platform-specific [installation
  prerequisites](https://docs.enclavia.io/install.md#prerequisites).
- `jq` for the shell snippets below.
- A paid or otherwise entitled Enclavia account for production Nitro
  enclaves.
- Browser access for the OAuth login flow.
- Nix and a local Enclavia `builder` binary only if using the optional
  `enclavia reproduce` verification step.

Install the CLI version used by this runbook. Tinylayer does not use control
keys, so disabling the optional YubiKey feature avoids a PC/SC dependency:

```bash
cargo install --locked \
  --version 0.2.0 \
  --no-default-features \
  enclavia-cli

enclavia --help
umask 077
enclavia auth login
chmod 700 "$HOME/.config/enclavia"
chmod 600 "$HOME/.config/enclavia/credentials.json"
enclavia enclave list
```

The login token is management-plane access stored under
`~/.config/enclavia/`; it is not a credential sent to the workload. CLI 0.2.0
relies on the caller's umask when creating that directory and credential file,
so retain the restrictive permissions above.

### Build the upload image

From the repository root:

```bash
IMAGE=tinylayer-workload:0.1.0

docker buildx build \
  --platform linux/amd64 \
  --load \
  --file enclave/Dockerfile \
  --tag "$IMAGE" \
  .

docker image inspect "$IMAGE"
```

### Production deployment

Use a new, non-upgradable, stateless production enclave:

```bash
DEPLOY_JSON=$(
  enclavia deploy "$IMAGE" \
    --instance-type small \
    --container-port 8080 \
    --name tinylayer-v1 \
    --visibility private \
    --production \
    --json
)

printf '%s\n' "$DEPLOY_JSON" | jq

ENCLAVE_ID=$(jq -er '.id' <<<"$DEPLOY_JSON")
ENCLAVE_URL=$(jq -er '.endpoint' <<<"$DEPLOY_JSON")
PCR0=$(jq -er '.pcrs.PCR0' <<<"$DEPLOY_JSON")
PCR1=$(jq -er '.pcrs.PCR1' <<<"$DEPLOY_JSON")
PCR2=$(jq -er '.pcrs.PCR2' <<<"$DEPLOY_JSON")
```

`deploy` creates a dedicated registry repository, pushes the local image,
waits for the enclave image to build, and returns only after it reaches
`running`. Progress and build logs go to standard error while `--json` reserves
standard output for the final enclave object. If the watch is interrupted, the
server-side deployment continues; resume inspection with:

```bash
enclavia enclave status "$ENCLAVE_ID"
enclavia enclave logs "$ENCLAVE_ID"
```

The selected flags are intentional:

| Choice | Reason |
| --- | --- |
| `--container-port 8080` | `EXPOSE 8080` in Docker metadata is not enough; Enclavia needs the inner forwarding port explicitly. |
| `--production` | Uses AWS Nitro hardware and production attestation. Without it, Enclavia creates a debug QEMU enclave. |
| No storage flag | The workload never writes `/data`; storage would not preserve signer state. |
| No egress flags | The signer makes no outbound requests. Enclavia therefore denies egress by default. |
| No `--upgradable` | Any upgrade destroys live signer state and changes the client trust policy. |
| `--visibility private` | Prevents anonymous image pulls. This controls registry visibility, not access to the workload API. |

### Debug deployment

For Enclavia transport testing without Nitro hardware, omit `--production` and
use a separate name:

```bash
DEBUG_JSON=$(
  enclavia deploy "$IMAGE" \
    --instance-type small \
    --container-port 8080 \
    --name tinylayer-v1-debug \
    --visibility private \
    --json
)

printf '%s\n' "$DEBUG_JSON" | jq
```

Debug enclaves provide no hardware isolation or confidentiality, and their
runtime log is visible to the host. The reference wallet permits debug
attestation only on Regtest. It still requires the exact PCR0, PCR1, and PCR2
reported for that debug enclave.

### Scripted deployment

For CI or automation, Enclavia recommends separate create, push, and status
steps instead of holding `deploy` open:

```bash
set -euo pipefail

CREATE_JSON=$(
  enclavia enclave create \
    --instance-type small \
    --container-port 8080 \
    --name tinylayer-v1 \
    --visibility private \
    --production \
    --json
)

ENCLAVE_ID=$(jq -er '.id' <<<"$CREATE_JSON")
enclavia push "$IMAGE" "$ENCLAVE_ID" --json | jq

while true; do
  STATUS_JSON=$(enclavia enclave status "$ENCLAVE_ID" --json)
  STATUS=$(jq -er '.status' <<<"$STATUS_JSON")

  case "$STATUS" in
    running)
      printf '%s\n' "$STATUS_JSON" | jq
      break
      ;;
    error)
      printf '%s\n' "$STATUS_JSON" | jq >&2
      enclavia enclave logs "$ENCLAVE_ID" >&2
      exit 1
      ;;
    waiting_for_image|building|deploying)
      sleep 2
      ;;
    *)
      printf 'Unexpected enclave status: %s\n' "$STATUS" >&2
      exit 1
      ;;
  esac
done
```

An enclave left in `waiting_for_image` for 30 minutes times out. Preserve the
create output immediately so the enclave ID is available if a later step
fails.

### Record and distribute the identity

PCRs are public trust anchors, not secrets, but their integrity matters. Save
an authenticated deployment record containing:

- Git commit (`git rev-parse HEAD`).
- Local Docker image ID and the pushed registry digest.
- Enclavia CLI version (`cargo install --list` reports it).
- Enclave ID, endpoint, production/debug mode, immutable create flags, and
  instance type.
- PCR0, PCR1, and PCR2.
- Deployment time and the result of `tinylayer-wallet enclave verify`.

Distribute the endpoint and PCRs to wallet users over an authenticated channel
independent of that endpoint. PCRs are specific to one enclave. Creating a new
enclave from the same Docker image produces a new identity, including a new
PCR2, because the enclave ID is part of the measured configuration.

With Nix installed and Enclavia's `builder` binary on `PATH` or selected with
`BUILDER_PATH`, owners can independently rebuild the deployed EIF and compare
PCRs locally:

```bash
enclavia reproduce "$ENCLAVE_ID"
```

The command pulls the image by its pinned digest, obtains the recorded builder
and Enclavia source revisions, invokes the local builder, and compares its PCRs
with the deployment record. See Enclavia's [reproduction
guide](https://docs.enclavia.io/reproduce.md) for builder setup. Reproduction
does not by itself prove that the Docker image was built from a particular Git
commit, which is why the deployment record must include source and image
identifiers.

## Configure the wallet

### Production Mutinynet wallet

Build the wallet from the same checkout:

```bash
cargo build --locked --release -p tinylayer-wallet
WALLET=./target/release/tinylayer-wallet
```

Create a private password file without putting the password in shell history:

```bash
PASSWORD_DIR="$HOME/.config/tinylayer"
umask 077
install -d -m 700 "$PASSWORD_DIR"
PASSWORD_FILE=$(mktemp "$PASSWORD_DIR/password.XXXXXX")
read -rsp 'Wallet password: ' WALLET_PASSWORD
printf '%s' "$WALLET_PASSWORD" >"$PASSWORD_FILE"
unset WALLET_PASSWORD
```

Initialize a wallet with the values from the production deployment:

```bash
DATA_DIR="$HOME/.local/share/tinylayer/alice"

"$WALLET" \
  --data-dir "$DATA_DIR" \
  --password-file "$PASSWORD_FILE" \
  --json \
  init \
  --network mutinynet \
  --enclave-url "$ENCLAVE_URL" \
  --pcr0 "$PCR0" \
  --pcr1 "$PCR1" \
  --pcr2 "$PCR2" \
  --min-confirmations 6 \
  --min-reaction-blocks 20
```

Mutinynet uses `https://mutinynet.com/api` as its default chain backend.
`init` validates local policy, PCR formatting, rejects all-zero debug
measurements in production mode, and validates chain configuration, but it does
not parse or connect to the production enclave endpoint. Verify the configured
attested connection before registering a coin:

```bash
"$WALLET" \
  --data-dir "$DATA_DIR" \
  --json \
  enclave verify | jq
```

`enclave verify` reads `config.json` without decrypting wallet state and checks
attestation plus the health endpoint. It is a preflight rather than wallet-state
authentication; `coin register` opens the authenticated wallet and repeats the
attested connection. Use `coin deposit-address` to obtain the encrypted wallet's
local Mutinynet P2TR source address. Do not run `coin fund` until registration
returns a result that the wallet has verified against the pinned identity and a
sufficient deposit is confirmed. Continue with the [wallet guide](../wallet/).

### Debug Enclavia wallet

Use a separate Regtest wallet, all three PCRs from the debug deployment, and
the explicit debug flag. This example uses a local Bitcoin Core node:

```bash
"$WALLET" \
  --data-dir /secure/path/debug-wallet \
  --password-file "$PASSWORD_FILE" \
  --json \
  init \
  --network regtest \
  --enclave-url "$(jq -er '.endpoint' <<<"$DEBUG_JSON")" \
  --debug-attestation \
  --pcr0 "$(jq -er '.pcrs.PCR0' <<<"$DEBUG_JSON")" \
  --pcr1 "$(jq -er '.pcrs.PCR1' <<<"$DEBUG_JSON")" \
  --pcr2 "$(jq -er '.pcrs.PCR2' <<<"$DEBUG_JSON")" \
  --bitcoin-rpc-url http://127.0.0.1:18443 \
  --bitcoin-cookie-file /secure/path/to/regtest/.cookie \
  --bitcoin-wallet funder \
  --min-confirmations 1
```

## How clients connect

### Attested direct connection

The reference wallet wraps `tinylayer_client::RemoteEnclave`, which wraps the
Rust Enclavia SDK pinned by this workspace. The URL is the root WebSocket
endpoint:

```text
wss://<enclave-id>.enclaves.beta.enclavia.io
```

Do not append `/health`, `/v1`, or `/proxy` to this WSS URL. Those HTTP paths
are request targets sent inside the encrypted channel.

On connection, the SDK:

1. Opens WSS to the Enclavia router.
2. Performs `Noise_NN_25519_ChaChaPoly_BLAKE2s`.
3. Requests an attestation document over the encrypted CBOR transport.
4. Checks that the attestation nonce binds this Noise handshake.
5. In production, verifies the AWS Nitro certificate chain and signature.
6. Checks exact PCR0, PCR1, and PCR2 equality.
7. Sends encrypted HTTP requests that Enclavia forwards to port 8080.

If attestation fails, the application request is not sent. Noise NN
authenticates the attested server to a client that pins its measurements; it
does not give the workload a client identity.

The SDK automatically re-establishes and re-attests a dead channel before a
later request. It does not silently replay an already-sent request because the
request may have committed before the connection dropped.

Minimal Rust connection code:

```rust
use enclavia::Pcrs;
use tinylayer_client::RemoteEnclave;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pcrs = Pcrs::from_hex("<PCR0>", "<PCR1>", "<PCR2>")?;
    let enclave = RemoteEnclave::connect(
        "wss://<enclave-id>.enclaves.beta.enclavia.io",
        pcrs,
    )
    .await?;

    enclave.health().await?;
    Ok(())
}
```

Use `RemoteEnclave::connect_debug` only for an Enclavia debug enclave. See the
[client guide](../client/) for the registration and recovery flow.

### Plaintext Regtest connection

The wallet has a separate plaintext transport for local tests:

```text
http://127.0.0.1:8080/health
http://127.0.0.1:8080/v1
```

It is restricted to Regtest, HTTP loopback hosts, no URL credentials, and no
base path. Redirects are disabled and requests have a 30-second timeout. The
`tinylayer-client` crate itself does not expose a plaintext remote client.

### Hosted HTTPS proxy

Enclavia also exposes an optional hosted proxy:

```text
https://<enclave-id>.enclaves.beta.enclavia.io/proxy/health
https://<enclave-id>.enclaves.beta.enclavia.io/proxy/v1
```

The `/proxy/` prefix is removed before forwarding. This is useful for `curl` or
a language without an Enclavia SDK, but Enclavia terminates TLS, verifies the
attestation on the caller's behalf, and can read the plaintext. PCR response
headers are assertions from that same proxy. Comparing them with an independent
record can detect accidental misrouting, but cannot authenticate the response
body or remove trust in the proxy because it supplies both. The Tinylayer
wallet and `RemoteEnclave` do not use this path.

Because the workload has no application authentication or rate limiting, do
not confuse registry `--visibility private`, TLS, or knowledge of the enclave
URL with client authorization.

### Wallet-to-wallet connection

Wallet ownership transfers do not pass through the enclave endpoint. The
receiver creates a transfer-request file and sends it to the current owner over
an authenticated out-of-band channel. The sender calls the enclave, then
encrypts the transfer package to the receiver using secp256k1 ECDH,
HKDF-SHA256, and XChaCha20-Poly1305. The receiver decrypts it and independently
checks the live enclave state, funding output, signed history, and reaction
window.

Encryption of the returned package does not authenticate the receiver's
original request. A substituted request can redirect the next recovery before
the sender encrypts the result, so the request channel itself must be
authenticated.

## HTTP API

The API is intentionally small:

| Method and path | Response |
| --- | --- |
| `GET /health` | HTTP 200 with body `ok`. |
| `POST /v1` | One JSON state-machine request and one JSON response. |

There is no `/v2`. The request body limit is 4 KiB. `POST /v1` requires
`Content-Type: application/json`.

With a local workload running, this registers a disposable test coin and reads
its public status:

```bash
API=http://127.0.0.1:8080

curl --fail-with-body "$API/health"

jq -nc '{
  method: "register",
  params: {
    coin_id: [range(32) | 1],
    initial_capability_hash: [range(32) | 2]
  }
}' | curl --fail-with-body \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  "$API/v1"

jq -nc '{
  method: "status",
  params: {coin_id: [range(32) | 1]}
}' | curl --fail-with-body \
  --header 'Content-Type: application/json' \
  --data-binary @- \
  "$API/v1"
```

The example supplies a capability hash directly and is only an HTTP smoke
test. A real client generates a capability preimage, computes its tagged hash,
and verifies the registration before funding.

### Encoding

- `coin_id`, capabilities, handoffs, digests, and authorization hashes are
  exactly 32 JSON integers in the range 0 through 255. They are not hex or
  base64 strings.
- secp256k1 x-only public keys are 64-character lowercase hex strings.
- BIP340 signatures are 128-character lowercase hex strings.
- Request objects use `method` and `params`.
- Response objects use `method` and `result`.
- Register/sign request structs and response payload structs reject unknown
  fields. Do not rely on the envelope or inline status request rejecting extra
  fields; send only the documented schema. Fixed-width values with the wrong
  length are rejected.

The abbreviated arrays in these JSONC examples mean exactly 32 integer values:

```jsonc
{
  "method": "register",
  "params": {
    "coin_id": [/* exactly 32 byte values */],
    "initial_capability_hash": [/* exactly 32 byte values */]
  }
}
```

```jsonc
{
  "method": "status",
  "params": {
    "coin_id": [/* exactly 32 byte values */]
  }
}
```

```jsonc
{
  "method": "sign",
  "params": {
    "coin_id": [/* exactly 32 byte values */],
    "current_capability": [/* exactly 32 byte values */],
    "current_handoff": [/* exactly 32 byte values */],
    "next_capability_hash": [/* exactly 32 byte values */],
    "sighash": [/* exactly 32 byte values */]
  }
}
```

Registration and status return the same response variant:

```jsonc
{
  "method": "status",
  "result": {
    "coin_id": [/* exactly 32 byte values */],
    "signing_pubkey": "<64 hex characters>",
    "authorization": [/* exactly 32 byte values */],
    "signature_count": 0
  }
}
```

Signing returns `method: "signature"`, not `method: "sign"`:

```jsonc
{
  "method": "signature",
  "result": {
    "signature": "<128 hex characters>",
    "next_handoff": [/* exactly 32 byte values */]
  }
}
```

The exact serialization is locked by [`tests/protocol.rs`](tests/protocol.rs).

### HTTP outcomes

| Condition | Result |
| --- | --- |
| Success | HTTP 200 with JSON. |
| Unknown coin | HTTP 409, `coin is not registered`. |
| 21,000-coin capacity reached | HTTP 409, `enclave coin capacity is exhausted`. |
| Wrong or stale capability/handoff | HTTP 409, `current capability or handoff is stale`. |
| Unchanged next capability | HTTP 409, `next capability is unchanged`. |
| Counter overflow | HTTP 409, `signature count is exhausted`. |
| Missing JSON content type | HTTP 415. |
| Malformed JSON or payload | HTTP 422 with the locked Axum version. |
| Body larger than 4 KiB | HTTP 413. |
| Unsupported method | HTTP 405. |
| Unknown path | HTTP 404. |

Policy-conflict bodies are plain text, not JSON. Client code must check the
HTTP status before decoding a success response.

## Operations

### Health and identity checks

Use both platform status and a client-side attested health check:

```bash
enclavia enclave status "$ENCLAVE_ID"

"$WALLET" \
  --data-dir "$DATA_DIR" \
  --json \
  enclave verify | jq
```

These checks prove that a measured process is reachable. They do not prove
that a particular coin survived. Online ownership and receipt operations also
call `status` for the coin and verify the public key, authorization, count, and
recovery history. Local recovery export and on-chain exit use already verified
wallet state and do not contact the enclave.

Maintain an external operational inventory of the deployment, registered coin
IDs, and whether funded coins still depend on it. The workload has no admin
endpoint, coin listing, metrics, or capacity counter. Treat that inventory as
operational metadata, not as a replacement for wallet verification.

### Logs

```bash
enclavia enclave status "$ENCLAVE_ID"
enclavia enclave logs "$ENCLAVE_ID"
```

Build logs are available while Enclavia constructs the enclave image. Debug
enclaves also expose runtime serial logs. Production Nitro enclaves do not have
runtime logs by design. The Tinylayer workload currently emits no structured
logs, metrics, access logs, or request IDs.

### Updating the workload

There is no in-place update path for a deployment with live coins. To release
a new version:

1. Keep the old enclave running for every coin registered there.
2. Build and deploy the new version as a separate non-upgradable enclave.
3. Publish and independently distribute the new endpoint and PCR set.
4. Send only new registrations to the new enclave.
5. Retire the old enclave only after no funded coin requires another
   transition and every owner has a durable, validated recovery.

Coins cannot migrate because their enclave private keys never leave the old
process.

### Decommissioning

Before stopping or destroying an enclave, confirm through operational records
that no funded coin depends on it and that current owners have durable recovery
transactions. Stopping is terminal for off-chain transfers even if Enclavia
allows the enclave record to be started again.

```bash
enclavia enclave stop "$ENCLAVE_ID"
enclavia enclave destroy "$ENCLAVE_ID"
```

Do not run either command as a routine maintenance action on a live signer.

## Troubleshooting

| Symptom | Likely cause and action |
| --- | --- |
| Local connection refused | Start the workload, check port 8080, and inspect whether another process already owns the port. |
| Container exits immediately | Inspect container stderr; the listener panics if port 8080 cannot be bound. |
| Enclavia remains `waiting_for_image` | The image was not pushed to that enclave ID. Run `enclavia push`; after 30 minutes, create a new enclave. |
| Enclavia reports `building` or `error` | Run `enclavia enclave logs <id>` and inspect the build log. |
| Attestation fails | Check endpoint, exact PCRs, and production versus debug mode. A recreated enclave has different measurements. |
| `/health` works but status says `coin is not registered` | The process restarted or the client is connected to a different enclave. Existing signing state is unrecoverable. |
| HTTP 409 stale capability/handoff | The wallet is stale, another request committed, or the wrong transfer state was supplied. Rerun the same journaled wallet command rather than constructing a new request. |
| HTTP 413, 415, or 422 | Respect the 4 KiB limit, set `Content-Type: application/json`, and use exact protocol fields and widths. |
| Production runtime log is empty | Expected for Nitro production enclaves. Use build logs, platform status, attested health, and per-coin status. |
| An attested request appears stuck | The locked SDK has no explicit connection/request timeout. Plaintext wallet requests have a 30-second timeout. |
| Hosted proxy returns `config_not_found` | The enclave is stopped, destroyed, or not registered with the proxy. |
| Hosted proxy returns `tunnel_dial` | The proxy could not establish or attest the enclave tunnel. Check platform status and build configuration. |

## Tests

From the repository root:

```bash
cargo test --locked -p tinylayer-enclave --all-features
cargo clippy --locked -p tinylayer-enclave --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

The binary test binds port 8080, so that port must be free. The suite covers
the state policy, exact wire format, HTTP boundaries, concurrent requests, and
the real workload process. It does not deploy to Enclavia or exercise real
Nitro hardware.
