# Tinylayer client

`tinylayer-client` is the untrusted reference library for connecting to the
Tinylayer v1 enclave and constructing and validating its Bitcoin transactions.
It is a Rust library, not a command-line program. Most users should start with
the [wallet](../wallet/); integrators can use this crate to build a
different wallet around the same protocol.

The [enclave guide](../enclave/) documents deployment, attestation,
the exact HTTP API, and enclave operations.

## Responsibilities

The enclave checks only bearer authorization and signs a supplied 32-byte
digest. This client is responsible for everything the enclave deliberately
does not know:

- Pinning and verifying the enclave identity through Enclavia attestation.
- Verifying registration and live coin status before funding.
- Deriving the exact two-party Taproot funding output.
- Observing the funding UTXO through an honest Bitcoin chain view.
- Constructing the canonical recovery transaction and its Taproot sighash.
- Verifying the enclave signature before adding the client signature.
- Verifying every prior recovery, signature count, authorization commitment,
  withdrawal key, and decreasing relative delay.
- Persisting secrets, prepared requests, responses, and signed history around
  irreversible network calls.

The crate does not provide a chain backend, wallet database, transfer-file
encryption, command-line interface, or plaintext remote transport. Those live
in `tinylayer-wallet`.

## Add the library

The workspace is currently unpublished. A path dependency from another local
workspace can use:

```toml
[dependencies]
enclavia = { version = "=0.2.0", features = ["json"] }
bitcoin = { version = "=0.32.102", default-features = false, features = ["serde", "std"] }
rand = "=0.9.2"
tinylayer-client = { path = "../tinylayer.org/client" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Adjust the path for the consuming project. Direct `bitcoin` and `rand`
dependencies provide the public argument types and entropy needed by the
lifecycle below. Keep their versions and the Enclavia version aligned with
Tinylayer's [`Cargo.toml`](../Cargo.toml).

## Connect to an enclave

Use the endpoint and PCR0/1/2 from an authenticated deployment record, not
values learned solely from the endpoint being authenticated:

```rust
use enclavia::Pcrs;
use tinylayer_client::RemoteEnclave;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pcrs = Pcrs::from_hex(
        "<PCR0 from deployment>",
        "<PCR1 from deployment>",
        "<PCR2 from deployment>",
    )?;
    let enclave = RemoteEnclave::connect(
        "wss://<enclave-id>.enclaves.beta.enclavia.io",
        pcrs,
    )
    .await?;

    enclave.health().await?;
    Ok(())
}
```

`RemoteEnclave::connect` verifies production Nitro attestation. Use
`RemoteEnclave::connect_debug` only for an Enclavia debug enclave and never for
real secrets or funds. Both methods pin all three PCR values.

The WSS URL is the transport endpoint itself; do not append `/health`, `/v1`,
or `/proxy`. `RemoteEnclave` sends those HTTP paths inside the attested Noise
channel.

The Enclavia SDK automatically reconnects and re-attests before a later call
when it knows the channel is dead. It never silently resends a call that may
already have reached the enclave. Treat an uncertain `sign` result as a reason
to retry the exact durably saved request, not to prepare a new one.

## Coin lifecycle

The safe library flow is staged so callers can persist around network and
chain operations.

### 1. Prepare and complete registration

1. Generate a client secp256k1 secret key and a random 32-byte initial
   capability.
2. Call `prepare_registration(client_secret, capability_hash(&capability))`.
3. Persist the secret, capability, and returned `Registration` before sending.
4. Call `RemoteEnclave::register(&registration.request)`.
5. Call `complete_registration(registration, &status)`.

`complete_registration` checks the coin ID, zero signature count, initial
authorization commitment, and that client and enclave keys differ. This check
is required because the first registration for a coin ID wins, including when
a later caller submits a conflicting capability hash.

`Registration` carries protocol version 1. `complete_registration` rejects a
staging value from another protocol identity before the caller can treat the
registration as safe to fund.

The resulting `CoinKeys` retains the checked protocol marker and derives the
funding output:

```rust
use tinylayer_client::{NetworkId, funding_address, funding_script};

let address = funding_address(&keys, NetworkId::Mutinynet);
let script_pubkey = funding_script(&keys);
```

Do not fund until registration has been completed and the enclave identity has
been independently pinned.

### 2. Bind and verify prepared funding

Finalize the funding transaction without broadcasting it, derive its txid and
Tinylayer output index, then combine `CoinKeys` with the network, exact
outpoint, and amount using `CoinKeys::metadata`. Call `verify_funding_utxo`
against the finalized output before requesting a recovery signature. After
broadcast, repeat this verification through an honest chain backend.

The funding txid must be stable before the recovery is signed. A safe builder
must use confirmed native SegWit or Taproot inputs, avoid signalling
replacement, preserve the exact finalized bytes, and never fee-bump or rebuild
the transaction after signing. Isolate the source wallet from concurrent
spenders; non-RBF policy is not a consensus-level prohibition on a conflicting
transaction. The reference wallet enforces the local construction rules with
Bitcoin Core.

The funding script is a one-leaf P2TR tree under the BIP341 NUMS internal key:

```text
<client_xonly> OP_CHECKSIGVERIFY <enclave_xonly> OP_CHECKSIG
```

There is no known key-path spend. A valid script-path spend requires both
ordinary BIP340 signatures.

### 3. Prepare a recovery

Query `RemoteEnclave::status`, call `verify_status`, and then call
`prepare_recovery` with:

- Exact coin metadata and current live status.
- Client secret key.
- Current capability and handoff.
- Hash of a fresh next capability.
- Current owner's withdrawal x-only public key.
- BIP68 block-relative delay and current funding confirmation count. Use zero
  confirmations while the finalized funding transaction is still unbroadcast.

`prepare_recovery` checks authorization, metadata, keys, unexpired delay,
amount bounds, dust, and canonical transaction construction. It returns a
`SignRequest` and opaque `PreparedRecovery`.

For every transfer, the caller must derive the new delay as the previous
recovery's `delay_blocks` minus `DELAY_STEP` and enforce its reaction margin
before sending the irreversible request. `prepare_recovery` has no
history argument and therefore cannot enforce that decrement. `verify_history`
will reject a wrong step afterward, but by then a successful `sign` call has
already rotated enclave authorization.

Persist both values before sending the request. The canonical recovery is a
version-3/TRUC transaction with `nLockTime = 0`, one funding input whose
sequence encodes the block-relative delay, one full-value P2TR output, and no
fee. It is intended to be broadcast later with a fee-paying TRUC child.

### 4. Commit and verify signing

1. Send the exact persisted request with `RemoteEnclave::sign`.
2. Query live status again.
3. Call `verify_sign_response` against the previous signature count, request,
   live status, and response.
4. Call `complete_recovery` to verify the enclave signature, add the client
   signature, and validate the final witness.
5. Persist the signed recovery, next capability, and returned handoff
   atomically before considering the transition complete.

The final witness has exactly four items in script order:

```text
enclave_signature
client_signature
tapscript_leaf
control_block
```

Only the latest exact `SignRequest` can recover a lost response from the
enclave's cache, and only while the same enclave process remains alive.

### 5. Verify history and transfer

Every successful signature rotates authorization and adds one signed recovery.
`verify_history` checks that:

- The enclave public key and coin ID match the original registration.
- The current capability and handoff open the live authorization commitment.
- `signature_count` equals the complete history length.
- Every recovery is canonical and has both valid signatures.
- The latest recovery pays the expected current withdrawal key.
- Each newer recovery delay is exactly ten blocks shorter than the previous
  recovery and remains safely greater than the funding confirmation count.

The client signing key stays with the coin and is transferred to the next
owner. The receiver contributes a fresh capability and withdrawal key. The
wallet adds encrypted transfer packaging, chain confirmation policy, and a
minimum reaction margin on top of these library checks.

Previous owners retain their already signed recoveries. Safety depends on each
new owner receiving a shorter delay and having enough time to react on chain.
All delays start from confirmation of the same funding transaction. The
library verifies the ten-block decrement when checking complete
history; the calling application must enforce it before signing and choose and
monitor an adequate policy margin.

### 6. Exit

Once the funding output has reached the current owner's relative delay,
`build_exit_child`
constructs and signs the fee-paying version-3 child. The parent and child must
be submitted as a package. The caller must choose a fee rate from a trusted
recommendation or explicit policy, impose an appropriate maximum fee, and
verify package acceptance through its chain backend.

## Public protocol types

The client re-exports the v1 enclave protocol types and helpers:

- `CoinId`, `Capability`, `HandoffToken`, and `INITIAL_HANDOFF`.
- `RegisterRequest`, `SignRequest`, `SignResponse`, and `CoinStatus`.
- `PROTOCOL_VERSION`, `capability_hash`, and `authorization`.

Wire encoding, status codes, retry rules, and security limitations are
specified in the [enclave HTTP API](../enclave/#http-api). Prefer the
typed `RemoteEnclave` methods over hand-building JSON.

`NetworkId` includes Mainnet so transaction helpers can represent Bitcoin
networks, but the reference wallet deliberately refuses Mainnet. The presence
of that enum variant is not a statement that Tinylayer is ready for Mainnet.

## Persistence rules

The crate's staged values are serializable so applications can journal them.
A safe integration must durably persist:

- Registration secrets and prepared registration before `register`.
- Exact finalized funding bytes and metadata before requesting the first
  recovery signature.
- The exact `SignRequest` and `PreparedRecovery` before `sign`.
- A returned response before discarding the old capability/handoff.
- Complete recovery history and current ownership secrets as one committed
  state transition.

The funding transaction must not be broadcast until that final state
transition has been durably persisted and independently verified.

The relative-delay `PreparedRecovery` and `SignedRecovery` JSON schemas are a
breaking change: old `locktime` records are rejected and cannot be converted
after signing because sequence and locktime are part of the sighash. This crate
does not add a format field to those low-level values; external integrators
must version the journal that contains them. The reference wallet uses file
format version 4 and has no version 3 migration.

Never resolve an uncertain network result by creating another request. Query
status first. If count and authorization still equal the prepared request's old
state, resend the exact saved request to commit it. If the count advanced by
one, resend that same request to recover the cached response. Fail closed for
any other live state. If the enclave process restarted, the retry cache and
signing key are gone and the operation cannot be reconciled through a
replacement enclave.

The reference wallet implements this journal and is the executable example.
See its recovery loop in `wallet/src/cli.rs` and storage implementation in
`wallet/src/store.rs`.

## Tests

From the repository root:

```bash
cargo test --locked -p tinylayer-client
cargo test --locked --workspace --all-features
```

The tests cover registration pinning, state transitions, exact retries,
Taproot construction, transaction mutations, persistence round trips, and a
synthetic Enclavia Noise/attestation server. They do not contact a real
Enclavia deployment or Nitro enclave.
