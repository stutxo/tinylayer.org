---
layout: default
title: Tinylayer protocol
---

# Tinylayer protocol

This is the compact interoperability description for Tinylayer protocol 1.
Wallet artifacts and the enclave wire protocol use version 1. Bitcoin
transaction policy remains deliberately outside the trusted signer.

## Funding output

Each coin has independent client and enclave x-only secp256k1 public keys. The
funding output is a one-leaf P2TR tree with the BIP341 NUMS internal key and
this exact 68-byte Tapscript:

```text
<client_xonly> OP_CHECKSIGVERIFY <enclave_xonly> OP_CHECKSIG
```

No key path is available because no discrete logarithm is known for the NUMS
internal key. A valid spend therefore needs both ordinary BIP340 signatures.

## Registration

The client generates a random coin ID, client signing key, and bearer
capability. It sends:

```text
coin_id
SHA256_tagged("Tinylayer/Capability/v1", capability)
```

The enclave generates an independent signing key and stores only the coin ID,
private signing key, authorization commitment, signature count, and latest
retry record. Initial authorization commits to the zero handoff token.

Registration must be journaled before it is sent. Funding must not be created
until the returned coin ID, enclave key, zero signature count, and initial
authorization are verified.

## Signer transition

A sign request contains the current capability and handoff, the next
capability hash, and one opaque 32-byte Bitcoin sighash. The enclave:

1. Verifies current authorization.
2. Rejects an unchanged capability hash.
3. Generates a fresh next handoff.
4. Signs the supplied digest.
5. Atomically advances authorization and signature count.
6. Caches the exact request and response for idempotent retry.

The enclave does not parse Bitcoin transactions or know funding amounts,
delays, recipients, or chain state.

## Recovery transaction

Every recovery is canonical:

```text
version:   3
nLockTime: 0
inputs:    exactly one funding outpoint
nSequence: BIP68 block delay
outputs:   exactly one P2TR withdrawal-key output for the full amount
fee:       zero
witness:   enclave signature, client signature, Tapscript, control block
```

The transaction uses a BIP342 default script-spend sighash over the exact
funding amount and output. `nSequence` is a block-relative delay anchored to
the funding output's confirmation. The first delay must be in `1..=65535`.
Every ownership transfer decreases it by exactly ten blocks.

## Safe funding

The wallet prepares and signs the funding transaction without broadcasting it.
The required order is:

```text
FundingPrepared
RecoveryPrepared
RecoveryResponded
RecoverySecured
FundingBroadcast
```

The exact recovery request is committed before enclave signing. The exact
response is committed before applying the transition. The complete recovery,
withdrawal key, and funding bytes are committed before broadcast. On an
ambiguous broadcast result, the wallet accepts only the exact saved transaction
at the expected txid.

## Transfer request

A receiver request binds format and protocol versions, request and coin IDs,
network, funding outpoint, exact amount, withdrawal key, next capability hash,
transport public key, and minimum reaction margin. Requests must travel over
an authenticated channel because replacing the receiver keys redirects both
ownership and recovery.

The strict version-1 JSON object has these fields:

```text
format_version, protocol_version, request_id, coin_id, network, outpoint,
expected_amount_sat, withdrawal_xonly_pubkey, next_capability_hash,
transport_public_key, min_reaction_blocks
```

IDs and hashes are lowercase 32-byte hex, the withdrawal key is 32-byte x-only
hex, the transport key is compressed secp256k1 hex, and the outpoint is
`txid:vout`. `network` is the lowercase `NetworkId` name. JSON whitespace and
object ordering are not cryptographic inputs; implementations parse strictly
and encode the following associated data:

```text
ASCII "Tinylayer/TransferPackage/v1"
protocol_version                         u32 big-endian
request_id                               32 raw bytes
coin_id                                  32 raw bytes
network                                  u8 (mutinynet=1, mainnet=2, regtest=3)
funding txid                             32 consensus-order bytes
funding vout                             u32 big-endian
expected_amount_sat                      u64 big-endian
withdrawal_xonly_pubkey                  32 bytes
next_capability_hash                     32 bytes
transport_public_key                     33 compressed bytes
min_reaction_blocks                      u32 big-endian
```

`wallet-core/src/transfer.rs` pins the complete associated-data bytes for a
fixed request as an interoperability vector.

The random request ID is not an artifact digest. Sender interfaces must show or
authenticate all three receiver-controlled keys or a digest of canonicalized
request JSON before signing.

## Transfer package

The sender prepares the next recovery with `previous_delay - 10`, journals it,
and performs one enclave transition. The package contains the client secret,
new handoff, immutable coin metadata, and complete signed recovery history.

Packages use ephemeral secp256k1 ECDH, HKDF-SHA256, and
XChaCha20-Poly1305. The complete transfer request is associated data under the
`Tinylayer/TransferPackage/v1` domain.

The 32-byte ECDH value is SHA-256 of the compressed shared secp256k1 point,
matching libsecp256k1's default ECDH hash function. HKDF uses the raw request ID
as salt, that ECDH value as input keying material, the same domain string as
`info`, and a 32-byte output.

The encrypted plaintext is compact UTF-8 JSON in this field order:

```text
format_version, protocol_version, request_id, client_secret, current_handoff,
metadata, history
```

`request_id` and `current_handoff` are 32-element byte arrays. `client_secret`
is lowercase 32-byte hex. `metadata` contains `keys`, `network`, `outpoint`, and
`amount_sat`; `keys` contains `protocol_version`, a 32-element `coin_id` byte
array, and lowercase x-only `client_pubkey` and `enclave_pubkey` hex. Each
`history` entry contains `transaction`, lowercase x-only
`withdrawal_xonly_pubkey`, and `delay_blocks`. Transactions use rust-bitcoin's
human-readable object encoding: numeric `version`, `lock_time`, and `sequence`;
string outpoints and scripts; satoshi `value`; and lowercase hex witness items.

`wallet-core/src/transfer.rs` pins a deterministic full version-1 vector for the
request AAD, ECDH value, HKDF key, compact plaintext, ephemeral public key,
nonce, and ciphertext.

The envelope is strict JSON with `format_version`, `request_id`, compressed
`ephemeral_public_key`, 24-byte hex `nonce`, and hex `ciphertext` including the
Poly1305 tag. Ciphertext is limited to 8 MiB minus 4096 bytes so the complete
envelope remains within the 16 MiB artifact limit. Authenticated plaintext is
strict version-1 JSON containing the complete signed recovery history.

## Receiver verification

Before accepting ownership, the receiver verifies:

- Production enclave attestation and encrypted channel.
- Coin ID, pinned enclave key, authorization, and signature count.
- Exact unspent funding output and required confirmations.
- Client key, amount, outpoint, network, capability, handoff, and withdrawal key.
- Every recovery transaction and both signatures.
- Exact ten-block delay decreases and remaining reaction margin.

Unknown signer state for an existing coin means transfers stop. The latest
already secured recovery remains usable.

## Exit package

The zero-fee recovery parent is a Taproot script-path spend. After its BIP68
delay matures, the owner builds a version 3 child that spends the recovery P2TR
output through its key path. The child pays the fee for both transactions, and
the pair is submitted as one package.

Wallets journal exact parent and child bytes before submission. A chain may
contain the same valid recovery parent with a different witness because the
txid does not commit to witness bytes; wallets revalidate that parent's complete
recovery signatures and txid-committed data. The wallet submits the child
byte-for-byte and compares raw bytes when available. After durable submission
authorization, a Core retry without indexed raw history may instead prove a
confirmed transaction's txid-committed data through its expected UTXO; it does
not claim witness-byte equality. Seeing the pair in a mempool is not terminal:
an observed journal may be rechecked and the saved bytes re-armed after
eviction. If the parent confirms without the child, the exact child can be
submitted alone. A current owner may conflict-submit its newer recovery when
the funding outspend is an unconfirmed txid from its already verified recovery
history; unknown spends and a different confirmed recovery fail closed.

## Failure model

Signer memory is process-local and has no persistence or replication. Restart
loses all coin state. Wallet journals are therefore protocol-critical. A
caller must durably commit each prepared request and received response before
performing the next irreversible step, and must resume saved bytes after a
crash rather than construct a replacement operation.
