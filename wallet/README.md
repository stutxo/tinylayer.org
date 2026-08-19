# Tinylayer wallet

`tinylayer-wallet` is the native command-line wallet and test harness for
Tinylayer. It manages an encrypted P2TR deposit key, safe funding construction,
recovery transactions, off-chain ownership transfers, receipts, and on-chain
exits.

The current wallet supports Regtest and Mutinynet. Mainnet is deliberately
unavailable. The local walkthrough below uses unsafe plaintext transport and
must only be used with Regtest.

## Requirements

- Rust 1.88 or newer.
- Bitcoin Core 28 or newer with a loaded, private-key-enabled wallet for the
  real Regtest flow.
- `bitcoin-cli`, `curl`, and `jq`.
- Free local ports 8080 for the workload and 18443 for Bitcoin Core RPC.
- An Enclavia account, Docker, and the `enclavia` CLI for an attested
  deployment; see the [enclave runbook](../enclave/).

Bitcoin Core 28 or newer is required because exits use version 3 transactions
and the `submitpackage` RPC.

## Build

From the repository root:

```bash
cargo build --locked \
  -p tinylayer-wallet \
  -p tinylayer-enclave \
  --features tinylayer-enclave/workload
```

The resulting binaries are:

```text
target/debug/tinylayer-wallet
target/debug/tinylayer-workload
```

Inspect the available commands with:

```bash
./target/debug/tinylayer-wallet --help
./target/debug/tinylayer-wallet coin --help
./target/debug/tinylayer-wallet transfer --help
```

Global options such as `--data-dir`, `--password-file`, and `--json` must
appear before the subcommand.

## Automated Regtest test

The repository includes a real Bitcoin Core end-to-end test. It creates Alice,
Bob, and Carol wallets; secures Alice's recovery before broadcasting funding;
transfers Alice to Bob to Carol; verifies the 100/90/80-block BIP68 maturity
order; then exits Carol with a fee-paying child transaction.

Start a clean Regtest node in one terminal:

```bash
BTC_DIR=$(mktemp -d "${TMPDIR:-/tmp}/tinylayer-bitcoin.XXXXXX")
bitcoind -regtest "-datadir=$BTC_DIR" -listen=0 \
  -fallbackfee=0.0002 -daemonwait
```

Run the end-to-end test from the repository root in the same terminal:

```bash
BITCOIN_DATADIR="$BTC_DIR" KEEP_TMP=1 \
  ./client/scripts/bitcoin-core-regtest.sh
```

`KEEP_TMP=1` prints and preserves the Alice, Bob, and Carol wallet directories,
transfer files, receipts, and raw recovery transactions. Omit it to remove
those artifacts automatically.

Stop Bitcoin Core when finished:

```bash
bitcoin-cli -regtest "-datadir=$BTC_DIR" stop
```

The script expects the default Regtest RPC port, 18443, and starts its own
workload on port 8080. Do not run another workload at the same time. For a
custom RPC port, put `rpcport=<PORT>` in the node's Regtest configuration and
also set `BITCOIN_RPC_URL=http://127.0.0.1:<PORT>`.

The script accepts these environment overrides:

| Variable | Purpose |
| --- | --- |
| `BITCOIN_CLI` | Path or command name for `bitcoin-cli`. |
| `BITCOIN_DATADIR` | Bitcoin Core data directory passed to `bitcoin-cli`. |
| `BITCOIN_RPC_URL` | Regtest RPC URL stored in each generated wallet. |
| `BITCOIN_COOKIE_FILE` | Explicit Bitcoin Core cookie path. |
| `KEEP_TMP=1` | Preserve the script-created wallet and transfer test directory. |
| `TMPDIR` | Parent directory for script-created temporary files. |

`KEEP_TMP` does not remove or preserve the separately created Bitcoin data
directory; the caller remains responsible for stopping the node and deleting
that directory when appropriate.

## Manual two-wallet walkthrough

The following walkthrough performs one Alice-to-Bob transfer and then exits
Bob on-chain. Use a new shell so the variables do not collide with another
test.

### 1. Start Bitcoin Core

```bash
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/tinylayer-manual.XXXXXX")
BTC_DIR="$ROOT/bitcoin"
mkdir -m 700 "$BTC_DIR"

bitcoind -regtest "-datadir=$BTC_DIR" -listen=0 \
  -fallbackfee=0.0002 -daemonwait

BASE=(bitcoin-cli -regtest "-datadir=$BTC_DIR")
"${BASE[@]}" createwallet funder >/dev/null
RPC=("${BASE[@]}" -rpcwallet=funder)

MINE_ADDRESS=$("${RPC[@]}" getnewaddress)
"${RPC[@]}" generatetoaddress 101 "$MINE_ADDRESS" >/dev/null
```

### 2. Start the workload

In another terminal, from the repository root:

```bash
./target/debug/tinylayer-workload
```

Keep this exact process alive for the complete test. All enclave state is held
in memory and is lost when the workload restarts.

Check it directly with:

```bash
curl --fail http://127.0.0.1:8080/health
```

### 3. Initialize Alice and Bob

Back in the first terminal, from the repository root:

```bash
WALLET="$PWD/target/debug/tinylayer-wallet"
ALICE="$ROOT/alice"
BOB="$ROOT/bob"
COOKIE="$BTC_DIR/regtest/.cookie"

export ENCLAVIA_WALLET_PASSWORD='regtest-only-password'

for DATA_DIR in "$ALICE" "$BOB"; do
  "$WALLET" --data-dir "$DATA_DIR" --json init \
    --network regtest \
    --enclave-url http://127.0.0.1:8080 \
    --unsafe-plaintext \
    --bitcoin-rpc-url http://127.0.0.1:18443 \
    --bitcoin-cookie-file "$COOKIE" \
    --bitcoin-wallet funder \
    --min-confirmations 1
done

"$WALLET" --data-dir "$ALICE" --json enclave verify | jq
```

For longer-lived wallets, use a mode-0600 password file and
`--password-file <FILE>` instead of an environment variable.

### 4. Register and fund Alice

```bash
REGISTERED=$("$WALLET" --data-dir "$ALICE" --json coin register)
printf '%s\n' "$REGISTERED" | jq

COIN_ID=$(jq -er '.coin_id' <<<"$REGISTERED")
FUNDED=$("$WALLET" --data-dir "$ALICE" --json coin fund \
  --amount-sat 100000 \
  --delay-blocks 100 \
  --fee-rate 2 \
  --max-fee-sat 10000)
printf '%s\n' "$FUNDED" | jq

FUND_TXID=$(jq -er '.funding_txid' <<<"$FUNDED")
OUTPOINT=$(jq -er '.outpoint' <<<"$FUNDED")
"${RPC[@]}" getmempoolentry "$FUND_TXID" >/dev/null
"${RPC[@]}" generatetoaddress 1 "$MINE_ADDRESS" >/dev/null
```

`coin fund` asks the configured Core wallet to create, sign, and finalize a
non-RBF transaction without broadcasting it. The command derives the final
txid and output, obtains and durably stores Alice's 100-block recovery, and only
then broadcasts those exact funding bytes. A retry resumes the journaled stage
instead of creating another transaction. Each transfer reduces the latest
relative delay by ten blocks. The walkthrough uses 100 blocks to keep Regtest
short; the command default is 2,016 and BIP68 permits at most 65,535.

### 5. Transfer Alice to Bob

```bash
BOB_REQUEST="$ROOT/bob-request.json"
ALICE_TO_BOB="$ROOT/alice-to-bob.json"

"$WALLET" --data-dir "$BOB" --json transfer request \
  --coin-id "$COIN_ID" \
  --outpoint "$OUTPOINT" \
  --amount-sat 100000 \
  --output "$BOB_REQUEST" | jq

"$WALLET" --data-dir "$ALICE" --json coin sign \
  --request "$BOB_REQUEST" \
  --output "$ALICE_TO_BOB" | jq

ACCEPTED=$("$WALLET" --data-dir "$BOB" --json transfer accept \
  --request "$BOB_REQUEST" \
  --package "$ALICE_TO_BOB")
printf '%s\n' "$ACCEPTED" | jq

"$WALLET" --data-dir "$BOB" --json coin status | jq
```

The receiver's request must be delivered over an authenticated channel. The
returned transfer package is encrypted, but that does not authenticate a
substituted request before Alice signs it.

### 6. Export and verify a receipt

```bash
RECEIPT="$ROOT/bob-receipt.json"

"$WALLET" --data-dir "$BOB" --json receipt export \
  --output "$RECEIPT" | jq

"$WALLET" --data-dir "$ALICE" --json receipt verify \
  --input "$RECEIPT" | jq
```

Receipt verification checks the live enclave status, Bitcoin funding output,
complete signed recovery history, and reaction window.

### 7. Exit Bob on-chain

```bash
BOB_DELAY=$(jq -er '.latest_delay_blocks' <<<"$ACCEPTED")
CONFIRMATIONS=$("${RPC[@]}" gettransaction "$FUND_TXID" | jq -er '.confirmations')

if (( CONFIRMATIONS < BOB_DELAY )); then
  "${RPC[@]}" generatetoaddress "$((BOB_DELAY - CONFIRMATIONS))" \
    "$MINE_ADDRESS" >/dev/null
fi

EXIT_ADDRESS=$("${RPC[@]}" getnewaddress)
EXITED=$("$WALLET" --data-dir "$BOB" --json coin exit \
  --destination "$EXIT_ADDRESS" \
  --fee-rate 2 \
  --max-fee-sat 10000)
printf '%s\n' "$EXITED" | jq

EXIT_TXID=$(jq -er '.exit_txid' <<<"$EXITED")
"${RPC[@]}" generatetoaddress 1 "$MINE_ADDRESS" >/dev/null
"${RPC[@]}" gettransaction "$EXIT_TXID" | jq '{confirmations}'
```

`coin exit` submits the zero-fee recovery parent together with a fee-paying v3
child. `coin recovery --output <FILE>` only exports the raw parent transaction;
it does not broadcast it. Add `--dry-run` to `coin exit` to return both package
transactions without submitting them.

Clean up with:

```bash
"${BASE[@]}" stop
unset ENCLAVIA_WALLET_PASSWORD
```

Stop the workload with Ctrl-C in its terminal.

## Recovery safety model

Every owner receives a valid recovery transaction that spends the same funding
output. Transferring the coin does not revoke or invalidate recoveries held by
previous owners. Instead, each new recovery uses a relative delay exactly ten
blocks shorter than the preceding recovery:

```text
Alice recovery: 100 blocks after funding confirms
Bob recovery:    90 blocks after funding confirms
Carol recovery:  80 blocks after funding confirms
```

This ordering gives the current owner a window in which to settle before an
older owner can use a superseded recovery. It requires an honest chain view and
active monitoring outside this CLI.

Recoveries use BIP68 block-based input sequences, transaction version 3, and
zero absolute `nLockTime`. Every recovery spends the same funding outpoint, so
every delay starts from confirmation of that funding transaction; a transfer
does not restart the clock.

`--min-reaction-blocks` defaults to 20 and must be at least 10. Before signing
or accepting a transfer, the wallet requires:

```text
latest recovery delay > funding confirmations + required reaction blocks
```

The receiver can request a larger margin in its transfer request. The sender
and receiver both enforce the maximum of the request's margin and their local
wallet policy. The inequality is strict, and funding confirmations can advance
between transfers. Choose an initial delay greater than the required reaction
margin, ten blocks for every planned transfer, and an allowance for the blocks
expected to be mined before those transfers.

Important operational consequences:

- `coin status` is a point-in-time check. The wallet does not run a monitoring
  daemon or automatically broadcast a recovery when the chain advances.
- Keep the current wallet online often enough to detect a changed enclave
  count, a spent funding output, and a shrinking reaction window.
- `coin exit` cannot broadcast until the funding output reaches the owner's
  relative delay.
- `coin fund` never broadcasts until a valid Alice recovery and its withdrawal
  secret are in the durably synced wallet state. Signer loss before that point
  leaves the selected source funds unbroadcast; signer loss afterward leaves
  Alice with a unilateral recovery.
- Confirm that `coin fund` or `transfer accept` has durably completed and
  that `coin recovery` can export the expected transaction before relying on
  it.
- Keep every exact enclave process alive while funded coins need another
  transfer. A restart destroys all signer keys even if attestation and
  `/health` still succeed afterward.

The real Regtest script exports Alice, Bob, and Carol's recoveries, verifies
their 100/90/80-block BIP68 boundaries with Bitcoin Core, and submits Carol's
complete TRUC package. Use that flow to observe the relative-delay ordering
directly.

## Transport modes

`init` supports three enclave transport modes:

| Mode | Flags | Intended use |
| --- | --- | --- |
| Plaintext | `--unsafe-plaintext` | Loopback-only Regtest development |
| Debug attestation | `--debug-attestation --pcr0 ... --pcr1 ... --pcr2 ...` | Regtest Enclavia QEMU debugging |
| Production attestation | `--pcr0 ... --pcr1 ... --pcr2 ...` | Attested Enclavia endpoint |

Plaintext transport requires an HTTP loopback URL. Bitcoin Core RPC is also
Regtest-only and requires a numeric loopback URL plus a private, non-symlink
cookie file. Core configuration also requires the name of a loaded,
private-key-enabled wallet. Production and debug attestation require all three
PCR values. Production mode rejects an all-zero debug measurement in any PCR.

The complete image build, Enclavia deployment, PCR recording, connection, and
lifecycle procedure is in [`enclave/README.md`](../enclave/). In
particular, registry `--visibility private` does not authenticate callers to
the workload, and restarting or upgrading the enclave loses all coin state.

### Production Mutinynet initialization

After deploying a production enclave, set these values from the authenticated
deployment record:

```bash
ENCLAVE_URL=wss://<enclave-id>.enclaves.beta.enclavia.io
PCR0=<pcr0>
PCR1=<pcr1>
PCR2=<pcr2>
```

Initialize and then verify a Mutinynet wallet:

```bash
./target/release/tinylayer-wallet \
  --data-dir /secure/path/alice \
  --password-file /secure/path/password \
  --json \
  init \
  --network mutinynet \
  --enclave-url "$ENCLAVE_URL" \
  --pcr0 "$PCR0" \
  --pcr1 "$PCR1" \
  --pcr2 "$PCR2" \
  --min-confirmations 6 \
  --min-reaction-blocks 20

./target/release/tinylayer-wallet \
  --data-dir /secure/path/alice \
  --json \
  enclave verify | jq
```

Mutinynet defaults to `https://mutinynet.com/api`. Production attestation is
selected when neither `--unsafe-plaintext` nor `--debug-attestation` is passed.
`init` validates the local policy, PCR formatting, and chain configuration, but
does not parse or connect to a production or debug enclave endpoint. Use
`enclave verify` as a preflight attestation and health check before registration.
It reads `config.json` directly and does not decrypt or authenticate wallet
state; `coin register` opens the authenticated wallet and performs its own
attested connection.

Show the wallet's stable deposit address, fund it with confirmed Mutinynet sats,
then register and fund one Tinylayer coin:

```bash
WALLET=./target/release/tinylayer-wallet
DATA_DIR=/secure/path/alice
PASSWORD=/secure/path/password

"$WALLET" --data-dir "$DATA_DIR" --password-file "$PASSWORD" \
  coin deposit-address

# Send one confirmed UTXO that covers the coin amount, funding fee, and a
# non-dust change output to the displayed address.

"$WALLET" --data-dir "$DATA_DIR" --password-file "$PASSWORD" \
  coin register

"$WALLET" --data-dir "$DATA_DIR" --password-file "$PASSWORD" \
  coin fund --amount-sat 100000 --max-fee-sat 1000
```

The deposit secret is generated locally, exists only inside encrypted
`wallet.enc`, and is separate from the coin's transferable client key and each
owner's withdrawal key. `coin fund` selects the largest confirmed non-coinbase
deposit output, signs one exact non-RBF P2TR transaction locally, durably
secures Alice's recovery, and only then submits those exact bytes to Esplora.

After funding, sweep confirmed deposit change and other unreserved deposits:

```bash
"$WALLET" --data-dir "$DATA_DIR" --password-file "$PASSWORD" \
  coin source-sweep \
  --destination tb1p... \
  --fee-rate 1 \
  --max-fee-sat 1000
```

Each sweep selects up to 100 of the largest outputs and excludes every input
reserved by the saved funding journal. Its exact inputs and transaction are
persisted before submission, so retries never silently select new coins. Once a
sweep reaches the wallet's minimum-confirmation policy, rerun the command to
sweep another batch or newer deposits.

### Chain backends

Regtest has no default chain backend. Supply either `--chain-url` or all of
`--bitcoin-rpc-url`, `--bitcoin-cookie-file`, and `--bitcoin-wallet`. Bitcoin
Core RPC is restricted to a numeric loopback HTTP base URL and a private
regular cookie file. The wallet name is encoded into the wallet RPC endpoint;
do not include `/wallet/...` in `--bitcoin-rpc-url`.

With Bitcoin Core, `coin fund` uses `walletcreatefundedpsbt`,
`walletprocesspsbt`, `finalizepsbt`, `testmempoolaccept`, and
`sendrawtransaction`. It rejects legacy or otherwise non-native-SegWit inputs,
RBF-signalling sequences, unconfirmed source inputs, an incomplete PSBT,
multiple Tinylayer outputs, a changed amount, a fee above `--max-fee-sat`, or a
returned txid that differs from the recovery outpoint. Selected inputs are
persistently locked before enclave signing. Use one dedicated Core wallet per
originating Tinylayer wallet and do not spend its selected inputs concurrently
through another RPC client. Receiver verification uses the confirmed
`gettxout` proof and therefore does not require `txindex` or access to the
sender's funding wallet. Armed exit retries can likewise prove a confirmed
parent or child through its expected unspent output when raw history is not
indexed.

With Esplora, `coin fund` spends the encrypted wallet's local deposit key. The
backend is never asked to hold or sign with private keys. Before trusting an
observation, the wallet fetches raw transaction bytes, checks txids and exact
outputs, verifies confirmed block hashes against the current chain, and obtains
the exact spending txid for spent outputs. On every connection it also requires
the explorer's genesis to match the configured network and pins a
Mutinynet-specific checkpoint so another Signet cannot be substituted. HTTP
responses are capped at 16 MiB, and deposit discovery performs detailed checks
on at most the 256 highest-value confirmed candidates per sweep.

Explorer URLs must use HTTPS unless the host is loopback, and cannot contain
credentials, a query, or a fragment. A custom explorer must support the
Esplora address-UTXO, raw transaction, transaction status, individual outspend,
block-height, tip, fee, and broadcast endpoints. Explorer-backed exits use
package submission:

```text
POST /txs/package
```

The wallet falls back to `POST /v1/txs/package` when the preferred route returns
HTTP 404.

When `coin exit` does not receive `--fee-rate`, an explorer must also support
`GET /v1/fees/recommended`; the wallet rounds its `fastestFee` response up to a
whole sat/vB. An explicit `--fee-rate` skips that request. Bitcoin Core uses 1
sat/vB when no explicit rate is supplied.

Package submission must accept a JSON array containing the parent and child
transaction hex and return JSON with `"package_msg":"success"`.
Ordinary transaction submission uses `POST /tx` with raw hex as `text/plain`.
Success is not inferred from the HTTP response alone: the wallet must retrieve
the same full transaction bytes afterward. This also reconciles timeouts and
already-known transactions without relying only on a witness-independent txid.

## Command summary

```text
tinylayer-wallet --data-dir DIR [--password-file FILE] [--json] init ...
tinylayer-wallet --data-dir DIR enclave verify
tinylayer-wallet --data-dir DIR coin deposit-address
tinylayer-wallet --data-dir DIR coin register
tinylayer-wallet --data-dir DIR coin fund --amount-sat SAT --max-fee-sat SAT [--delay-blocks BLOCKS] [--fee-rate SAT_VB]
tinylayer-wallet --data-dir DIR coin status
tinylayer-wallet --data-dir DIR coin sign --request FILE --output FILE
tinylayer-wallet --data-dir DIR coin recovery --output FILE
tinylayer-wallet --data-dir DIR coin source-sweep --destination ADDRESS --max-fee-sat SAT [--fee-rate SAT_VB]
tinylayer-wallet --data-dir DIR coin exit --destination ADDRESS --max-fee-sat SAT [--dry-run]
tinylayer-wallet --data-dir DIR transfer request ... --output FILE
tinylayer-wallet --data-dir DIR transfer accept --request FILE --package FILE
tinylayer-wallet --data-dir DIR receipt export --output FILE
tinylayer-wallet --data-dir DIR receipt verify --input FILE
```

Use `--json` for scripting. After command-line parsing succeeds, successful
commands emit one JSON object on standard output and runtime failures emit one
JSON object on standard error. Clap argument, subcommand, and value-parsing
errors occur before the application handles `--json`; those errors remain
human-readable text with a nonzero exit code.

## Wallet files

Each data directory contains:

- `config.json`: network, enclave, chain backend, and confirmation policy.
- `wallet.enc`: Argon2id/XChaCha20-Poly1305 encrypted wallet state, local
  deposit secret, and exit/sweep journals.
- `.lock`: prevents concurrent wallet processes from modifying the same state.

The password is read from `--password-file`, then
`ENCLAVIA_WALLET_PASSWORD`, then an interactive prompt. Do not edit
`config.json`: it is authenticated as part of the encrypted state. The data
directory, `config.json`, `wallet.enc`, and password file must not be symlinks.
On Unix, they must not be accessible by group or other users. The `.lock` file
is created with a private mode on Unix, but an existing lock file is not
subjected to the same path validation; keep the entire data directory private
and do not modify its contents manually.

Each wallet directory currently holds at most one coin. Use separate data
directories for Alice, Bob, and every other independent wallet.

Wallet protocol state, native encrypted storage, and transfer artifacts use
format version 1. Local-only keys and submission journals remain in native
storage and never enter transfer packages. There are no older supported wallet
formats or compatibility decoders. Treat transfer requests, encrypted packages,
and receipts as opaque version-1 artifacts.

Input and artifact files are limited to 16 MiB, encrypted transfer ciphertext
is limited to slightly under 8 MiB, and `wallet.enc` is limited to 64 MiB to
cover its hex-encoded encrypted representation. Accepted-package replay stores
a fixed-size fingerprint of the envelope, and a transferred sender retains only
its own recovery outside the replayable encrypted package; these bounds ensure
that every permitted package has a persistable post-sign state.

Wallet configuration, transfer requests, encrypted transfer payloads, and
receipts carry protocol version 1, the first supported Tinylayer protocol. The
configuration version is bound to encrypted wallet state, and the request
version is authenticated into the encrypted package and checked before the
sender signs. Wallets, pending operations, and transfer artifacts created by
experimental builds with another protocol identity are not supported;
initialize a fresh wallet and enclave deployment rather than mixing them with
this version.

### Interrupted operations

Registration, funding, and transfer signing are journaled before irreversible
effects. If a command times out, loses its connection, or the wallet process
crashes, rerun the same operation. Registration has no operation-specific
arguments. For transfer signing, supply a request file with the exact same
content; the file and output paths may differ. The wallet queries live status
and, if the count advanced, retries the exact journaled request against the
enclave's latest-response cache. Retrying transfer acceptance requires both the
same request and the same encrypted-envelope fields; JSON whitespace and object
ordering may differ, but reusing an accepted request ID with different envelope
content fails closed.

Before a transfer signing request reaches the enclave, the wallet sizes the
prospective package with a maximum-width recovery witness and handoff. A history
that cannot fit the artifact limit is rejected before signer state can advance.

For funding, rerun `coin fund` with exactly the same amount, delay, fee rate,
and maximum fee. Its persisted stages are `Prepared`, `RecoverySecured`, and
`Broadcast`. A crash before `RecoverySecured` cannot broadcast. A crash after
that durable transition can safely resume broadcasting, and a lost
`sendrawtransaction` response is reconciled against the exact wallet
transaction bytes before any retry. An evicted unconfirmed transaction is
rebroadcast byte-for-byte; the transaction is never rebuilt or fee-bumped.
If the enclave response itself was already durably journaled, the wallet still
checks live status from the same signer before applying its handoff and securing
Alice's recovery.

For `coin source-sweep`, rerun with the same destination, fee rate, and maximum
fee. For `coin exit` with either chain backend, rerun with the same destination
and maximum fee; omit the fee rate again or provide the exact saved value. Both
operations persist transactions in `Prepared`, `SubmissionArmed`, and
`Observed` stages. Submission occurs only after `SubmissionArmed` is durable.
Before submission is armed, rerunning with a different policy safely replaces a
`Prepared` sweep or exit; after arming, retries must use the saved policy and
exact transaction.
If an observed transaction is evicted, the wallet re-arms and submits the same
bytes. An exit with an observed parent and missing child submits only the exact
saved child.

Core coin selection initially locks inputs in memory. The wallet journals the
finalized transaction before upgrading those locks to persistent storage and
before asking the enclave to sign. If preparation fails or the process dies
before that first journal, rerun `coin fund` first. If the wallet still reports
only `registered` and Core shows locked inputs, no recovery signature or
funding broadcast occurred; an operator may inspect `listlockunspent` and
explicitly unlock those source outputs before abandoning that registration.

Do not delete `wallet.enc`, create a replacement transfer request, or manually
edit the journal to recover from an uncertain result. Before a response is
saved, only the exact latest request accepted by the enclave is retryable and
reconciliation requires the same enclave process. Funding and transfer
completion also require live status. If that process restarted, its signing key
and retry cache are gone; only an already secured recovery remains usable.

Transfer JSON outputs may already exist only when their content exactly matches
the artifact being written; the wallet refuses to replace different content.
The output path itself is not journaled and may be changed when resuming.
`coin recovery` is stricter and requires its output path not to exist, even if
an existing file contains the same transaction.

### Backup and restore

There is no tested import, restore, reset, or password-change command.
`config.json` and `wallet.enc` form one authenticated pair and must be backed up
together while no wallet process is running. Preserve the data directory's
private permissions and do not restore through symlinks.

Preserve the wallet password or its mode-0600 password file separately from
the encrypted-state backup. There is no password recovery path if both are
lost. Protecting the password file is equivalent to protecting access to the
wallet state.

A stale backup can contain a capability, handoff, pending operation, or history
that the live enclave has already superseded. Restoring it can therefore make
the wallet unable to prove current ownership or recover an uncertain response.
Do not treat periodic rollback to an old copy as a recovery strategy. Keep the
current data directory durable, and retain exported signed recoveries
separately as settlement artifacts. An exported recovery is only the zero-fee
parent transaction; constructing its fee-paying exit child still requires the
withdrawal secret stored inside the current encrypted wallet state.

## Test suite

Run all Rust tests, including mocked chain services, separate CLI processes,
transport tests, transaction mutation tests, and workload concurrency tests:

```bash
cargo test --locked --workspace --all-features
```

Run strict linting and formatting checks with:

```bash
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Only `client/scripts/bitcoin-core-regtest.sh` exercises a real Bitcoin Core
node. The attested transport tests use a synthetic test attestation. The
[Enclavia runbook](../enclave/) documents a real deployment and
verification procedure, but the automated suite does not deploy to Enclavia or
exercise Nitro hardware.

## Current limitations

- Mainnet is not supported.
- Explorer funding currently uses one locally signed confirmed P2TR input; it
  does not combine deposits for one coin or support hardware wallets.
- The workload stores signing state only in memory; restarting it loses every
  registered coin and retry record.
- A wallet directory holds one coin and has no reset or import command.
- Transfer requests require an authenticated out-of-band channel.
- A transfer is not atomic with payment or delivery of anything else.
- The wallet must have an honest view of the Bitcoin chain.
- Local plaintext testing provides no enclave attestation or transport
  confidentiality.
- The workload has no application authentication, rate limiting, metrics, or
  state-listing endpoint.
- Wallet backups have no supported rollback or import workflow.
