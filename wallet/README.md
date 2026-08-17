# Tinylayer wallet

`tinylayer-wallet` is the native command-line wallet and test harness for
Tinylayer. It manages registration, funding verification, recovery
transactions, off-chain ownership transfers, receipts, and on-chain exits.

The current wallet supports Regtest and Mutinynet. Mainnet is deliberately
unavailable. The local walkthrough below uses unsafe plaintext transport and
must only be used with Regtest.

## Requirements

- Rust 1.88 or newer.
- Bitcoin Core 28 or newer with wallet support for the real Regtest flow.
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
Bob, and Carol wallets; funds Alice; transfers Alice to Bob to Carol; verifies
a receipt and the superseded recoveries; then exits Carol with a fee-paying
child transaction.

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
FUND_ADDRESS=$(jq -er '.funding_address' <<<"$REGISTERED")
FUND_SCRIPT=$(jq -er '.funding_script_hex' <<<"$REGISTERED")

FUND_TXID=$("${RPC[@]}" sendtoaddress "$FUND_ADDRESS" 0.001)
FUND_VOUT=$(
  "${RPC[@]}" getrawtransaction "$FUND_TXID" true |
    jq -er --arg script "$FUND_SCRIPT" \
      '.vout[] | select(.scriptPubKey.hex == $script) | .n'
)
OUTPOINT="$FUND_TXID:$FUND_VOUT"

"${RPC[@]}" generatetoaddress 1 "$MINE_ADDRESS" >/dev/null

"$WALLET" --data-dir "$ALICE" --json coin fund \
  --outpoint "$OUTPOINT" \
  --amount-sat 100000 | jq

TIP=$("${RPC[@]}" getblockcount)
ALICE_LOCKTIME=$((TIP + 50))

"$WALLET" --data-dir "$ALICE" --json coin activate \
  --locktime "$ALICE_LOCKTIME" | jq
```

The locktime must leave enough blocks for every planned transfer. Each
transfer reduces the latest recovery locktime by ten blocks.

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
BOB_LOCKTIME=$(jq -er '.latest_locktime' <<<"$ACCEPTED")
TIP=$("${RPC[@]}" getblockcount)

if (( TIP < BOB_LOCKTIME )); then
  "${RPC[@]}" generatetoaddress "$((BOB_LOCKTIME - TIP))" \
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
it does not broadcast it.

Clean up with:

```bash
"${BASE[@]}" stop
unset ENCLAVIA_WALLET_PASSWORD
```

Stop the workload with Ctrl-C in its terminal.

## Recovery safety model

Every owner receives a valid recovery transaction that spends the same funding
output. Transferring the coin does not revoke or invalidate recoveries held by
previous owners. Instead, each new recovery becomes final exactly ten blocks
earlier than the preceding recovery:

```text
Alice recovery: initial locktime
Bob recovery:   initial locktime - 10
Carol recovery: initial locktime - 20
```

This ordering gives the current owner a window in which to settle before an
older owner can use a superseded recovery. It requires an honest chain view and
active monitoring outside this CLI.

`--min-reaction-blocks` defaults to 20 and must be at least 10. Before signing
or accepting a transfer, the wallet requires:

```text
latest recovery locktime > current tip + required reaction blocks
```

The receiver can request a larger margin in its transfer request. The sender
and receiver both enforce the maximum of the request's margin and their local
wallet policy. The inequality is strict, and the tip can advance between
transfers. Choose an initial activation locktime greater than the current tip
plus the required reaction margin, ten blocks for every planned transfer, and
an allowance for the blocks expected to be mined before those transfers.

Important operational consequences:

- `coin status` is a point-in-time check. The wallet does not run a monitoring
  daemon or automatically broadcast a recovery when the chain advances.
- Keep the current wallet online often enough to detect a changed enclave
  count, a spent funding output, and a shrinking reaction window.
- `coin exit` cannot broadcast until the current recovery locktime is final.
- The unrecoverable interval starts when the funding transaction is broadcast,
  not when `coin fund` runs. `coin fund` waits for the configured confirmations,
  so signer loss any time between broadcast and successful `coin activate` can
  strand the funding output permanently. Plan to activate as soon as the
  confirmation policy allows, without weakening that policy merely to shorten
  the interval.
- Confirm that `coin activate` or `transfer accept` has durably completed and
  that `coin recovery` can export the expected transaction before relying on
  it.
- Keep every exact enclave process alive while funded coins need another
  transfer. A restart destroys all signer keys even if attestation and
  `/health` still succeed afterward.

The real Regtest script exports Alice, Bob, and Carol's recoveries and verifies
that the superseded transactions remain non-final while Carol can exit. Use
that flow to observe the locktime ordering directly.

## Transport modes

`init` supports three enclave transport modes:

| Mode | Flags | Intended use |
| --- | --- | --- |
| Plaintext | `--unsafe-plaintext` | Loopback-only Regtest development |
| Debug attestation | `--debug-attestation --pcr0 ... --pcr1 ... --pcr2 ...` | Regtest Enclavia QEMU debugging |
| Production attestation | `--pcr0 ... --pcr1 ... --pcr2 ...` | Attested Enclavia endpoint |

Plaintext transport requires an HTTP loopback URL. Bitcoin Core RPC is also
Regtest-only and requires a numeric loopback URL plus a private, non-symlink
cookie file. Production and debug attestation require all three PCR values.

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

### Chain backends

Regtest has no default chain backend. Supply either `--chain-url` or both
`--bitcoin-rpc-url` and `--bitcoin-cookie-file`. Bitcoin Core RPC is restricted
to a numeric loopback HTTP URL and a private regular cookie file.

Explorer URLs must use HTTPS unless the host is loopback, and cannot contain
credentials, a query, or a fragment. A custom explorer must support the
Esplora transaction, outspend, block-height, and tip endpoints used for
funding verification. Explorer-backed exits always require package submission:

```text
POST /v1/txs/package
```

When `coin exit` does not receive `--fee-rate`, an explorer must also support
`GET /v1/fees/recommended`; the wallet rounds its `fastestFee` response up to a
whole sat/vB. An explicit `--fee-rate` skips that request. Bitcoin Core uses 1
sat/vB when no explicit rate is supplied.

Package submission must accept a JSON array containing the parent and child
transaction hex and return JSON with `"package_msg":"success"`.

## Command summary

```text
tinylayer-wallet --data-dir DIR [--password-file FILE] [--json] init ...
tinylayer-wallet --data-dir DIR enclave verify
tinylayer-wallet --data-dir DIR coin register
tinylayer-wallet --data-dir DIR coin fund --outpoint TXID:VOUT --amount-sat SAT
tinylayer-wallet --data-dir DIR coin activate --locktime HEIGHT
tinylayer-wallet --data-dir DIR coin status
tinylayer-wallet --data-dir DIR coin sign --request FILE --output FILE
tinylayer-wallet --data-dir DIR coin recovery --output FILE
tinylayer-wallet --data-dir DIR coin exit --destination ADDRESS --max-fee-sat SAT
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
- `wallet.enc`: Argon2id/XChaCha20-Poly1305 encrypted wallet state.
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

Wallet state and transfer artifacts currently use file format version 3 and
have no migration command. Many payload structs reject unknown fields, but
forward-compatible extension is not guaranteed for every tagged journal
variant. Treat transfer requests, encrypted packages, and receipts as opaque
artifacts for the same wallet version rather than a stable cross-version
interoperability contract.

Wallet configuration, transfer requests, encrypted transfer payloads, and
receipts carry protocol version 1, the first supported Tinylayer protocol. The
configuration version is bound to encrypted wallet state, and the request
version is authenticated into the encrypted package and checked before the
sender signs. Wallets, pending operations, and transfer artifacts created by
experimental builds with another protocol identity are not supported;
initialize a fresh wallet and enclave deployment rather than mixing them with
this version.

### Interrupted operations

Registration, activation, and transfer signing are journaled before an
irreversible enclave request. If a command times out, loses its connection, or
the wallet process crashes, rerun the same operation. Registration has no
operation-specific arguments. For transfer signing, supply a request file with
the exact same content; the file and output paths may differ. The wallet queries
live status and, if the count advanced, retries the exact journaled request
against the enclave's latest-response cache.

For activation, first rerun `coin activate` with the same locktime. If chain
growth has made that locktime fail the reaction margin, rerun it with a later
safe locktime. The wallet queries live status before changing the request. It
supersedes the old attempt only when that attempt is proven uncommitted, while
retaining enough journal state to recover the old response if the enclave
actually committed it.

Do not delete `wallet.enc`, create a replacement transfer request, or manually
edit the journal to recover from an uncertain result. Only the exact latest
request accepted by the enclave is retryable, and reconciliation requires the
same enclave process. If that process restarted, its signing key and retry
cache are gone.

Transfer JSON outputs may already exist only when their content exactly matches
the artifact being written; the wallet refuses to replace different content.
The output path itself is not journaled and may be changed when resuming.
`coin recovery` is stricter and requires its output path not to exist, even if
an existing file contains the same transaction.

### Backup and restore

There is no tested import, restore, reset, password-change, or migration
command. `config.json` and `wallet.enc` form one authenticated pair and must be
backed up together while no wallet process is running. Preserve the data
directory's private permissions and do not restore through symlinks.

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
- Wallet backups have no supported rollback, import, or migration workflow.
