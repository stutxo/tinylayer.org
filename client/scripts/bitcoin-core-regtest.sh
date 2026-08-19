#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORKSPACE_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
CLI="${BITCOIN_CLI:-bitcoin-cli}"
RPC_BASE=("$CLI" -regtest)
if [[ -n "${BITCOIN_DATADIR:-}" ]]; then
  RPC_BASE+=("-datadir=$BITCOIN_DATADIR")
fi
WALLET_NAME="tinylayer-wallet-e2e-$$"
RPC=("${RPC_BASE[@]}" "-rpcwallet=$WALLET_NAME")
RPC_URL="${BITCOIN_RPC_URL:-http://127.0.0.1:18443}"
COOKIE_FILE="${BITCOIN_COOKIE_FILE:-${BITCOIN_DATADIR:-$HOME/.bitcoin}/regtest/.cookie}"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/tinylayer-wallet-e2e.XXXXXX")
PASSWORD_FILE="$TEST_ROOT/password"
WORKLOAD_LOG="$TEST_ROOT/workload.log"
printf '%s\n' 'regtest-only-test-password' >"$PASSWORD_FILE"
chmod 600 "$PASSWORD_FILE"

cleanup() {
  if [[ -n "${workload_pid:-}" ]]; then
    kill -TERM "$workload_pid" 2>/dev/null || true
    wait "$workload_pid" 2>/dev/null || true
  fi
  if [[ "${KEEP_TMP:-0}" == 1 ]]; then
    printf 'Preserved test files at %s\n' "$TEST_ROOT"
  else
    rm -rf "$TEST_ROOT"
  fi
}
trap cleanup EXIT

cargo build --quiet --locked --manifest-path "$WORKSPACE_ROOT/Cargo.toml" \
  -p tinylayer-wallet -p tinylayer-enclave --features tinylayer-enclave/workload
WALLET_BIN="$WORKSPACE_ROOT/target/debug/tinylayer-wallet"
WORKLOAD_BIN="$WORKSPACE_ROOT/target/debug/tinylayer-workload"

"$WORKLOAD_BIN" >"$WORKLOAD_LOG" 2>&1 &
workload_pid=$!
for _ in {1..100}; do
  if curl --silent --fail http://127.0.0.1:8080/health >/dev/null; then
    break
  fi
  if ! kill -0 "$workload_pid" 2>/dev/null; then
    cat "$WORKLOAD_LOG" >&2
    exit 1
  fi
  sleep 0.05
done
curl --silent --fail http://127.0.0.1:8080/health >/dev/null

wallet() {
  local data_dir=$1
  shift
  "$WALLET_BIN" --data-dir "$data_dir" --password-file "$PASSWORD_FILE" --json "$@"
}

initialize_wallet() {
  wallet "$1" init \
    --network regtest \
    --enclave-url http://127.0.0.1:8080 \
    --unsafe-plaintext \
    --bitcoin-rpc-url "$RPC_URL" \
    --bitcoin-cookie-file "$COOKIE_FILE" \
    --bitcoin-wallet "$WALLET_NAME" \
    --min-confirmations 1 >/dev/null
}

if ! "${RPC[@]}" getwalletinfo >/dev/null 2>&1; then
  "${RPC_BASE[@]}" createwallet "$WALLET_NAME" >/dev/null
fi
mine_address=$("${RPC[@]}" getnewaddress)
"${RPC[@]}" generatetoaddress 101 "$mine_address" >/dev/null

ALICE="$TEST_ROOT/alice"
BOB="$TEST_ROOT/bob"
CAROL="$TEST_ROOT/carol"
initialize_wallet "$ALICE"
initialize_wallet "$BOB"
initialize_wallet "$CAROL"
wallet "$ALICE" enclave verify | jq -e '.client_protocol_version == 1' >/dev/null

registered=$(wallet "$ALICE" coin register)
coin_id=$(jq -er '.coin_id' <<<"$registered")
funded=$(wallet "$ALICE" coin fund --amount-sat 100000 \
  --delay-blocks 100 --fee-rate 2 --max-fee-sat 10000)
jq -e 'select(.status == "funding_broadcast" and .recovery_secured == true)' \
  <<<"$funded" >/dev/null
fund_txid=$(jq -er '.funding_txid' <<<"$funded")
outpoint=$(jq -er '.outpoint' <<<"$funded")
alice_delay=$(jq -er '.delay_blocks' <<<"$funded")
"${RPC[@]}" getmempoolentry "$fund_txid" >/dev/null
wallet "$ALICE" coin fund --amount-sat 100000 \
  --delay-blocks 100 --fee-rate 2 --max-fee-sat 10000 | \
  jq -e 'select(.status == "already_funded")' >/dev/null
"${RPC[@]}" generatetoaddress 1 "$mine_address" >/dev/null

bob_request="$TEST_ROOT/bob-request.json"
alice_to_bob="$TEST_ROOT/alice-to-bob.json"
wallet "$BOB" transfer request --coin-id "$coin_id" --outpoint "$outpoint" \
  --amount-sat 100000 --output "$bob_request" >/dev/null
jq -e '.protocol_version == 1' "$bob_request" >/dev/null
wallet "$ALICE" coin sign --request "$bob_request" --output "$alice_to_bob" >/dev/null
wallet "$BOB" transfer accept --request "$bob_request" --package "$alice_to_bob" >/dev/null

carol_request="$TEST_ROOT/carol-request.json"
bob_to_carol="$TEST_ROOT/bob-to-carol.json"
wallet "$CAROL" transfer request --coin-id "$coin_id" --outpoint "$outpoint" \
  --amount-sat 100000 --output "$carol_request" >/dev/null
wallet "$BOB" coin sign --request "$carol_request" --output "$bob_to_carol" >/dev/null
accepted=$(wallet "$CAROL" transfer accept --request "$carol_request" --package "$bob_to_carol")
carol_delay=$(jq -er '.latest_delay_blocks' <<<"$accepted")

receipt="$TEST_ROOT/receipt.json"
wallet "$CAROL" receipt export --output "$receipt" >/dev/null
jq -e '.protocol_version == 1' "$receipt" >/dev/null
wallet "$ALICE" receipt verify --input "$receipt" >/dev/null

alice_tx_file="$TEST_ROOT/alice.hex"
bob_tx_file="$TEST_ROOT/bob.hex"
carol_tx_file="$TEST_ROOT/carol.hex"
wallet "$ALICE" coin recovery --output "$alice_tx_file" >/dev/null
wallet "$BOB" coin recovery --output "$bob_tx_file" >/dev/null
wallet "$CAROL" coin recovery --output "$carol_tx_file" >/dev/null
alice_tx=$(<"$alice_tx_file")
bob_tx=$(<"$bob_tx_file")
carol_tx=$(<"$carol_tx_file")

confirmations=$("${RPC[@]}" gettransaction "$fund_txid" | jq -er '.confirmations')
"${RPC[@]}" generatetoaddress "$((carol_delay - confirmations))" "$mine_address" >/dev/null
printf 'Bob rejection before its relative delay: '
"${RPC[@]}" testmempoolaccept "[\"$bob_tx\"]" | jq -e '.[0] | select(.allowed == false and .["reject-reason"] == "non-BIP68-final") | {allowed, reject_reason: .["reject-reason"]}'
printf 'Alice rejection before its relative delay: '
"${RPC[@]}" testmempoolaccept "[\"$alice_tx\"]" | jq -e '.[0] | select(.allowed == false and .["reject-reason"] == "non-BIP68-final") | {allowed, reject_reason: .["reject-reason"]}'
exit_address=$("${RPC[@]}" getnewaddress)
carol_package=$(wallet "$CAROL" coin exit --destination "$exit_address" \
  --fee-rate 2 --max-fee-sat 10000 --dry-run)
carol_parent=$(jq -er '.parent_hex' <<<"$carol_package")
carol_child=$(jq -er '.child_hex' <<<"$carol_package")
printf 'Carol maturity at %s confirmations: ' "$carol_delay"
"${RPC[@]}" testmempoolaccept "[\"$carol_parent\",\"$carol_child\"]" | \
  jq -e 'select(length == 2 and .[0].allowed == false and .[0]["reject-reason"] == "min relay fee not met" and .[1]["reject-reason"] == null) | map({txid, allowed, reject_reason: .["reject-reason"]})'

"${RPC[@]}" generatetoaddress 10 "$mine_address" >/dev/null
printf 'Alice rejection while Bob is valid: '
"${RPC[@]}" testmempoolaccept "[\"$alice_tx\"]" | jq -e '.[0] | select(.allowed == false and .["reject-reason"] == "non-BIP68-final") | {allowed, reject_reason: .["reject-reason"]}'
bob_package=$(wallet "$BOB" coin exit --destination "$exit_address" \
  --fee-rate 2 --max-fee-sat 10000 --dry-run)
bob_parent=$(jq -er '.parent_hex' <<<"$bob_package")
bob_child=$(jq -er '.child_hex' <<<"$bob_package")
printf 'Bob maturity at %s confirmations: ' "$((carol_delay + 10))"
"${RPC[@]}" testmempoolaccept "[\"$bob_parent\",\"$bob_child\"]" | \
  jq -e 'select(length == 2 and .[0].allowed == false and .[0]["reject-reason"] == "min relay fee not met" and .[1]["reject-reason"] == null) | map({txid, allowed, reject_reason: .["reject-reason"]})'

"${RPC[@]}" generatetoaddress 10 "$mine_address" >/dev/null
alice_package=$(wallet "$ALICE" coin exit --destination "$exit_address" \
  --fee-rate 2 --max-fee-sat 10000 --dry-run)
alice_parent=$(jq -er '.parent_hex' <<<"$alice_package")
alice_child=$(jq -er '.child_hex' <<<"$alice_package")
printf 'Alice maturity at %s confirmations: ' "$alice_delay"
"${RPC[@]}" testmempoolaccept "[\"$alice_parent\",\"$alice_child\"]" | \
  jq -e 'select(length == 2 and .[0].allowed == false and .[0]["reject-reason"] == "min relay fee not met" and .[1]["reject-reason"] == null) | map({txid, allowed, reject_reason: .["reject-reason"]})'

submitted=$(wallet "$CAROL" coin exit --destination "$exit_address" --fee-rate 2 --max-fee-sat 10000)
jq -e 'select(.status == "package_submitted")' <<<"$submitted" >/dev/null
withdrawal_txid=$(jq -er '.exit_txid' <<<"$submitted")
carol_recovery_txid=$("${RPC_BASE[@]}" decoderawtransaction "$carol_tx" | jq -er '.txid')
[[ $(jq -er '.recovery_txid' <<<"$submitted") == "$carol_recovery_txid" ]]
"${RPC[@]}" generatetoaddress 1 "$mine_address" >/dev/null
"${RPC[@]}" gettransaction "$withdrawal_txid" | \
  jq -e 'select(.confirmations >= 1) | {confirmations}' >/dev/null
"${RPC_BASE[@]}" decoderawtransaction "$("${RPC[@]}" gettransaction "$withdrawal_txid" | jq -er '.hex')" | \
  jq -e --arg addr "$exit_address" \
    'select(any(.vout[]; .scriptPubKey.address == $addr)) | {txid}' >/dev/null
echo "Confirmed Carol exit: $withdrawal_txid"
echo "Only funding $fund_txid and final exit $withdrawal_txid were required on-chain."
