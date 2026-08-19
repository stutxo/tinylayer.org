# Tinylayer wallet core

`tinylayer-wallet-core` is the I/O-independent native Rust library used by the
CLI and available to downstream native adapters. It contains no filesystem,
HTTP, terminal, or Bitcoin Core RPC code. Browser and WASM targets are not part
of this release.

It owns:

- Wallet and operation-journal types.
- Resumable registration, recovery-before-broadcast funding, transfer, and
  receiver-acceptance transitions.
- Local P2TR source funding and sweep transaction construction.
- Transfer request encryption and authentication.
- Canonical exit packages with prepared, submission-armed, and observed journal
  states that can safely re-arm the same bytes after eviction.
- Funding, known-recovery conflict, and public-history validation.
- Argon2id and XChaCha20-Poly1305 encrypted-state byte codec.

Adapters are responsible for durable atomic storage, one-writer locking,
attested enclave transport, an honest chain view, and exact-byte broadcast.
The native adapter is [`../wallet`](../wallet/).

Run its tests from the repository root:

```bash
cargo test --locked -p tinylayer-wallet-core
```
