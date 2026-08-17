# Security Policy

## Project status

Tinylayer is an experimental proof of concept. No release is supported for
production custody, and the reference wallet deliberately disables Mainnet.
The documented trust assumptions and current limitations remain part of the
security model rather than guarantees provided by this policy.

## Report a vulnerability

Send vulnerability reports privately to
[`stutxo@proton.me`](mailto:stutxo@proton.me). Encrypt sensitive reports with
the repository's [`SECURITY-PGP.asc`](SECURITY-PGP.asc) key.

```text
Fingerprint: 2985 A7C4 18D7 7EB6 EEEF 608D 4B57 B009 340A EBD2
Key ID:      4B57 B009 340A EBD2
```

The same public key is independently published by
[GitHub](https://github.com/stutxo.gpg) and
[keys.openpgp.org](https://keys.openpgp.org/vks/v1/by-fingerprint/2985A7C418D77EB6EEEF608D4B57B009340AEBD2).
Verify the full fingerprint before encrypting.

Include the affected commit or version, impact, prerequisites, reproduction
steps, and any proposed mitigation. Remove real wallet secrets, capabilities,
handoffs, private keys, passwords, and funded transaction data from examples.

Do not disclose exploit details in a public issue or discussion before a fix
and coordinated disclosure date have been agreed. Reports are handled on a
best-effort basis; this experimental project does not promise a response or
remediation SLA.

## Relevant scope

Security-sensitive areas include:

- Enclavia/Nitro attestation or PCR-policy bypass.
- Enclave key, capability, handoff, or wallet-secret disclosure.
- Unauthorized signing or authorization-state transitions.
- Incorrect transaction, funding, recovery-history, reaction-window, or
  signature acceptance.
- Wallet encryption, file-permission, journaling, or crash-recovery failures.
- Transfer-package authentication or confidentiality failures.
- Silent enclave-state loss, rollback, or unsafe lifecycle behavior beyond the
  documented fail-stop model.

Availability loss, process-memory-only state, lack of endpoint authentication
or rate limiting, and Mainnet unavailability are known limitations documented
in [`enclave/README.md`](enclave/README.md) and
[`wallet/README.md`](wallet/README.md). A report demonstrating a new impact or
a way those boundaries can be bypassed is still useful.
