# ezcrypt

A local iOS SSH certificate authority toolkit. Create any number of host or user
CAs, issue and inspect certificates, and export portable encrypted software keys.

- **Hardware CAs:** P-256 keys generated in the Secure Enclave, non-exportable.
- **Software CAs:** Ed25519, P-256, P-384, or P-521; encrypted with a per-CA
  Secure Enclave key. Plaintext CA keys are handled only in Rust.
- Face ID, Touch ID, or device passcode gates sensitive operations.
- Principals, key ID, 64-bit serials, scheduled/finite/**forever** validity,
  PTY/forwarding/user-rc permissions, force-command, and source CIDRs.
- Searchable certificate inventory, duplicate/overlap warnings, and exact
  certificate redelivery without another signature.
- Encrypted OpenSSH private-key export with a passphrase, or GPG encryption to
  a supplied OpenPGP public key. Neither recovery path requires ezcrypt.

## Workspace

```
ios/                 SwiftUI app, Xcode project, Apple bridge, Swift/UI tests
crates/ezcrypt-core/  Portable Rust certificate, custody, and export core
docs/                Custody/format design and validation record
.scratch/            Ignored working notes
.build/              Ignored dependencies, build products, disposable test keys
```

Requires macOS, Xcode 26+, rustup, and Just. Rust 1.94.0 is pinned in
`rust-toolchain.toml`. OpenSSH and GnuPG are required for core
interoperability tests. iOS deployment target is 26.0. Builds currently target
Apple Silicon simulators and arm64 devices.

```
just bootstrap
just test-core
just build-ios
just test-ios
just xcode
```

The Xcode target builds its Rust library automatically. Pick your development
team in Xcode before running on an iPhone. No signing identity is committed.

Simulator has no Secure Enclave. For interactive development, add `--demo` to
Xcode's Run arguments (Debug, Simulator only). This enables isolated disposable
Keychain keys and an explicit **SIMULATOR · TEST KEYS** banner. A normal Simulator
launch refuses hardware operations; device/Release builds cannot use the demo
backend. Test hosts use the equally restricted `EZCRYPT_TEST_MODE=1` switch.
No fixture CA or plaintext private key ships with the app.

## Portable recovery

Passphrase exports are ordinary encrypted OpenSSH private-key files:

```
chmod 600 backup.key
ssh-keygen -y -f backup.key                 # verify/recover its public key
ssh-keygen -s backup.key -I example -n alice -V +1d subject.pub
```

GPG exports contain an OpenSSH private key:

```
gpg --output ca.key --decrypt backup.gpg
chmod 600 ca.key
ssh-keygen -y -f ca.key
```

The OpenPGP path accepts one armored public certificate with a currently valid,
bound encryption subkey. The app shows primary and encryption-subkey
fingerprints before export. Unrelated third-party certifications are ignored;
only verified self-signatures supply validity policy. It does not look up keys or
revocations online.

Use explicit usernames with servers configured through `TrustedUserCAKeys`.
The advanced all-principals user option instead requires per-account CA trust in
`authorized_keys` without a principals restriction. Source CIDRs must be network
addresses (such as `192.0.2.0/24`), or `/32`/`/128` for individual addresses.

Backups currently contain the CA private key, not the inventory. Software-key
import/restore into ezcrypt, sync, RSA SSH keys, and revocation-list generation
are intentionally outside v1. Deleting a key does not revoke certificates already
issued. Secure Enclave CAs have no portable private-key backup.

Read [custody and formats](docs/architecture.md) and
[validation and remaining device checks](docs/validation.md) before using real CAs.
