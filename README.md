# ezcrypt

A local iPhone, iPad, and native Mac SSH certificate authority toolkit. Create any number of host or user
CAs, issue and inspect certificates, and export portable encrypted software keys.

- **Hardware CAs:** P-256 keys generated in the Secure Enclave, non-exportable.
- **Software CAs:** Ed25519, P-256, P-384, or P-521; encrypted with a per-CA
  Secure Enclave key. Plaintext CA keys are handled only in Rust.
- Face ID, Touch ID, or device passcode gates sensitive operations.
- Principals, key ID, 64-bit serials, scheduled/finite/**forever** validity,
  PTY/forwarding/user-rc permissions, force-command, and source CIDRs.
- Sign Ed25519, ECDSA, and FIDO2 SSH public keys (`ed25519-sk` / `ecdsa-sk`),
  including resident keys, through the same paste or file-import flow.
- Searchable certificate inventory, duplicate/overlap warnings, and exact
  certificate redelivery without another signature.
- Each CA shows its fingerprint as OpenSSH randomart, identical to
  `ssh-keygen -lv -f ca.pub`, for quick visual verification on a computer.
- Encrypted OpenSSH private-key export with a passphrase, or GPG encryption to
  a supplied OpenPGP public key. Neither recovery path requires ezcrypt.

## Workspace

```
ios/                 Shared SwiftUI app, iOS/Mac targets, Apple bridge, Swift/UI tests
crates/ezcrypt-core/  Portable Rust certificate, custody, and export core
docs/                Custody/format design and validation record
.scratch/            Ignored working notes
.build/              Ignored dependencies, build products, disposable test keys
```

Requires macOS, Xcode 26+, rustup, and Just. Rust 1.94.0 is pinned in
`rust-toolchain.toml`. OpenSSH and GnuPG are required for core
interoperability tests. iOS deployment target is 26.0. Builds currently target
Apple silicon simulators, arm64 iOS devices, and Apple silicon Macs on macOS 26+.

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

## Native Mac app

Open `ios/ezcrypt.xcodeproj`, choose the **ezcryptMac** scheme and **My Mac**.
Select your Apple development team in Signing & Capabilities. The Mac target
requires a development profile authorizing its app-specific Keychain access group;
the Mac must be registered with that team. No team or signing identity is committed.

```sh
just build-mac DEVELOPMENT_TEAM=YOUR_TEAM_ID
just test-mac
just check-mac
```

The Mac app shares its Rust core, models, inventory store, cryptographic bridge,
detail screens, and creation/signing/export forms with iOS. It adds a resizable
three-column browser, search and certificate filters, File → New Authority (⌘N),
Mac clipboard handling, and native Save panels for certificates and encrypted backups.
It has a single inventory window and uses App Sandbox with user-selected file access.

`test-mac` uses local ad-hoc signing and `ezcryptMac-local.entitlements` for
filesystem/model tests and UI inspection only. That build lacks the Keychain
entitlement needed for real key operations. `build-mac` uses the full entitlements;
`check-mac` compiles Release without signing. Neither local signing nor a successful
build proves Secure Enclave or authentication behavior. The Simulator software-key
backend remains unavailable on Mac, including Debug builds.

Inventories are currently separate on every device. Mac key creation, lookup, and
delete explicitly select the data-protection Keychain, preserving hardware-only
key custody and the existing user-presence policy. Interactive Mac hardware
validation is still required; see [validation](docs/validation.md).

The next phases are iCloud inventory sync **without CA private keys**, followed by
explicit authorization of another device to sign for a software CA. Neither is
implemented in this phase. The local JSON currently includes device-wrapped
software-key envelopes and must not simply be uploaded as the future sync format.

## Organizing the inventory

Authority and certificate lists have an **Active / Archived / All** inventory
filter on iPhone, iPad, and Mac. Open a record for its archive/restore actions.

- **Archive Authority** keeps the private key and issued history, hides the CA
  from the active list, and prevents new signing until **Restore Authority**.
  **Remove Private Key** remains a separate permanent operation. An authority
  whose key was removed remains viewable in Archived but cannot be restored.
- **Archive Certificate** is reversible and keeps the record in duplicate checks.
- **Delete Certificate** permanently removes its inventory record after
  confirmation. It no longer contributes to duplicate warnings. CA serial
  counters are never reset or reused by archiving or deleting records.

These actions do not revoke certificates or remove copies already saved elsewhere.

## Portable recovery

Passphrase exports are ordinary encrypted OpenSSH private-key files:

```
chmod 600 backup.key
ssh-keygen -y -f backup.key                 # verify/recover its public key
ssh-keygen -s backup.key -I example -n alice -V +1d subject.pub
```

OpenPGP exports are ASCII-armored `.asc` files containing an encrypted OpenSSH
private key. Use **Copy encrypted backup** to copy the same armored text:

```
gpg --output ca.key --decrypt backup.asc
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

For FIDO2 keys, paste or import the OpenSSH `.pub` key beginning with
`sk-ssh-ed25519@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com`.
The certificate preserves the key's application identifier. Resident-key
discovery and enrollment remain on your computer; ezcrypt only needs the public
key to certify it. Save the issued certificate alongside the corresponding SSH
key as `<key-name>-cert.pub`.

Backups currently contain the CA private key, not the inventory. Software-key
import/restore into ezcrypt, sync, RSA SSH keys, and revocation-list generation
are intentionally outside v1. Deleting a key does not revoke certificates already
issued. Secure Enclave CAs have no portable private-key backup.

Read [custody and formats](docs/architecture.md) and
[validation and remaining device checks](docs/validation.md) before using real CAs.
