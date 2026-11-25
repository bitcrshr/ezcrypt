# ezcrypt

Use your iPhone as a hardware SSH certificate authority. CA keys live in the
Secure Enclave (or are wrapped by it), and every signature requires Face ID,
Touch ID, or the device passcode. ezcrypt also runs natively on Apple silicon Macs.

A command-line tool removes the manual work around signing: one command on a
server or client prints a QR code, you scan it with the phone, approve, and the
CA public key or signed certificate is installed for you.

## Features

- **Hardware CAs:** P-256 keys generated in the Secure Enclave, non-exportable.
- **Software CAs:** Ed25519, P-256, P-384, or P-521, encrypted with a per-CA
  Secure Enclave key. Plaintext CA keys are handled only in Rust.
- Principals, key ID, 64-bit serials, scheduled, finite or forever validity,
  PTY/forwarding/user-rc permissions, force-command, and source CIDRs.
- Signs Ed25519, ECDSA, and FIDO2 (`ed25519-sk` / `ecdsa-sk`) SSH public keys.
- Searchable certificate inventory, duplicate and overlap warnings, and exact
  certificate redelivery without another signature.
- Each CA shows its fingerprint as OpenSSH randomart, identical to
  `ssh-keygen -lv -f ca.pub`.
- Encrypted OpenSSH private-key export with a passphrase, or GPG encryption to
  an OpenPGP public key. Neither recovery path requires ezcrypt.

## Install the CLI

The `ezcrypt` CLI runs `trust` on Linux servers and `enroll` on Linux, macOS,
and Windows clients. Release binaries and installers are published with the
first tag; until then, build from source (below).

```sh
# Linux and macOS
curl -fsSL https://github.com/bitcrshr/ezcrypt/releases/latest/download/install.sh | sh

# Windows (PowerShell)
irm https://github.com/bitcrshr/ezcrypt/releases/latest/download/install.ps1 | iex

# Nix
nix run github:bitcrshr/ezcrypt
```

From source, with the pinned Rust toolchain: `cargo install --locked --path crates/ezcrypt-cli`.

## Quickstart

Install the app on your iPhone (see [Build the app](#build-the-app)) and create a
user CA.

**Trust a CA on a server.** Run on the server:

```sh
sudo ezcrypt trust
```

It prints a QR code and the same payload as text. Scan it with the Camera or the
app's Scan action, choose which user CA to send, and tap Send. The terminal then
shows the CA name, fingerprint, and randomart and asks you to confirm. Only after
you accept does ezcrypt write the `TrustedUserCAKeys` configuration, validate it
with `sshd -t` and `sshd -T`, and reload `sshd`. If `sshd` isn't running, the
configuration is kept and applies when it starts.

**Get a certificate on a client.** Run on the machine that holds the SSH key:

```sh
ezcrypt enroll
```

Scan the QR code, check that the key fingerprint matches the one in the terminal,
review the certificate in the usual signing screen, and approve with Face ID. The
certificate is saved next to the key as `<key-name>-cert.pub`, where `ssh` finds it
automatically.

Only public keys and certificates cross the link. CA private keys never leave the
phone, and the CLI never signs. Each session uses a fresh QR code carrying a
one-time secret and expires after 10 minutes. If the phone cannot reach the machine,
the app copies a short reply, a few lines of text, that you can paste into the
waiting CLI. See the
[design](docs/superpowers/specs/2026-11-24-distribution-design.md) for the protocol.

## Build the app

Requires macOS, Xcode 26 or newer, [rustup](https://rustup.rs), and
[Just](https://github.com/casey/just). Rust 1.94.0 is pinned in
`rust-toolchain.toml`. OpenSSH and GnuPG are needed for the core interoperability
tests. The iOS deployment target is 26.0.

```sh
just bootstrap     # Rust Apple targets and locked dependencies
just test-core     # Rust tests, clippy, rustfmt
just build-ios     # Simulator build
just test-ios      # Swift integration and UI tests
just check-device  # unsigned Release build for iOS devices
just build-mac     # native Mac build
just test-trust    # end-to-end `ezcrypt trust` against sshd in a container (Docker)
just xcode         # open the project
```

The Xcode targets build their Rust library automatically.

**Signing.** No team ID is committed. `ios/Config/Signing.xcconfig` optionally
includes an untracked `ios/Config/Signing.local.xcconfig`. To run on a device,
create it with your Apple development team:

```
DEVELOPMENT_TEAM = YOUR_TEAM_ID
```

The Mac target also needs a development profile that authorizes its app-specific
Keychain access group, so the Mac must be registered with that team.

The Simulator has no Secure Enclave. For interactive development, add `--demo` to
Xcode's Run arguments (Debug, Simulator only). This enables isolated disposable
Keychain keys and a **SIMULATOR · TEST KEYS** banner. Device and Release builds cannot
use the demo backend, and no fixture CA or plaintext private key ships with the app.

`just test-mac` uses ad-hoc signing and `ezcryptMac-local.entitlements`, which lack
the Keychain entitlement, so it covers filesystem and model tests only. `just check-mac`
compiles Release without signing. Neither proves Secure Enclave behavior.

## Security model

- Swift owns screens, the public inventory, Keychain references, and authentication.
  Rust owns software CA generation, serialization, encryption, signatures, and
  exports. There is no plaintext CA export operation in the app bridge.
- Hardware CAs use non-exportable Secure Enclave P-256 keys with user presence required
  on each use. Software CAs are sealed in an AES-256-GCM envelope keyed by ECDH with a
  per-CA Secure Enclave key.
- The distribution link carries only public keys and certificates, requires a
  one-time secret from the QR code, and runs only while a session sheet is open.
- Deleting a key or certificate does not revoke certificates already issued.

Read [custody and formats](docs/architecture.md) for the full model.

## Status

The Rust core, CLI, and app have automated test coverage, described in
[validation](docs/validation.md). The interactive device validation checklist in that
document, covering Secure Enclave signing, authentication, and Mac key operations,
is still pending. The link flow (scan, deliver, trust, enroll) is covered by
automated tests only: it hasn't yet run against a real phone, real relays, Windows,
CI, or a release build. Treat ezcrypt as pre-release and use disposable CAs until
this is done.
iCloud inventory sync and cross-device signing are not implemented, and the local
inventory JSON must not be uploaded as a sync format. Mac inventories are separate
from iOS inventories.

## Workspace

```
crates/ezcrypt-core/  Certificates, custody, and exports; portable and network-free
crates/ezcrypt-ffi/   Static C bridge linked into the app
crates/ezcrypt-link/  QR offers and replies, and the Iroh session
crates/ezcrypt-cli/   The ezcrypt binary: trust and enroll
ios/                  SwiftUI app, iOS and Mac targets, Swift and UI tests
tests/trust/          Container end-to-end test for `ezcrypt trust`
docs/                 Architecture, validation, and design records
```

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

## License

[MIT](LICENSE)
