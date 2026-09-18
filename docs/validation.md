# Validation

Validation was performed on macOS with Xcode 26.2, an iPhone 17 Pro Simulator
running iOS 26.2, and pinned Rust 1.94.0. No real CA keys or external servers were
used. The generated test material is confined to ignored `.build/` directories
and the explicitly marked Simulator demo store.

**Result after the review fixes:** 5 Rust integration tests and 8 Simulator tests passed. Strict Clippy,
rustfmt, and swift-format lint passed. The generic iOS Release build passed.

## Native Mac first cut — 2026-09-17

- Native Apple silicon Debug and unsigned Release builds passed with Xcode 26.2.
- Four native Mac tests passed: Simulator-backend exclusion, inventory reload and
  corruption handling, native filesystem acceptance of storage/backup options,
  and lossless OpenSSH certificate file delivery / maximum-serial round trips.
  File-option acceptance is not proof of iOS-equivalent locked-device protection.
- All 10 shared Swift integration/model tests passed on iPhone 17 Pro Simulator.
  The iOS UI suite was not rerun for this change; Rust source was unchanged.
- Opened the local Mac build and inspected the three-column empty inventory,
  authority editor, software-custody algorithm picker, and Command-N sheet flow.
  Screenshots: `.build/mac-review/inventory.png` and
  `.build/mac-review/create-authority.png`. Populated signing/export flows and
  Save-panel delivery have not yet been exercised on Mac.
- Full Mac entitlements request an app-specific Keychain group. Local tests use
  the separate ad-hoc entitlements without that group; they do not create keys,
  request authentication, or prove hardware support.
- Development signing reached a concrete prerequisite: this Mac is not yet
  registered with the existing Apple developer team, so Xcode could not obtain a
  Mac development profile for `app.ezcrypt.mac`. Automatic approval review blocked
  agent-driven device registration. The user is updating Xcode and will register
  the Mac themselves; further Xcode builds were stopped for that update.

After registration, select the development team for `ezcryptMac` and run on
**My Mac**. With disposable CAs, check hardware P-256 signing and software-CA
wrapping/signing/export for every supported algorithm; cancel authentication and
verify failure; relaunch and sign again; save certificates and encrypted backups
through the native file panel; remove only the disposable keys and confirm their
history remains. Validate the existing `WhenPasscodeSetThisDeviceOnly` /
`userPresence` policy on the Mac, including password/Touch ID and lock behavior.
No claim of complete Mac Secure Enclave validation is made by this first cut.

## Automated coverage

`just test-core` runs five integration tests plus strict Clippy and rustfmt:

- Each of Ed25519/P-256/P-384/P-521 creates a software envelope, decrypts with the
  matching ECDH key, and issues both host and user certificates, finite and forever.
  OpenSSH `ssh-keygen -Lf` parses the certificate, maximum u64 serial, restrictions,
  and no-end-time validity. Finite certificates are also cryptographically
  validated with the Rust parser against the expected CA fingerprint.
- Each algorithm's passphrase-encrypted export is opened by `ssh-keygen -y`, with
  the recovered public key compared to the original CA.
- GnuPG generates a disposable Ed25519 certification key plus Curve25519 encryption
  subkey. It decrypts exports for all four CA algorithms, and the recovered
  OpenSSH keys match their original public keys. Wrong recipient fingerprints,
  multiple armor blocks, trailing data/packets, an unbound user packet, and an
  invalid armor checksum are rejected. Truncated old/new packet headers and
  bodies are rejected. A valid third-party certification is accepted and exports
  decrypt with GnuPG; retaining only that certification without a valid
  self-signature is rejected.
- Modified ciphertext/nonce/salt/metadata, wrong CA identifier or purpose, and the
  wrong device wrapping key fail. Duplicate normalization and interval boundaries
  are checked, including a genuine unlimited end.
- IPv4 and IPv6 source CIDRs reject nonzero host bits, including `/0` edge cases;
  valid network and single-address prefixes remain unchanged.

The iOS tests exercise the public C bridge and native Apple crypto APIs:

- Software CA creation, ECDH callback signing, and passphrase export for all four
  algorithms.
- P-256 signing callback, purpose mismatch rejection, and deleted-key failure.
- Persistent inventory reload, serial allocation, duplicate refusal/override, and
  retaining certificate history after CA removal.
- A missing device key consumes its reserved serial without issuing a certificate.
- Corrupt and unsupported-version inventories fail closed across reloads.
  Replacing the unreadable inventory with valid data allows retry; a missing file
  on retry does not silently become an empty store.
- A simulated final-write failure retains the exact signed certificate. Retrying
  after deleting the signing key persists and returns that same record, without
  another signature or serial reservation. Repeated retry is a no-op.
- Validity is start-inclusive/end-exclusive and Forever survives persistence.

The UI test drives creation, public-key entry, Forever validity, certificate
review/signing/inspection, duplicate warning, encrypted export, and relaunch with
persisted inventory. It retains screenshots of the authority, issued certificate,
duplicate warning, and portable backup screens in the Xcode test result bundle.
The user all-principals toggle is checked for its `TrustedUserCAKeys` warning.
Light and dark appearance were also inspected visually.

`just check-device` builds the Release app for generic arm64 iOS without code
signing. This compiles the real Secure Enclave access policy and excludes the
Simulator test backend. It does not install or execute on physical hardware.

## Physical-device checks still required

Before entrusting real CA keys to this initial implementation:

1. On a passcode-enabled iPhone, create each custody mode, sign, export software
   keys, and remove keys. Confirm fresh Face ID/Touch ID/passcode authorization for
   each sensitive operation, including cancellation and biometric fallback.
2. Confirm the actual Secure Enclave key attributes and that hardware CA private
   export is unavailable. Check that wrapping/signing fail with a missing device
   key and after the applicable device passcode/key-access changes.
3. Lock/background the app during operations, relaunch it, and inspect inventory
   protection and error handling on-device.
4. Recover a disposable phone-created export using ordinary OpenSSH/GnuPG on a
   separate machine, and use a phone-issued certificate against a disposable sshd.

This is an initial implementation with automated interoperability evidence, not a
cryptographic audit. Memory hygiene reduces exposure but cannot prove that every
compiler, library, or OS copy was erased. Crash-safe serial reservation is not a
complete audit log: a crash after signing but before saving can lose an undelivered
certificate while preserving the serial gap.

The GPG test covers a common Curve25519 recipient. Other recipient algorithms the
PGP library accepts have not all been qualified. Import into ezcrypt, sync,
inventory backup, and revocation distribution are not implemented.
