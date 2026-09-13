# Validation

Validation was performed on macOS with Xcode 26.2, an iPhone 17 Pro Simulator
running iOS 26.2, and pinned Rust 1.94.0. No real CA keys or external servers were
used. The generated test material is confined to ignored `.build/` directories
and the explicitly marked Simulator demo store.

**Result:** 4 Rust integration tests and 7 Simulator tests passed. Strict Clippy,
rustfmt, and swift-format lint passed. The generic iOS Release build passed.

## Automated coverage

`just test-core` runs four integration tests plus strict Clippy and rustfmt:

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
  invalid armor checksum are rejected.
- Modified ciphertext/nonce/salt/metadata, wrong CA identifier or purpose, and the
  wrong device wrapping key fail. Duplicate normalization and interval boundaries
  are checked, including a genuine unlimited end.

The iOS tests exercise the public C bridge and native Apple crypto APIs:

- Software CA creation, ECDH callback signing, and passphrase export for all four
  algorithms.
- P-256 signing callback, purpose mismatch rejection, and deleted-key failure.
- Persistent inventory reload, serial allocation, duplicate refusal/override, and
  retaining certificate history after CA removal.
- A missing device key consumes its reserved serial without issuing a certificate.
- Corrupt inventory fails closed; validity is start-inclusive/end-exclusive and
  Forever survives persistence.

The UI test drives creation, public-key entry, Forever validity, certificate
review/signing/inspection, duplicate warning, encrypted export, and relaunch with
persisted inventory. It retains screenshots of the authority, issued certificate,
duplicate warning, and portable backup screens in the Xcode test result bundle.
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
