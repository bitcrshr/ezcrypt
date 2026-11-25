# Distributing CA keys and certificates

Status: proposed, 2026-11-24.

## Intent

The iPhone is the everyday hardware token: CA keys live in the Secure
Enclave (or are wrapped by it) and every signature requires Face ID.
What is still painful is everything around signing:

- **Servers:** getting a user CA public key onto a machine, and writing
  the right `sshd_config` that points to the right file.
- **Clients:** getting the client's SSH public key to the phone, and the
  signed certificate back to the client.

Today this is done by hand with LocalSend and manual config edits. The goal
is for both jobs to feel the same on any machine, including a fresh VM:

```text
run one command  →  scan the QR code with the phone  →  approve  →  done
```

## Goals

1. `sudo ezcrypt trust` on a Linux server receives a user CA public key from
   the phone and installs a correct, validated `TrustedUserCAKeys`
   configuration.
2. `ezcrypt enroll` on a Linux, macOS, or Windows client sends the user's SSH public
   key to the phone and installs the signed user certificate next to the key,
   where `ssh` uses it with no configuration.
3. A fresh machine can get the CLI with one command: `curl … | sh` (or Nix)
   on Linux and macOS, and a PowerShell one-liner on Windows.
4. The repository is polished and made public before the first release.
   Everything (app, core, link, CLI, releases) stays in this single repo.

## Non-goals (v1)

- Host certificates. The session protocol leaves room for a later
  `ezcrypt host` that sends the host key and installs `HostCertificate`.
- FIDO certificate options, iCloud sync, KRLs, and the Mac app. These are
  separate projects.
- macOS or Windows as a `trust` target. `enroll` supports Linux, macOS, and
  Windows.
- Persistent pairing between phone and machines. Every session starts from a
  fresh QR code.
- An inventory of which servers trust which CA (possible later).

## Anti-goals

The feature fails, even if it works, if any of these happen:

- CA private material crosses the link. Only CA public keys, subject public
  keys, and certificates are transferred. The CLI never signs.
- Someone who did not scan the QR code can complete a session, or can make
  the CLI install a key or certificate.
- `trust` leaves `sshd` with a broken or unloadable configuration, or with a
  configuration whose effective `TrustedUserCAKeys` is not the one it wrote.
- The app gains a long-lived network identity, a background listener, or any
  networking outside an open session sheet.
- Signing becomes less deliberate. Enrollment goes through the existing
  review screen and Face ID approval.

## Constraints

- Keep the existing custody design. `ezcrypt-core` keeps owning all
  cryptography and remains network-free and testable on its own.
- The current C bridge is synchronous JSON (`ezcrypt_call`). Networking is
  asynchronous and must not block the main actor, or the crypto actor while
  it waits on Face ID.
- The QR code must scan reliably from a terminal. Target fitting an 80-column
  terminal using half-block rendering. QR version ~12 or below is about
  65 modules plus a quiet zone. The worst case is a security-key subject key
  plus hostname, user, endpoint ID, and secret, roughly 300 bytes. Keep the
  payload compact (no key comments, compact encodings).
- `ssh`/`sshd`: `Include` needs OpenSSH 8.2+. Most `sshd_config` keywords,
  including `TrustedUserCAKeys`, use the first value read, so a drop-in can
  be shadowed by an earlier setting.
- The repository is private today, and `project.pbxproj` commits a
  `DEVELOPMENT_TEAM` despite the README saying no team is committed.
- Iroh 1.5 is the current stable release.

## Approaches

| Option | Summary | Trade-off |
| --- | --- | --- |
| **A. QR + Iroh (chosen)** | QR code carries the CLI's ephemeral Iroh endpoint ID and a one-time secret. Phone dials exactly that endpoint over an encrypted QUIC connection. | Works across NAT, cloud, and VPNs. Adds a sizable networking stack to the app and CLI. Uses n0's public relays when a direct path is unavailable (relays see metadata, not content). |
| B. QR + magic-wormhole | Mature PAKE protocol and existing `wormhole` tool. | Main benefit is avoiding a CLI install, but the CLI is needed anyway to write config correctly. Less direct than A. |
| C. QR one way, paste back | No networking. Phone copies the reply; user pastes into the waiting CLI. | Only works where the phone's clipboard reaches the terminal. |

**Decision:** A, chosen by the user. C is built in as a fallback (my call).
It is nearly free because the QR already carries everything the phone
needs, and it covers machines without internet access.

## Design

### Components

- `crates/ezcrypt-link`: session payloads, QR encoding, and Iroh transport,
  shared by the CLI and the app.
- `crates/ezcrypt-cli`: the `ezcrypt` binary. Depends on `ezcrypt-link`, and
  on `ezcrypt-core` only for public-key and certificate parsing and display
  (fingerprints, randomart).
- **App:** the staticlib also links `ezcrypt-link`, exposed through a small
  session API. There is a new **Scan** action and an `ezcrypt://` URL scheme,
  so the iPhone Camera app can open a session as well.

### Session

1. The CLI starts an ephemeral Iroh endpoint (a fresh key for each session),
   generates a 128-bit random secret, and prints:
   - the QR code,
   - the same payload as copyable text,
   - and, for `enroll`, the subject key fingerprint to compare on the phone.
2. The QR payload is a URL with all the phone needs, so the paste fallback
   works offline:
   `ezcrypt://link?v=1&k=<trust|enroll>&n=<endpoint id>&s=<secret>&h=<hostname>&u=<user>[&p=<subject public key>]`.
   Use Iroh's default discovery so the endpoint ID is enough to dial. Add a
   relay URL only when a non-default relay is configured.
3. The phone scans the code and shows what is being requested before doing
   anything:
   - **Trust:** hostname, then pick an active (non-archived) user CA, then
     **Send**. This is a public key, so no Face ID is needed, but an explicit
     tap is required.
   - **Enroll:** hostname and subject key fingerprint. Then the existing
     signing flow, with the public key filled in and principals pre-filled
     with `u` as an editable suggestion. Then the existing review and Face ID.
4. The phone dials the endpoint over ALPN `ezcrypt/link/1` and sends
   `{secret, result}`, where `result` is a CA public key and CA name, or a
   certificate. The CLI compares the secret in constant time, then validates
   the result (below) and replies `{ok}` or `{error}`, but only after
   installation finishes. `trust` waits for the user to confirm at the
   terminal, so the app shows "Waiting for confirmation on <hostname>" until
   the reply arrives, then shows the outcome.
5. A session accepts at most one successful reply, then closes. Sessions time
   out after 10 minutes.
6. **Fallback.** If dialing fails, or the user taps **Copy instead**, the app
   copies a one-line reply (`ezcrypt1:` + base64 of the same message). The CLI
   reads stdin concurrently and accepts a pasted reply with the same checks.
7. Payloads carry a version (`v=1`). Unknown versions fail with a message
   telling the user which side to update.

### `ezcrypt trust` (Linux, root)

- Refuse to run without root, with a clear message.
- After receiving the key, show its fingerprint and randomart. These match
  what the app displays for the CA. Install after confirmation (`--yes`
  skips the confirmation).
- Key file: `/etc/ssh/ezcrypt/trusted_user_ca_keys`, one key per line, with
  the CA name as the comment. Adding a key already present is a no-op, so
  rerunning or adding a second (backup) CA is safe.
- Drop-in: `/etc/ssh/sshd_config.d/10-ezcrypt.conf` containing
  `TrustedUserCAKeys /etc/ssh/ezcrypt/trusted_user_ca_keys`.
- If `sshd_config` does not include `sshd_config.d`, add the `Include` line
  at the top.
- Confirm with `sshd -T` that the **effective** `trustedusercakeys` is our
  file.
  - If another file wins, stop and explain.
  - Offer `--use-existing` to append the CA to the file that is in effect.
- Validate with `sshd -t`.
  - On any failure, restore every file changed.
  - On success, reload sshd: `systemctl reload ssh` or `sshd`, falling back
    to SIGHUP.
- Print the result, including the reminder that certificate principals must
  match account names (`TrustedUserCAKeys` semantics).

### `ezcrypt enroll` (Linux, macOS, Windows)

- Select the key:
  - `--key PATH`, otherwise the first of `id_ed25519`, `id_ecdsa`,
    `id_ed25519_sk`, `id_ecdsa_sk` in `~/.ssh` (`%USERPROFILE%\.ssh` on
    Windows, where the built-in OpenSSH client uses the same `-cert.pub`
    naming).
  - If none exists, offer to run `ssh-keygen -t ed25519`. It ships with
    Windows OpenSSH too.
  - RSA is rejected, as in the app.
- Suggest the username from `$USER` (`%USERNAME%` on Windows).
- The QR code renders with Unicode half-blocks. On consoles that cannot draw
  them (legacy Windows conhost), print the copyable payload and tell the user
  to use Windows Terminal or the paste flow.
- Validate the returned certificate:
  - it is a user certificate,
  - it certifies exactly the key that was sent,
  - its signature verifies against its CA.
- Write `<key>-cert.pub` atomically and replace any previous certificate.
  Print the principals, the expiry, and the CA fingerprint.

### App

- **Scan** in the Authorities toolbar (VisionKit `DataScannerViewController`),
  plus `ezcrypt://` deep links.
- The session runs while its sheet is open. Closing the sheet ends it.
- Enrolled certificates are recorded in the inventory through the existing
  issuance path. The link only delivers.
- New Info.plist strings: camera, and local network (Iroh may use direct LAN
  paths).
- Demo/simulator mode accepts a deep link in place of scanning, for UI tests.

### Prerequisites

1. **Crash safety.** Remove `panic = "abort"` from the release profile, so
   the FFI's `catch_unwind` works in Release. This matters more once
   networking code runs in-process.
2. **Make the repo public-ready:**
   - Rewrite the README around what ezcrypt is, install, and usage.
   - Add an MIT LICENSE (user's choice).
   - Remove the committed `DEVELOPMENT_TEAM`.
   - Scan the full history for secrets.
   - Fix the `test-ios` Simulator destination for Xcode 27.
   - Add GitHub Actions CI: Rust tests, Clippy and fmt on Linux, macOS, and
     Windows (CLI and link crates), plus the iOS device build.
3. **Releases**, from this repo's GitHub Releases:
   - A tag builds static `x86_64`/`aarch64` Linux (musl), `aarch64` macOS,
     and `x86_64`/`aarch64` Windows (MSVC) binaries, with checksums.
   - `install.sh` (`curl -fsSL …/install.sh | sh`) verifies the checksum and
     installs to `~/.local/bin`, or `/usr/local/bin` as root.
   - `install.ps1` (`irm …/install.ps1 | iex`) does the same for the user's
     profile and adds it to the user's `PATH`.
   - A Nix flake (`nix run github:bitcrshr/ezcrypt`).

### Testing

- **Link:**
  - two in-process endpoints complete `trust` and `enroll` sessions,
  - a wrong secret, a second reply, an expired session, and an unknown
    version are each rejected,
  - the paste fallback round-trips.
- **`trust`**, in an `openssh-server` container:
  - fresh install,
  - rerun (no change),
  - second CA,
  - missing `Include`,
  - a pre-existing `TrustedUserCAKeys` (refuses or `--use-existing`),
  - forced `sshd -t` failure (restores files),
  - end-to-end login with a core-signed user certificate.
- **`enroll`:** a mismatched certificate key is rejected, a certificate for
  the right key is written atomically, and `ssh` then uses it. Key discovery
  and atomic replacement also run on the Windows CI runner.
- **App:** a UI test drives a deep-link session in demo mode for both
  `trust` and `enroll`.

## Left to the builder

- Exact crate boundaries and the FFI shape for asynchronous sessions.
- Iroh discovery and relay configuration details.
- QR encoding (base32 vs base64url) and terminal rendering crate.
- Release tooling (cargo-dist or a hand-written workflow).
- Message wording and minor UI layout.
