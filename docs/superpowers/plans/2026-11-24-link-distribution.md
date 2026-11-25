# Link Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sudo ezcrypt trust` (Linux) and `ezcrypt enroll` (Linux/macOS/Windows) receive a CA public key or a signed user certificate from the iPhone app over a QR-initiated Iroh session (with a paste fallback), and the repo is made public-ready with installable releases.

**Architecture:**
- A new transport crate, `ezcrypt-link`, holds the offer/reply formats and the Iroh session.
- A new `ezcrypt-cli` binary implements `trust` and `enroll` on top of it.
- A new `ezcrypt-ffi` staticlib replaces the core's C bridge and adds a blocking, cancellable delivery call for the app.
- `ezcrypt-core` stays network-free. It gains one function to inspect and verify certificates without `ssh-key`'s certificate parser, which rejects the forever sentinel.
- SwiftUI gains Scan, deep links, and trust/enroll delivery screens.

**Tech Stack:**
- Rust 1.94 (pinned): `iroh` 1.5, `tokio`, `qr2term`, `clap`, `url`, `subtle`, `tempfile`.
- SwiftUI on iOS 26 with VisionKit `DataScannerViewController`.
- GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-24-distribution-design.md`

## Global Constraints

- Rust toolchain stays `1.94.0` (`rust-toolchain.toml`); `iroh` 1.5 requires ≥ 1.91.
- `ezcrypt-core` must not depend on `ezcrypt-link`, `iroh`, `tokio`, or any networking crate.
- Only CA public keys, subject public keys, and certificates cross the link. The CLI never signs and never handles CA private material.
- ALPN `ezcrypt/link/1`. Payload version `1`. Unknown versions fail with a message naming which side to update.
- Secret: 16 random bytes, compared in constant time.
- Session lifetime on the CLI: 10 minutes. At most one successful reply per session.
- The QR code for a ~300-byte offer URL renders ≤ 80 terminal columns wide.
- `trust`: key file `/etc/ssh/ezcrypt/trusted_user_ca_keys`; drop-in `/etc/ssh/sshd_config.d/10-ezcrypt.conf` containing exactly `TrustedUserCAKeys /etc/ssh/ezcrypt/trusted_user_ca_keys`; validate with `sshd -t`; verify the effective value with `sshd -T`; restore every touched file on failure.
- `enroll` key search order in `~/.ssh` (`%USERPROFILE%\.ssh` on Windows): `id_ed25519`, `id_ecdsa`, `id_ed25519_sk`, `id_ecdsa_sk`. RSA rejected. The certificate is written to `<private key path>-cert.pub`.
- The app only networks while a link sheet is open. Every endpoint key is ephemeral.
- License: MIT. Everything stays in the single `bitcrshr/ezcrypt` repo.
- Commits are GPG-signed by the repo's git config. Never bypass signing.

## Review Focus

1. **A `.pub` file with CRLF line endings, a trailing comment, or surrounding whitespace** (common on Windows) is accepted by `enroll` as the same key. Test in Task 6.
2. **A pasted reply that the terminal wrapped across lines or indented** is still accepted. Test in Task 4.
3. **A malicious or garbled QR** (control characters or over-long host/user, an invalid endpoint key, an oversized subject) is rejected before anything is shown on the phone. Test in Task 4.
4. **The phone scans after the CLI has exited.** Delivery fails within the connect timeout with "The terminal session has ended. Run the command again." It does not hang. Test in Task 5.
5. **A server with no `sshd_config.d` directory and no `Include` line** ends up with both created and a valid config. Test in Task 7.

---

### Task 1: Crash safety and a working `test-ios` recipe

**Files:**
- Modify: `Cargo.toml` (remove `panic = "abort"` from `[profile.release]`)
- Modify: `Justfile` (`build-ios`, `test-ios` destinations)

**Interfaces:**
- Produces: `just test-ios` and `just build-ios` work on Xcode 27, where name-based Simulator destinations no longer resolve.

- [ ] **Step 1: Reproduce the failure.**
  Run: `just test-ios`
  Expected: `Unable to find a device matching the provided destination specifier`.
- [ ] **Step 2: Resolve the Simulator by ID.**
  In both recipes, resolve the ID with `xcrun simctl list devices available | awk -F'[()]' '/ {{simulator}} \(/{print $2; exit}'`. Fail with a clear message if it's empty, and pass `-destination "platform=iOS Simulator,id=$id"`.
- [ ] **Step 3: Remove `panic = "abort"`.**
  Delete the line from `[profile.release]`. Keep `lto` and `strip`.
- [ ] **Step 4: Verify.**
  Run: `just test-ios && just check-device`
  Expected: `** TEST SUCCEEDED **` with 16 tests passing, then `** BUILD SUCCEEDED **`.
- [ ] **Step 5: Commit.** `git commit -am "Fix Xcode 27 simulator destination; keep FFI panics catchable in release"`

### Task 2: Certificate inspection in the core

**Files:**
- Modify: `crates/ezcrypt-core/src/certificate.rs`
- Test: `crates/ezcrypt-core/tests/interoperability.rs`

**Interfaces:**
- Produces:

  ```rust
  pub struct Inspected {
      pub purpose: Purpose,
      pub subject: ssh_key::PublicKey,
      pub key_id: String,
      pub serial: u64,
      pub principals: Vec<String>,
      pub valid_after: u64,
      pub valid_before: Option<u64>, // None = forever (u64::MAX on the wire)
      pub ca: ssh_key::PublicKey,
  }
  pub fn inspect(certificate: &str) -> Result<Inspected> // verifies the CA signature
  ```

- [ ] **Step 1: Write the failing tests** in `interoperability.rs`:
  - `inspect_round_trips_issued_certificates`: for each algorithm and both finite and forever validity, `issue(...)` then `inspect(&issued.certificate)`. Assert:
    - `purpose`, `serial`, `principals`, `valid_after` and `valid_before` equal the request,
    - `subject` equals the parsed request key,
    - `ca` fingerprint equals `issued.ca_fingerprint`.
  - `inspect_round_trips_security_key_subjects`: the same for an `sk-ssh-ed25519@openssh.com` subject (reuse the existing sk fixture).
  - `inspect_rejects_tampering`: flipping any one byte of the decoded wire blob (re-encoded) makes `inspect` return `Err`. So do trailing bytes, an RSA cert type, and a line longer than 16 KiB.
- [ ] **Step 2: Confirm they fail.**
  Run: `cargo test --locked -p ezcrypt-core inspect`
  Expected: compile error, `inspect` not found.
- [ ] **Step 3: Implement `inspect`** with `ssh_encoding::Reader`, mirroring `issue`:
  - Read the cert type string and map it to the base algorithm.
  - Read the nonce.
  - Read the subject key fields per type:
    - ed25519: `pk`
    - ecdsa: `curve`, `Q`
    - sk-ed25519: `pk`, `application`
    - sk-ecdsa: `curve`, `Q`, `application`
  - Rebuild the subject blob as `string(base alg) || fields` and parse it with `PublicKey::from_bytes`.
  - Then read `serial`, `type` (1 = user, 2 = host), `key_id`, `principals`, `valid_after`, `valid_before`, `critical_options`, `extensions`, `reserved`, and `signature_key`.
  - The signed bytes are everything before the final `signature` string.
  - Verify with `Verifier::verify(&ca, signed, &Signature::try_from(sig_bytes)?)`.
  - Reject trailing bytes.
- [ ] **Step 4: Verify.**
  Run: `just test-core`
  Expected: all tests pass, and Clippy and fmt are clean.
- [ ] **Step 5: Commit.** `git commit -am "Inspect and verify certificates in the core, including forever validity"`

### Task 3: Split the C bridge into `ezcrypt-ffi`

**Files:**
- Create: `crates/ezcrypt-ffi/Cargo.toml` (`crate-type = ["staticlib"]`, depends on `ezcrypt-core`)
- Move: `crates/ezcrypt-core/src/ffi.rs` → `crates/ezcrypt-ffi/src/lib.rs`
- Modify: `crates/ezcrypt-core/Cargo.toml` (`crate-type = ["rlib"]`)
- Modify: `crates/ezcrypt-core/src/lib.rs` (drop `mod ffi`; make `invalid` `pub`)
- Modify: `Cargo.toml` (workspace members)
- Modify: `ios/ezcrypt.xcodeproj/project.pbxproj`:
  - both "Build Rust core" scripts: `cargo build --locked -p ezcrypt-ffi …`
  - all four `OTHER_LDFLAGS`: `-lezcrypt_ffi`

**Interfaces:**
- Produces: the same C ABI as today (`ezcrypt_call`, `ezcrypt_free`), now built from `libezcrypt_ffi.a`. Later crates can be added to the workspace without being built for iOS.

- [ ] **Step 1: Move the file and update the manifests and pbxproj** as listed. No behavior changes.
- [ ] **Step 2: Verify the core stays network-free.**
  Run: `cargo tree -p ezcrypt-core -e normal | grep -E 'iroh|tokio' ; test $? -eq 1`
  Expected: exit 0 (no matches).
- [ ] **Step 3: Verify the app builds and passes.**
  Run: `just test-core && just test-ios && just check-device`
  Expected: all pass.
- [ ] **Step 4: Commit.** `git commit -am "Move the C bridge into an ezcrypt-ffi staticlib"`

### Task 4: `ezcrypt-link` offers and replies

**Files:**
- Create: `crates/ezcrypt-link/Cargo.toml`
  - edition 2024
  - deps: `serde`, `serde_json`, `base64`, `url`, `rand`, `subtle`, `thiserror`, `iroh` (for `EndpointId`)
- Create: `crates/ezcrypt-link/src/lib.rs`, `src/offer.rs`, `src/reply.rs`, `src/error.rs`
- Test: `crates/ezcrypt-link/tests/formats.rs`

**Interfaces:**
- Produces:

  ```rust
  pub const VERSION: u8 = 1;
  pub const ALPN: &[u8] = b"ezcrypt/link/1";
  pub enum Kind { Trust, Enroll } // URL values "trust" / "enroll"
  pub struct Offer {
      pub kind: Kind,
      pub endpoint: iroh::EndpointId,
      pub secret: [u8; 16],
      pub host: String,
      pub user: String,
      pub subject: Option<Vec<u8>>, // SSH wire public-key blob; required for Enroll, absent for Trust
  }
  impl Offer {
      pub fn to_url(&self) -> String;
      pub fn from_url(url: &str) -> Result<Offer, LinkError>;
  }
  #[serde(tag = "type", rename_all = "snake_case")]
  pub enum Payload {
      CaKey { public_key: String, name: String },
      Certificate { certificate: String },
  }
  pub struct Reply { pub secret: [u8; 16], pub payload: Payload } // JSON: {"v":1,"secret":"<b64url>","payload":{…}}
  impl Reply {
      pub fn to_text(&self) -> String;                   // "ezcrypt1:" + base64url-nopad(JSON)
      pub fn from_text(text: &str) -> Result<Reply, LinkError>; // strips all ASCII whitespace first
  }
  #[serde(tag = "outcome", rename_all = "snake_case")]
  pub enum Outcome { Ok { message: String }, Error { message: String } }
  pub enum LinkError {
      Version { theirs: u8 }, Malformed(String), WrongSecret, WrongPayload,
      Unreachable, Timeout, Rejected(String), Network(String),
  }
  ```

  URL form: `ezcrypt://link?v=1&k=<kind>&n=<b64url endpoint>&s=<b64url secret>&h=<host>&u=<user>[&p=<b64url subject>]`, with base64url without padding.

- [ ] **Step 1: Write the failing tests** in `formats.rs`:
  - `offer_url_round_trips` for both kinds.
  - `offer_url_rejects`, one case each:
    - missing parameter
    - `v=2` → `LinkError::Version { theirs: 2 }`
    - unknown kind
    - an endpoint that isn't a valid ed25519 point
    - a secret that isn't 16 bytes
    - an empty host or user
    - a host over 253 bytes or a user over 64 bytes
    - a control character in host or user
    - a subject over 1024 bytes
    - `Enroll` without `p`
    - `Trust` with `p`
    - total URL over 1024 bytes
  - `reply_text_round_trips` for both payload types.
  - `reply_text_tolerates_wrapping`: insert `"\n  "` every 40 characters and a trailing `"\r\n"`. The reply still decodes. (Review Focus 2)
  - `reply_text_rejects`: wrong prefix, bad base64, `"v":2`, and JSON over 64 KiB.
- [ ] **Step 2: Confirm they fail.**
  Run: `cargo test --locked -p ezcrypt-link`
  Expected: compile errors for the missing items.
- [ ] **Step 3: Implement** `offer.rs`, `reply.rs`, `error.rs`.
  - Parse with `url::Url` and its query pairs.
  - Build `EndpointId` with `EndpointId::from_bytes`.
  - `LinkError` `Display` strings:
    - `Version`: "This QR code needs a newer ezcrypt app" when `theirs > VERSION`, else "Update the ezcrypt command-line tool".
    - `Unreachable`: "The terminal session has ended. Run the command again."
- [ ] **Step 4: Verify.**
  Run: `cargo test --locked -p ezcrypt-link && cargo clippy --locked -p ezcrypt-link --all-targets -- -D warnings`
  Expected: pass.
- [ ] **Step 5: Commit.** `git commit -am "Add ezcrypt-link offer and reply formats"`

### Task 5: `ezcrypt-link` Iroh session

**Files:**
- Create: `crates/ezcrypt-link/src/session.rs`
- Modify: `crates/ezcrypt-link/Cargo.toml` (`tokio` with `rt-multi-thread`, `time`, `macros`)
- Test: `crates/ezcrypt-link/tests/session.rs`

**Interfaces:**
- Consumes: Task 4 types.
- Produces:

  ```rust
  pub enum Network { N0, Local } // N0 = iroh::endpoint::presets::N0; Local = presets::Minimal with RelayMode::Disabled (tests only)
  pub struct Request { pub kind: Kind, pub host: String, pub user: String, pub subject: Option<Vec<u8>> }
  pub struct Listener { /* iroh::Endpoint, secret, request */ }
  impl Listener {
      pub async fn bind(network: Network, request: Request) -> Result<Listener, LinkError>;
      pub fn offer(&self) -> Offer;
      pub fn addr(&self) -> iroh::EndpointAddr;
      pub async fn next(&self) -> Result<Incoming, LinkError>; // loops past bad replies
      pub fn accept_pasted(&self, text: &str) -> Result<Payload, LinkError>;
      pub async fn close(self);
  }
  pub struct Incoming { pub payload: Payload, /* streams */ }
  impl Incoming {
      pub async fn respond(self, outcome: Outcome) -> Result<(), LinkError>;
  }
  pub async fn deliver(network: Network, offer: &Offer, payload: Payload) -> Result<Outcome, LinkError>;
  pub async fn deliver_to(
      network: Network,
      addr: iroh::EndpointAddr,
      secret: [u8; 16],
      payload: Payload,
      connect_timeout: std::time::Duration,
  ) -> Result<Outcome, LinkError>;
  ```

  - **Protocol:** one bidirectional stream. The dialer writes the `Reply` JSON (≤ 64 KiB) and finishes. The listener reads to end, then checks:
    - version,
    - secret (`subtle::ConstantTimeEq`),
    - payload type against the kind (`Trust` ⇒ `CaKey`, `Enroll` ⇒ `Certificate`).

    A failed check writes `Outcome::Error` and keeps listening. A passing check returns `Incoming`.
  - `respond` writes the `Outcome` JSON (≤ 4 KiB), finishes, and waits up to 5 s for the peer to close.
  - `deliver` uses a 30 s connect timeout and waits up to 11 minutes for the `Outcome`.
  - `accept_pasted` applies the same checks as `next`.

- [ ] **Step 1: Write the failing tests** in `session.rs`, all with `Network::Local` and `deliver_to(listener.addr(), …)`:
  - `trust_session_delivers_ca_key_and_outcome`
  - `enroll_session_delivers_certificate`
  - `wrong_secret_is_rejected_and_listener_keeps_waiting`: a bad delivery gets `Outcome::Error`, then a good one succeeds.
  - `wrong_payload_type_is_rejected`
  - `pasted_reply_is_accepted_with_same_checks`
  - `delivery_to_closed_listener_fails_fast`: close the listener, then `deliver_to(..., Duration::from_secs(2))` returns `Err(LinkError::Unreachable)` within 5 s. (Review Focus 4)
- [ ] **Step 2: Confirm they fail.**
  Run: `cargo test --locked -p ezcrypt-link --test session`
  Expected: compile errors.
- [ ] **Step 3: Implement `session.rs`** with `Endpoint::builder(preset).alpns(vec![ALPN.to_vec()]).bind()`, `accept()`/`accept_bi()`, and `connect(addr, ALPN)`/`open_bi()`. Generate the secret with `rand::rngs::OsRng`.
- [ ] **Step 4: Verify.**
  Run: `cargo test --locked -p ezcrypt-link && cargo clippy --locked -p ezcrypt-link --all-targets -- -D warnings`
  Expected: pass.
- [ ] **Step 5: Commit.** `git commit -am "Add ezcrypt-link Iroh session with paste fallback"`

### Task 6: CLI with `ezcrypt enroll`

**Files:**
- Create: `crates/ezcrypt-cli/Cargo.toml`
  - `[[bin]] name = "ezcrypt"`
  - deps: `ezcrypt-core`, `ezcrypt-link`, `clap` (derive), `tokio`, `qr2term`, `tempfile`, `anyhow`, `gethostname`
- Create: `crates/ezcrypt-cli/src/main.rs`, `src/qr.rs`, `src/session.rs`, `src/enroll.rs`
- Test: unit tests in `enroll.rs` and `qr.rs`

**Interfaces:**
- Consumes: `ezcrypt_core::certificate::{inspect, parse_public}`, and Task 5's `Listener`/`Incoming`.
- Produces:

  ```rust
  // qr.rs
  pub fn render(url: &str) -> anyhow::Result<String>;

  // session.rs: prints the QR, the copyable URL, and an optional fingerprint line,
  // then races the network against a stdin paste for up to 10 minutes.
  pub enum Received { Network(ezcrypt_link::Incoming), Pasted(ezcrypt_link::Payload) }
  pub async fn run(request: ezcrypt_link::Request, fingerprint: Option<String>) -> anyhow::Result<Received>;
  pub async fn finish(received: Received, result: &anyhow::Result<String>) // sends Outcome on the network path

  // enroll.rs
  pub struct KeyChoice { pub private: PathBuf, pub public_line: String, pub cert_path: PathBuf }
  pub fn find_key(ssh_dir: &Path, explicit: Option<&Path>) -> anyhow::Result<Option<KeyChoice>>;
  pub fn check_certificate(key: &KeyChoice, certificate: &str) -> anyhow::Result<ezcrypt_core::certificate::Inspected>;
  pub fn write_certificate(path: &Path, certificate: &str) -> anyhow::Result<()>;
  ```

  - CLI: `ezcrypt enroll [--key PATH]`, `ezcrypt trust [--yes] [--use-existing]`, `ezcrypt --version`.
  - The `trust` subcommand is a stub until Task 8.
  - Suggested user: `$USER`, or `%USERNAME%` on Windows.
  - With no key found, ask `No SSH key found. Create ~/.ssh/id_ed25519 now? [Y/n]` and run `ssh-keygen -t ed25519 -f <path>` with inherited stdio.

- [ ] **Step 1: Write the failing tests:**
  - `qr::fits_eighty_columns`: render a 300-byte URL, strip ANSI escapes, and assert every line is ≤ 80 characters wide.
  - `enroll::finds_keys_in_order`: a temp dir containing `id_ecdsa.pub` and `id_ed25519.pub` picks `id_ed25519`. An `id_rsa.pub`-only dir returns `Ok(None)`. An explicit RSA key is `Err`.
  - `enroll::accepts_crlf_comment_whitespace`: a `.pub` file containing `"  ssh-ed25519 AAAA… user@host\r\n"` gives the same `public_line` as the clean key. (Review Focus 1)
  - `enroll::check_certificate_requires_matching_user_cert`. Using the core's `issue` with a throwaway software Ed25519 CA:
    - a user cert for the key → `Ok`,
    - a host cert → `Err`,
    - a cert for a different key → `Err`.
  - `enroll::write_certificate_replaces_atomically`: an existing cert file is replaced, no temp files are left behind, and the content ends with `\n`.
- [ ] **Step 2: Confirm they fail.**
  Run: `cargo test --locked -p ezcrypt-cli`
  Expected: compile errors.
- [ ] **Step 3: Implement** `qr.rs`, `session.rs`, `enroll.rs` and `main.rs`.
  - If `qr2term` renders wider than 80 columns, render with `qrcode` `Dense1x2` plus explicit ANSI black-on-white instead.
  - The URL is always printed under the QR code. On Windows, also print `If the code doesn't display, use Windows Terminal, or open this link on your phone:`.
  - `write_certificate`: `tempfile::NamedTempFile::new_in(dir)` then `persist(path)`.
  - Success output: `Installed <cert path>`, then the principals, `Expires <date>` or `Never expires`, and the CA fingerprint.
- [ ] **Step 4: Verify.**
  Run: `cargo test --locked -p ezcrypt-cli && cargo clippy --locked -p ezcrypt-cli --all-targets -- -D warnings`
  Expected: pass.
- [ ] **Step 5: Commit.** `git commit -am "Add ezcrypt CLI with enroll"`

### Task 7: `trust` installer logic

**Files:**
- Create: `crates/ezcrypt-cli/src/trust.rs`
- Test: unit tests in `trust.rs`

**Interfaces:**
- Produces:

  ```rust
  pub trait Sshd {
      fn test(&self) -> anyhow::Result<()>;                                // sshd -t
      fn effective_trusted_user_ca_keys(&self) -> anyhow::Result<Option<String>>; // sshd -T value, `none` → None
      fn reload(&self) -> anyhow::Result<()>;
  }
  pub struct SystemSshd; // `sshd -t`, `sshd -T`; reload via `systemctl reload ssh`, then `sshd`, then SIGHUP to the pid in /run/sshd.pid
  pub struct Report { pub key_file: PathBuf, pub already_present: bool, pub added_include: bool }
  pub fn install(root: &Path, ca_line: &str, ca_name: &str, use_existing: bool, sshd: &dyn Sshd) -> anyhow::Result<Report>;
  ```

  **Algorithm.** All paths are joined under `root` (`/` in production).
  1. Snapshot each file it may touch, recording its original bytes or that it was absent.
  2. Append `<ca key> <ca_name>` to the key file unless the same key bytes are already present (mode 0644, parent dirs created).
  3. Write the drop-in, creating `sshd_config.d` if needed.
  4. If `sshd_config` has no `Include` matching `sshd_config.d/*.conf`, insert `Include /etc/ssh/sshd_config.d/*.conf` as its first line.
  5. Run `sshd.test()`.
  6. Read the effective value.
     - If it isn't our key file and `use_existing` is false, restore everything and fail: `TrustedUserCAKeys is already set to <path>. Rerun with --use-existing to add this CA there.`
     - If `use_existing`, restore the drop-in and the `Include`, append the key to that file instead (idempotently), then rerun `sshd.test()`.
  7. Reload.
  8. Any error restores all snapshots.

- [ ] **Step 1: Write the failing tests** with a temp `root` and a `FakeSshd` that records calls and returns scripted results:
  - `fresh_install_writes_key_dropin_and_reloads`
  - `rerun_is_a_no_op`: `already_present` is true and the key file is unchanged.
  - `second_ca_appends`
  - `missing_dropin_dir_and_include_are_created`: no `sshd_config.d` dir, and an `sshd_config` without `Include`. (Review Focus 5)
  - `shadowed_setting_refuses_and_restores`: the effective value is `/etc/ssh/other_ca`. Assert `Err` and that every file is byte-identical to before.
  - `use_existing_appends_to_effective_file`
  - `failed_validation_restores_everything`: `test()` fails, so every file is restored and reload is not called.
- [ ] **Step 2: Confirm they fail.**
  Run: `cargo test --locked -p ezcrypt-cli trust`
  Expected: compile errors.
- [ ] **Step 3: Implement `trust.rs`** following the algorithm above.
- [ ] **Step 4: Verify.**
  Run: `cargo test --locked -p ezcrypt-cli`
  Expected: pass.
- [ ] **Step 5: Commit.** `git commit -am "Add trust installer with validation and rollback"`

### Task 8: `ezcrypt trust` command and container test

**Files:**
- Modify: `crates/ezcrypt-cli/src/main.rs` (wire `trust`)
- Create: `tests/trust/Containerfile` (Debian stable + `openssh-server`; builds the musl CLI into the image)
- Create: `tests/trust/run.sh`
- Create: `crates/ezcrypt-link/examples/make-reply.rs`: prints `Reply { secret: [0; 16], payload: CaKey { public_key: <argv[1] file contents>, name: argv[2] } }.to_text()`
- Modify: `Justfile` (add a `test-trust` recipe; `test-core` already tests every workspace member)

**Interfaces:**
- Consumes: Task 6 `session::run` and `finish`, Task 7 `install` and `SystemSshd`.

**Command flow:**
1. On a non-Linux OS, exit with `ezcrypt trust supports Linux servers only.`
2. If not root, exit with `Run with sudo: sudo ezcrypt trust`.
3. Run `session::run(Request { kind: Trust, … }, None)`.
4. Parse `CaKey` with `parse_public`.
5. Print the name, fingerprint and `fingerprint.to_randomart(...)`.
6. Unless `--yes`, prompt `Trust this CA for user logins on <host>? [y/N]`. A "no" responds `Outcome::Error { "Declined on <host>" }`.
7. Run `install(Path::new("/"), …)`.
8. Respond with the result.
9. On success, print `Users can now log in with certificates from <name> whose principals match their account names.`

`run.sh` uses a hidden `ezcrypt trust --from-reply <file>` flag. It applies the paste path non-interactively and is compiled only with the `test-hooks` feature, so the container test needs no phone. The script:
1. Builds the image.
2. Generates a throwaway Ed25519 user CA and user key with `ssh-keygen`, and signs a cert with `ssh-keygen -s`.
3. Produces a `Reply` text for the CA with a small `cargo run --example make-reply` from `ezcrypt-link`. The secret matches because `--from-reply` skips the secret check under `test-hooks` only.
4. Runs `ezcrypt trust --yes --from-reply` in the container.
5. Asserts `ssh -i user -o CertificateFile=user-cert.pub testuser@container true` succeeds.
6. Repeats `trust` and asserts no change.
7. Asserts a pre-set `TrustedUserCAKeys /etc/ssh/other` makes it fail with the shadowing message.

- [ ] **Step 1: Write `run.sh`** with the assertions above. Run `just test-trust`.
  Expected: fails (`trust` is still a stub).
- [ ] **Step 2: Wire the `trust` command** and the `test-hooks` `--from-reply` flag.
- [ ] **Step 3: Verify.**
  Run: `just test-trust`
  Expected: `PASS: login with certificate`, `PASS: rerun unchanged`, `PASS: shadowed setting refused`.
- [ ] **Step 4: Commit.** `git commit -am "Wire ezcrypt trust; add container end-to-end test"`

### Task 9: Link delivery through the FFI

**Files:**
- Modify: `crates/ezcrypt-ffi/Cargo.toml` (add `ezcrypt-link`, `tokio`, `tokio-util`)
- Create: `crates/ezcrypt-ffi/src/link.rs`
- Modify: `crates/ezcrypt-ffi/src/lib.rs` (new `ezcrypt_call` ops)
- Modify: `ios/Bridge/ezcrypt.h`
- Test: `crates/ezcrypt-ffi/tests/link.rs`

**Interfaces:**
- Produces, in C:

  ```c
  typedef struct ezcrypt_link ezcrypt_link;
  ezcrypt_link *ezcrypt_link_new(void);
  char *ezcrypt_link_deliver(ezcrypt_link *link, const uint8_t *input, size_t length); // blocking; free with ezcrypt_free
  void ezcrypt_link_cancel(ezcrypt_link *link);  // thread-safe; deliver returns {"error":"Cancelled"}
  void ezcrypt_link_free(ezcrypt_link *link);
  ```

  - `deliver` input: `{"offer":"<url>","payload":{…Payload JSON…}}`.
    - Debug builds only (`cfg(debug_assertions)`) also accept `"network":"local","addr":<EndpointAddr JSON>`.
  - `deliver` output: `{"ok":{"outcome":"ok"|"error","message":…}}` or `{"error":…}`.
  - New `ezcrypt_call` ops:
    - `{"op":"link_offer","url":…}` → `{"kind":"trust"|"enroll","host","user","subject_public_key"?,"subject_fingerprint"?}`. The subject is rendered as an OpenSSH line and a SHA256 fingerprint via the core.
    - `{"op":"link_reply_text","url":…,"payload":{…}}` → `{"text":"ezcrypt1:…"}`.
  - A process-wide multi-thread tokio runtime is created lazily (`OnceLock`).
  - Every entry point runs inside `catch_unwind`.

- [ ] **Step 1: Write the failing tests** in `tests/link.rs`, calling the `extern "C"` functions:
  - `ffi_delivers_to_local_listener`: start an `ezcrypt_link::Listener` with `Network::Local` in the test runtime. Call `ezcrypt_link_deliver` from a thread with its `offer().to_url()` and `addr()`. Assert the listener receives the payload and the returned JSON is `outcome: ok`.
  - `ffi_cancel_unblocks_deliver`: deliver to a listener that never responds, call `ezcrypt_link_cancel` after 200 ms, and assert `{"error":"Cancelled"}` within 2 s.
  - `link_offer_op_renders_subject`: an enroll URL built from a known Ed25519 key returns that key's OpenSSH line and fingerprint.
  - `link_reply_text_op_round_trips`: decoding the text with `Reply::from_text` gives the same payload and the offer's secret.
- [ ] **Step 2: Confirm they fail.**
  Run: `cargo test --locked -p ezcrypt-ffi`
  Expected: compile errors.
- [ ] **Step 3: Implement `link.rs`** (opaque struct holding a `CancellationToken`, then `block_on(select!(deliver, cancelled))`), the new ops, and the header.
- [ ] **Step 4: Verify.**
  Run: `cargo test --locked -p ezcrypt-ffi && just check-device`
  Expected: pass, and the iOS release build links (iroh compiles for `aarch64-apple-ios`).
- [ ] **Step 5: Commit.** `git commit -am "Expose cancellable link delivery and offer parsing over the FFI"`

### Task 10: App — scan, deep link, and trust delivery

**Files:**
- Create: `ios/ezcrypt/Link.swift` (FFI wrapper and models)
- Create: `ios/ezcrypt/LinkView.swift` (offer header, trust CA picker, `DeliveryView`)
- Create: `ios/ezcrypt/ScanView.swift` (VisionKit scanner on iOS; a paste-URL field on macOS so the Mac target compiles)
- Create: `ios/Config/ezcrypt-Info.plist` (`CFBundleURLTypes`, scheme `ezcrypt`). It lives outside the synchronized `ios/ezcrypt` group so it isn't copied as a resource.
- Modify: `project.pbxproj`, iOS target:
  - `INFOPLIST_FILE = Config/ezcrypt-Info.plist`
  - `INFOPLIST_KEY_NSCameraUsageDescription = "Scan QR codes shown by the ezcrypt command-line tool."`
  - `INFOPLIST_KEY_NSLocalNetworkUsageDescription = "Connect directly to a computer running the ezcrypt command-line tool."`
- Modify: `ios/ezcrypt/EzcryptApp.swift` (`LinkRouter` in the environment, `.onOpenURL`, sheet)
- Modify: `ios/ezcrypt/AuthoritiesView.swift` (Scan toolbar button, `qrcode.viewfinder`)
- Modify: `ios/ezcrypt/InventoryStore.swift` (`func linkAuthorities(_ kind: LinkKind) -> [Authority]`)
- Test: `ios/ezcryptTests/LinkTests.swift`, `ios/ezcryptUITests/EzcryptUITests.swift`

**Interfaces:**
- Consumes: Task 9's C API and ops.
- Produces:

  ```swift
  enum LinkKind: String, Decodable { case trust, enroll }
  struct LinkOffer: Identifiable, Hashable {
      let id: UUID; let url: String; let kind: LinkKind; let host: String; let user: String
      let subjectPublicKey: String?; let subjectFingerprint: String?
  }
  enum LinkPayload { case caKey(publicKey: String, name: String); case certificate(String) }
  struct LinkOutcome: Decodable { let ok: Bool; let message: String }
  enum Link {
      static func offer(_ url: String) throws -> LinkOffer
      static func replyText(_ offer: LinkOffer, _ payload: LinkPayload) throws -> String
      static func deliver(_ offer: LinkOffer, _ payload: LinkPayload) async throws -> LinkOutcome // runs off the main actor; Task cancellation → ezcrypt_link_cancel
  }
  @MainActor @Observable final class LinkRouter { var offer: LinkOffer?; var error: String?; func open(_ url: URL) }
  struct DeliveryView: View { init(offer: LinkOffer, payload: LinkPayload) }
  ```

  - `linkAuthorities(.trust)` returns active (non-archived), user-purpose authorities.
  - `linkAuthorities(.enroll)` returns the same list.
  - `DeliveryView` states:
    - `Sending to <host>…`
    - then `Waiting for confirmation on <host>`
    - then a success or error result
  - A **Copy instead** button is always visible. It copies `replyText`, cancels delivery, and shows "Paste this into the waiting terminal." above the reply in a selectable monospaced `Text` (`accessibilityIdentifier("reply-text")`). UI tests read that element because reading the pasteboard from the test runner triggers iOS's paste-permission prompt.
  - Dismissing the sheet cancels the delivery.

- [ ] **Step 1: Write the failing tests:**
  - `LinkTests.testOfferParsesTrustAndEnroll`: use URLs built from a fixed 32-byte Ed25519 endpoint key. Assert the kind, host and user, and for enroll the subject fingerprint.
  - `LinkTests.testOfferRejectsGarbage`: a non-ezcrypt URL and `v=9` both throw.
  - `LinkTests.testLinkAuthoritiesExcludeHostAndArchived`
  - `EzcryptUITests.testTrustOfferCopyInstead`, in demo mode:
    1. Create a user CA.
    2. `app.open(URL(string: trustURL)!)`.
    3. Pick the CA and tap **Send**.
    4. Tap **Copy instead**.
    5. Assert the `reply-text` element's label starts with `ezcrypt1:`.
- [ ] **Step 2: Confirm they fail.**
  Run: `just test-ios`
  Expected: build errors for missing `Link` and `LinkRouter`.
- [ ] **Step 3: Implement** the files and pbxproj settings above. Wire the Scan button and `.onOpenURL` through `LinkRouter`.
- [ ] **Step 4: Verify.**
  Run: `just test-ios && just check-device && just build-mac`
  Expected: all succeed.
- [ ] **Step 5: Commit.** `git commit -am "App: scan and deep-link offers, deliver CA keys to ezcrypt trust"`

### Task 11: App — enroll delivery

**Files:**
- Modify: `ios/ezcrypt/SigningView.swift` (`init(authority:, link: LinkOffer? = nil)`)
- Modify: `ios/ezcrypt/LinkView.swift` (enroll: pick CA → `SigningView(authority:, link:)`)
- Test: `ios/ezcryptUITests/EzcryptUITests.swift`

**Interfaces:**
- Consumes: Task 10's `LinkOffer`, `DeliveryView` and `LinkRouter`.

**Behavior with `link` set:**
- `publicKey` is prefilled from `subjectPublicKey` and read-only.
- `principalText` is prefilled with `link.user` and editable.
- The header shows `For <user>@<host>` and the subject fingerprint.
- After a successful `store.issue`, the view shows `DeliveryView(offer: link, payload: .certificate(record.payload.certificate))` instead of `CertificateDetail`. The certificate is already saved to the inventory by the existing issuance path.

- [ ] **Step 1: Write the failing test** `EzcryptUITests.testEnrollOfferSignsAndCopies`, in demo mode:
  1. Create a user CA.
  2. Open an enroll URL whose `p` is the test's fixed Ed25519 key.
  3. Pick the CA. Assert the key field is filled and the usernames field equals the offer's user.
  4. Review, then **Sign Certificate**, then **Copy instead**.
  5. Assert the `reply-text` element starts with `ezcrypt1:` and the Certificates tab lists one certificate.
- [ ] **Step 2: Confirm it fails.**
  Run: `just test-ios`
  Expected: the new test fails at the prefilled-field assertion.
- [ ] **Step 3: Implement** the `link` mode in `SigningView` and the enroll path in `LinkView`.
- [ ] **Step 4: Verify.**
  Run: `just test-ios`
  Expected: `** TEST SUCCEEDED **`.
- [ ] **Step 5: Manual device check.** Record it in `docs/validation.md` under a new dated section. On the iPhone:
  - **enroll:** run `cargo run -p ezcrypt-cli -- enroll` on the Mac and on a Linux VM, scan the code, sign, and confirm `ssh` uses the cert.
  - **trust:** run `sudo ezcrypt trust` on the VM and confirm a login.
  - **paste:** the same flows using **Copy instead**.
- [ ] **Step 6: Commit.** `git commit -am "App: enroll offers sign and deliver certificates"`

### Task 12: Public-ready repository and CI

**Files:**
- Create: `LICENSE` (MIT, `Copyright (c) 2026 Chandler Davis`)
- Rewrite: `README.md`:
  - what ezcrypt is (the phone as a hardware SSH CA)
  - screenshots from the UI test results
  - installing the CLI
  - `ezcrypt trust` / `ezcrypt enroll` quickstart
  - building the app
  - security model summary linking `docs/architecture.md`
- Create: `ios/Config/Signing.xcconfig` (`#include? "Signing.local.xcconfig"`). Add `ios/Config/Signing.local.xcconfig` to `.gitignore`.
- Modify: `project.pbxproj`:
  - remove both `DEVELOPMENT_TEAM` lines
  - set `baseConfigurationReference` to `Signing.xcconfig` for the app targets
- Create: `.github/workflows/ci.yml`:
  - **rust** job (ubuntu, macos, windows): `cargo test --locked --workspace`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`
  - **apple** job (macos): `just test-core` and `just check-device`
  - **trust** job (ubuntu): `just test-trust`

- [ ] **Step 1: Scan history for secrets.**
  Run: `gitleaks detect --log-opts="--all" --redact`
  Expected: `no leaks found`. If any are found, stop and report to the user before continuing.
- [ ] **Step 2: Write the files** and make the pbxproj change. Create your local `Signing.local.xcconfig` with `DEVELOPMENT_TEAM = <your team ID>` (ignored, not committed).
- [ ] **Step 3: Verify.**
  - Run: `just check-device && git grep -n DEVELOPMENT_TEAM -- ios/ezcrypt.xcodeproj ; test $? -eq 1`
    Expected: build succeeds and the grep finds nothing.
  - Push the branch.
    Expected: all CI jobs green.
- [ ] **Step 4: Commit.** `git commit -am "Prepare repository for publication: license, README, CI, no committed team"`

### Task 13: Releases and installers

**Files:**
- Create: `.github/workflows/release.yml`. On tag `v*`, build `ezcrypt` for:
  - `x86_64-unknown-linux-musl`
  - `aarch64-unknown-linux-musl`
  - `aarch64-apple-darwin`
  - `x86_64-pc-windows-msvc`
  - `aarch64-pc-windows-msvc`

  Archives are named `ezcrypt-<target>.tar.gz` (`.zip` on Windows), alongside `SHA256SUMS`, `install.sh` and `install.ps1`, uploaded to the GitHub Release.
- Create: `install/install.sh`:
  - POSIX sh, detects OS and architecture
  - downloads from `https://github.com/bitcrshr/ezcrypt/releases/latest/download/`
  - verifies against `SHA256SUMS`
  - installs to `/usr/local/bin` as root, else `~/.local/bin`, with a PATH hint
  - honors `EZCRYPT_BASE_URL` for testing
- Create: `install/install.ps1`: the same steps for Windows, installing to `$env:LOCALAPPDATA\Programs\ezcrypt` and adding it to the user `PATH`. It honors `EZCRYPT_BASE_URL`.
- Create: `flake.nix`: `packages.default` builds `ezcrypt-cli`, so `nix run github:bitcrshr/ezcrypt` works.

- [ ] **Step 1: Test `install.sh` locally.**
  Serve a fake release directory (built with `cargo build -p ezcrypt-cli --release` plus a generated `SHA256SUMS`) via `python3 -m http.server`. Run `EZCRYPT_BASE_URL=http://127.0.0.1:8000 sh install/install.sh`.
  Expected: it installs, and `ezcrypt --version` prints the crate version. Then corrupt the archive and rerun.
  Expected: `checksum mismatch` and a nonzero exit.
- [ ] **Step 2: Lint.**
  Run: `shellcheck install/install.sh && nix flake check`
  Expected: no findings, and the check passes.
- [ ] **Step 3: Dry-run the release workflow.**
  Push a `v0.0.0-rc1` tag to a fork or run `workflow_dispatch` on the branch.
  Expected: all 5 archives and `SHA256SUMS` are attached. Install via `install.ps1` on the Windows runner as a workflow step.
- [ ] **Step 4: Commit.** `git commit -am "Add release workflow, installers, and Nix flake"`

---

**Publishing the repository is the user's call.** After Task 13 and a final review, the user flips `bitcrshr/ezcrypt` to public and pushes the first `v0.1.0` tag.
