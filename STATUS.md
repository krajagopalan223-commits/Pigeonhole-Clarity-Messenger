# Implementation Status

An honest, section-by-section accounting of what exists in this repository,
what is deliberately deferred, and what was rejected — mapped against the
original [Clarity Technical Specification](docs/source/clarity-technical-specification-v1.0.txt).

**Version:** v0.1 foundation · **Tests:** 53 Rust (5 crates) + 21 Dart
(native FFI round trip, mesh bridge, models) · **Code:** ~4,100 lines Rust,
~1,900 lines Dart · **Audited:** no.

Legend: ✅ built & tested · 🟡 built, needs device/integration work ·
🔜 deferred (planned) · ❌ rejected (with reason)

---

## 1. At a glance

| Area | Status |
|------|--------|
| End-to-end encryption (1:1) | ✅ |
| Post-quantum handshake (ML-KEM-1024) | ✅ |
| Double Ratchet (forward secrecy + break-in recovery) | ✅ |
| Untrusted prekey server / MITM-resistant key exchange | ✅ |
| Safety numbers (out-of-band verification) | ✅ |
| Session + account persistence | ✅ |
| Store-and-forward relay (offline delivery) | ✅ |
| Tor transport (`.onion`, SOCKS5) | ✅ |
| Bluetooth mesh (off-grid, store-carry-forward) | ✅ routing / 🟡 radio |
| TEE / enclave boundary | ✅ boundary / 🔜 hardware binding |
| Flutter app — Linux desktop | ✅ built, analyzed, smoke-tested end-to-end |
| Flutter app — iOS · Android | 🟡 code complete, unbuilt on device |
| Group messaging | 🔜 (via MLS) |
| Metadata minimization (sealed sender, rotating inbox IDs) | ✅ |
| Message size padding (bucketed sealed payloads) | ✅ |
| Encrypted message history at rest | ✅ |
| Disappearing messages (per-conversation retention) | ✅ synced via in-band control (best effort) |
| One-time prekey replenishment | ✅ auto restock + republish |
| Relay durability + abuse guards | ✅ file snapshots · mail TTL · size caps · rate limit |
| Onion network of our own, CLR token, steganography | ❌ |
| Independent security audit | 🔜 **required before real use** |

---

## 2. What is built and tested

### `clarity-core` — the cryptographic core (27 tests)
`#![forbid(unsafe_code)]`, no home-grown cryptography.

- **Identity & prekeys** — Ed25519 identity key, X25519 identity DH key, signed
  prekey, ML-KEM-1024 prekey, and a pool of one-time prekeys. Matches the
  spec's §9.1 three-tier hierarchy (IK / SPK / OPK).
- **PQXDH handshake** — X3DH (four X25519 DH terms) **plus** an ML-KEM-1024
  encapsulation, all combined through HKDF-SHA256. Delivers the spec's §11.4
  "harvest now, decrypt later" goal.
- **Double Ratchet** — symmetric chain ratchet per message (forward secrecy) and
  DH ratchet per round-trip (break-in recovery), with bounded out-of-order and
  skipped-key handling.
- **Signed prekey bundles** — every field signed by the identity key and verified
  client-side, so a malicious prekey server cannot MITM (spec §9.4). Verified by
  test: a substituted identity key and a flipped prekey byte are both rejected.
- **Safety numbers** — 60-digit, order-independent fingerprints for out-of-band
  verification.
- **Persistence** — account and full session state serialize and restore;
  conversations survive an app restart.
- **Enclave boundary** — a stateless `Enclave` where all secrets cross into the
  untrusted host **only as sealed AEAD blobs** (see [`TEE.md`](TEE.md)).
- **Sealed-sender envelopes** (spec §8.5) — every payload is encrypted to the
  recipient's identity DH key with the sender's identity *inside*; transports
  see only an ephemeral key and ciphertext, and payloads are **padded to
  size buckets** (512 B → powers of two → 8 KiB steps) so length reveals only
  the bucket. Forged sender claims fail the inner handshake and are dropped.
- **Rotating inbox IDs** (spec §8) — relay mail is addressed to
  `SHA-256(identity ‖ epoch)` rotating every 24 h (the spec said BLAKE3; same
  construction, the codebase's existing hash), with a catch-up poll window so
  offline gaps and clock skew don't strand mail.

Tests cover: bidirectional conversations, 50-message bursts, out-of-order and
dropped delivery, tamper rejection, MITM/bundle-substitution rejection, one-time
prekey consumption, mid-conversation serialize/restore, full conversations
driven entirely through the sealed enclave ABI, sealed-envelope round trips
(wrong-recipient/tamper/forgery rejection, pairwise unlinkability), and inbox
rotation.

### `clarity-relay` — store-and-forward server (7 tests, opaque mailboxes)
Prekey directory (one one-time prekey dispensed per fetch) plus an offline
mailbox holding opaque ciphertext. JSON API: `/publish`, `/bundle`, `/send`,
`/poll`, `/health`. **Sees no plaintext, ever.** Optional file-backed
persistence (atomic snapshots throttled to 1/sec) survives a restart —
proven by a `kill -9` test that recovers queued mail; queued messages expire
after a configurable TTL (default 30 days), oversized messages are rejected,
per-mailbox count/byte caps drop oldest-first, and an optional per-IP rate
limit sheds abuse. Run `clarity-relay --state FILE --ttl-days N --rate-limit N`.

### `clarity-net` — relay transport, direct or over Tor (4 tests)
Same wire protocol either way; the Tor mode routes through a SOCKS5 proxy
(system `tor` / Orbot) and supports relays published as `.onion` hidden
services, so neither the relay nor the network learns the client's IP.
See [`TOR.md`](TOR.md).

### `clarity-mesh` — Bluetooth store-carry-forward mesh (6 tests)
TTL-bounded flooding, `msg_id` dedup, carry-forward store, recipient matching,
and bounded memory against floods. Tests prove multi-hop delivery, dedup, TTL
limits, **carry-forward across a disconnected mesh** (a courier physically
carries a message between two nodes that never meet), and a real end-to-end
encrypted message relayed by a courier that cannot read it. See [`MESH.md`](MESH.md).

### `clarity-ffi` — C ABI for the app (9 tests)
Opaque handles with documented ownership rules, plus a hand-written header
([`ffi/include/clarity.h`](ffi/include/clarity.h)). Exposes accounts, sessions,
session persistence, safety numbers, sealed envelopes, rotating inbox IDs,
verified bundle-key extraction, one-time-prekey stock checks and
replenishment, the relay/Tor transport, and the mesh node.
Tests drive the whole protocol **through the C ABI only**, including a live
relay round-trip.

### `app/` — Flutter client (iOS · Android · Linux) (21 Dart tests)
One Dart codebase: `dart:ffi` bindings, a memory-safe wrapper, a background
**isolate** for blocking relay/Tor calls, a mesh bridge, secure-storage
persistence of account/contacts/sessions, a transport switcher (direct/Tor), and
chat + safety-number UI. All outgoing payloads are sealed and addressed to
rotating inboxes; polling walks a persisted catch-up window of epochs, and
adding a contact now also verifies the fetched bundle belongs to the identity
that was asked for. Conversation history persists encrypted at rest (OS secure
storage). Inside the encryption, messages use a small versioned content schema
(text | timer update, with plain-text fallback), so the per-conversation
disappearing-messages timer propagates to the contact as an in-band control
message — best effort: a compliant client applies it, nothing can force a
hostile one. The one-time prekey pool auto-replenishes when it runs low (new
secrets persisted, bundle republished).

Verified on Linux desktop: `flutter analyze` is clean; the Dart test suite
drives the real native library through the same FFI wrapper the app uses
(PQXDH + Double Ratchet round trip, tamper rejection, safety numbers,
serialize/restore, and mesh delivery over a loopback radio); and a built app
exchanged live encrypted messages with a second client via `clarity-relay`,
restoring its account, contact list, and sessions across a restart.

---

## 3. What needs device work before it runs

These are written and reviewed but cannot be compiled or exercised in this
environment. Treat them as **unverified until run on a real target**.

| Item | What's needed |
|------|---------------|
| **iOS / Android app build** | The Linux desktop build is done (runner committed under `app/linux/`, zero analyzer issues, tests passing, live relay round trip verified). iOS/Android still need their runner folders (`flutter create --platforms=android,ios .`), the native lib (`tool/build_rust.sh android\|ios`), and a first build on a real device. |
| **Bluetooth radio** | `clarity-mesh` is routing only. A platform plugin must implement the `MeshRadio` interface (Android Nearby/BLE, iOS MultipeerConnectivity, Linux BlueZ). |
| **Tor on device** | Needs a running Tor: system daemon (Linux), Orbot (Android), or an embedded Tor/Arti (iOS). |
| **TEE hardware binding** | The enclave sealing key is currently OS-random in process memory. Binding it to Secure Enclave / StrongBox / TPM is per-platform work (see [`TEE.md`](TEE.md) Level 1). |

---

## 4. Deferred (planned, not built)

| Feature | Why deferred / what it needs |
|---------|------------------------------|
| **Group messaging** (spec §6 TreeKEM) | Should use an audited **MLS (RFC 9420)** library, not a bespoke TreeKEM. The spec's own design signs every group message while claiming deniability — contradictory; MLS handles this deliberately. |
| **Cover traffic, timing noise** (spec §8.3–8.4) | Size padding is **done** (sealed payloads pad to 512 B–8 KiB power-of-two buckets, then 8 KiB steps). Cover traffic and timing noise have real battery/latency costs and should be measured, not assumed. |
| **In-enclave execution** (TEE Level 2) | Running the ratchet inside SGX/TrustZone. Needs the platform SDK and a `no_std` build. |
| **`no_std` core** | Only required for bare-metal enclaves (Fortanix SGX-EDP, Trusty). Mainstream runtimes (Gramine, Occlum, OP-TEE) run the current `std` build as-is. |
| **Multi-device sync & recovery** (spec §9.3) | BIP-39 recovery phrase and multi-device registration. Needs careful design — recovery is where most messengers leak. |
| **Post-quantum signatures** (spec §11.3 Phase 2) | ML-DSA/Dilithium to replace Ed25519. Reasonable roadmap item; not urgent, since signatures aren't subject to harvest-now-decrypt-later. |
| **Client hardening** (spec §10.1) | Screen-capture blocking, clipboard protection, binary integrity. Worth doing. Note: **jailbreak/root detection is not a security boundary** — it is trivially bypassed by the attacker it claims to stop. |
| **Independent security audit** | **The single most important remaining item.** Nothing here should protect anyone at risk until this happens. |

---

## 5. Rejected, and why

These were in the source documents and are **not** being built as specified.

| Proposal | Why rejected |
|----------|--------------|
| **Custom 5-hop onion network** (spec §7.2, §8.1) | Building a new anonymity network is a multi-year research project, and a small one is *less* anonymous than a large mature one — anonymity loves crowds. Tor is used instead, which achieves the actual goal today. |
| **PBFT consensus for message ordering** (spec §7.3) | Byzantine consensus is for agreeing on a *shared ordered log*. Point-to-point message delivery does not need global ordering; this adds enormous complexity for no security gain. |
| **CLR utility token, staking, slashing** (spec §7.4) | A cryptoeconomic system, not a messaging feature. It introduces financial/regulatory risk and a Sybil problem it does not actually solve. Self-hosted and volunteer relays cover the need. |
| **Steganographic transports** | Largely detectable in practice; Tor pluggable transports do this better, and badly-done steganography actively endangers users by giving false confidence. |
| **Redundant `HMAC-SHA3-256` per packet** (spec §4.4) | The AEAD tag already authenticates. A second MAC adds key management surface and bugs, not security. |
| **Timestamp/counter-derived nonces** (spec §4.3) | Nonces are derived by HKDF from unique per-message ratchet keys instead. Timestamps collide; the spec's own claim that "nonce reuse is cryptographically impossible" did not hold for its construction. |
| **"Nonce misuse resistance" of ChaCha20-Poly1305** (spec §3.2) | **Factually false** — nonce reuse leaks the Poly1305 key and breaks integrity. Switched to XChaCha20-Poly1305 with per-message derived nonces so the failure mode cannot occur. |
| **Kernel-level installation** (requested in discussion) | The kernel is the most *privileged* code, not the most *secure*. A parser bug at ring 0 is total system compromise. The correct inversion — isolating secrets *from* the kernel in a TEE — was built instead. |
| **Claimed audits, users, and infrastructure** | Removed entirely. See [`docs/source/README.md`](docs/source/README.md). |

---

## 6. Known limitations (say these out loud)

1. **Not audited.** No third party has reviewed this code.
2. **Metadata.** Relay mail is sealed (no visible sender) and addressed to
   rotating inbox IDs (no stable recipient), so the relay no longer collects a
   contact graph from mailbox traffic — but it still sees network addresses
   and timing unless you run over Tor, message counts and timing patterns
   (sizes are bucket-padded; cover traffic remains future work),
   and identity-keyed prekey fetches when someone adds a new contact. The mesh
   routes by identity and broadcasts presence by design.
3. **The mesh broadcasts presence.** Joining a Bluetooth mesh announces that you
   run Clarity and roughly where you are. It is for reachability when
   infrastructure is gone — **not** for anonymity. Tor is the opposite trade.
4. **Only the Linux build has run.** The app now builds, passes `flutter
   analyze` with zero issues, passes 14 Dart tests (including a native FFI
   round trip and the mesh bridge), and has exchanged live encrypted messages
   with a second client through a relay — on Linux desktop. iOS and Android
   have still never been compiled; expect ordinary first-build fixes there.
5. **The relay has no authentication.** It now persists to disk, expires and
   caps queued mail, and rate-limits per IP, but anyone may publish a bundle
   or poll any mailbox — access control and spam resistance beyond volume
   caps are out of scope for v0.1.
6. **1:1 only.** No group messaging.
7. **Endpoint compromise is out of scope**, as the spec itself acknowledges
   (§2.3). Malware on an unlocked device reads plaintext; no messenger prevents
   this.

---

## 7. Suggested order of work

1. ~~**Build and run the Flutter app** on one platform end-to-end~~ **Done
   on Linux**: the app builds, boots, publishes its bundle, and exchanges
   live encrypted messages with a second client through a relay, with
   account/contacts/sessions surviving a restart. Repeat on Android/iOS.
2. **Independent security review** of `clarity-core` before anything ships.
3. ~~**Sealed sender + rotating inbox IDs**~~ **Done**: every payload ships in
   a sealed envelope addressed to a daily-rotating inbox ID, adopted through
   core, FFI, and the app, and proven live against a relay whose
   identity-keyed mailboxes stayed empty.
4. **Bind the enclave key to secure hardware** (TEE Level 1).
5. **Group messaging via MLS.**
6. **A Bluetooth radio plugin** to make the mesh real on a device.
