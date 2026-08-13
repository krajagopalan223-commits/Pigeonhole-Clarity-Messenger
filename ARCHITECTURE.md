# Clarity Messenger — Architecture

This document describes the system as **actually built**, its trust boundary,
and what is deliberately deferred.

## Overview

```
   ┌─────────────┐        signed prekey bundles        ┌─────────────┐
   │  Alice app  │  ───────── publish / fetch ───────► │             │
   │ (Flutter)   │                                     │   Relay     │
   │             │  ───────── send (ciphertext) ─────► │  (server)   │
   │  clarity-   │  ◄──────── poll  (ciphertext) ───── │             │
   │  core (FFI) │                                     └─────────────┘
   └─────────────┘                                            ▲
          ▲                                                   │
          │  E2E: PQXDH handshake + Double Ratchet            │
          ▼                                                   ▼
   ┌─────────────┐                                     ┌─────────────┐
   │   Bob app   │  ◄───────────────────────────────► │  Bob polls  │
   └─────────────┘                                     └─────────────┘
```

Every app embeds the same Rust `clarity-core` (via a C FFI). The relay is a dumb
pipe: it stores public prekeys and queues opaque ciphertext. All confidentiality
and integrity live in the endpoints.

## Components

### `clarity-core` (Rust)

The security-critical library, `#![forbid(unsafe_code)]`, shared by every
platform.

- **`identity`** — an `Account` holds the long-term Ed25519 identity key, an
  X25519 identity DH key, a signed prekey, an ML-KEM-1024 prekey, and a pool of
  one-time prekeys. It publishes a **signed** `PreKeyBundle` and verifies
  fetched bundles (every field is signed by the identity key, so a malicious
  prekey server can't substitute keys).
- **`handshake`** — **PQXDH**: X3DH (four X25519 DH terms) extended with an
  ML-KEM-1024 encapsulation. All secrets are concatenated and run through
  HKDF-SHA256 to produce the session root. An attacker must break *every* DH
  **and** ML-KEM to recover it.
- **`ratchet`** — the Double Ratchet. A symmetric chain-key ratchet advances per
  message (forward secrecy); a DH ratchet advances per round-trip (break-in
  recovery). Out-of-order/dropped messages are handled with bounded skipped-key
  caching.
- **`kdf` / `pqkem`** — the symmetric key schedule and a byte-oriented ML-KEM
  wrapper.
- **`session`** — the small API app code uses: `initiate`, `respond`, `encrypt`,
  `decrypt`.
- **`safety`** — 60-digit safety numbers for out-of-band verification.
- **`wire`** — plain-bytes, bincode-encoded message and bundle types.

### `clarity-ffi` (Rust → C ABI)

Opaque `Account`/`Session` handles and byte buffers with explicit ownership
rules, plus a hand-written header at `ffi/include/clarity.h`. Builds as a
`cdylib`/`staticlib` linked into the Flutter app.

### `clarity-relay` (Rust)

Two responsibilities, nothing more:

1. **Prekey directory** — stores each user's base bundle plus a pool of one-time
   prekeys, dispensing one per fetch.
2. **Offline mailbox** — queues opaque messages per recipient until they poll.

A small `tiny_http` JSON API exposes `/publish`, `/bundle`, `/send`, `/poll`,
`/health`. TLS is expected from a reverse proxy in front. With `--state FILE`
it persists prekeys and queued mail as atomic bincode snapshots (surviving a
restart); queued mail expires on a TTL, per-mailbox count/byte caps bound
memory, and an optional per-IP rate limit sheds abuse.

### `clarity-group` (Rust)

Group messaging via **MLS (RFC 9420)**, built on the audited **OpenMLS**
library rather than a bespoke TreeKEM. A `GroupClient` is a user's MLS
identity and key store (it publishes key packages much as a 1:1 identity
publishes a prekey bundle, and its whole state exports for encrypted-at-rest
storage); a `Group` is one conversation. Adding a member yields a *commit*
(fan out to existing members) and a *welcome* (send to the newcomer); every
inbound blob — application message or membership change — is processed
uniformly. All bytes are transport-ready MLS messages, so group traffic rides
the same sealed-envelope + relay path as 1:1 traffic and the relay learns
nothing new. This crate is the tested protocol foundation; FFI + app wiring
(group UI, commit fan-out) is follow-up work.

### `app` (Flutter/Dart)

`dart:ffi` bindings → a safe `Account`/`Session` wrapper → `AppState` (sessions,
contacts, poll loop) → Material UI. Talks to the relay over HTTPS.

## Message flow

1. **Bob** publishes his signed bundle + one-time prekeys to the relay.
2. **Alice** fetches Bob's bundle, **verifies its signatures**, and runs PQXDH to
   derive the session root. She initializes her Double Ratchet.
3. Alice's first message is a **PreKey message** carrying the handshake header;
   subsequent messages are plain ratchet messages.
4. Bob polls, runs `respond` (recomputing the root, consuming the one-time
   prekey), and decrypts. From then on both sides ratchet normally.

## Trust boundary

| Party | Can it read messages? | Can it forge/tamper? | What it *does* learn |
|-------|----------------------|----------------------|----------------------|
| Endpoint (your device) | Yes (it's the plaintext) | — | Everything (out of scope: device compromise) |
| Relay operator | **No** | **No** (AEAD + signed bundles) | Timing, sizes, network addresses (unless Tor), directory fetches — but **no sender** and **no stable recipient** on mailbox traffic (sealed envelopes + rotating inboxes) |
| Passive network | No | No | Same metadata as the relay, minus server state |
| Malicious prekey server | No | **No** — bundles are identity-signed and client-verified | Which identities are fetched |

## Metadata: the honest story

Two of the three planned mitigations are now **built and tested**:

- **Sealed-sender envelopes** (`core/src/envelope.rs`): every payload travels
  inside an encryption to the recipient's identity DH key, with the sender's
  identity keys *inside* it. The relay and mesh couriers see a fresh ephemeral
  key and ciphertext — no sender field, and no initiator identity in the
  first-message handshake header either. The outer layer deliberately
  authenticates nobody; authenticity still comes from the inner
  handshake/ratchet, so a forged sender claim simply fails to decrypt.
- **Rotating inbox IDs** (`core/src/inbox.rs`): relay mail is addressed to
  `SHA-256("Clarity-inbox-v1" ‖ identity ‖ epoch)`, rotating every 24 h (the
  spec's construction, with the codebase's one hash instead of a new BLAKE3
  dependency). The mailbox store holds no stable recipient identifier;
  receivers poll a catch-up window of adjacent epochs so clock skew and
  offline gaps don't strand mail.

What the relay operator can **still** learn, stated plainly:

- **Network linkage**: your IP contacts the relay. Run over **Tor** (built) to
  remove it — without Tor, address-plus-timing can substitute for the deleted
  routing metadata.
- **Directory lookups**: fetching a *new* contact's prekey bundle names that
  identity — inherent to a directory. High-volume mailbox traffic no longer
  does.
- **Counts and timing**: sealed payloads are padded to size buckets
  (512 B → powers of two → 8 KiB steps), so only the bucket is visible — but
  message counts and timing patterns remain; cover traffic is future work.
- The **mesh** still routes by identity and broadcasts presence by design;
  couriers now at least carry sealed envelopes they cannot attribute.

Inventing a *new* onion network (as the source spec proposed) is strictly worse
than reusing a mature, audited one — so that is explicitly not in scope.

## Deliberately deferred

| Feature from the source spec | Why it's deferred |
|------------------------------|-------------------|
| Custom decentralized relay network + PBFT + token | A separate distributed-systems/economics project; Tor + simple relays cover the need. |
| Steganographic transports (TCP ISN, DNS, etc.) | Largely detectable in practice; Tor pluggable transports do this better and safer. |
| NFC dead drops | Niche transport with little v1 value. (The Bluetooth mesh, by contrast, *is* built — routing tested, radio plugin pending; see `MESH.md`.) |
| PQ *ratchet* (not just handshake) | We match Signal's PQXDH: PQ on setup. A PQ ratchet is a live research area. |

## Testing

`cargo test --workspace` runs 57 tests: full protocol round-trips, out-of-order
and dropped delivery, tamper/MITM rejection, prekey consumption, account
persistence, an in-memory relay exchange, and a real HTTP round-trip carrying a
live session.
