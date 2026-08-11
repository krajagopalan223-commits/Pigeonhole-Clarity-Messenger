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
`/health`. TLS is expected from a reverse proxy in front.

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
| Relay operator | **No** | **No** (AEAD + signed bundles) | Contact graph, timing, sizes |
| Passive network | No | No | Same metadata as the relay, minus server state |
| Malicious prekey server | No | **No** — bundles are identity-signed and client-verified | Which identities are fetched |

## Metadata: the honest story

The relay routes by a **stable recipient identity key**, and the app wraps each
payload in a `{sender, payload}` envelope so the recipient can pick the right
session. Both choices expose a **contact graph** to whoever runs the relay. This
is a conscious v1 trade-off for simplicity and reliability.

The right mitigations are **transport-layer**, kept separate from the crypto
core:

- Run all relay traffic over **Tor** (or an equivalent), so the relay can't tie
  requests to network identities.
- Rotate to **anonymous inbox IDs** (`BLAKE3(identity ‖ epoch)`) instead of raw
  identity keys.
- Sealed-sender style envelopes so the relay can't see the sender field.

Inventing a *new* onion network (as the source spec proposed) is strictly worse
than reusing a mature, audited one — so that is explicitly not in scope.

## Deliberately deferred

| Feature from the source spec | Why it's deferred |
|------------------------------|-------------------|
| Custom decentralized relay network + PBFT + token | A separate distributed-systems/economics project; Tor + simple relays cover the need. |
| Steganographic transports (TCP ISN, DNS, etc.) | Largely detectable in practice; Tor pluggable transports do this better and safer. |
| Bluetooth mesh / NFC dead drops | Niche transports; each is its own effort with little v1 value. |
| Group messaging | Should use an audited **MLS** (RFC 9420) library, not a bespoke TreeKEM. |
| PQ *ratchet* (not just handshake) | We match Signal's PQXDH: PQ on setup. A PQ ratchet is a live research area. |

## Testing

`cargo test --workspace` runs 21 tests: full protocol round-trips, out-of-order
and dropped delivery, tamper/MITM rejection, prekey consumption, account
persistence, an in-memory relay exchange, and a real HTTP round-trip carrying a
live session.
