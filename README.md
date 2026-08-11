# Clarity Messenger

A cross-platform (**iOS · Android · Linux**) end-to-end encrypted messenger built
on a shared, tested Rust cryptographic core — with post-quantum session setup,
a Tor transport, and an off-grid Bluetooth mesh.

> ⚠️ **Not audited. Not finished.** This is a v0.1 foundation. Do not use it to
> protect anyone at risk until it has had an independent security review.

```
┌──────────────┐   PQXDH + Double Ratchet (end-to-end)   ┌──────────────┐
│  Alice       │◄──────────────────────────────────────►│  Bob         │
│  Flutter UI  │                                         │  Flutter UI  │
│  clarity-core│   ciphertext only ─────┐   ┌──────────  │  clarity-core│
└──────────────┘                        ▼   ▼            └──────────────┘
                          ┌─────────────────────────┐
                          │  Relay (untrusted)      │  ← over Tor, or
                          │  prekeys + mailbox      │  ← Bluetooth mesh
                          └─────────────────────────┘     (no server at all)
```

---

## Table of contents

- [What this is](#what-this-is)
- [Where it came from](#where-it-came-from)
- [Security properties](#security-properties-what-we-actually-claim)
- [What we do *not* claim](#what-we-do-not-claim)
- [Architecture](#architecture)
- [Transports](#transports-pick-your-threat-model)
- [Cryptography](#cryptography)
- [Quickstart](#quickstart)
- [Testing](#testing)
- [Status](#status)
- [Documentation map](#documentation-map)
- [Contributing & security reports](#contributing--security-reports)

---

## What this is

Clarity is an honest implementation of a secure messenger:

- **One Rust core, every platform.** All security-critical code lives in
  `clarity-core` — no garbage collector, explicit key zeroization, constant-time
  primitives, and `#![forbid(unsafe_code)]`. The UI layer never touches keys.
- **No home-grown cryptography.** Every primitive comes from the RustCrypto and
  dalek ecosystems.
- **Post-quantum from the first message.** Session setup is a hybrid
  X25519 + ML-KEM-1024 exchange, so traffic recorded today survives a future
  quantum computer.
- **The server is untrusted by construction.** The relay holds public keys and
  ciphertext. That's all it can hold.
- **Three transports, one seam.** Relay, Tor, or Bluetooth mesh — chosen per
  threat model, behind a single `MessageTransport` interface.

It is deliberately **not** a reimplementation of everything in the original
pitch. See [Where it came from](#where-it-came-from).

## Where it came from

This project began from two documents, preserved verbatim in
[`docs/source/`](docs/source/): a 16-page *Technical Architecture & Security
Specification* and an *"MI6-Grade Encrypted Communication"* overview.

The specification is ambitious and in places genuinely well-informed — the
hybrid post-quantum exchange, the untrusted prekey server, the three-tier key
hierarchy, and rotating inbox identifiers are all good ideas, and this codebase
adopts them. It is also, in places, **wrong about cryptography**, and it
describes audits, a token economy, a 5,000-node network, and shipped clients on
six platforms that **do not exist**.

So the first engineering act was a sanity check, not a build. The result:

- ✅ **Kept and built** the sound core: PQXDH, the Double Ratchet, signed prekey
  bundles, the untrusted server model, safety numbers.
- 🔧 **Corrected** the errors — most importantly the claim that
  ChaCha20-Poly1305 is *"nonce misuse resistant."* It is not; nonce reuse leaks
  the Poly1305 key. We use XChaCha20-Poly1305 with per-message derived nonces so
  the failure mode cannot occur. Five further corrections are itemized in
  [`SECURITY.md`](SECURITY.md).
- ❌ **Rejected** the custom onion network, PBFT consensus, the CLR token, and
  steganographic transports — each with a reason, in
  [`STATUS.md`](STATUS.md#5-rejected-and-why).
- 🗑️ **Deleted** every fabricated audit, user count, and marketing superlative.

The gap between those documents and this code is the most useful artifact here,
which is why both are kept side by side.

## Security properties (what we actually claim)

- **End-to-end encryption** of message content, with **per-message forward
  secrecy** and **break-in recovery** via the Double Ratchet. Compromising your
  device today does not expose yesterday's messages, and stops exposing new ones
  once the ratchet turns.
- **Post-quantum confidentiality** on session establishment (ML-KEM-1024,
  FIPS 203), defeating "harvest now, decrypt later."
- **An untrusted server.** A malicious relay can drop messages; it cannot read,
  forge, or undetectably alter them.
- **MITM-resistant key exchange.** Prekey bundles are signed by the owner's
  identity key and verified by the client — a hostile prekey server cannot
  substitute its own keys. Tested.
- **Human-verifiable identities** via 60-digit safety numbers.
- **Infrastructure independence.** With the Bluetooth mesh, messages move with no
  internet, cell service, or servers at all.

## What we do *not* claim

No "unbreakable," no "MI6-grade," no metadata magic.

- **Metadata is not fully protected.** Over a relay, the operator learns the
  contact graph unless you run over Tor. Both relay and mesh currently route by a
  stable identity key.
- **The Bluetooth mesh broadcasts your presence** — that is the opposite of
  anonymity. It exists for reachability when infrastructure is gone.
- **Endpoint compromise is out of scope.** Malware on an unlocked device reads
  plaintext. No messenger prevents that.
- **No group messaging yet**, and **no independent audit yet**.

## Architecture

```
core/    clarity-core   the protocol: identity, PQXDH, Double Ratchet,
                        safety numbers, TEE enclave boundary
ffi/     clarity-ffi    stable C ABI + header for dart:ffi
relay/   clarity-relay  store-and-forward server (library + binary)
net/     clarity-net    relay transport, direct or over Tor
mesh/    clarity-mesh   Bluetooth store-carry-forward routing
app/     Flutter client one Dart codebase for iOS, Android, Linux
tool/    build_rust.sh  build the native lib per platform
docs/    source/        the original Clarity documents, verbatim
```

| Crate | Purpose | Tests |
|-------|---------|-------|
| [`clarity-core`](core) | Identity, PQXDH handshake, Double Ratchet, safety numbers, enclave boundary | ✅ 17 |
| [`clarity-ffi`](ffi) | C ABI over the core for Flutter/`dart:ffi` | ✅ 7 |
| [`clarity-relay`](relay) | Zero-plaintext prekey directory + offline mailbox | ✅ 3 |
| [`clarity-net`](net) | Relay transport with first-class Tor (SOCKS5/`.onion`) | ✅ 3 |
| [`clarity-mesh`](mesh) | Bluetooth mesh routing (flooding, dedup, carry-forward) | ✅ 6 |
| [`app`](app) | Flutter UI, FFI bindings, isolate worker, mesh bridge | 🟡 unbuilt |

Because the core is transport-agnostic, all three transports implement one
`MessageTransport` trait — the app can hold a `dyn MessageTransport` and switch
per conversation, or run several at once.

### Message flow

1. Bob publishes a **signed** prekey bundle (identity key, signed prekey,
   ML-KEM prekey, one-time prekeys) to a relay.
2. Alice fetches it and **verifies every signature**, then runs **PQXDH**:
   four X25519 Diffie-Hellman terms *plus* an ML-KEM-1024 encapsulation, all
   combined through HKDF-SHA256 into a session root key.
3. Alice's first message carries the handshake header; Bob reconstructs the same
   root, consuming the one-time prekey.
4. Both sides run the **Double Ratchet** from there — a new message key per
   message, a new root key per round-trip.

## Transports (pick your threat model)

| | Relay (direct) | **Relay over Tor** | Bluetooth mesh |
|---|---|---|---|
| Hides content | ✅ | ✅ | ✅ |
| Hides your IP from the relay | ❌ | ✅ | n/a |
| Works with no internet | ❌ | ❌ | ✅ |
| Hides your location/presence | partial | ✅ | ❌ **broadcasts it** |
| Offline delivery | ✅ | ✅ | ✅ (carry-forward) |
| Best for | development | **everyday use** | blackouts, censorship, off-grid |

**Recommendation: Tor.** It is both the safest and the cheapest to adopt — it
reuses the relay protocol unchanged, keeps offline delivery, and unlike raw
peer-to-peer it never exposes your IP to the person you're messaging. Relays can
be published as `.onion` hidden services. See [`TOR.md`](TOR.md).

The **mesh** is a deliberate trade, not an upgrade: it gets a message out when
there is no network, at the cost of announcing that you're there. Content stays
encrypted — couriers relay ciphertext they cannot read, which is proven by test.
See [`MESH.md`](MESH.md).

## Cryptography

All primitives from RustCrypto / dalek. **No custom cryptography anywhere.**

| Purpose | Primitive | Notes |
|---------|-----------|-------|
| Identity signatures | Ed25519 | Signs prekeys; basis of the safety number |
| Classical key exchange | X25519 | Four-DH X3DH |
| Post-quantum KEM | ML-KEM-1024 (FIPS 203) | Hybrid; handshake only, as in Signal's PQXDH |
| AEAD | XChaCha20-Poly1305 | Per-message derived key **and** 192-bit nonce |
| Root/session KDF | HKDF-SHA256 | Domain-separated context strings |
| Chain KDF | HMAC-SHA256 | `0x01` → message key, `0x02` → next chain key |
| Secrets at rest | OS keystore | Keychain / Android Keystore / libsecret |

The core is `#![forbid(unsafe_code)]`. The only `unsafe` in the project is the
thin FFI boundary, whose contract is documented in `ffi/src/lib.rs` and
`ffi/include/clarity.h`.

### Hardening

- **TEE / enclave boundary** — a stateless `Enclave` where all secrets cross into
  the untrusted host **only as sealed AEAD blobs**, mapping onto SGX `ECALL`,
  Apple Secure Enclave, Android StrongBox, and TPM. See [`TEE.md`](TEE.md).
- **Note on "kernel-level":** running a messenger at ring 0 would *reduce*
  security — a parser bug there is total system compromise. The correct
  inversion is isolating secrets *from* the kernel, which is what the enclave
  boundary does.

## Quickstart

Requires a recent Rust toolchain (built and tested on 1.94).

```bash
# Build and test everything
cargo test --workspace          # 36 tests

# Run a local relay
cargo run -p clarity-relay -- 127.0.0.1:8080
```

### Running the app

Flutter is not required to build or test the Rust stack, only the UI.

```bash
cd app
flutter create --platforms=android,ios,linux .   # generate runner folders once
flutter pub get
cd .. && tool/build_rust.sh linux                # build + place the native lib
cd app && flutter run --dart-define=CLARITY_RELAY=http://127.0.0.1:8080
```

Over Tor (with a Tor daemon or Orbot running):

```bash
flutter run \
  --dart-define=CLARITY_RELAY=http://<relay>.onion \
  --dart-define=CLARITY_TOR=true \
  --dart-define=CLARITY_SOCKS=127.0.0.1:9050
```

Full per-platform instructions — including Android `cargo-ndk`, iOS static
libraries, and publishing the relay as an onion service — are in
[`app/README.md`](app/README.md) and [`TOR.md`](TOR.md).

## Testing

```bash
cargo test --workspace     # 36 tests
cargo clippy --workspace --all-targets   # clean
```

The tests are behavioral, not decorative. They prove:

- full bidirectional conversations, 50-message bursts, and DH ratchet turnover;
- **out-of-order and dropped** message delivery;
- **tampered ciphertext is rejected** (AEAD);
- **MITM is rejected** — a substituted identity key and a flipped prekey byte
  both fail bundle verification;
- one-time prekeys are consumed exactly once;
- accounts and sessions **survive serialization** mid-conversation;
- a full conversation driven **entirely through the sealed enclave ABI**, with
  sealed blobs proven opaque, enclave-bound, and tamper-evident;
- a live **HTTP round-trip** through a real relay on an ephemeral port;
- mesh **multi-hop delivery, dedup, TTL bounds, and carry-forward across a
  disconnected mesh**, plus a real encrypted message relayed by a courier that
  cannot read it;
- the whole protocol driven **through the C ABI only**, as Dart will drive it.

## Status

See **[`STATUS.md`](STATUS.md)** for the full section-by-section accounting
against the original specification.

**Built & tested:** E2E encryption · PQ handshake · Double Ratchet · signed
prekey bundles · safety numbers · session & account persistence · relay · Tor
transport · mesh routing · enclave boundary · C ABI.

**Needs device work:** Flutter app build · Bluetooth radio plugin · Tor on
device · TEE hardware key binding.

**Deferred:** group messaging (via MLS) · sealed sender & rotating inbox IDs ·
padding/cover traffic · `no_std` core · multi-device recovery · disappearing
messages · **independent audit**.

**Next up, in order:** build the app end-to-end on Linux → get an independent
review of `clarity-core` → sealed sender + rotating inbox IDs → bind enclave keys
to secure hardware → groups via MLS.

## Documentation map

| Document | What's in it |
|----------|--------------|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Components, message flow, trust boundary, metadata analysis |
| [`SECURITY.md`](SECURITY.md) | Threat model, the six corrections to the source spec, limitations |
| [`STATUS.md`](STATUS.md) | Implemented / deferred / rejected, mapped to the original spec |
| [`TEE.md`](TEE.md) | Enclave boundary and per-platform secure-hardware mapping |
| [`TOR.md`](TOR.md) | Tor transport, onion services, why not raw P2P |
| [`MESH.md`](MESH.md) | Bluetooth mesh, the presence trade-off, radio integration |
| [`app/README.md`](app/README.md) | Flutter build and per-platform native linking |
| [`docs/source/`](docs/source/) | The original Clarity documents, verbatim |

## Contributing & security reports

This is a pre-release project. If you find a security issue, report it privately
to the maintainers rather than opening a public issue. A real deployment would
publish a dedicated security contact and PGP key here.

Before any real-world use, this code needs an **independent security audit**.
That is the single most important item on the roadmap.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
