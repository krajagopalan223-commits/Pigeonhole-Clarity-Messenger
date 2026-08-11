# Clarity Messenger

A cross-platform (**iOS · Android · Linux**) end-to-end encrypted messenger,
built on a shared, tested Rust cryptographic core.

This repository is the honest, buildable subset of the original Clarity design.
It deliberately does **not** implement the marketing-deck features that are
either unsound or multi-year projects on their own (a bespoke onion network, a
utility token, steganographic transports). Instead it does the part that
actually protects users — correct, modern E2E messaging — and does it on top of
vetted primitives rather than home-grown cryptography. See
[`SECURITY.md`](SECURITY.md) for the full reasoning and the corrections made to
the source specification.

## What's here

| Crate / dir | What it is | Status |
|-------------|-----------|--------|
| [`core/`](core) | `clarity-core`: identity, PQXDH handshake, Double Ratchet, safety numbers, TEE enclave boundary | ✅ built, 17 tests |
| [`ffi/`](ffi) | `clarity-ffi`: C ABI over the core for `dart:ffi` | ✅ built, 4 tests |
| [`relay/`](relay) | `clarity-relay`: thin zero-plaintext store-and-forward server | ✅ built, 3 tests |
| [`net/`](net) | `clarity-net`: relay transport with first-class Tor (SOCKS5/onion) support | ✅ built, 3 tests |
| [`app/`](app) | Flutter app for iOS/Android/Linux, one codebase | ✅ code complete; runner folders via `flutter create` |

Hardening docs: [`SECURITY.md`](SECURITY.md) · [`ARCHITECTURE.md`](ARCHITECTURE.md) · [`TEE.md`](TEE.md) (enclave/secure-hardware) · [`TOR.md`](TOR.md) (metadata-protecting transport).

### Security properties (the ones we actually claim)

- **End-to-end encryption** of message content with **per-message forward
  secrecy** and **break-in recovery** (Double Ratchet).
- **Post-quantum protection** on session setup: a hybrid X25519 + **ML-KEM-1024**
  (FIPS 203) handshake, so traffic recorded today resists a future quantum
  computer ("harvest now, decrypt later").
- **Untrusted server:** the relay only ever holds public keys and ciphertext; it
  cannot read, forge, or undetectably tamper with messages.
- **MITM-resistant key exchange:** prekey bundles are signed by the owner's
  identity key and verified by the client; **safety numbers** let users confirm
  identities out-of-band.

### What we do *not* claim

No metadata magic, no "unbreakable," no "MI6-grade." The relay learns who talks
to whom (contact graph) unless you run it over an anonymizing transport such as
Tor. Group messaging, and anonymous routing, are out of scope for this version.
[`SECURITY.md`](SECURITY.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md) spell out
exactly what is and isn't protected.

## Cryptographic building blocks

All from RustCrypto / dalek — **no custom cryptography**:

- Identity signatures: **Ed25519**
- Key agreement: **X25519** (classical) + **ML-KEM-1024** (post-quantum), combined
- AEAD: **XChaCha20-Poly1305** with a per-message derived nonce
- KDFs: **HKDF-SHA256** (root/session) and **HMAC-SHA256** (chain)
- Account-at-rest: OS secure storage (Keychain / Keystore / libsecret)

## Quickstart

Requires a recent Rust toolchain.

```bash
# Build and test the whole native workspace
cargo test --workspace

# Run a local relay
cargo run -p clarity-relay -- 127.0.0.1:8080
```

To run the app, install Flutter and follow [`app/README.md`](app/README.md)
(generate the platform runners with `flutter create`, build the native lib with
`tool/build_rust.sh`, then `flutter run`).

## Repository layout

```
core/    clarity-core   — the cryptographic protocol (shared by all platforms)
ffi/     clarity-ffi    — C ABI + header (ffi/include/clarity.h)
relay/   clarity-relay  — store-and-forward server (library + binary)
app/     Flutter client — dart:ffi bindings, relay client, UI
tool/    build_rust.sh  — build the native lib for a platform
```

## Status & roadmap

This is a **v0.1 foundation**, not a finished product.

Done since the first cut:
- ✅ Serializable session state (conversations survive app restarts).
- ✅ TEE enclave boundary — secrets cross into the untrusted host only as sealed
  blobs; maps to SGX / Secure Enclave / StrongBox (see [`TEE.md`](TEE.md)).
- ✅ Tor transport (`clarity-net`) hiding the client IP from relay and network
  (see [`TOR.md`](TOR.md)).

Honest next steps, in priority order:

1. Wire `clarity-net` (Tor) + session persistence into the Flutter app via FFI.
2. Bind the enclave sealing key to real secure hardware per platform (TEE Level 1).
3. Rotating-inbox-ID / sealed-sender to shrink the contact graph the relay sees.
4. Group messaging via an audited **MLS** (RFC 9420) implementation.
5. Independent security review before any real-world use.

> ⚠️ **Not yet audited.** Do not rely on this to protect anyone at risk until it
> has had an independent security review.

## License

Apache-2.0.
