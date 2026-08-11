//! # clarity-core
//!
//! The cryptographic heart of Clarity Messenger, shared by every platform
//! (iOS, Android, Linux) through a thin FFI layer. It is deliberately small,
//! `#![forbid(unsafe_code)]`, and built entirely from vetted RustCrypto / dalek
//! primitives — **no home-grown cryptography**.
//!
//! ## What this implements
//!
//! * **Identity & prekeys** ([`identity`]): long-term Ed25519 identity, X25519
//!   identity DH key, signed prekey, ML-KEM prekey, and one-time prekeys, plus
//!   signed [`PreKeyBundle`](wire::PreKeyBundle) publication and verification.
//! * **PQXDH handshake** ([`handshake`]): X3DH extended with an ML-KEM-1024 leg,
//!   giving classical + post-quantum ("harvest now, decrypt later") security on
//!   the very first message.
//! * **Double Ratchet** ([`ratchet`]): per-message forward secrecy and break-in
//!   recovery, with bounded out-of-order handling.
//! * **Sessions** ([`session`]): the small API application code calls.
//! * **Safety numbers** ([`safety`]): out-of-band identity verification.
//!
//! ## What this deliberately does NOT implement
//!
//! The source specification described a bespoke decentralized onion network, a
//! utility token, and steganographic transports. Those are out of scope by
//! design: transport anonymity is far better served by running over an existing,
//! audited network (e.g. Tor) than by inventing one, and the token/relay economy
//! is a separate system entirely. This crate secures *message content and
//! session state*; see `ARCHITECTURE.md` for the honest system boundary.
//!
//! ## Corrections vs. the source spec
//!
//! * AEAD is **XChaCha20-Poly1305** with a per-message derived nonce — the spec's
//!   claim that ChaCha20-Poly1305 is "nonce-misuse resistant" is false, so we
//!   removed the failure mode instead of relying on it.
//! * There is **no redundant packet HMAC**; the AEAD tag authenticates.
//! * Group messaging (MLS/TreeKEM) is intentionally left to a dedicated,
//!   audited implementation rather than reimplemented here.

#![forbid(unsafe_code)]

pub mod enclave;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod kdf;
pub mod pqkem;
pub mod ratchet;
pub mod safety;
pub mod session;
pub mod transport;
pub mod wire;

pub use enclave::{Enclave, Sealed};
pub use error::{Error, Result};
pub use identity::{verify_bundle, Account};
pub use safety::safety_number;
pub use session::Session;
pub use transport::{MessageTransport, TransportError};
pub use wire::{HandshakeHeader, Message, PreKeyBundle, RatchetHeader, PROTOCOL_VERSION};

#[cfg(test)]
mod tests;
