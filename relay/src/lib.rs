//! # clarity-relay
//!
//! A thin, zero-plaintext store-and-forward relay for Clarity Messenger.
//!
//! The relay does two jobs and nothing more:
//!
//! 1. **Prekey directory** — stores each user's signed [`PreKeyBundle`] and a
//!    pool of one-time prekeys, dispensing one per fetch.
//! 2. **Offline mailbox** — queues opaque, end-to-end-encrypted messages until
//!    the recipient polls for them.
//!
//! It can read *none* of the message content: everything it queues is ciphertext
//! sealed by [`clarity_core`]. A compromised relay can learn who fetched whose
//! bundle and drop/deny messages, but it cannot forge, read, or undetectably
//! tamper with them. See `ARCHITECTURE.md` for the honest trust boundary and the
//! metadata caveats.
//!
//! [`PreKeyBundle`]: clarity_core::PreKeyBundle

pub mod protocol;
pub mod server;
pub mod store;

pub use server::{serve, serve_on};
pub use store::{split_bundle, RelayStore};

#[cfg(test)]
mod tests;
