//! Transport abstraction.
//!
//! The cryptographic core is transport-agnostic: a [`crate::wire::Message`] is
//! just opaque bytes once encoded, so it can travel over an HTTPS relay, over
//! Tor, or hop device-to-device across a Bluetooth mesh. This trait is the seam
//! that lets an app pick a transport (or several) per threat model without the
//! protocol code caring.
//!
//! Implementations:
//! * `clarity_net::RelayTransport` — relay over HTTP(S), optionally via Tor.
//! * `clarity_mesh::MeshTransport` — Bluetooth store-carry-forward mesh.
//!
//! Both move the *same* opaque payloads; carriers in a mesh, like the relay,
//! only ever see ciphertext.

/// A message transport addressed by opaque 32-byte mailbox keys.
///
/// The address is whatever the caller routes by: for relay traffic that should
/// be a *rotating inbox ID* ([`crate::inbox`]) rather than a raw identity key,
/// so the carrier never holds a stable recipient identifier; the mesh still
/// routes by identity (its radio broadcasts presence anyway). `send` hands an
/// opaque, already-encrypted payload toward an address; `receive` returns
/// payloads queued for `me`. Neither the relay nor a mesh carrier can read a
/// payload — that guarantee comes from the layers above (and with sealed
/// envelopes, [`crate::envelope`], they cannot read the sender either).
pub trait MessageTransport {
    /// Route an opaque payload toward a mailbox address.
    fn send(&self, recipient: &[u8; 32], payload: &[u8]) -> Result<(), TransportError>;

    /// Collect any payloads queued for the mailbox address `me`.
    fn receive(&self, me: &[u8; 32]) -> Result<Vec<Vec<u8>>, TransportError>;
}

/// A transport-layer error, kept deliberately simple and string-based so any
/// transport (HTTP, Tor, radio) can map into it.
#[derive(Debug, Clone)]
pub struct TransportError(pub String);

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "transport error: {}", self.0)
    }
}

impl std::error::Error for TransportError {}

impl From<&str> for TransportError {
    fn from(s: &str) -> Self {
        TransportError(s.to_string())
    }
}

impl From<String> for TransportError {
    fn from(s: String) -> Self {
        TransportError(s)
    }
}
