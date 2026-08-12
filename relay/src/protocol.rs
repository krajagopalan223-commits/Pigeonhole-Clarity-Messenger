//! JSON request/response types for the relay HTTP API.
//!
//! All binary fields are base64 (standard alphabet). Keeping the wire format
//! human-readable makes the relay easy to debug and reimplement in any client
//! language (the Flutter app talks to it over plain HTTPS).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// `POST /publish` — upload prekeys.
#[derive(Debug, Serialize, Deserialize)]
pub struct PublishRequest {
    /// base64 of the base [`clarity_core::PreKeyBundle`] (bincode-encoded).
    pub bundle: String,
    /// One-time prekeys to dispense, one per bundle fetch.
    pub one_time: Vec<OneTimePrekey>,
}

/// A single one-time prekey entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct OneTimePrekey {
    pub id: u32,
    /// base64 of the 32-byte X25519 public key.
    pub public: String,
}

/// `GET /bundle?identity=<base64>` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct BundleResponse {
    /// base64 of the bincode-encoded [`clarity_core::PreKeyBundle`].
    pub bundle: String,
}

/// `POST /send` — queue a message for a mailbox.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendRequest {
    /// base64 of the 32-byte mailbox key. Clients pass a *rotating inbox ID*
    /// (`clarity_core::inbox`), never a raw identity; the relay treats the
    /// value as opaque either way.
    pub recipient: String,
    /// base64 of an opaque sealed envelope (`clarity_core::envelope`).
    pub message: String,
}

/// `GET /poll?recipient=<base64>` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct PollResponse {
    /// base64-encoded messages, in delivery order.
    pub messages: Vec<String>,
}

/// Encode bytes as standard base64.
pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode standard base64 into bytes.
pub fn unb64(s: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(s).map_err(|e| e.to_string())
}

/// Decode a base64 string that must be exactly 32 bytes.
pub fn unb64_key(s: &str) -> Result<[u8; 32], String> {
    let bytes = unb64(s)?;
    bytes.try_into().map_err(|_| "expected 32-byte key".to_string())
}
