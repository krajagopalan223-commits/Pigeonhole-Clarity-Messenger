//! The on-air mesh frame.

use serde::{Deserialize, Serialize};

use crate::MeshError;

/// A single mesh frame as it travels device-to-device over the radio.
///
/// The `payload` is an opaque, already-end-to-end-encrypted
/// [`clarity_core::wire::Message`] (typically wrapped in the app's
/// `{sender,payload}` envelope). Carriers relay it without being able to read
/// it. The `recipient` field is visible to carriers — that is metadata; see the
/// privacy note in the crate docs and `MESH.md`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshFrame {
    /// Random per-message identifier, used for flood dedup.
    pub msg_id: [u8; 16],
    /// Routing target: the recipient's 32-byte identity (or a rotating inbox ID).
    pub recipient: [u8; 32],
    /// Remaining hop budget. Decremented each forward; a frame at 0 is not relayed.
    pub ttl: u8,
    /// Opaque, end-to-end-encrypted payload. Carriers cannot read it.
    pub payload: Vec<u8>,
}

impl MeshFrame {
    /// Serialize for transmission over the radio link.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("mesh frame is always serializable")
    }

    /// Parse a frame received from the radio link.
    pub fn decode(bytes: &[u8]) -> Result<MeshFrame, MeshError> {
        bincode::deserialize(bytes).map_err(|e| MeshError::Decode(e.to_string()))
    }
}
