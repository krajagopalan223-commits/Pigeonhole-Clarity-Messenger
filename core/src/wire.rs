//! On-the-wire data types and their binary encoding.
//!
//! Wire types hold *plain bytes only* — never live key objects. That keeps the
//! serialization trivial and side-effect free, and means the relay (which
//! handles these blobs) can never be handed anything secret by construction.
//!
//! Encoding is `bincode` (compact, deterministic, length-prefixed). For a v1
//! this is fine and fully specified; a production build would likely move to a
//! versioned protobuf/flatbuffer, but the shape below is the contract.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Current wire protocol version. Bumped on any breaking change to these types.
pub const PROTOCOL_VERSION: u8 = 1;

/// A batch of one-time prekey public keys, as `(id, x25519_public)` pairs.
pub type OneTimePrekeyPublics = Vec<(u32, [u8; 32])>;

/// A published prekey bundle. Everything here is public and signed by the
/// owner's long-term identity key so a malicious prekey server cannot swap in
/// its own keys to mount a MITM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreKeyBundle {
    /// Ed25519 identity verifying key (the stable, human-verifiable identity).
    pub identity_ed: [u8; 32],
    /// X25519 long-term identity DH key.
    pub identity_dh: [u8; 32],
    /// Signature by `identity_ed` over `identity_dh`.
    pub identity_dh_sig: Vec<u8>,
    /// Medium-term signed prekey (X25519), rotated periodically.
    pub signed_prekey: [u8; 32],
    /// Identifier for the signed prekey.
    pub signed_prekey_id: u32,
    /// Signature by `identity_ed` over `signed_prekey`.
    pub signed_prekey_sig: Vec<u8>,
    /// ML-KEM-1024 encapsulation key for the post-quantum handshake leg.
    pub kyber_prekey: Vec<u8>,
    /// Identifier for the Kyber prekey.
    pub kyber_prekey_id: u32,
    /// Signature by `identity_ed` over `kyber_prekey`.
    pub kyber_prekey_sig: Vec<u8>,
    /// Optional one-time prekey (X25519). Consumed on use; improves forward
    /// secrecy for the very first message before the ratchet gets going.
    pub one_time_prekey: Option<[u8; 32]>,
    /// Identifier for the one-time prekey, if present.
    pub one_time_prekey_id: Option<u32>,
}

/// Per-message Double Ratchet header (public metadata needed to advance the
/// ratchet on the receiving side).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RatchetHeader {
    /// Sender's current ratchet public key (X25519).
    pub dh_pub: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub pn: u32,
    /// Message number within the current sending chain.
    pub n: u32,
}

/// The extra header carried on the initiator's first message(s), letting the
/// responder reconstruct the shared secret (X3DH + ML-KEM / "PQXDH").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeHeader {
    /// Initiator's Ed25519 identity verifying key.
    pub identity_ed: [u8; 32],
    /// Initiator's X25519 long-term identity DH key.
    pub identity_dh: [u8; 32],
    /// Initiator's ephemeral X25519 key for this handshake.
    pub ephemeral_dh: [u8; 32],
    /// Which of the responder's signed prekeys was used.
    pub signed_prekey_id: u32,
    /// Which one-time prekey was consumed, if any.
    pub one_time_prekey_id: Option<u32>,
    /// Which Kyber prekey was targeted.
    pub kyber_prekey_id: u32,
    /// ML-KEM ciphertext encapsulating the PQ shared secret to the responder.
    pub kyber_ciphertext: Vec<u8>,
}

/// A wire message: either an initial "prekey" message that carries the
/// handshake header, or a normal ratchet message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Message {
    /// First message of a session, includes the handshake header.
    PreKey {
        handshake: HandshakeHeader,
        header: RatchetHeader,
        ciphertext: Vec<u8>,
    },
    /// Subsequent messages once the session is established.
    Normal {
        header: RatchetHeader,
        ciphertext: Vec<u8>,
    },
}

impl Message {
    /// The ratchet header, regardless of variant.
    pub fn header(&self) -> &RatchetHeader {
        match self {
            Message::PreKey { header, .. } => header,
            Message::Normal { header, .. } => header,
        }
    }

    /// Serialize to bytes for transmission.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.push(PROTOCOL_VERSION);
        // bincode of a small struct is infallible in practice; treat any error
        // as a programming bug.
        let body = bincode::serialize(self).expect("Message is always serializable");
        out.extend_from_slice(&body);
        out
    }

    /// Parse bytes produced by [`Message::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Message> {
        let (&version, body) = bytes
            .split_first()
            .ok_or_else(|| Error::Wire("empty message".into()))?;
        if version != PROTOCOL_VERSION {
            return Err(Error::Wire(format!("unsupported version {version}")));
        }
        bincode::deserialize(body).map_err(|e| Error::Wire(e.to_string()))
    }
}

impl PreKeyBundle {
    /// Serialize the bundle for publication to a prekey server.
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("PreKeyBundle is always serializable")
    }

    /// Parse a published bundle.
    pub fn decode(bytes: &[u8]) -> Result<PreKeyBundle> {
        bincode::deserialize(bytes).map_err(|e| Error::Wire(e.to_string()))
    }
}
