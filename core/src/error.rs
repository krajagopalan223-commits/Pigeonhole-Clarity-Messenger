//! Error types for the Clarity core.

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong in the cryptographic core.
///
/// Error messages are deliberately coarse: an attacker who can distinguish
/// "bad signature" from "bad MAC" from "unknown prekey" learns more than we
/// want to give away, so the decrypt path collapses most failures into
/// [`Error::Decrypt`].
#[derive(Debug, Error)]
pub enum Error {
    /// A signature over a prekey / bundle field did not verify.
    #[error("signature verification failed")]
    BadSignature,

    /// A public key or ciphertext had the wrong length or was malformed.
    #[error("malformed key or ciphertext")]
    MalformedKey,

    /// AEAD open failed, or a ratchet/handshake step could not be completed.
    /// Intentionally opaque — see the module docs above.
    #[error("decryption failed")]
    Decrypt,

    /// The referenced one-time prekey or signed prekey is not in the store
    /// (already consumed, or never existed).
    #[error("unknown prekey id")]
    UnknownPrekey,

    /// Wire (de)serialization failed.
    #[error("wire encoding error: {0}")]
    Wire(String),

    /// A message arrived that this session cannot process in its current state
    /// (e.g. a normal message before the handshake completed).
    #[error("unexpected message for session state")]
    UnexpectedMessage,
}
