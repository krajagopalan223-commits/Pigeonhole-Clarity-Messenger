//! High-level session API: what application code actually calls.
//!
//! A [`Session`] is one end of an encrypted conversation with a single contact.
//! Create one with [`Session::initiate`] (you're reaching out) or
//! [`Session::respond`] (you received a first message), then use
//! [`Session::encrypt`] / [`Session::decrypt`] for every message after.

use x25519_dalek::StaticSecret;

use crate::error::{Error, Result};
use crate::handshake;
use crate::identity::{verify_bundle, Account};
use crate::ratchet::DoubleRatchet;
use crate::wire::{Message, PreKeyBundle};

/// One end of an end-to-end encrypted conversation.
pub struct Session {
    ratchet: DoubleRatchet,
    /// Associated data mixed into every message: `initiator_ed || responder_ed`.
    /// Binds the ciphertext to both identities, so a message can't be replayed
    /// into a different conversation.
    ad_prefix: Vec<u8>,
    /// Present on the initiator until the first reply arrives; carried on each
    /// outgoing message as a PreKey header so the responder can (re)establish
    /// the session even if an earlier copy was lost.
    pending_handshake: Option<crate::wire::HandshakeHeader>,
}

impl Session {
    /// Begin a session with a contact, given their verified prekey bundle.
    ///
    /// Verifies every signature in the bundle first; a tampered bundle (e.g. a
    /// malicious prekey server swapping keys) is rejected here.
    pub fn initiate(me: &Account, their_bundle: &PreKeyBundle) -> Result<Session> {
        verify_bundle(their_bundle)?;
        let (root, handshake_header, remote_spk) = handshake::initiate(me, their_bundle)?;
        let ad_prefix = ad_prefix(&handshake_header.identity_ed, &their_bundle.identity_ed);
        let ratchet = DoubleRatchet::init_initiator(root, remote_spk);
        Ok(Session {
            ratchet,
            ad_prefix,
            pending_handshake: Some(handshake_header),
        })
    }

    /// Accept an inbound first message, establishing the session and returning
    /// the decrypted plaintext of that first message.
    pub fn respond(me: &mut Account, first_message: &Message) -> Result<(Session, Vec<u8>)> {
        let (handshake_header, header, ciphertext) = match first_message {
            Message::PreKey {
                handshake,
                header,
                ciphertext,
            } => (handshake, header, ciphertext),
            Message::Normal { .. } => return Err(Error::UnexpectedMessage),
        };

        let root = handshake::respond(me, handshake_header)?;
        let ad_prefix = ad_prefix(&handshake_header.identity_ed, &me.identity_ed_bytes());

        // The responder's signed prekey doubles as its first ratchet key.
        let spk = StaticSecret::from(me.signed_prekey(handshake_header.signed_prekey_id)?.to_bytes());
        let mut ratchet = DoubleRatchet::init_responder(root, spk);

        let plaintext = ratchet.decrypt(header, ciphertext, &ad_prefix)?;
        let session = Session {
            ratchet,
            ad_prefix,
            pending_handshake: None,
        };
        Ok((session, plaintext))
    }

    /// Encrypt an outgoing message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Message> {
        let (header, ciphertext) = self.ratchet.encrypt(plaintext, &self.ad_prefix)?;
        Ok(match &self.pending_handshake {
            Some(hs) => Message::PreKey {
                handshake: hs.clone(),
                header,
                ciphertext,
            },
            None => Message::Normal { header, ciphertext },
        })
    }

    /// Decrypt an incoming message.
    pub fn decrypt(&mut self, message: &Message) -> Result<Vec<u8>> {
        let (header, ciphertext) = match message {
            Message::PreKey {
                header, ciphertext, ..
            } => (header, ciphertext),
            Message::Normal { header, ciphertext } => (header, ciphertext),
        };
        let plaintext = self.ratchet.decrypt(header, ciphertext, &self.ad_prefix)?;
        // Once we've heard back, the peer clearly has a working session; stop
        // attaching the (larger) handshake header to our outgoing messages.
        self.pending_handshake = None;
        Ok(plaintext)
    }
}

/// Associated-data prefix: the two identities in a fixed (initiator, responder)
/// order so both ends compute the same bytes.
fn ad_prefix(initiator_ed: &[u8; 32], responder_ed: &[u8; 32]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(initiator_ed);
    ad.extend_from_slice(responder_ed);
    ad
}
