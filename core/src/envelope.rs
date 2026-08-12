//! Sealed-sender envelopes (metadata protection, half 2 of 2).
//!
//! Previously the app wrapped every payload in a *plaintext* `{sender,
//! payload}` envelope so the recipient could pick the right session — which
//! meant the relay (and any mesh courier) could read the sender's identity off
//! every message, and the first message of a session additionally exposed the
//! initiator's identity keys inside the clear handshake header. A sealed
//! envelope hides all of it: the transport now carries only an opaque blob.
//!
//! ## Construction
//!
//! ```text
//! eph               = fresh X25519 keypair, one per envelope
//! shared            = DH(eph_secret, recipient_identity_dh)
//! seal_key          = HKDF-SHA256(salt = "Clarity-sealed-salt-v1", ikm = shared,
//!                                 info = "Clarity-sealed-v1" ‖ eph_pub ‖ recipient_dh)
//! blob              = 0x02 ‖ eph_pub(32) ‖ AEAD(seal_key, plaintext, aad = eph_pub)
//! plaintext         = sender_identity_ed(32) ‖ sender_identity_dh(32)
//!                     ‖ payload_len_le32 ‖ payload ‖ zero padding
//! ```
//!
//! ## Size padding
//!
//! The payload is padded to a **size bucket** before sealing (spec §8.2), so
//! ciphertext length reveals only the bucket, not the message length: two
//! messages in the same bucket produce byte-for-byte equal-length blobs.
//! Buckets: 512 bytes minimum, then powers of two up to 8 KiB, then multiples
//! of 8 KiB. Geometric buckets cap the overhead at 2× while keeping the
//! number of distinguishable sizes logarithmic; message *counts and timing*
//! are still visible — that is cover traffic's job, which remains future work
//! with a real battery cost to measure first.
//!
//! AEAD is the crate-standard XChaCha20-Poly1305 with the (key, nonce) pair
//! HKDF-derived from `seal_key` ([`crate::kdf`]); the key is unique per
//! envelope because the ephemeral is, so nonce handling cannot be misused.
//!
//! The sender's identity *DH* key rides along inside so the recipient of a
//! sealed first message can seal replies back without a directory lookup.
//!
//! ## Properties — claimed and disclaimed
//!
//! * **Hides the sender from the transport.** The relay/courier sees a fresh
//!   ephemeral key and ciphertext; envelopes are pairwise unlinkable.
//! * **The outer layer authenticates nobody, on purpose.** Anyone can seal an
//!   envelope claiming any sender; authenticity comes from the *inner*
//!   Double-Ratchet/handshake payload exactly as before (a forged claim just
//!   fails to decrypt and is dropped). This mirrors Signal's sealed sender.
//! * **No forward secrecy at this layer.** A recipient's long-term identity DH
//!   key, if compromised, lets recorded envelopes be opened to reveal *sender
//!   identity metadata* (the inner ratchet ciphertext keeps its own forward
//!   secrecy for content). Same trade as Signal's design.
//! * The recipient must try their key on every incoming blob; there is no
//!   routable recipient hint inside — that is what rotating inbox IDs
//!   ([`crate::inbox`]) are for.

use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::identity::Account;
use crate::kdf::{aead_open, aead_seal};

/// Version byte prefixed to every sealed envelope. v2 added size padding.
pub const SEALED_ENVELOPE_VERSION: u8 = 2;

/// Fixed overhead: version(1) + ephemeral public(32) + Poly1305 tag(16).
const HEADER_LEN: usize = 1 + 32;
const INNER_PREFIX_LEN: usize = 64;
/// Length prefix in front of the padded payload.
const LEN_PREFIX: usize = 4;
/// Smallest padded payload size.
const MIN_BUCKET: usize = 512;
/// Above this, buckets grow linearly instead of doubling.
const MAX_POW2_BUCKET: usize = 8 * 1024;

/// The padded size for a payload of `len` bytes (length prefix included):
/// 512 minimum, then the next power of two up to 8 KiB, then the next
/// multiple of 8 KiB.
fn bucket(len: usize) -> usize {
    let needed = len + LEN_PREFIX;
    if needed <= MIN_BUCKET {
        return MIN_BUCKET;
    }
    if needed <= MAX_POW2_BUCKET {
        return needed.next_power_of_two();
    }
    needed.div_ceil(MAX_POW2_BUCKET) * MAX_POW2_BUCKET
}

/// A successfully opened sealed envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedEnvelope {
    /// Sender's claimed Ed25519 identity key (authenticate via the payload!).
    pub sender_identity_ed: [u8; 32],
    /// Sender's claimed X25519 identity DH key, for sealing replies.
    pub sender_identity_dh: [u8; 32],
    /// The inner payload (an encoded wire [`crate::Message`], to this design).
    pub payload: Vec<u8>,
}

/// Seal `payload` to a recipient's X25519 identity DH key, embedding the
/// sender's identity keys inside the encryption.
pub fn seal_envelope(
    sender: &Account,
    recipient_identity_dh: &[u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret).to_bytes();

    let recipient_pub = PublicKey::from(*recipient_identity_dh);
    let mut shared = eph_secret.diffie_hellman(&recipient_pub).to_bytes();
    let mut seal_key = derive_seal_key(&shared, &eph_pub, recipient_identity_dh);
    shared.zeroize();

    let padded = bucket(payload.len());
    let mut inner = Vec::with_capacity(INNER_PREFIX_LEN + padded);
    inner.extend_from_slice(&sender.identity_public());
    inner.extend_from_slice(&sender.identity_dh_public());
    inner.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    inner.extend_from_slice(payload);
    inner.resize(INNER_PREFIX_LEN + padded, 0);

    let ciphertext = aead_seal(&seal_key, &inner, &eph_pub);
    seal_key.zeroize();
    inner.zeroize();

    let mut blob = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    blob.push(SEALED_ENVELOPE_VERSION);
    blob.extend_from_slice(&eph_pub);
    blob.extend_from_slice(&ciphertext);
    blob
}

/// Open a sealed envelope with the recipient's identity DH secret.
///
/// Fails opaquely ([`Error::Decrypt`]) for anything that is not a valid
/// envelope sealed to this account — malformed, tampered, or someone else's.
pub fn open_envelope(recipient: &Account, blob: &[u8]) -> Result<OpenedEnvelope> {
    if blob.len() <= HEADER_LEN || blob[0] != SEALED_ENVELOPE_VERSION {
        return Err(Error::Decrypt);
    }
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&blob[1..HEADER_LEN]);
    let ciphertext = &blob[HEADER_LEN..];

    let recipient_dh_pub = recipient.identity_dh_public();
    let mut shared = recipient
        .dh_identity()
        .diffie_hellman(&PublicKey::from(eph_pub))
        .to_bytes();
    let mut seal_key = derive_seal_key(&shared, &eph_pub, &recipient_dh_pub);
    shared.zeroize();

    let opened = aead_open(&seal_key, ciphertext, &eph_pub);
    seal_key.zeroize();
    let mut inner = opened?;

    if inner.len() < INNER_PREFIX_LEN + LEN_PREFIX {
        inner.zeroize();
        return Err(Error::Decrypt);
    }
    let mut sender_ed = [0u8; 32];
    let mut sender_dh = [0u8; 32];
    sender_ed.copy_from_slice(&inner[..32]);
    sender_dh.copy_from_slice(&inner[32..64]);
    let payload_len = u32::from_le_bytes(
        inner[INNER_PREFIX_LEN..INNER_PREFIX_LEN + LEN_PREFIX]
            .try_into()
            .expect("slice is 4 bytes"),
    ) as usize;
    let start = INNER_PREFIX_LEN + LEN_PREFIX;
    if payload_len > inner.len() - start {
        inner.zeroize();
        return Err(Error::Decrypt);
    }
    let payload = inner[start..start + payload_len].to_vec();
    inner.zeroize();

    Ok(OpenedEnvelope {
        sender_identity_ed: sender_ed,
        sender_identity_dh: sender_dh,
        payload,
    })
}

fn derive_seal_key(shared: &[u8; 32], eph_pub: &[u8; 32], recipient_dh: &[u8; 32]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"Clarity-sealed-salt-v1"), shared);
    let mut info = Vec::with_capacity(17 + 64);
    info.extend_from_slice(b"Clarity-sealed-v1");
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(recipient_dh);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 is a valid HKDF-SHA256 length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_reveals_sender_only_to_recipient() {
        let alice = Account::generate();
        let bob = Account::generate();

        let blob = seal_envelope(&alice, &bob.identity_dh_public(), b"hello bob");

        // Nothing sender-linked is visible in the blob.
        let alice_ed = alice.identity_public();
        let alice_dh = alice.identity_dh_public();
        assert!(!blob
            .windows(32)
            .any(|w| w == alice_ed.as_slice() || w == alice_dh.as_slice()));

        let opened = open_envelope(&bob, &blob).expect("bob opens");
        assert_eq!(opened.sender_identity_ed, alice_ed);
        assert_eq!(opened.sender_identity_dh, alice_dh);
        assert_eq!(opened.payload, b"hello bob");
    }

    #[test]
    fn wrong_recipient_and_tampering_fail_opaquely() {
        let alice = Account::generate();
        let bob = Account::generate();
        let eve = Account::generate();

        let blob = seal_envelope(&alice, &bob.identity_dh_public(), b"secret");

        assert!(matches!(open_envelope(&eve, &blob), Err(Error::Decrypt)));

        let mut flipped = blob.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(matches!(open_envelope(&bob, &flipped), Err(Error::Decrypt)));

        let mut bad_version = blob.clone();
        bad_version[0] = 0xFF;
        assert!(matches!(open_envelope(&bob, &bad_version), Err(Error::Decrypt)));

        assert!(matches!(open_envelope(&bob, b"short"), Err(Error::Decrypt)));
    }

    #[test]
    fn envelopes_are_pairwise_unlinkable() {
        let alice = Account::generate();
        let bob = Account::generate();
        let a = seal_envelope(&alice, &bob.identity_dh_public(), b"same payload");
        let b = seal_envelope(&alice, &bob.identity_dh_public(), b"same payload");
        // Fresh ephemeral per envelope: nothing in common but the version byte.
        assert_ne!(a[1..33], b[1..33]);
        assert_ne!(a[33..], b[33..]);
    }

    #[test]
    fn empty_payload_round_trips() {
        let alice = Account::generate();
        let bob = Account::generate();
        let blob = seal_envelope(&alice, &bob.identity_dh_public(), b"");
        assert_eq!(open_envelope(&bob, &blob).unwrap().payload, Vec::<u8>::new());
    }

    #[test]
    fn blob_length_reveals_only_the_bucket() {
        let alice = Account::generate();
        let bob = Account::generate();
        let dh = bob.identity_dh_public();
        let blob_len = |n: usize| seal_envelope(&alice, &dh, &vec![0xAA; n]).len();

        // Everything in the first bucket is byte-for-byte the same length.
        let min = blob_len(0);
        assert_eq!(blob_len(1), min);
        assert_eq!(blob_len(200), min);
        assert_eq!(blob_len(508), min); // 508 + 4-byte length prefix = 512
        // Fixed framing: version + eph(32) + inner prefix(64) + bucket + tag(16).
        assert_eq!(min, 1 + 32 + 64 + 512 + 16);

        // One byte over the boundary jumps to the next power of two...
        assert_eq!(blob_len(509), 1 + 32 + 64 + 1024 + 16);
        assert_eq!(blob_len(1020), blob_len(509));
        // ...and past 8 KiB buckets grow linearly.
        assert_eq!(blob_len(100_000), 1 + 32 + 64 + 106_496 + 16);
    }

    #[test]
    fn padded_payloads_round_trip_at_boundaries() {
        let alice = Account::generate();
        let bob = Account::generate();
        let dh = bob.identity_dh_public();
        for n in [0usize, 1, 508, 509, 8188, 8189, 100_000] {
            let payload = vec![0x5A; n];
            let blob = seal_envelope(&alice, &dh, &payload);
            assert_eq!(open_envelope(&bob, &blob).unwrap().payload, payload, "n={n}");
        }
    }
}
