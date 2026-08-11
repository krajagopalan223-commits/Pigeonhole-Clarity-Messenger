//! The initial key agreement: X3DH extended with an ML-KEM leg ("PQXDH").
//!
//! This runs once, when a session is first established, and produces the 32-byte
//! root secret the Double Ratchet starts from. It combines several independent
//! Diffie-Hellman results with a post-quantum KEM secret so that:
//!
//! * an attacker must break *every* DH **and** ML-KEM to recover the root, and
//! * traffic recorded today cannot be decrypted by a future quantum computer
//!   (the ML-KEM leg is quantum-resistant), which is the "harvest now, decrypt
//!   later" defense.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};
use crate::identity::Account;
use crate::kdf::kdf_root_from_ikm;
use crate::pqkem;
use crate::wire::{HandshakeHeader, PreKeyBundle};

/// Initiator side (Alice). Consumes a verified `bundle` and returns the shared
/// root secret, the handshake header to send, and the responder's signed-prekey
/// public key (which seeds the Double Ratchet).
///
/// The caller is responsible for having verified the bundle's signatures first
/// (see [`crate::identity::verify_bundle`]).
pub fn initiate(
    my: &Account,
    bundle: &PreKeyBundle,
) -> Result<([u8; 32], HandshakeHeader, [u8; 32])> {
    let ephemeral = StaticSecret::random_from_rng(rand_core::OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral).to_bytes();

    // The four X3DH Diffie-Hellman terms (DH4 only if a one-time prekey exists).
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&dh(my.dh_identity(), &bundle.signed_prekey)); // DH1
    ikm.extend_from_slice(&dh(&ephemeral, &bundle.identity_dh)); // DH2
    ikm.extend_from_slice(&dh(&ephemeral, &bundle.signed_prekey)); // DH3
    if let Some(opk) = bundle.one_time_prekey {
        ikm.extend_from_slice(&dh(&ephemeral, &opk)); // DH4
    }

    // Post-quantum leg: encapsulate to the responder's Kyber prekey.
    let (kyber_ciphertext, kyber_secret) = pqkem::encapsulate(&bundle.kyber_prekey)?;
    ikm.extend_from_slice(&kyber_secret);

    let root = kdf_root_from_ikm(&ikm);

    let header = HandshakeHeader {
        identity_ed: my.identity_ed_bytes(),
        identity_dh: PublicKey::from(my.dh_identity()).to_bytes(),
        ephemeral_dh: ephemeral_pub,
        signed_prekey_id: bundle.signed_prekey_id,
        one_time_prekey_id: bundle.one_time_prekey_id,
        kyber_prekey_id: bundle.kyber_prekey_id,
        kyber_ciphertext,
    };

    Ok((root, header, bundle.signed_prekey))
}

/// Responder side (Bob). Reconstructs the shared root secret from an inbound
/// handshake header, consuming the referenced one-time prekey.
pub fn respond(my: &mut Account, hs: &HandshakeHeader) -> Result<[u8; 32]> {
    if hs.kyber_prekey_id != my.kyber_prekey_id() {
        return Err(Error::UnknownPrekey);
    }

    // Gather the private keys we need before any mutation.
    let signed_prekey = clone_secret(my.signed_prekey(hs.signed_prekey_id)?);
    let identity_dh = clone_secret(my.dh_identity());

    // Consume the one-time prekey if the initiator used one.
    let one_time = match hs.one_time_prekey_id {
        Some(id) => Some(my.take_one_time_prekey(id)?),
        None => None,
    };

    // Same four DH terms as the initiator, with roles reversed. X25519 DH is
    // symmetric, so each term equals its counterpart on Alice's side.
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&dh(&signed_prekey, &hs.identity_dh)); // DH1
    ikm.extend_from_slice(&dh(&identity_dh, &hs.ephemeral_dh)); // DH2
    ikm.extend_from_slice(&dh(&signed_prekey, &hs.ephemeral_dh)); // DH3
    if let Some(opk) = &one_time {
        ikm.extend_from_slice(&dh(opk, &hs.ephemeral_dh)); // DH4
    }

    // Post-quantum leg: decapsulate to recover the same shared secret.
    let kyber_secret = my.kyber().decapsulate(&hs.kyber_ciphertext)?;
    ikm.extend_from_slice(&kyber_secret);

    Ok(kdf_root_from_ikm(&ikm))
}

/// X25519 Diffie-Hellman returning the raw 32-byte output.
fn dh(secret: &StaticSecret, their_pub: &[u8; 32]) -> [u8; 32] {
    secret.diffie_hellman(&PublicKey::from(*their_pub)).to_bytes()
}

/// Rebuild a `StaticSecret` from its bytes (x25519-dalek's `StaticSecret` is
/// intentionally not `Clone`, so we round-trip through the byte encoding).
fn clone_secret(secret: &StaticSecret) -> StaticSecret {
    StaticSecret::from(secret.to_bytes())
}
