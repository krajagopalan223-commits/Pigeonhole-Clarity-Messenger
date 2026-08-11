//! Key-derivation and AEAD helpers.
//!
//! All symmetric key schedule operations live here so the ratchet and handshake
//! code reads as protocol logic, not byte-plumbing.
//!
//! Design notes / deliberate choices:
//!
//! * **AEAD is XChaCha20-Poly1305**, not ChaCha20-Poly1305. The extended
//!   24-byte nonce lets us derive a fresh (key, nonce) pair per message from the
//!   ratchet message key without worrying about a 96-bit counter wrapping. The
//!   spec these docs were derived from claimed ChaCha20-Poly1305 is
//!   "nonce-misuse resistant" — it is not; nonce reuse leaks the Poly1305 key.
//!   We sidestep the whole class of bug: every message key is unique (it comes
//!   from a one-way ratchet), and we HKDF-expand it into a unique nonce too.
//!
//! * **We do not add a second HMAC over the packet.** The AEAD tag already
//!   provides integrity + authenticity. A redundant MAC (as the source spec
//!   proposed) only adds key-management surface and bugs.

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// Fill a fixed-size array from the operating system CSPRNG.
///
/// Panics only if the OS entropy source is unavailable, which on the platforms
/// we target (Linux/iOS/Android) indicates a broken system we cannot safely
/// continue on.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG unavailable");
    buf
}

/// Root-key KDF (the asymmetric / DH ratchet step).
///
/// `HKDF-SHA256(salt = root_key, ikm = dh_output)` → 64 bytes, split into the
/// next root key and a fresh chain key.
pub fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut okm = [0u8; 64];
    hk.expand(b"ClarityRootKDF-v1", &mut okm)
        .expect("64 is a valid HKDF-SHA256 length");
    let mut rk = [0u8; 32];
    let mut ck = [0u8; 32];
    rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (rk, ck)
}

/// Chain-key KDF (the symmetric ratchet step).
///
/// Returns `(next_chain_key, message_key)`:
/// * `message_key = HMAC-SHA256(chain_key, 0x01)`
/// * `next_chain_key = HMAC-SHA256(chain_key, 0x02)`
///
/// The previous chain key must be discarded by the caller after this call;
/// that one-way step is what gives forward secrecy.
pub fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let message_key = hmac_one(chain_key, &[0x01]);
    let next_chain = hmac_one(chain_key, &[0x02]);
    (next_chain, message_key)
}

fn hmac_one(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// Expand a per-message ratchet key into an AEAD (key, nonce) pair.
fn derive_message_material(message_key: &[u8; 32]) -> ([u8; 32], [u8; 24]) {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), message_key);
    let mut okm = [0u8; 56];
    hk.expand(b"ClarityMsgKey-v1", &mut okm)
        .expect("56 is a valid HKDF-SHA256 length");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (key, nonce)
}

/// AEAD-seal `plaintext` under a ratchet message key, binding `associated_data`.
pub fn aead_seal(message_key: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> Vec<u8> {
    let (mut key, nonce) = derive_message_material(message_key);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .expect("XChaCha20-Poly1305 sealing is infallible for valid inputs");
    key.zeroize();
    ct
}

/// AEAD-open a ciphertext produced by [`aead_seal`]. Returns [`Error::Decrypt`]
/// on any failure (bad key, tampered ciphertext, or wrong associated data).
pub fn aead_open(
    message_key: &[u8; 32],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    let (mut key, nonce) = derive_message_material(message_key);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let pt = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::Decrypt);
    key.zeroize();
    pt
}

/// Compress input key material for the initial handshake into the 32-byte root
/// seed the Double Ratchet starts from.
pub fn kdf_root_from_ikm(ikm: &[u8]) -> [u8; 32] {
    // Salt is a fixed context string; the security comes from the IKM, which
    // already contains multiple independent DH secrets plus the ML-KEM secret.
    let hk = Hkdf::<Sha256>::new(Some(b"Clarity-PQXDH-salt-v1"), ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"Clarity-PQXDH-root-v1", &mut okm)
        .expect("32 is a valid HKDF-SHA256 length");
    okm
}
