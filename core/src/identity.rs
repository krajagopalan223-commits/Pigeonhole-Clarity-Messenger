//! Long-term identity and prekey management.
//!
//! An [`Account`] holds everything secret about a user: their Ed25519 identity
//! signing key, their X25519 identity DH key, a signed prekey, an ML-KEM prekey,
//! and a pool of one-time prekeys. From it we can publish a signed
//! [`PreKeyBundle`] (all public) and answer inbound handshakes.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};
use crate::pqkem::KyberKeyPair;
use crate::wire::{OneTimePrekeyPublics, PreKeyBundle};

// Domain-separation tags so a signature over one field can never be replayed as
// a signature over another.
const SIG_CTX_IDENTITY_DH: &[u8] = b"Clarity-sig-identity-dh-v1";
const SIG_CTX_SIGNED_PREKEY: &[u8] = b"Clarity-sig-signed-prekey-v1";
const SIG_CTX_KYBER_PREKEY: &[u8] = b"Clarity-sig-kyber-prekey-v1";

/// Number of one-time prekeys minted for a fresh account.
pub const DEFAULT_ONE_TIME_PREKEYS: u32 = 100;

/// A user's secret key material.
pub struct Account {
    ed_signing: SigningKey,
    dh_identity: StaticSecret,
    signed_prekey_id: u32,
    signed_prekey: StaticSecret,
    kyber_prekey_id: u32,
    kyber: KyberKeyPair,
    one_time_prekeys: BTreeMap<u32, StaticSecret>,
    next_opk_id: u32,
}

impl Account {
    /// Create a brand-new account with a full batch of one-time prekeys.
    pub fn generate() -> Self {
        Self::generate_with_prekeys(DEFAULT_ONE_TIME_PREKEYS)
    }

    /// Create a new account, minting `count` one-time prekeys.
    pub fn generate_with_prekeys(count: u32) -> Self {
        let ed_signing = SigningKey::generate(&mut OsRng);
        let dh_identity = StaticSecret::random_from_rng(OsRng);
        let signed_prekey = StaticSecret::random_from_rng(OsRng);
        let kyber = KyberKeyPair::generate();

        let mut one_time_prekeys = BTreeMap::new();
        for id in 0..count {
            one_time_prekeys.insert(id, StaticSecret::random_from_rng(OsRng));
        }

        Account {
            ed_signing,
            dh_identity,
            signed_prekey_id: 0,
            signed_prekey,
            kyber_prekey_id: 0,
            kyber,
            one_time_prekeys,
            next_opk_id: count,
        }
    }

    /// The stable public identity: the Ed25519 verifying key. This is what a
    /// contact verifies out-of-band (the "safety number" is derived from it).
    pub fn identity_public(&self) -> [u8; 32] {
        self.ed_signing.verifying_key().to_bytes()
    }

    /// The X25519 identity DH public key — what sealed-sender envelopes
    /// ([`crate::envelope`]) are encrypted to. Published in the prekey bundle.
    pub fn identity_dh_public(&self) -> [u8; 32] {
        PublicKey::from(&self.dh_identity).to_bytes()
    }

    /// Publish a signed prekey bundle. Includes the lowest-id one-time prekey
    /// still available (the relay is responsible for handing out a distinct one
    /// per fetch in a real deployment).
    pub fn bundle(&self) -> PreKeyBundle {
        let identity_dh_pub = PublicKey::from(&self.dh_identity).to_bytes();
        let signed_prekey_pub = PublicKey::from(&self.signed_prekey).to_bytes();
        let kyber_pub = self.kyber.public_bytes();

        let (one_time_prekey, one_time_prekey_id) = match self.one_time_prekeys.iter().next() {
            Some((&id, sk)) => (Some(PublicKey::from(sk).to_bytes()), Some(id)),
            None => (None, None),
        };

        PreKeyBundle {
            identity_ed: self.identity_public(),
            identity_dh: identity_dh_pub,
            identity_dh_sig: self.sign(SIG_CTX_IDENTITY_DH, &identity_dh_pub),
            signed_prekey: signed_prekey_pub,
            signed_prekey_id: self.signed_prekey_id,
            signed_prekey_sig: self.sign(SIG_CTX_SIGNED_PREKEY, &signed_prekey_pub),
            kyber_prekey: kyber_pub.clone(),
            kyber_prekey_id: self.kyber_prekey_id,
            kyber_prekey_sig: self.sign(SIG_CTX_KYBER_PREKEY, &kyber_pub),
            one_time_prekey,
            one_time_prekey_id,
        }
    }

    fn sign(&self, context: &[u8], message: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(context.len() + message.len());
        buf.extend_from_slice(context);
        buf.extend_from_slice(message);
        self.ed_signing.sign(&buf).to_bytes().to_vec()
    }

    // --- Accessors used by the handshake / session layer -------------------

    pub(crate) fn dh_identity(&self) -> &StaticSecret {
        &self.dh_identity
    }

    pub(crate) fn identity_ed_bytes(&self) -> [u8; 32] {
        self.identity_public()
    }

    pub(crate) fn kyber(&self) -> &KyberKeyPair {
        &self.kyber
    }

    pub(crate) fn kyber_prekey_id(&self) -> u32 {
        self.kyber_prekey_id
    }

    /// Look up a signed-prekey private key by id.
    pub(crate) fn signed_prekey(&self, id: u32) -> Result<&StaticSecret> {
        if id == self.signed_prekey_id {
            Ok(&self.signed_prekey)
        } else {
            Err(Error::UnknownPrekey)
        }
    }

    /// Consume a one-time prekey by id, removing it from the pool. A one-time
    /// prekey is, by definition, usable exactly once.
    pub(crate) fn take_one_time_prekey(&mut self, id: u32) -> Result<StaticSecret> {
        self.one_time_prekeys
            .remove(&id)
            .ok_or(Error::UnknownPrekey)
    }

    /// Number of one-time prekeys still available (for replenishment logic).
    pub fn one_time_prekeys_remaining(&self) -> usize {
        self.one_time_prekeys.len()
    }

    /// Public halves of all one-time prekeys, for batch upload to a prekey
    /// server. The server hands these out one per fetch; the private halves stay
    /// on this device until the matching handshake consumes them.
    pub fn one_time_prekey_publics(&self) -> OneTimePrekeyPublics {
        self.one_time_prekeys
            .iter()
            .map(|(&id, sk)| (id, PublicKey::from(sk).to_bytes()))
            .collect()
    }

    /// Mint `count` additional one-time prekeys, returning the new ids.
    pub fn replenish_one_time_prekeys(&mut self, count: u32) -> Vec<u32> {
        let mut ids = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let id = self.next_opk_id;
            self.next_opk_id += 1;
            self.one_time_prekeys
                .insert(id, StaticSecret::random_from_rng(OsRng));
            ids.push(id);
        }
        ids
    }

    // --- Persistence -------------------------------------------------------

    /// Serialize the full secret account state (for encrypted-at-rest storage).
    ///
    /// The caller MUST store the result under OS-backed protection
    /// (Keychain / Keystore / libsecret) — this is raw secret key material.
    pub fn to_bytes(&self) -> Vec<u8> {
        let stored = StoredAccount {
            ed_signing: self.ed_signing.to_bytes(),
            dh_identity: self.dh_identity.to_bytes(),
            signed_prekey_id: self.signed_prekey_id,
            signed_prekey: self.signed_prekey.to_bytes(),
            kyber_prekey_id: self.kyber_prekey_id,
            kyber_private: self.kyber.private_bytes(),
            one_time_prekeys: self
                .one_time_prekeys
                .iter()
                .map(|(&id, sk)| (id, sk.to_bytes()))
                .collect(),
            next_opk_id: self.next_opk_id,
        };
        bincode::serialize(&stored).expect("account is always serializable")
    }

    /// Restore an account previously produced by [`Account::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let stored: StoredAccount =
            bincode::deserialize(bytes).map_err(|e| Error::Wire(e.to_string()))?;
        let kyber = KyberKeyPair::from_private_bytes(&stored.kyber_private)?;
        Ok(Account {
            ed_signing: SigningKey::from_bytes(&stored.ed_signing),
            dh_identity: StaticSecret::from(stored.dh_identity),
            signed_prekey_id: stored.signed_prekey_id,
            signed_prekey: StaticSecret::from(stored.signed_prekey),
            kyber_prekey_id: stored.kyber_prekey_id,
            kyber,
            one_time_prekeys: stored
                .one_time_prekeys
                .into_iter()
                .map(|(id, sk)| (id, StaticSecret::from(sk)))
                .collect(),
            next_opk_id: stored.next_opk_id,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct StoredAccount {
    ed_signing: [u8; 32],
    dh_identity: [u8; 32],
    signed_prekey_id: u32,
    signed_prekey: [u8; 32],
    kyber_prekey_id: u32,
    kyber_private: Vec<u8>,
    one_time_prekeys: Vec<(u32, [u8; 32])>,
    next_opk_id: u32,
}

/// Verify every signature in a fetched [`PreKeyBundle`].
///
/// This is the linchpin of the "untrusted prekey server" property: the client
/// checks that all prekeys are signed by the identity key it expects, so a
/// malicious server cannot substitute its own keys to MITM the session.
pub fn verify_bundle(bundle: &PreKeyBundle) -> Result<()> {
    let vk = VerifyingKey::from_bytes(&bundle.identity_ed).map_err(|_| Error::MalformedKey)?;

    verify_sig(&vk, SIG_CTX_IDENTITY_DH, &bundle.identity_dh, &bundle.identity_dh_sig)?;
    verify_sig(
        &vk,
        SIG_CTX_SIGNED_PREKEY,
        &bundle.signed_prekey,
        &bundle.signed_prekey_sig,
    )?;
    verify_sig(
        &vk,
        SIG_CTX_KYBER_PREKEY,
        &bundle.kyber_prekey,
        &bundle.kyber_prekey_sig,
    )?;
    Ok(())
}

fn verify_sig(vk: &VerifyingKey, context: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let sig = Signature::from_slice(sig_bytes).map_err(|_| Error::BadSignature)?;
    let mut buf = Vec::with_capacity(context.len() + message.len());
    buf.extend_from_slice(context);
    buf.extend_from_slice(message);
    vk.verify(&buf, &sig).map_err(|_| Error::BadSignature)
}
