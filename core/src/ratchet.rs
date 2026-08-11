//! The Double Ratchet (Signal-style), driving per-message forward secrecy and
//! break-in recovery.
//!
//! Two interlocking ratchets:
//! * a **symmetric** chain-key ratchet that advances on every message and gives
//!   forward secrecy (old message keys are deleted and cannot be rederived);
//! * a **Diffie-Hellman** ratchet that advances on each round-trip and gives
//!   future secrecy (an attacker who steals the current state loses access once
//!   the peers exchange fresh ratchet keys).
//!
//! Out-of-order and dropped messages are handled by caching skipped message
//! keys, bounded by [`MAX_SKIP`] per chain to prevent a memory-exhaustion DoS.

use std::collections::BTreeMap;

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::kdf::{aead_open, aead_seal, kdf_ck, kdf_rk};
use crate::wire::RatchetHeader;

/// Maximum number of message keys we will skip (and cache) within a single
/// receiving chain before declaring the gap hostile.
pub const MAX_SKIP: u32 = 1000;

/// Total cap on cached skipped keys across all chains.
const MAX_SKIPPED_CACHE: usize = 4000;

/// A live Double Ratchet session state.
pub struct DoubleRatchet {
    root_key: [u8; 32],
    dh_self: StaticSecret,
    dh_self_pub: [u8; 32],
    dh_remote: Option<[u8; 32]>,
    chain_send: Option<[u8; 32]>,
    chain_recv: Option<[u8; 32]>,
    n_send: u32,
    n_recv: u32,
    pn: u32,
    skipped: BTreeMap<([u8; 32], u32), [u8; 32]>,
}

impl DoubleRatchet {
    /// Initialize the ratchet for the session **initiator** (Alice).
    ///
    /// `root` is the shared secret from the handshake; `remote_dh_pub` is the
    /// responder's signed prekey, which doubles as their first ratchet key.
    pub fn init_initiator(root: [u8; 32], remote_dh_pub: [u8; 32]) -> Self {
        let dh_self = StaticSecret::random_from_rng(rand_core::OsRng);
        let dh_self_pub = PublicKey::from(&dh_self).to_bytes();
        let (root_key, chain_send) = kdf_rk(&root, &dh(&dh_self, &remote_dh_pub));
        DoubleRatchet {
            root_key,
            dh_self,
            dh_self_pub,
            dh_remote: Some(remote_dh_pub),
            chain_send: Some(chain_send),
            chain_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: BTreeMap::new(),
        }
    }

    /// Initialize the ratchet for the session **responder** (Bob).
    ///
    /// `dh_self` is the responder's signed prekey keypair (the same key the
    /// initiator used as `remote_dh_pub`).
    pub fn init_responder(root: [u8; 32], dh_self: StaticSecret) -> Self {
        let dh_self_pub = PublicKey::from(&dh_self).to_bytes();
        DoubleRatchet {
            root_key: root,
            dh_self,
            dh_self_pub,
            dh_remote: None,
            chain_send: None,
            chain_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: BTreeMap::new(),
        }
    }

    /// Encrypt `plaintext`, binding `ad_prefix` (the session-level associated
    /// data) plus the ratchet header into the AEAD.
    pub fn encrypt(&mut self, plaintext: &[u8], ad_prefix: &[u8]) -> Result<(RatchetHeader, Vec<u8>)> {
        let ck = self.chain_send.ok_or(Error::UnexpectedMessage)?;
        let (next_ck, mut mk) = kdf_ck(&ck);
        let header = RatchetHeader {
            dh_pub: self.dh_self_pub,
            pn: self.pn,
            n: self.n_send,
        };
        self.chain_send = Some(next_ck);
        self.n_send += 1;

        let ad = associated_data(ad_prefix, &header);
        let ciphertext = aead_seal(&mk, plaintext, &ad);
        mk.zeroize();
        Ok((header, ciphertext))
    }

    /// Decrypt a message given its ratchet `header` and the session `ad_prefix`.
    pub fn decrypt(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
        ad_prefix: &[u8],
    ) -> Result<Vec<u8>> {
        let ad = associated_data(ad_prefix, header);

        // 1. A message from a chain we've already ratcheted past — use a cached key.
        if let Some(mut mk) = self.skipped.remove(&(header.dh_pub, header.n)) {
            let pt = aead_open(&mk, ciphertext, &ad);
            mk.zeroize();
            return pt;
        }

        // 2. New remote ratchet key → perform a DH ratchet step.
        if self.dh_remote != Some(header.dh_pub) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header.dh_pub);
        }

        // 3. Skip forward within the current receiving chain if needed.
        self.skip_message_keys(header.n)?;

        let ck = self.chain_recv.ok_or(Error::Decrypt)?;
        let (next_ck, mut mk) = kdf_ck(&ck);
        self.chain_recv = Some(next_ck);
        self.n_recv += 1;

        let pt = aead_open(&mk, ciphertext, &ad);
        mk.zeroize();
        pt
    }

    /// Advance the receiving chain, caching skipped message keys up to `until`.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if self.chain_recv.is_none() {
            // No receiving chain yet (nothing to skip). If a gap is implied we
            // simply cannot recover those keys; that's handled by the DH ratchet.
            return Ok(());
        }
        if until < self.n_recv {
            return Ok(());
        }
        if until - self.n_recv > MAX_SKIP {
            return Err(Error::Decrypt);
        }
        let remote = self.dh_remote.ok_or(Error::Decrypt)?;
        let mut ck = self.chain_recv.expect("checked is_some above");
        while self.n_recv < until {
            let (next_ck, mk) = kdf_ck(&ck);
            if self.skipped.len() >= MAX_SKIPPED_CACHE {
                return Err(Error::Decrypt);
            }
            self.skipped.insert((remote, self.n_recv), mk);
            ck.zeroize();
            ck = next_ck;
            self.n_recv += 1;
        }
        self.chain_recv = Some(ck);
        Ok(())
    }

    /// Perform a Diffie-Hellman ratchet step against a new remote public key.
    fn dh_ratchet(&mut self, remote_pub: [u8; 32]) {
        self.pn = self.n_send;
        self.n_send = 0;
        self.n_recv = 0;
        self.dh_remote = Some(remote_pub);

        let (root_key, chain_recv) = kdf_rk(&self.root_key, &dh(&self.dh_self, &remote_pub));
        self.root_key = root_key;
        self.chain_recv = Some(chain_recv);

        let new_self = StaticSecret::random_from_rng(rand_core::OsRng);
        self.dh_self_pub = PublicKey::from(&new_self).to_bytes();
        self.dh_self = new_self;

        let (root_key, chain_send) = kdf_rk(&self.root_key, &dh(&self.dh_self, &remote_pub));
        self.root_key = root_key;
        self.chain_send = Some(chain_send);
    }
}

/// X25519 Diffie-Hellman, returning the raw 32-byte shared output.
fn dh(secret: &StaticSecret, their_pub: &[u8; 32]) -> [u8; 32] {
    let their = PublicKey::from(*their_pub);
    secret.diffie_hellman(&their).to_bytes()
}

/// Associated data bound into every message: the session prefix followed by a
/// canonical encoding of the ratchet header.
fn associated_data(prefix: &[u8], header: &RatchetHeader) -> Vec<u8> {
    let header_bytes = bincode::serialize(header).expect("header is always serializable");
    let mut ad = Vec::with_capacity(prefix.len() + header_bytes.len());
    ad.extend_from_slice(prefix);
    ad.extend_from_slice(&header_bytes);
    ad
}
