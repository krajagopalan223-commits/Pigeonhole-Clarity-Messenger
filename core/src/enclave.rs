//! Trusted Execution Environment (TEE) boundary.
//!
//! This module expresses the security architecture for running Clarity inside a
//! secure enclave: **all long-term and session secrets live behind a seal, and
//! the untrusted host only ever holds opaque [`Sealed`] blobs and ciphertext.**
//!
//! The [`Enclave`] is *stateless* between calls: you pass sealed state in and
//! get new sealed state out. That is exactly the shape you marshal across an
//! Intel SGX `ECALL`, an ARM TrustZone secure-world call, an Apple Secure
//! Enclave request, or an Android StrongBox operation — the trusted side never
//! keeps plaintext secrets in host-accessible memory between operations.
//!
//! ## What is real here vs. what a device provides
//!
//! This is a **software reference** implementation of the boundary:
//!
//! * The **API shape, the sealing discipline, and the "secrets never cross the
//!   boundary unsealed" invariant are the real, portable design** — and are
//!   tested.
//! * The **sealing key** here is generated from OS entropy and held in normal
//!   process memory. In a genuine TEE it is **hardware-derived and never
//!   extractable** (SGX seal key, Secure Enclave / StrongBox key), and this
//!   entire type executes *inside* the enclave. See `TEE.md` for the per-platform
//!   mapping.
//!
//! Because `clarity-core` is `#![forbid(unsafe_code)]` and (optionally) `no_std`,
//! the same code compiles into an SGX enclave, a TrustZone trusted app, or a
//! Gramine/Occlum unikernel without modification.

use zeroize::Zeroize;

use crate::error::Result;
use crate::identity::Account;
use crate::kdf::{aead_open, aead_seal, random_bytes};
use crate::session::Session;
use crate::wire::{Message, OneTimePrekeyPublics, PreKeyBundle};

// Domain-separated sealing contexts, so an account blob can never be opened as a
// session blob or vice versa.
const SEAL_AD_ACCOUNT: &[u8] = b"Clarity-seal-account-v1";
const SEAL_AD_SESSION: &[u8] = b"Clarity-seal-session-v1";

/// An opaque, sealed blob. Only the [`Enclave`] that sealed it (i.e. the holder
/// of the sealing key) can open it. To the untrusted host this is ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed(pub Vec<u8>);

impl Sealed {
    /// The raw sealed bytes, for the host to persist. Opaque and safe to store.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Wrap raw sealed bytes read back from host storage.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Sealed(bytes)
    }
}

/// The trusted core. Owns the sealing key; exposes only sealed-in / sealed-out
/// operations. No plaintext secret ever leaves an `Enclave` method.
pub struct Enclave {
    seal_key: [u8; 32],
}

impl Enclave {
    /// Initialize a new enclave with a fresh sealing key.
    ///
    /// SOFTWARE REFERENCE: the key comes from OS entropy and lives in process
    /// memory. On real hardware the sealing key is derived inside the TEE and is
    /// never extractable.
    pub fn initialize() -> Self {
        Enclave {
            seal_key: random_bytes::<32>(),
        }
    }

    /// Reconstruct an enclave from a previously held sealing key.
    ///
    /// On real hardware you would NOT store the seal key at all — it is
    /// re-derived from the hardware root of trust on each boot. This exists so
    /// the software reference can persist across process restarts in tests/dev.
    pub fn from_seal_key(seal_key: [u8; 32]) -> Self {
        Enclave { seal_key }
    }

    /// Export the sealing key (software reference only; a real TEE never lets
    /// this leave secure hardware).
    pub fn seal_key(&self) -> [u8; 32] {
        self.seal_key
    }

    // --- Account operations -------------------------------------------------

    /// Create a new identity inside the enclave. Returns the sealed account (for
    /// the host to persist) and the public identity key (safe to publish).
    pub fn create_account(&self) -> (Sealed, [u8; 32]) {
        let account = Account::generate();
        let identity = account.identity_public();
        let sealed = self.seal_secret(SEAL_AD_ACCOUNT, account.to_bytes());
        (sealed, identity)
    }

    /// Produce the public prekey material to upload to a relay: the base bundle
    /// (no one-time prekey) and the pool of one-time prekey publics. All public.
    pub fn account_bundle(
        &self,
        sealed_account: &Sealed,
    ) -> Result<(PreKeyBundle, OneTimePrekeyPublics)> {
        let account = self.open_account(sealed_account)?;
        let mut base = account.bundle();
        base.one_time_prekey = None;
        base.one_time_prekey_id = None;
        Ok((base, account.one_time_prekey_publics()))
    }

    // --- Session operations (stateless: sealed in → sealed out) -------------

    /// Begin a session with a contact from their bundle. Returns the sealed
    /// session state.
    pub fn initiate(&self, sealed_account: &Sealed, bundle: &PreKeyBundle) -> Result<Sealed> {
        let account = self.open_account(sealed_account)?;
        let session = Session::initiate(&account, bundle)?;
        Ok(self.seal_secret(SEAL_AD_SESSION, session.serialize()))
    }

    /// Accept an inbound first message. Returns the (re-sealed, since a one-time
    /// prekey was consumed) account, the sealed session, and the first plaintext.
    pub fn respond(
        &self,
        sealed_account: &Sealed,
        first_message: &Message,
    ) -> Result<(Sealed, Sealed, Vec<u8>)> {
        let mut account = self.open_account(sealed_account)?;
        let (session, plaintext) = Session::respond(&mut account, first_message)?;
        let new_account = self.seal_secret(SEAL_AD_ACCOUNT, account.to_bytes());
        let sealed_session = self.seal_secret(SEAL_AD_SESSION, session.serialize());
        Ok((new_account, sealed_session, plaintext))
    }

    /// Encrypt a message. Returns the advanced sealed session and the wire message.
    pub fn encrypt(&self, sealed_session: &Sealed, plaintext: &[u8]) -> Result<(Sealed, Message)> {
        let mut session = self.open_session(sealed_session)?;
        let message = session.encrypt(plaintext)?;
        Ok((self.seal_secret(SEAL_AD_SESSION, session.serialize()), message))
    }

    /// Decrypt a message. Returns the advanced sealed session and the plaintext.
    pub fn decrypt(&self, sealed_session: &Sealed, message: &Message) -> Result<(Sealed, Vec<u8>)> {
        let mut session = self.open_session(sealed_session)?;
        let plaintext = session.decrypt(message)?;
        Ok((self.seal_secret(SEAL_AD_SESSION, session.serialize()), plaintext))
    }

    // --- Sealing internals --------------------------------------------------

    fn seal_secret(&self, context: &[u8], mut plaintext: Vec<u8>) -> Sealed {
        let sealed = Sealed(aead_seal(&self.seal_key, &plaintext, context));
        // Wipe the transient plaintext copy of the secret from memory.
        plaintext.zeroize();
        sealed
    }

    fn open_account(&self, sealed: &Sealed) -> Result<Account> {
        let mut bytes = aead_open(&self.seal_key, &sealed.0, SEAL_AD_ACCOUNT)?;
        let account = Account::from_bytes(&bytes);
        bytes.zeroize();
        account
    }

    fn open_session(&self, sealed: &Sealed) -> Result<Session> {
        let mut bytes = aead_open(&self.seal_key, &sealed.0, SEAL_AD_SESSION)?;
        let session = Session::deserialize(&bytes);
        bytes.zeroize();
        session
    }
}
