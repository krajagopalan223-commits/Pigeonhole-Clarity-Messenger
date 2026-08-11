//! Thin, byte-oriented wrapper over ML-KEM-1024 (FIPS 203, the standardized
//! CRYSTALS-Kyber-1024 parameter set).
//!
//! The `ml-kem` crate speaks in generic `hybrid_array::Array` types; this module
//! translates to and from plain byte buffers so the rest of the core never has
//! to name those generics. ML-KEM is used only for the *initial* handshake
//! (see [`crate::handshake`]) — it provides "harvest-now, decrypt-later"
//! protection so traffic recorded today survives a future quantum computer.
//! The ongoing Double Ratchet remains classical, exactly as Signal's PQXDH does
//! today; that is an honest, deliberate scope choice, not an oversight.

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
use rand_core::OsRng;

use crate::error::{Error, Result};

/// Length of an ML-KEM-1024 encapsulation (public) key, in bytes.
pub const KYBER_PUBLIC_LEN: usize = 1568;
/// Length of an ML-KEM-1024 ciphertext, in bytes.
pub const KYBER_CIPHERTEXT_LEN: usize = 1568;
/// Length of the derived shared secret, in bytes.
pub const KYBER_SHARED_LEN: usize = 32;

type DecapKey = <MlKem1024 as KemCore>::DecapsulationKey;
type EncapKey = <MlKem1024 as KemCore>::EncapsulationKey;

/// A freshly generated ML-KEM keypair.
pub struct KyberKeyPair {
    decap: DecapKey,
}

impl KyberKeyPair {
    /// Generate a new ML-KEM-1024 keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        let (decap, _encap) = MlKem1024::generate(&mut OsRng);
        Self { decap }
    }

    /// The public (encapsulation) key, serialized to [`KYBER_PUBLIC_LEN`] bytes.
    pub fn public_bytes(&self) -> Vec<u8> {
        self.decap.encapsulation_key().as_bytes().to_vec()
    }

    /// Serialize the private (decapsulation) key so an account can be persisted.
    pub fn private_bytes(&self) -> Vec<u8> {
        self.decap.as_bytes().to_vec()
    }

    /// Reconstruct a keypair from previously serialized private-key bytes.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self> {
        let arr = Array::try_from(bytes).map_err(|_| Error::MalformedKey)?;
        let decap = DecapKey::from_bytes(&arr);
        Ok(Self { decap })
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; KYBER_SHARED_LEN]> {
        let ct = Array::try_from(ciphertext).map_err(|_| Error::MalformedKey)?;
        let ss = self.decap.decapsulate(&ct).map_err(|_| Error::Decrypt)?;
        let mut out = [0u8; KYBER_SHARED_LEN];
        out.copy_from_slice(&ss);
        Ok(out)
    }
}

/// Encapsulate to a peer's public key. Returns `(ciphertext, shared_secret)`.
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, [u8; KYBER_SHARED_LEN])> {
    let arr = Array::try_from(public_key).map_err(|_| Error::MalformedKey)?;
    let encap = EncapKey::from_bytes(&arr);
    let (ct, ss) = encap.encapsulate(&mut OsRng).map_err(|_| Error::Decrypt)?;
    let mut secret = [0u8; KYBER_SHARED_LEN];
    secret.copy_from_slice(&ss);
    Ok((ct.to_vec(), secret))
}
