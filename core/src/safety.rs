//! Safety numbers: a human-comparable fingerprint of two identities.
//!
//! Two contacts read these digits to each other (or scan a QR code) to confirm
//! there's no machine-in-the-middle. The construction mirrors Signal's: each
//! identity is hashed with many iterations (slowing brute-force of a colliding
//! key), then the two per-identity fingerprints are combined in a fixed order
//! so both sides display the same number.

use sha2::{Digest, Sha512};

/// Iteration count for the fingerprint hash. Matches Signal's default.
const ITERATIONS: u32 = 5200;
/// Digits taken from each identity's fingerprint (30 + 30 = 60 total).
const CHUNKS_PER_IDENTITY: usize = 6;

/// Compute the 60-digit safety number for a pair of Ed25519 identity keys.
///
/// The result is independent of argument order, so both contacts see the same
/// string regardless of who computes it.
pub fn safety_number(identity_a: &[u8; 32], identity_b: &[u8; 32]) -> String {
    let fp_a = fingerprint(identity_a);
    let fp_b = fingerprint(identity_b);

    // Order the two fingerprints deterministically before concatenating.
    let (first, second) = if fp_a <= fp_b {
        (&fp_a, &fp_b)
    } else {
        (&fp_b, &fp_a)
    };

    let mut out = String::with_capacity(60 + 12);
    push_digits(&mut out, first);
    out.push(' ');
    push_digits(&mut out, second);
    out
}

/// Iterated hash of a single identity key, domain-separated.
fn fingerprint(identity: &[u8; 32]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(b"Clarity-safety-number-v1");
    hasher.update(identity);
    let mut digest = hasher.finalize();

    for _ in 1..ITERATIONS {
        let mut h = Sha512::new();
        h.update(digest);
        h.update(identity);
        digest = h.finalize();
    }

    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// Encode a fingerprint as groups of 5 decimal digits (like Signal).
fn push_digits(out: &mut String, fingerprint: &[u8; 64]) {
    for chunk_index in 0..CHUNKS_PER_IDENTITY {
        let start = chunk_index * 5;
        // Take 5 bytes, interpret as a big-endian integer, mod 100000 → 5 digits.
        let mut acc: u64 = 0;
        for i in 0..5 {
            acc = (acc << 8) | u64::from(fingerprint[start + i]);
        }
        let value = acc % 100_000;
        if chunk_index > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{value:05}"));
    }
}
