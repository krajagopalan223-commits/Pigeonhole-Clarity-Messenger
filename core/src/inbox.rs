//! Rotating anonymous inbox identifiers (metadata protection, half 1 of 2).
//!
//! Instead of addressing a mailbox by the recipient's stable identity key —
//! which hands the relay operator a long-term identifier to build a contact
//! graph around — mail is queued under an *inbox ID* that rotates every epoch:
//!
//! ```text
//! inbox_id = SHA-256("Clarity-inbox-v1" ‖ identity_ed ‖ epoch_le64)
//! epoch    = unix_seconds / 86 400          (24-hour windows, UTC)
//! ```
//!
//! Senders derive the recipient's current inbox ID themselves (they know the
//! identity key), so nothing extra is exchanged. The relay sees only unlinked
//! 32-byte mailbox keys that change daily; its mailbox store is already
//! key-agnostic, so no server change is required.
//!
//! The source spec (§8) proposed `BLAKE3(identity ‖ epoch)`. We keep the
//! construction but use SHA-256: it is already the only hash in this codebase,
//! and the property needed here is only preimage resistance / PRF behaviour,
//! which both provide. One hash, fewer dependencies.
//!
//! ## What this does and does not achieve — honestly
//!
//! * The relay no longer holds a *stable* recipient identifier. Linking two
//!   epochs' inboxes requires knowing the identity key (or correlating by
//!   network address / timing — run over Tor for that half).
//! * The prekey *directory* is still keyed by identity: fetching a bundle for
//!   a new contact necessarily names them. That is inherent to a directory;
//!   what rotates is the high-volume, long-lived mailbox traffic.
//! * Clock skew across an epoch boundary is absorbed by polling a window of
//!   adjacent epochs (see [`inbox_window`]); senders just use their own clock.

use sha2::{Digest, Sha256};

/// Length of one inbox epoch, in seconds (24 hours, per the source spec §8).
pub const INBOX_EPOCH_SECONDS: u64 = 86_400;

/// The inbox epoch containing the given unix timestamp (seconds).
pub fn epoch_for_unix(unix_seconds: u64) -> u64 {
    unix_seconds / INBOX_EPOCH_SECONDS
}

/// The rotating inbox ID for `identity_ed` during `epoch`.
pub fn inbox_id(identity_ed: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"Clarity-inbox-v1");
    h.update(identity_ed);
    h.update(epoch.to_le_bytes());
    h.finalize().into()
}

/// Inbox IDs for every epoch in `from_epoch..=to_epoch`, oldest first.
/// Used by receivers to poll a catch-up window (e.g. last poll − 1 .. now + 1)
/// so mail queued under an older epoch's inbox is still collected. Returns an
/// empty vec if the range is inverted.
pub fn inbox_window(identity_ed: &[u8; 32], from_epoch: u64, to_epoch: u64) -> Vec<[u8; 32]> {
    if from_epoch > to_epoch {
        return Vec::new();
    }
    (from_epoch..=to_epoch)
        .map(|e| inbox_id(identity_ed, e))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_epoch_dependent() {
        let id = [7u8; 32];
        assert_eq!(inbox_id(&id, 20_000), inbox_id(&id, 20_000));
        assert_ne!(inbox_id(&id, 20_000), inbox_id(&id, 20_001));
        assert_ne!(inbox_id(&id, 20_000), inbox_id(&[8u8; 32], 20_000));
        // The inbox ID must not be the raw identity.
        assert_ne!(inbox_id(&id, 20_000), id);
    }

    #[test]
    fn epoch_boundaries() {
        assert_eq!(epoch_for_unix(0), 0);
        assert_eq!(epoch_for_unix(INBOX_EPOCH_SECONDS - 1), 0);
        assert_eq!(epoch_for_unix(INBOX_EPOCH_SECONDS), 1);
    }

    #[test]
    fn window_covers_inclusive_range() {
        let id = [1u8; 32];
        let w = inbox_window(&id, 10, 12);
        assert_eq!(w.len(), 3);
        assert_eq!(w[0], inbox_id(&id, 10));
        assert_eq!(w[2], inbox_id(&id, 12));
        assert!(inbox_window(&id, 12, 10).is_empty());
    }
}
