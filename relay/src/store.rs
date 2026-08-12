//! In-memory relay state: published prekeys and per-mailbox message queues.
//!
//! The store never holds plaintext. Bundles are public key material; queued
//! messages are opaque ciphertext blobs the relay cannot open.
//!
//! Mailbox keys are **opaque 32-byte values** — the store neither knows nor
//! cares what they are. Clients route to *rotating anonymous inbox IDs*
//! (`clarity_core::inbox`, `SHA-256(identity ‖ epoch)`) inside sealed-sender
//! envelopes, so this store holds no stable recipient identifier and no sender
//! at all for queued mail. Only the prekey *directory* is identity-keyed —
//! fetching a bundle for a new contact necessarily names them. Full metadata
//! story: `ARCHITECTURE.md`.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use clarity_core::identity::Account;
use clarity_core::PreKeyBundle;

/// Maximum messages queued per recipient before the oldest are dropped.
const MAX_QUEUE_PER_RECIPIENT: usize = 10_000;

struct StoredKeys {
    /// Base bundle with no one-time prekey attached.
    base_bundle: PreKeyBundle,
    /// Pool of unused one-time prekeys, handed out one per fetch.
    one_time: VecDeque<(u32, [u8; 32])>,
}

#[derive(Default)]
struct Inner {
    keys: HashMap<[u8; 32], StoredKeys>,
    queues: HashMap<[u8; 32], VecDeque<Vec<u8>>>,
}

/// Thread-safe relay store.
#[derive(Default)]
pub struct RelayStore {
    inner: Mutex<Inner>,
}

impl RelayStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish (or replace) a user's prekeys.
    ///
    /// `base_bundle.one_time_prekey` is ignored; the one-time pool is supplied
    /// separately in `one_time` so the store can dispense a distinct key per
    /// fetch.
    pub fn publish(&self, base_bundle: PreKeyBundle, one_time: Vec<(u32, [u8; 32])>) {
        let identity = base_bundle.identity_ed;
        let mut base_bundle = base_bundle;
        base_bundle.one_time_prekey = None;
        base_bundle.one_time_prekey_id = None;

        let mut inner = self.lock();
        inner.keys.insert(
            identity,
            StoredKeys {
                base_bundle,
                one_time: one_time.into_iter().collect(),
            },
        );
    }

    /// Fetch a bundle for `identity`, consuming one one-time prekey if any
    /// remain. Returns `None` if the identity is unknown.
    pub fn fetch_bundle(&self, identity: &[u8; 32]) -> Option<PreKeyBundle> {
        let mut inner = self.lock();
        let stored = inner.keys.get_mut(identity)?;
        let mut bundle = stored.base_bundle.clone();
        if let Some((id, public)) = stored.one_time.pop_front() {
            bundle.one_time_prekey = Some(public);
            bundle.one_time_prekey_id = Some(id);
        }
        Some(bundle)
    }

    /// How many one-time prekeys remain for an identity (for replenish hints).
    pub fn one_time_remaining(&self, identity: &[u8; 32]) -> usize {
        self.lock()
            .keys
            .get(identity)
            .map(|k| k.one_time.len())
            .unwrap_or(0)
    }

    /// Queue an opaque ciphertext message for `recipient`.
    pub fn enqueue(&self, recipient: [u8; 32], message: Vec<u8>) {
        let mut inner = self.lock();
        let queue = inner.queues.entry(recipient).or_default();
        if queue.len() >= MAX_QUEUE_PER_RECIPIENT {
            queue.pop_front();
        }
        queue.push_back(message);
    }

    /// Drain and return all queued messages for `recipient`, in delivery order.
    pub fn poll(&self, recipient: &[u8; 32]) -> Vec<Vec<u8>> {
        let mut inner = self.lock();
        match inner.queues.get_mut(recipient) {
            Some(queue) => queue.drain(..).collect(),
            None => Vec::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("relay store mutex poisoned")
    }
}

/// Split an [`Account`]'s published material into the base bundle plus the pool
/// of one-time prekeys, ready for [`RelayStore::publish`] or the HTTP client.
pub fn split_bundle(account: &Account) -> (PreKeyBundle, Vec<(u32, [u8; 32])>) {
    let mut base = account.bundle();
    base.one_time_prekey = None;
    base.one_time_prekey_id = None;
    (base, account.one_time_prekey_publics())
}
