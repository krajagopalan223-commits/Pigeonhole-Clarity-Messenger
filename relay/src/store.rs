//! Relay state: published prekeys and per-mailbox message queues, with
//! optional file-backed persistence, mail expiry, and size caps.
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
//!
//! ## Durability
//!
//! [`RelayStore::open`] loads a bincode snapshot and re-writes it (atomically:
//! temp file + rename) when dirty, throttled to once per second by
//! [`RelayStore::maybe_flush`] — the server calls that after each request. A
//! hard kill can lose at most the last second of mutations; queued mail is
//! end-to-end acknowledged by the ratchet above, so a lost tail is equivalent
//! to network loss, which the protocol already tolerates. [`RelayStore::new`]
//! stays memory-only for tests and ephemeral relays.
//!
//! ## Bounds
//!
//! * Queued messages expire after [`StoreLimits::mail_ttl_secs`] (default 30
//!   days) — checked on poll and by [`RelayStore::sweep_expired`].
//! * A single message larger than [`StoreLimits::max_message_bytes`] is
//!   rejected outright.
//! * A mailbox is capped by message count **and** total bytes; the oldest
//!   messages fall off first, like any store-and-forward system.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use clarity_core::identity::Account;
use clarity_core::PreKeyBundle;

/// Snapshot format version, bumped on breaking layout changes.
const SNAPSHOT_VERSION: u8 = 1;
/// Minimum interval between snapshot writes.
const FLUSH_INTERVAL_SECS: u64 = 1;

/// Tunable bounds for the store. The defaults suit a small volunteer relay.
#[derive(Debug, Clone, Copy)]
pub struct StoreLimits {
    /// Queued mail older than this is dropped (seconds). Default 30 days.
    pub mail_ttl_secs: u64,
    /// Largest single message accepted, in bytes. Default 256 KiB — well
    /// above the largest sealed-envelope padding bucket in normal use.
    pub max_message_bytes: usize,
    /// Maximum messages queued per mailbox before the oldest are dropped.
    pub max_mailbox_messages: usize,
    /// Maximum total bytes queued per mailbox before the oldest are dropped.
    pub max_mailbox_bytes: usize,
}

impl Default for StoreLimits {
    fn default() -> Self {
        StoreLimits {
            mail_ttl_secs: 30 * 24 * 60 * 60,
            max_message_bytes: 256 * 1024,
            max_mailbox_messages: 10_000,
            max_mailbox_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Why an enqueue was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The message exceeds [`StoreLimits::max_message_bytes`].
    MessageTooLarge,
}

#[derive(Serialize, Deserialize)]
struct StoredKeys {
    /// Base bundle with no one-time prekey attached.
    base_bundle: PreKeyBundle,
    /// Pool of unused one-time prekeys, handed out one per fetch.
    one_time: VecDeque<(u32, [u8; 32])>,
}

/// A queued message and the unix time it arrived.
#[derive(Serialize, Deserialize)]
struct QueuedMessage {
    enqueued_at: u64,
    bytes: Vec<u8>,
}

#[derive(Default, Serialize, Deserialize)]
struct Inner {
    keys: HashMap<[u8; 32], StoredKeys>,
    queues: HashMap<[u8; 32], VecDeque<QueuedMessage>>,
}

#[derive(Deserialize)]
struct Snapshot {
    version: u8,
    inner: Inner,
}

/// Borrowing twin of [`Snapshot`] so a flush serializes in place.
#[derive(Serialize)]
struct SnapshotRef<'a> {
    version: u8,
    inner: &'a Inner,
}

struct Persistence {
    path: PathBuf,
    dirty: bool,
    last_flush: Instant,
}

/// Thread-safe relay store.
pub struct RelayStore {
    inner: Mutex<Inner>,
    limits: StoreLimits,
    persistence: Mutex<Option<Persistence>>,
}

impl Default for RelayStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayStore {
    /// Create an empty, memory-only store with default limits.
    pub fn new() -> Self {
        Self::with_limits(StoreLimits::default())
    }

    /// Create a memory-only store with explicit limits.
    pub fn with_limits(limits: StoreLimits) -> Self {
        RelayStore {
            inner: Mutex::new(Inner::default()),
            limits,
            persistence: Mutex::new(None),
        }
    }

    /// Open a file-backed store: loads the snapshot at `path` if present
    /// (rejecting unknown snapshot versions), then persists mutations back to
    /// it via [`RelayStore::maybe_flush`].
    pub fn open(path: impl Into<PathBuf>, limits: StoreLimits) -> std::io::Result<Self> {
        let path = path.into();
        let inner = match std::fs::read(&path) {
            Ok(bytes) => {
                let snapshot: Snapshot = bincode::deserialize(&bytes)
                    .map_err(|e| std::io::Error::other(format!("corrupt relay state: {e}")))?;
                if snapshot.version != SNAPSHOT_VERSION {
                    return Err(std::io::Error::other(format!(
                        "relay state version {} unsupported (expected {SNAPSHOT_VERSION})",
                        snapshot.version
                    )));
                }
                snapshot.inner
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Inner::default(),
            Err(e) => return Err(e),
        };
        Ok(RelayStore {
            inner: Mutex::new(inner),
            limits,
            persistence: Mutex::new(Some(Persistence {
                path,
                dirty: false,
                last_flush: Instant::now(),
            })),
        })
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
        drop(inner);
        self.mark_dirty();
    }

    /// Fetch a bundle for `identity`, consuming one one-time prekey if any
    /// remain. Returns `None` if the identity is unknown.
    pub fn fetch_bundle(&self, identity: &[u8; 32]) -> Option<PreKeyBundle> {
        let mut inner = self.lock();
        let stored = inner.keys.get_mut(identity)?;
        let mut bundle = stored.base_bundle.clone();
        let consumed = stored.one_time.pop_front();
        if let Some((id, public)) = consumed {
            bundle.one_time_prekey = Some(public);
            bundle.one_time_prekey_id = Some(id);
        }
        drop(inner);
        if consumed.is_some() {
            self.mark_dirty();
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
    pub fn enqueue(&self, recipient: [u8; 32], message: Vec<u8>) -> Result<(), StoreError> {
        self.enqueue_at(recipient, message, now_unix())
    }

    pub(crate) fn enqueue_at(
        &self,
        recipient: [u8; 32],
        message: Vec<u8>,
        now: u64,
    ) -> Result<(), StoreError> {
        if message.len() > self.limits.max_message_bytes {
            return Err(StoreError::MessageTooLarge);
        }
        let mut inner = self.lock();
        let queue = inner.queues.entry(recipient).or_default();
        queue.push_back(QueuedMessage {
            enqueued_at: now,
            bytes: message,
        });
        // Enforce count and byte caps, oldest first.
        while queue.len() > self.limits.max_mailbox_messages {
            queue.pop_front();
        }
        let mut total: usize = queue.iter().map(|m| m.bytes.len()).sum();
        while total > self.limits.max_mailbox_bytes {
            match queue.pop_front() {
                Some(dropped) => total -= dropped.bytes.len(),
                None => break,
            }
        }
        drop(inner);
        self.mark_dirty();
        Ok(())
    }

    /// Drain and return all unexpired queued messages for `recipient`, in
    /// delivery order.
    pub fn poll(&self, recipient: &[u8; 32]) -> Vec<Vec<u8>> {
        self.poll_at(recipient, now_unix())
    }

    pub(crate) fn poll_at(&self, recipient: &[u8; 32], now: u64) -> Vec<Vec<u8>> {
        let cutoff = now.saturating_sub(self.limits.mail_ttl_secs);
        let mut inner = self.lock();
        let drained: Vec<QueuedMessage> = match inner.queues.remove(recipient) {
            Some(queue) => queue.into_iter().collect(),
            None => return Vec::new(),
        };
        drop(inner);
        self.mark_dirty();
        drained
            .into_iter()
            .filter(|m| m.enqueued_at >= cutoff)
            .map(|m| m.bytes)
            .collect()
    }

    /// Drop expired mail and empty mailboxes across the whole store. Returns
    /// how many messages were removed. The server calls this opportunistically.
    pub fn sweep_expired(&self) -> usize {
        self.sweep_expired_at(now_unix())
    }

    pub(crate) fn sweep_expired_at(&self, now: u64) -> usize {
        let cutoff = now.saturating_sub(self.limits.mail_ttl_secs);
        let mut removed = 0;
        let mut inner = self.lock();
        inner.queues.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|m| m.enqueued_at >= cutoff);
            removed += before - queue.len();
            !queue.is_empty()
        });
        drop(inner);
        if removed > 0 {
            self.mark_dirty();
        }
        removed
    }

    /// Write a snapshot if the store is dirty and at least a second has passed
    /// since the last write. Atomic: temp file in the same directory, then
    /// rename. No-op for memory-only stores.
    pub fn maybe_flush(&self) -> std::io::Result<()> {
        let mut guard = self.persistence.lock().expect("persistence mutex poisoned");
        let Some(p) = guard.as_mut() else {
            return Ok(());
        };
        if !p.dirty || p.last_flush.elapsed().as_secs() < FLUSH_INTERVAL_SECS {
            return Ok(());
        }
        let bytes = {
            let inner = self.lock();
            bincode::serialize(&SnapshotRef {
                version: SNAPSHOT_VERSION,
                inner: &inner,
            })
            .map_err(|e| std::io::Error::other(e.to_string()))?
        };
        let tmp = p.path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &p.path)?;
        p.dirty = false;
        p.last_flush = Instant::now();
        Ok(())
    }

    /// Force a snapshot write now (used on shutdown paths and in tests).
    pub fn flush(&self) -> std::io::Result<()> {
        {
            let mut guard = self.persistence.lock().expect("persistence mutex poisoned");
            if let Some(p) = guard.as_mut() {
                p.dirty = true;
                p.last_flush = Instant::now()
                    .checked_sub(std::time::Duration::from_secs(FLUSH_INTERVAL_SECS + 1))
                    .unwrap_or_else(Instant::now);
            }
        }
        self.maybe_flush()
    }

    fn mark_dirty(&self) {
        if let Some(p) = self
            .persistence
            .lock()
            .expect("persistence mutex poisoned")
            .as_mut()
        {
            p.dirty = true;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("relay store mutex poisoned")
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs()
}

/// Split an [`Account`]'s published material into the base bundle plus the pool
/// of one-time prekeys, ready for [`RelayStore::publish`] or the HTTP client.
pub fn split_bundle(account: &Account) -> (PreKeyBundle, Vec<(u32, [u8; 32])>) {
    let mut base = account.bundle();
    base.one_time_prekey = None;
    base.one_time_prekey_id = None;
    (base, account.one_time_prekey_publics())
}
