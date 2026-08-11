//! # clarity-mesh
//!
//! Bluetooth **store-carry-forward** mesh routing for Clarity — messaging with
//! no internet, no cell, no servers, by hopping phone-to-phone over short-range
//! radio. Useful during network blackouts, censorship, or in remote areas.
//!
//! This crate is **transport-only routing logic** and is fully testable in
//! isolation. The actual Bluetooth radio I/O (advertising, scanning, GATT
//! transfer) is platform-specific and provided by the app through Flutter/native
//! plugins; this crate tells that radio layer *what* to send and *what to do*
//! with what it receives.
//!
//! ## How it works
//!
//! * Every message becomes a [`MeshFrame`] with a random `msg_id`, a `recipient`
//!   identity, a hop-limited `ttl`, and an opaque encrypted `payload`.
//! * Nodes **flood** frames to every peer they meet, but **dedup** by `msg_id`
//!   so a frame is processed once and doesn't loop.
//! * Nodes **store** frames they've seen and **re-offer** them to each newly
//!   encountered peer ("carry-forward"), so a message reaches a recipient who was
//!   never directly connected to the sender — carried across the mesh by
//!   intermediaries.
//! * `ttl` bounds how far a frame travels; a bounded seen-set and store bound
//!   memory against floods.
//!
//! ## Security / privacy (read this)
//!
//! * **Content is safe:** payloads are end-to-end encrypted by
//!   [`clarity_core`]; carriers relay ciphertext they cannot read.
//! * **Presence is exposed:** participating in a Bluetooth mesh broadcasts that
//!   you run Clarity and, via proximity, roughly where you are. This is the
//!   *opposite* of the anonymity Tor provides — use the mesh for
//!   infrastructure-independence, not for hiding your location. The app must
//!   make it explicitly opt-in. See `MESH.md`.

mod frame;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

pub use frame::MeshFrame;

use clarity_core::transport::{MessageTransport, TransportError};

/// Default hop budget for a newly originated frame.
pub const DEFAULT_TTL: u8 = 16;

/// Cap on remembered `msg_id`s for dedup (bounds memory under a flood).
const SEEN_CAP: usize = 8192;
/// Cap on stored frames available for carry-forward (bounds memory).
const STORE_CAP: usize = 2048;

/// What happened when a node handled an incoming frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reception {
    /// Already seen this `msg_id`; ignored.
    Duplicate,
    /// Newly accepted.
    Accepted {
        /// True if this frame was addressed to us (delivered to our inbox).
        for_me: bool,
        /// True if we will carry/forward it onward (ttl still had budget).
        will_forward: bool,
    },
}

/// One participant in the mesh. Pure routing state — no radio, no threads.
///
/// The app drives it: call [`MeshNode::originate`] to inject a message,
/// [`MeshNode::handle_incoming`] for each frame the radio receives, and
/// [`MeshNode::outbound`] / [`MeshNode::on_new_peer`] to learn what to broadcast.
pub struct MeshNode {
    me: [u8; 32],
    ttl: u8,
    seen: HashSet<[u8; 16]>,
    seen_order: VecDeque<[u8; 16]>,
    store: HashMap<[u8; 16], MeshFrame>,
    store_order: VecDeque<[u8; 16]>,
    inbox: Vec<Vec<u8>>,
}

impl MeshNode {
    /// Create a node identified by our 32-byte identity key.
    pub fn new(me: [u8; 32]) -> Self {
        Self::with_ttl(me, DEFAULT_TTL)
    }

    /// Create a node with a custom hop budget.
    pub fn with_ttl(me: [u8; 32], ttl: u8) -> Self {
        MeshNode {
            me,
            ttl,
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            store: HashMap::new(),
            store_order: VecDeque::new(),
            inbox: Vec::new(),
        }
    }

    /// Inject a new message addressed to `recipient`. Returns the frame to
    /// broadcast (it is also stored for carry-forward). `payload` must already
    /// be end-to-end encrypted.
    pub fn originate(&mut self, recipient: [u8; 32], payload: Vec<u8>) -> MeshFrame {
        let mut msg_id = [0u8; 16];
        getrandom::getrandom(&mut msg_id).expect("OS CSPRNG unavailable");
        let frame = MeshFrame {
            msg_id,
            recipient,
            ttl: self.ttl,
            payload,
        };
        self.mark_seen(msg_id);
        self.store_frame(frame.clone());
        frame
    }

    /// Process a frame received from a peer. Delivers to our inbox if it's for
    /// us, and stores a decremented copy for onward carry-forward if it has hop
    /// budget left.
    pub fn handle_incoming(&mut self, frame: MeshFrame) -> Reception {
        if self.seen.contains(&frame.msg_id) {
            return Reception::Duplicate;
        }
        self.mark_seen(frame.msg_id);

        let for_me = frame.recipient == self.me;
        if for_me {
            self.inbox.push(frame.payload.clone());
        }

        let forward_ttl = frame.ttl.saturating_sub(1);
        let will_forward = forward_ttl > 0;
        if will_forward {
            let mut onward = frame;
            onward.ttl = forward_ttl;
            self.store_frame(onward);
        }

        Reception::Accepted { for_me, will_forward }
    }

    /// Frames this node currently offers to peers (its carry-forward store).
    pub fn outbound(&self) -> Vec<MeshFrame> {
        self.store_order
            .iter()
            .filter_map(|id| self.store.get(id).cloned())
            .collect()
    }

    /// What to offer a newly encountered peer: everything we're carrying. This
    /// is the "carry-forward" step that lets messages cross a disconnected mesh.
    pub fn on_new_peer(&self) -> Vec<MeshFrame> {
        self.outbound()
    }

    /// Drain payloads addressed to us that have arrived so far.
    pub fn take_inbox(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.inbox)
    }

    /// Number of frames currently held for carry-forward.
    pub fn stored(&self) -> usize {
        self.store.len()
    }

    fn mark_seen(&mut self, id: [u8; 16]) {
        if self.seen.insert(id) {
            self.seen_order.push_back(id);
            if self.seen_order.len() > SEEN_CAP {
                if let Some(old) = self.seen_order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }

    fn store_frame(&mut self, frame: MeshFrame) {
        let id = frame.msg_id;
        if self.store.insert(id, frame).is_none() {
            self.store_order.push_back(id);
            if self.store_order.len() > STORE_CAP {
                if let Some(old) = self.store_order.pop_front() {
                    self.store.remove(&old);
                }
            }
        }
    }
}

/// A [`MessageTransport`] backed by a [`MeshNode`], so the mesh is
/// interchangeable with the relay/Tor transport behind `dyn MessageTransport`.
///
/// `send` originates a frame; `receive` drains the inbox. The app's radio layer
/// bridges the airwaves by calling [`MeshTransport::ingest`] for each received
/// frame and broadcasting [`MeshTransport::pending_broadcast`].
pub struct MeshTransport {
    node: Mutex<MeshNode>,
}

impl MeshTransport {
    /// Wrap a node as a transport.
    pub fn new(node: MeshNode) -> Self {
        MeshTransport {
            node: Mutex::new(node),
        }
    }

    /// Feed a raw frame received from the radio into the mesh.
    pub fn ingest(&self, frame_bytes: &[u8]) -> Result<Reception, TransportError> {
        let frame = MeshFrame::decode(frame_bytes).map_err(|e| TransportError(e.to_string()))?;
        Ok(self.lock().handle_incoming(frame))
    }

    /// Encoded frames the radio should broadcast (the carry-forward store).
    pub fn pending_broadcast(&self) -> Vec<Vec<u8>> {
        self.lock().outbound().iter().map(MeshFrame::encode).collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MeshNode> {
        self.node.lock().expect("mesh node mutex poisoned")
    }
}

impl MessageTransport for MeshTransport {
    fn send(&self, recipient: &[u8; 32], payload: &[u8]) -> Result<(), TransportError> {
        self.lock().originate(*recipient, payload.to_vec());
        Ok(())
    }

    fn receive(&self, _me: &[u8; 32]) -> Result<Vec<Vec<u8>>, TransportError> {
        Ok(self.lock().take_inbox())
    }
}

/// Errors from mesh frame handling.
#[derive(Debug, Clone)]
pub enum MeshError {
    /// A received frame could not be decoded.
    Decode(String),
}

impl core::fmt::Display for MeshError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MeshError::Decode(m) => write!(f, "mesh frame decode error: {m}"),
        }
    }
}

impl std::error::Error for MeshError {}

#[cfg(test)]
mod tests;
