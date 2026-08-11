//! C ABI over `clarity_mesh::MeshNode` — the Bluetooth store-carry-forward mesh.
//!
//! The Rust side owns the routing logic; the Dart/platform side owns the radio.
//! The bridge is four calls:
//!   * `originate` — inject a message, get the frame bytes to broadcast;
//!   * `ingest` — feed a frame received over the radio;
//!   * `pending_broadcast` — the frames the radio should (re)broadcast;
//!   * `take_inbox` — payloads delivered to us.

use std::ptr;

use clarity_mesh::{MeshFrame, MeshNode};

use crate::{as_slice, encode_byte_list, ClarityBuffer};

unsafe fn read_key(p: *const u8) -> Option<[u8; 32]> {
    if p.is_null() {
        return None;
    }
    let mut key = [0u8; 32];
    ptr::copy_nonoverlapping(p, key.as_mut_ptr(), 32);
    Some(key)
}

/// Create a mesh node for our 32-byte identity (or rotating inbox ID).
///
/// # Safety
/// `me` points to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn clarity_mesh_node_new(me: *const u8) -> *mut MeshNode {
    match read_key(me) {
        Some(id) => Box::into_raw(Box::new(MeshNode::new(id))),
        None => ptr::null_mut(),
    }
}

/// Release a mesh node handle.
///
/// # Safety
/// `node` must be a handle from this library, or null.
#[no_mangle]
pub unsafe extern "C" fn clarity_mesh_node_free(node: *mut MeshNode) {
    if !node.is_null() {
        drop(Box::from_raw(node));
    }
}

/// Inject a message addressed to `recipient`. Returns the encoded frame to
/// broadcast immediately; null on error. `payload` must already be encrypted.
///
/// # Safety
/// `node` valid; `recipient` points to 32 readable bytes; payload region readable.
#[no_mangle]
pub unsafe extern "C" fn clarity_mesh_originate(
    node: *mut MeshNode,
    recipient: *const u8,
    payload: *const u8,
    payload_len: usize,
) -> ClarityBuffer {
    let node = match node.as_mut() {
        Some(n) => n,
        None => return ClarityBuffer::null(),
    };
    let recipient = match read_key(recipient) {
        Some(r) => r,
        None => return ClarityBuffer::null(),
    };
    let frame = node.originate(recipient, as_slice(payload, payload_len).to_vec());
    ClarityBuffer::from_vec(frame.encode())
}

/// Feed a frame received from the radio into the mesh. Returns 0 on success,
/// -1 if the frame could not be decoded.
///
/// # Safety
/// `node` valid; frame region readable.
#[no_mangle]
pub unsafe extern "C" fn clarity_mesh_ingest(
    node: *mut MeshNode,
    frame: *const u8,
    frame_len: usize,
) -> i32 {
    let node = match node.as_mut() {
        Some(n) => n,
        None => return -1,
    };
    match MeshFrame::decode(as_slice(frame, frame_len)) {
        Ok(f) => {
            node.handle_incoming(f);
            0
        }
        Err(_) => -1,
    }
}

/// The frames the radio should broadcast now (the carry-forward store), as an
/// encoded list (see [`crate::encode_byte_list`]). Null on error.
///
/// # Safety
/// `node` valid.
#[no_mangle]
pub unsafe extern "C" fn clarity_mesh_pending_broadcast(node: *const MeshNode) -> ClarityBuffer {
    let node = match node.as_ref() {
        Some(n) => n,
        None => return ClarityBuffer::null(),
    };
    let frames: Vec<Vec<u8>> = node.outbound().iter().map(MeshFrame::encode).collect();
    ClarityBuffer::from_vec(encode_byte_list(&frames))
}

/// Drain payloads delivered to us, as an encoded list. Null on error.
///
/// # Safety
/// `node` valid.
#[no_mangle]
pub unsafe extern "C" fn clarity_mesh_take_inbox(node: *mut MeshNode) -> ClarityBuffer {
    let node = match node.as_mut() {
        Some(n) => n,
        None => return ClarityBuffer::null(),
    };
    ClarityBuffer::from_vec(encode_byte_list(&node.take_inbox()))
}
