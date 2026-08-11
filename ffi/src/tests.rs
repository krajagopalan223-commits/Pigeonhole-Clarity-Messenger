//! Tests that drive the C ABI exactly as a host language would: only through
//! the `extern "C"` functions and raw pointers/buffers.

use std::ffi::CString;
use std::sync::Arc;

use super::*;
use crate::mesh_ffi::*;
use crate::transport_ffi::*;

/// Read a [`ClarityBuffer`] into an owned Vec and free it.
unsafe fn take_buffer(buf: ClarityBuffer) -> Option<Vec<u8>> {
    if buf.ptr.is_null() {
        return None;
    }
    let out = std::slice::from_raw_parts(buf.ptr, buf.len).to_vec();
    clarity_buffer_free(buf);
    Some(out)
}

/// Decode the `[u32 count]([u32 len][bytes])*` list format from the FFI.
fn decode_list(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let mut i = 4;
    for _ in 0..count {
        let len = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        out.push(bytes[i..i + len].to_vec());
        i += len;
    }
    out
}

/// Start a real relay on an ephemeral port; returns its base URL.
fn spawn_relay() -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
    let addr = server.server_addr().to_ip().expect("ip");
    let store = Arc::new(clarity_relay::RelayStore::new());
    std::thread::spawn(move || clarity_relay::serve_on(server, store));
    format!("http://{addr}")
}

#[test]
fn full_session_over_ffi() {
    unsafe {
        let alice = clarity_account_generate();
        let bob = clarity_account_generate();
        assert!(!alice.is_null() && !bob.is_null());

        // Bob's bundle (base) as the app would upload / Alice would fetch.
        let bundle = take_buffer(clarity_account_bundle_base(bob)).expect("bundle");

        // Alice initiates.
        let alice_session =
            clarity_session_initiate(alice, bundle.as_ptr(), bundle.len());
        assert!(!alice_session.is_null(), "initiate should succeed");

        // Alice encrypts the first message.
        let plaintext = b"ffi hello";
        let msg = take_buffer(clarity_session_encrypt(
            alice_session,
            plaintext.as_ptr(),
            plaintext.len(),
        ))
        .expect("encrypt");

        // Bob responds, recovering the first plaintext.
        let mut out = ClarityBuffer::null();
        let bob_session =
            clarity_session_respond(bob, msg.as_ptr(), msg.len(), &mut out as *mut _);
        assert!(!bob_session.is_null(), "respond should succeed");
        let recovered = take_buffer(out).expect("plaintext out");
        assert_eq!(recovered, plaintext);

        // Bob replies; Alice decrypts.
        let reply = b"ffi reply";
        let reply_msg = take_buffer(clarity_session_encrypt(
            bob_session,
            reply.as_ptr(),
            reply.len(),
        ))
        .expect("encrypt reply");
        let dec = take_buffer(clarity_session_decrypt(
            alice_session,
            reply_msg.as_ptr(),
            reply_msg.len(),
        ))
        .expect("decrypt reply");
        assert_eq!(dec, reply);

        // Safety numbers agree across the boundary.
        let mut a_id = [0u8; 32];
        let mut b_id = [0u8; 32];
        clarity_account_identity_public(alice, a_id.as_mut_ptr());
        clarity_account_identity_public(bob, b_id.as_mut_ptr());
        let sn = clarity_safety_number(a_id.as_ptr(), b_id.as_ptr());
        assert!(!sn.is_null());
        let s = std::ffi::CStr::from_ptr(sn).to_str().unwrap().to_string();
        assert_eq!(s.chars().filter(|c| c.is_ascii_digit()).count(), 60);
        clarity_string_free(sn);

        clarity_session_free(alice_session);
        clarity_session_free(bob_session);
        clarity_account_free(alice);
        clarity_account_free(bob);
    }
}

#[test]
fn account_serialize_roundtrip_over_ffi() {
    unsafe {
        let acct = clarity_account_generate();
        let bytes = take_buffer(clarity_account_serialize(acct)).expect("serialize");
        let restored = clarity_account_deserialize(bytes.as_ptr(), bytes.len());
        assert!(!restored.is_null());

        let mut id1 = [0u8; 32];
        let mut id2 = [0u8; 32];
        clarity_account_identity_public(acct, id1.as_mut_ptr());
        clarity_account_identity_public(restored, id2.as_mut_ptr());
        assert_eq!(id1, id2);

        clarity_account_free(acct);
        clarity_account_free(restored);
    }
}

#[test]
fn malformed_bundle_returns_null() {
    unsafe {
        let alice = clarity_account_generate();
        let garbage = [0xffu8; 16];
        let session = clarity_session_initiate(alice, garbage.as_ptr(), garbage.len());
        assert!(session.is_null(), "malformed bundle must not create a session");
        clarity_account_free(alice);
    }
}

#[test]
fn one_time_publics_is_valid_json() {
    unsafe {
        let acct = clarity_account_generate();
        let json = take_buffer(clarity_account_one_time_publics(acct)).expect("json");
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert!(parsed.as_array().is_some_and(|a| !a.is_empty()));
        clarity_account_free(acct);
    }
}

#[test]
fn session_persistence_over_ffi() {
    unsafe {
        let alice = clarity_account_generate();
        let bob = clarity_account_generate();
        let bundle = take_buffer(clarity_account_bundle_base(bob)).unwrap();

        let alice_session = clarity_session_initiate(alice, bundle.as_ptr(), bundle.len());
        let first = take_buffer(clarity_session_encrypt(alice_session, b"hi".as_ptr(), 2)).unwrap();
        let mut out = ClarityBuffer::null();
        let bob_session = clarity_session_respond(bob, first.as_ptr(), first.len(), &mut out);
        let _ = take_buffer(out);

        // "Restart": serialize Alice's session, free it, restore, keep chatting.
        let blob = take_buffer(clarity_session_serialize(alice_session)).unwrap();
        clarity_session_free(alice_session);
        let restored = clarity_session_deserialize(blob.as_ptr(), blob.len());
        assert!(!restored.is_null());

        let msg = take_buffer(clarity_session_encrypt(restored, b"after".as_ptr(), 5)).unwrap();
        let got = take_buffer(clarity_session_decrypt(bob_session, msg.as_ptr(), msg.len())).unwrap();
        assert_eq!(got, b"after");

        clarity_session_free(restored);
        clarity_session_free(bob_session);
        clarity_account_free(alice);
        clarity_account_free(bob);
    }
}

#[test]
fn relay_transport_over_ffi() {
    unsafe {
        let url = CString::new(spawn_relay()).unwrap();
        let transport = clarity_relay_transport_direct(url.as_ptr());
        assert!(!transport.is_null());

        let alice = clarity_account_generate();
        let bob = clarity_account_generate();
        assert_eq!(clarity_relay_publish_account(transport, bob), 0);

        let mut bob_id = [0u8; 32];
        clarity_account_identity_public(bob, bob_id.as_mut_ptr());

        // Fetch Bob's bundle through the transport.
        let bundle = take_buffer(clarity_relay_fetch_bundle(transport, bob_id.as_ptr()))
            .expect("fetch not error");
        assert!(!bundle.is_empty(), "bundle should be present");

        // Alice initiates, sends via the transport.
        let alice_session = clarity_session_initiate(alice, bundle.as_ptr(), bundle.len());
        let msg = take_buffer(clarity_session_encrypt(alice_session, b"via ffi relay".as_ptr(), 13))
            .unwrap();
        assert_eq!(
            clarity_relay_send(transport, bob_id.as_ptr(), msg.as_ptr(), msg.len()),
            0
        );

        // Bob polls via the transport and decrypts.
        let list = take_buffer(clarity_relay_poll(transport, bob_id.as_ptr())).unwrap();
        let messages = decode_list(&list);
        assert_eq!(messages.len(), 1);
        let mut out = ClarityBuffer::null();
        let bob_session =
            clarity_session_respond(bob, messages[0].as_ptr(), messages[0].len(), &mut out);
        assert_eq!(take_buffer(out).unwrap(), b"via ffi relay");

        // Unknown identity fetch returns an empty (not null) buffer.
        let unknown = [9u8; 32];
        let none = clarity_relay_fetch_bundle(transport, unknown.as_ptr());
        assert!(!none.ptr.is_null() && none.len == 0);
        clarity_buffer_free(none);

        clarity_session_free(alice_session);
        clarity_session_free(bob_session);
        clarity_account_free(alice);
        clarity_account_free(bob);
        clarity_relay_transport_free(transport);
    }
}

#[test]
fn mesh_over_ffi() {
    unsafe {
        let a_id = [1u8; 32];
        let b_id = [2u8; 32];
        let a = clarity_mesh_node_new(a_id.as_ptr());
        let b = clarity_mesh_node_new(b_id.as_ptr());

        let payload = b"mesh over ffi";
        let frame = take_buffer(clarity_mesh_originate(
            a,
            b_id.as_ptr(),
            payload.as_ptr(),
            payload.len(),
        ))
        .expect("frame");

        // Deliver the frame to B.
        assert_eq!(clarity_mesh_ingest(b, frame.as_ptr(), frame.len()), 0);

        // B's inbox has exactly the payload.
        let inbox = decode_list(&take_buffer(clarity_mesh_take_inbox(b)).unwrap());
        assert_eq!(inbox, vec![payload.to_vec()]);

        // A is carrying the frame for rebroadcast.
        let pending = decode_list(&take_buffer(clarity_mesh_pending_broadcast(a)).unwrap());
        assert_eq!(pending.len(), 1);

        clarity_mesh_node_free(a);
        clarity_mesh_node_free(b);
    }
}
