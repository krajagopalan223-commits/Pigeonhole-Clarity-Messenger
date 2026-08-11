//! Tests that drive the C ABI exactly as a host language would: only through
//! the `extern "C"` functions and raw pointers/buffers.

use super::*;

/// Read a [`ClarityBuffer`] into an owned Vec and free it.
unsafe fn take_buffer(buf: ClarityBuffer) -> Option<Vec<u8>> {
    if buf.ptr.is_null() {
        return None;
    }
    let out = std::slice::from_raw_parts(buf.ptr, buf.len).to_vec();
    clarity_buffer_free(buf);
    Some(out)
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
