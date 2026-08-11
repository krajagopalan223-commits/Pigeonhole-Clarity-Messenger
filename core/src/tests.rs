//! Integration-style tests exercising the full protocol through the public API.

use crate::enclave::{Enclave, Sealed};
use crate::identity::{verify_bundle, Account};
use crate::safety::safety_number;
use crate::wire::{Message, PreKeyBundle};
use crate::Session;

/// Establish an Alice→Bob session and return both ends plus the first plaintext.
fn establish() -> (Account, Account, Session, Session) {
    let alice = Account::generate_with_prekeys(10);
    let mut bob = Account::generate_with_prekeys(10);

    let bob_bundle = bob.bundle();
    let mut alice_session = Session::initiate(&alice, &bob_bundle).expect("initiate");

    let first = alice_session.encrypt(b"hello bob").expect("encrypt");
    let (bob_session, pt) = Session::respond(&mut bob, &first).expect("respond");
    assert_eq!(pt, b"hello bob");

    (alice, bob, alice_session, bob_session)
}

#[test]
fn handshake_and_first_message() {
    let _ = establish();
}

#[test]
fn full_bidirectional_conversation() {
    let (_alice, _bob, mut alice_s, mut bob_s) = establish();

    // Bob replies (this is Bob's first send; it triggers his sending chain).
    let m1 = bob_s.encrypt(b"hi alice").unwrap();
    assert_eq!(alice_s.decrypt(&m1).unwrap(), b"hi alice");

    // A back-and-forth exchange advancing the DH ratchet repeatedly.
    for i in 0..20u32 {
        let a = format!("alice #{i}");
        let msg = alice_s.encrypt(a.as_bytes()).unwrap();
        assert_eq!(bob_s.decrypt(&msg).unwrap(), a.as_bytes());

        let b = format!("bob #{i}");
        let msg = bob_s.encrypt(b.as_bytes()).unwrap();
        assert_eq!(alice_s.decrypt(&msg).unwrap(), b.as_bytes());
    }
}

#[test]
fn many_messages_same_chain() {
    let (_alice, _bob, mut alice_s, mut bob_s) = establish();
    // Alice sends many without Bob replying — exercises the symmetric ratchet.
    for i in 0..50u32 {
        let text = format!("burst {i}");
        let msg = alice_s.encrypt(text.as_bytes()).unwrap();
        assert_eq!(bob_s.decrypt(&msg).unwrap(), text.as_bytes());
    }
}

#[test]
fn out_of_order_delivery() {
    let (_alice, _bob, mut alice_s, mut bob_s) = establish();

    let m0 = alice_s.encrypt(b"m0").unwrap();
    let m1 = alice_s.encrypt(b"m1").unwrap();
    let m2 = alice_s.encrypt(b"m2").unwrap();

    // Deliver 2, then 0, then 1 — skipped keys must be cached and reused.
    assert_eq!(bob_s.decrypt(&m2).unwrap(), b"m2");
    assert_eq!(bob_s.decrypt(&m0).unwrap(), b"m0");
    assert_eq!(bob_s.decrypt(&m1).unwrap(), b"m1");
}

#[test]
fn dropped_message_then_continue() {
    let (_alice, _bob, mut alice_s, mut bob_s) = establish();

    let _dropped = alice_s.encrypt(b"lost to the network").unwrap();
    let delivered = alice_s.encrypt(b"this one arrives").unwrap();

    // Bob never sees the first; he should still decrypt the second.
    assert_eq!(bob_s.decrypt(&delivered).unwrap(), b"this one arrives");
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let (_alice, _bob, mut alice_s, mut bob_s) = establish();
    let mut msg = alice_s.encrypt(b"authentic").unwrap();
    match &mut msg {
        Message::PreKey { ciphertext, .. } | Message::Normal { ciphertext, .. } => {
            ciphertext[0] ^= 0x01;
        }
    }
    assert!(bob_s.decrypt(&msg).is_err());
}

#[test]
fn third_party_cannot_decrypt() {
    let (_alice, _bob, mut alice_s, _bob_s) = establish();
    let mut mallory = Account::generate_with_prekeys(10);

    let msg = alice_s.encrypt(b"secret").unwrap();
    // Mallory tries to respond/decrypt with her own account — must fail.
    assert!(Session::respond(&mut mallory, &msg).is_err());
}

#[test]
fn tampered_bundle_is_rejected() {
    let bob = Account::generate_with_prekeys(10);
    let mut bundle = bob.bundle();

    // Flip a byte in the signed prekey; signature check must fail.
    bundle.signed_prekey[0] ^= 0x01;
    assert!(verify_bundle(&bundle).is_err());

    let alice = Account::generate_with_prekeys(10);
    assert!(Session::initiate(&alice, &bundle).is_err());
}

#[test]
fn substituted_identity_key_is_rejected() {
    // A malicious prekey server swaps in its own identity key but keeps the
    // victim's signatures — every signature should now fail to verify.
    let bob = Account::generate_with_prekeys(10);
    let mallory = Account::generate_with_prekeys(10);
    let mut bundle = bob.bundle();
    bundle.identity_ed = mallory.identity_public();
    assert!(verify_bundle(&bundle).is_err());
}

#[test]
fn one_time_prekey_is_consumed() {
    let alice = Account::generate_with_prekeys(3);
    let mut bob = Account::generate_with_prekeys(3);
    let before = bob.one_time_prekeys_remaining();

    let bundle = bob.bundle();
    let mut s = Session::initiate(&alice, &bundle).unwrap();
    let first = s.encrypt(b"hi").unwrap();
    let (_bs, _pt) = Session::respond(&mut bob, &first).unwrap();

    assert_eq!(bob.one_time_prekeys_remaining(), before - 1);
}

#[test]
fn account_persistence_roundtrip() {
    let bob = Account::generate_with_prekeys(5);
    let bytes = bob.to_bytes();
    let mut restored = Account::from_bytes(&bytes).expect("restore");

    assert_eq!(bob.identity_public(), restored.identity_public());

    // A session established against the ORIGINAL bundle must work with the
    // RESTORED account — proving all private keys survived serialization.
    let alice = Account::generate_with_prekeys(5);
    let bundle = bob.bundle();
    let mut s = Session::initiate(&alice, &bundle).unwrap();
    let first = s.encrypt(b"persist test").unwrap();
    let (_bs, pt) = Session::respond(&mut restored, &first).unwrap();
    assert_eq!(pt, b"persist test");
}

#[test]
fn safety_number_is_symmetric_and_stable() {
    let a = Account::generate_with_prekeys(1);
    let b = Account::generate_with_prekeys(1);
    let ab = safety_number(&a.identity_public(), &b.identity_public());
    let ba = safety_number(&b.identity_public(), &a.identity_public());
    assert_eq!(ab, ba, "safety number must not depend on argument order");
    assert_eq!(ab, safety_number(&a.identity_public(), &b.identity_public()));
    // 60 digits shown as 12 groups of 5 → 11 spaces plus the middle separator.
    assert_eq!(ab.chars().filter(|c| c.is_ascii_digit()).count(), 60);
}

#[test]
fn session_survives_serialization_mid_conversation() {
    let (_alice, _bob, mut alice_s, mut bob_s) = establish();

    // Exchange a couple of messages so both ratchets have advanced.
    let m = bob_s.encrypt(b"hi").unwrap();
    assert_eq!(alice_s.decrypt(&m).unwrap(), b"hi");
    let m = alice_s.encrypt(b"hey").unwrap();
    assert_eq!(bob_s.decrypt(&m).unwrap(), b"hey");

    // "Restart the app": serialize both sessions and restore fresh objects.
    let alice_blob = alice_s.serialize();
    let bob_blob = bob_s.serialize();
    let mut alice_r = Session::deserialize(&alice_blob).unwrap();
    let mut bob_r = Session::deserialize(&bob_blob).unwrap();

    // The restored sessions continue the conversation seamlessly.
    let m = alice_r.encrypt(b"after restart").unwrap();
    assert_eq!(bob_r.decrypt(&m).unwrap(), b"after restart");
    let m = bob_r.encrypt(b"still works").unwrap();
    assert_eq!(alice_r.decrypt(&m).unwrap(), b"still works");
}

#[test]
fn enclave_full_conversation_through_sealed_state() {
    // Each side runs its own enclave. The "host" only ever holds Sealed blobs.
    let alice_tee = Enclave::initialize();
    let bob_tee = Enclave::initialize();

    let (alice_acct, _alice_id) = alice_tee.create_account();
    let (mut bob_acct, bob_id) = bob_tee.create_account();

    // Bob publishes; the bundle is public (leaves the enclave in the clear).
    let (bob_base, _bob_otps) = bob_tee.account_bundle(&bob_acct).unwrap();
    // (In a real system bob_base + otps are uploaded; alice fetches bob_base.)
    let _ = bob_id;

    // Alice initiates and sends the first message — all via sealed calls.
    let mut alice_sess = alice_tee.initiate(&alice_acct, &bob_base).unwrap();
    let (alice_sess2, first) = alice_tee.encrypt(&alice_sess, b"sealed hello").unwrap();
    alice_sess = alice_sess2;

    // Bob responds inside his enclave; his account is re-sealed (OPK consumed).
    let (bob_acct2, mut bob_sess, pt) = bob_tee.respond(&bob_acct, &first).unwrap();
    bob_acct = bob_acct2;
    assert_eq!(pt, b"sealed hello");
    let _ = &alice_acct;
    let _ = &bob_acct;

    // Full back-and-forth, threading the new sealed state each step.
    for i in 0..5u32 {
        let (bs, msg) = bob_tee.encrypt(&bob_sess, format!("bob {i}").as_bytes()).unwrap();
        bob_sess = bs;
        let (asess, got) = alice_tee.decrypt(&alice_sess, &msg).unwrap();
        alice_sess = asess;
        assert_eq!(got, format!("bob {i}").as_bytes());

        let (asess, msg) = alice_tee.encrypt(&alice_sess, format!("alice {i}").as_bytes()).unwrap();
        alice_sess = asess;
        let (bs, got) = bob_tee.decrypt(&bob_sess, &msg).unwrap();
        bob_sess = bs;
        assert_eq!(got, format!("alice {i}").as_bytes());
    }
}

#[test]
fn sealed_blobs_are_opaque_and_enclave_bound() {
    let tee = Enclave::initialize();
    let other = Enclave::initialize();

    let (account, identity) = tee.create_account();

    // The sealed account must not contain the raw identity key bytes in the clear.
    assert!(
        !contains_subsequence(account.as_bytes(), &identity),
        "sealed blob leaked plaintext key material"
    );

    // A different enclave (different sealing key) cannot open the blob.
    let (bundle, _) = tee.account_bundle(&account).unwrap();
    assert!(other.initiate(&account, &bundle).is_err());

    // A tampered sealed blob is rejected.
    let mut tampered = account.as_bytes().to_vec();
    tampered[0] ^= 0x01;
    assert!(tee.account_bundle(&Sealed::from_bytes(tampered)).is_err());
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn wire_message_roundtrip() {
    let (_alice, _bob, mut alice_s, _bob_s) = establish();
    let msg = alice_s.encrypt(b"encode me").unwrap();
    let bytes = msg.encode();
    let decoded = Message::decode(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn wire_bundle_roundtrip() {
    let bob = Account::generate_with_prekeys(2);
    let bundle = bob.bundle();
    let bytes = bundle.encode();
    let decoded = PreKeyBundle::decode(&bytes).unwrap();
    assert_eq!(bundle, decoded);
    assert!(verify_bundle(&decoded).is_ok());
}
