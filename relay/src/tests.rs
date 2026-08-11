//! Relay tests: a pure in-memory end-to-end exchange, and a full HTTP round-trip
//! carrying a real clarity-core session between two parties.

use std::sync::Arc;

use clarity_core::identity::Account;
use clarity_core::{Message, PreKeyBundle, Session};

use crate::protocol::{
    b64, unb64, BundleResponse, OneTimePrekey, PollResponse, PublishRequest, SendRequest,
};
use crate::store::{split_bundle, RelayStore};

#[test]
fn end_to_end_through_store() {
    let store = RelayStore::new();

    let alice = Account::generate_with_prekeys(5);
    let mut bob = Account::generate_with_prekeys(5);

    // Bob publishes his prekeys.
    let (base, one_time) = split_bundle(&bob);
    store.publish(base, one_time);

    let bob_id = bob.identity_public();
    let alice_id = alice.identity_public();

    // Alice fetches Bob's bundle and opens a session.
    let bundle = store.fetch_bundle(&bob_id).expect("bundle present");
    let mut alice_session = Session::initiate(&alice, &bundle).unwrap();

    // Alice sends the first (prekey) message via the relay.
    let msg = alice_session.encrypt(b"meet at the usual place").unwrap();
    store.enqueue(bob_id, msg.encode());

    // Bob polls, decodes, and establishes his side.
    let inbox = store.poll(&bob_id);
    assert_eq!(inbox.len(), 1);
    let incoming = Message::decode(&inbox[0]).unwrap();
    let (mut bob_session, plaintext) = Session::respond(&mut bob, &incoming).unwrap();
    assert_eq!(plaintext, b"meet at the usual place");

    // Bob replies via the relay.
    let reply = bob_session.encrypt(b"understood").unwrap();
    store.enqueue(alice_id, reply.encode());

    let inbox = store.poll(&alice_id);
    let incoming = Message::decode(&inbox[0]).unwrap();
    assert_eq!(alice_session.decrypt(&incoming).unwrap(), b"understood");

    // The relay's queues are now empty (messages are drained on poll).
    assert!(store.poll(&alice_id).is_empty());
    assert!(store.poll(&bob_id).is_empty());
}

#[test]
fn one_time_prekey_dispensed_per_fetch() {
    let store = RelayStore::new();
    let bob = Account::generate_with_prekeys(2);
    let (base, one_time) = split_bundle(&bob);
    store.publish(base, one_time);
    let id = bob.identity_public();

    let first = store.fetch_bundle(&id).unwrap();
    let second = store.fetch_bundle(&id).unwrap();
    let third = store.fetch_bundle(&id).unwrap();

    assert!(first.one_time_prekey_id.is_some());
    assert!(second.one_time_prekey_id.is_some());
    assert_ne!(first.one_time_prekey_id, second.one_time_prekey_id);
    // Pool of 2 exhausted; further fetches carry no one-time prekey.
    assert!(third.one_time_prekey_id.is_none());
}

#[test]
fn http_round_trip_carries_a_real_session() {
    // Bind an ephemeral port and run the real HTTP server in a background thread.
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
    let addr = server.server_addr().to_ip().expect("ip addr");
    let base_url = format!("http://{addr}");
    let store = Arc::new(RelayStore::new());
    let store_bg = store.clone();
    let handle = std::thread::spawn(move || {
        crate::server::serve_on(server, store_bg);
    });

    let agent = ureq::AgentBuilder::new().build();

    let alice = Account::generate_with_prekeys(5);
    let mut bob = Account::generate_with_prekeys(5);
    let bob_id = bob.identity_public();

    // Bob publishes over HTTP.
    let (base, one_time) = split_bundle(&bob);
    let publish = PublishRequest {
        bundle: b64(&base.encode()),
        one_time: one_time
            .into_iter()
            .map(|(id, public)| OneTimePrekey {
                id,
                public: b64(&public),
            })
            .collect(),
    };
    agent
        .post(&format!("{base_url}/publish"))
        .send_json(serde_json::to_value(&publish).unwrap())
        .expect("publish");

    // Alice fetches Bob's bundle over HTTP.
    let resp: BundleResponse = agent
        .get(&format!("{base_url}/bundle"))
        .query("identity", &b64(&bob_id))
        .call()
        .expect("fetch")
        .into_json()
        .expect("json");
    let bundle = PreKeyBundle::decode(&unb64(&resp.bundle).unwrap()).unwrap();

    // Alice initiates and sends over HTTP.
    let mut alice_session = Session::initiate(&alice, &bundle).unwrap();
    let msg = alice_session.encrypt(b"http hello").unwrap();
    let send = SendRequest {
        recipient: b64(&bob_id),
        message: b64(&msg.encode()),
    };
    agent
        .post(&format!("{base_url}/send"))
        .send_json(serde_json::to_value(&send).unwrap())
        .expect("send");

    // Bob polls over HTTP and decrypts.
    let poll: PollResponse = agent
        .get(&format!("{base_url}/poll"))
        .query("recipient", &b64(&bob_id))
        .call()
        .expect("poll")
        .into_json()
        .expect("json");
    assert_eq!(poll.messages.len(), 1);
    let incoming = Message::decode(&unb64(&poll.messages[0]).unwrap()).unwrap();
    let (_bob_session, plaintext) = Session::respond(&mut bob, &incoming).unwrap();
    assert_eq!(plaintext, b"http hello");

    // Shut the server down by dropping our references and detaching the thread.
    drop(handle);
}
