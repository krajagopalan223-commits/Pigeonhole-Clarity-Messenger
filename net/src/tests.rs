//! Transport tests. We run a full clarity-core session through `RelayTransport`
//! against a real in-process relay (direct mode). The Tor path uses the exact
//! same code with a SOCKS5 proxy in front, so a green direct test plus a
//! constructible Tor transport covers the logic; live Tor bootstrap is an
//! on-device concern, not a unit test.

use std::sync::Arc;

use clarity_core::identity::Account;
use clarity_core::{Message, Session};
use clarity_relay::{split_bundle, RelayStore};

use crate::RelayTransport;

/// Start a real relay on an ephemeral port; returns its base URL.
fn spawn_relay() -> String {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
    let addr = server.server_addr().to_ip().expect("ip");
    let store = Arc::new(RelayStore::new());
    std::thread::spawn(move || clarity_relay::serve_on(server, store));
    format!("http://{addr}")
}

#[test]
fn session_through_direct_transport() {
    let url = spawn_relay();
    let transport = RelayTransport::direct(url);

    let alice = Account::generate_with_prekeys(5);
    let mut bob = Account::generate_with_prekeys(5);
    let bob_id = bob.identity_public();

    // Bob publishes via the transport.
    let (base, one_time) = split_bundle(&bob);
    transport.publish(&base, &one_time).expect("publish");

    // Alice fetches, initiates, sends.
    let bundle = transport.fetch_bundle(&bob_id).expect("fetch").expect("present");
    let mut alice_session = Session::initiate(&alice, &bundle).unwrap();
    let msg = alice_session.encrypt(b"over the wire").unwrap();
    transport.send(&bob_id, &msg.encode()).expect("send");

    // Bob polls and decrypts.
    let inbox = transport.poll(&bob_id).expect("poll");
    assert_eq!(inbox.len(), 1);
    let incoming = Message::decode(&inbox[0]).unwrap();
    let (_bob_session, plaintext) = Session::respond(&mut bob, &incoming).unwrap();
    assert_eq!(plaintext, b"over the wire");
}

#[test]
fn fetch_unknown_identity_returns_none() {
    let url = spawn_relay();
    let transport = RelayTransport::direct(url);
    let unknown = [7u8; 32];
    assert!(transport.fetch_bundle(&unknown).expect("fetch").is_none());
}

#[test]
fn tor_transport_is_constructible() {
    // We can't bootstrap Tor in CI, but the Tor transport must build with a
    // SOCKS5 proxy configured (the request path is identical to direct mode).
    let transport = RelayTransport::over_tor("http://exampleonionaddress.onion", "127.0.0.1:9050");
    assert!(transport.is_ok(), "Tor transport should construct with a valid proxy addr");
}
