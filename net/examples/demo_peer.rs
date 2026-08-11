//! A second Clarity user at the command line, for exercising a running app
//! end-to-end through a relay: fetches the app user's prekey bundle, opens a
//! PQXDH session, sends one encrypted message, then polls for an encrypted
//! reply and prints the decrypted text.
//!
//! Usage:
//!   cargo run -p clarity-net --example demo_peer -- \
//!     <relay-url> <their-identity-base64> <message> [poll-seconds]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clarity_core::{Account, Session};
use clarity_net::RelayTransport;

fn main() {
    let mut args = std::env::args().skip(1);
    let relay_url = args.next().expect("relay url");
    let their_id_b64 = args.next().expect("their identity (base64)");
    let text = args.next().expect("message text");
    let poll_secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(120);

    let their_id: [u8; 32] = B64
        .decode(their_id_b64.trim())
        .expect("valid base64")
        .try_into()
        .expect("identity must be 32 bytes");

    let relay = RelayTransport::direct(relay_url);

    let bundle = relay
        .fetch_bundle(&their_id)
        .expect("relay reachable")
        .expect("no bundle published for that identity");
    println!("fetched their bundle from the relay");

    let me = Account::generate();
    let my_id = me.identity_public();
    println!("my identity: {}", B64.encode(my_id));

    let mut session = Session::initiate(&me, &bundle).expect("bundle verified + session opened");
    let wire = session.encrypt(text.as_bytes()).expect("encrypt").encode();

    // The app routes by an outer {sender, payload} JSON envelope (see
    // app/lib/src/state/app_state.dart).
    let envelope = serde_json::json!({
        "sender": B64.encode(my_id),
        "payload": B64.encode(&wire),
    })
    .to_string();

    relay.send(&their_id, envelope.as_bytes()).expect("send");
    println!("sent: {text:?}");

    println!("polling up to {poll_secs}s for a reply...");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(poll_secs);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let envelopes = match relay.poll(&my_id) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for raw in envelopes {
            let v: serde_json::Value = match serde_json::from_slice(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let payload = match v["payload"].as_str().and_then(|p| B64.decode(p).ok()) {
                Some(p) => p,
                None => continue,
            };
            let msg = match clarity_core::Message::decode(&payload) {
                Ok(m) => m,
                Err(_) => continue,
            };
            match session.decrypt(&msg) {
                Ok(plain) => {
                    println!("decrypted reply: {:?}", String::from_utf8_lossy(&plain));
                    return;
                }
                Err(e) => println!("undecryptable envelope: {e:?}"),
            }
        }
    }
    eprintln!("no reply within {poll_secs}s");
    std::process::exit(2);
}
