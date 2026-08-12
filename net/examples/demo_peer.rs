//! A second Clarity user at the command line, for exercising a running app
//! end-to-end through a relay: fetches the app user's prekey bundle, opens a
//! PQXDH session, sends one message inside a sealed-sender envelope addressed
//! to the recipient's rotating inbox, then polls its own rotating inbox for an
//! encrypted reply and prints the decrypted text.
//!
//! Usage:
//!   cargo run -p clarity-net --example demo_peer -- \
//!     <relay-url> <their-identity-base64> <message> [poll-seconds]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clarity_core::{
    epoch_for_unix, inbox_id, inbox_window, open_envelope, seal_envelope, Account, Session,
};
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
    // Inside the encryption, chat messages use the app's typed content schema.
    let content = serde_json::json!({"v": 1, "t": "text", "body": text}).to_string();
    let wire = session.encrypt(content.as_bytes()).expect("encrypt").encode();

    // Seal the wire message (sender identity travels inside the encryption)
    // and address the recipient's rotating inbox for the current epoch — the
    // relay sees neither of our identity keys on the mailbox path.
    let epoch = epoch_for_unix(unix_now());
    let blob = seal_envelope(&me, &bundle.identity_dh, &wire);
    relay
        .send(&inbox_id(&their_id, epoch), &blob)
        .expect("send");
    println!("sent (sealed, inbox epoch {epoch}): {text:?}");

    println!("polling my rotating inbox up to {poll_secs}s for a reply...");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(poll_secs);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let now_epoch = epoch_for_unix(unix_now());
        for ib in inbox_window(&my_id, now_epoch.saturating_sub(1), now_epoch + 1) {
            let envelopes = match relay.poll(&ib) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for raw in envelopes {
                let opened = match open_envelope(&me, &raw) {
                    Ok(o) => o,
                    Err(_) => continue,
                };
                let msg = match clarity_core::Message::decode(&opened.payload) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                match session.decrypt(&msg) {
                    Ok(plain) => {
                        let sender = B64.encode(opened.sender_identity_ed);
                        // Typed content: show text bodies and timer controls
                        // distinctly; anything else prints raw.
                        match serde_json::from_slice::<serde_json::Value>(&plain) {
                            Ok(v) if v["v"] == 1 && v["t"] == "text" => {
                                println!("decrypted reply from {sender}: {:?}", v["body"].as_str().unwrap_or(""));
                                return;
                            }
                            Ok(v) if v["v"] == 1 && v["t"] == "timer" => {
                                println!("timer control from {sender}: retention = {:?} seconds", v["seconds"]);
                            }
                            _ => {
                                println!("decrypted reply from {sender}: {:?}", String::from_utf8_lossy(&plain));
                                return;
                            }
                        }
                    }
                    Err(e) => println!("undecryptable envelope: {e:?}"),
                }
            }
        }
    }
    eprintln!("no reply within {poll_secs}s");
    std::process::exit(2);
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs()
}
