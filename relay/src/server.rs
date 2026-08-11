//! A minimal synchronous HTTP front-end over [`RelayStore`] using `tiny_http`.
//!
//! Endpoints (all JSON, see [`crate::protocol`]):
//!
//! | Method & path        | Purpose                                   |
//! |----------------------|-------------------------------------------|
//! | `POST /publish`      | Upload a bundle + one-time prekeys        |
//! | `GET  /bundle?identity=<b64>` | Fetch a bundle (consumes one OPK) |
//! | `POST /send`         | Queue an opaque message for a recipient   |
//! | `GET  /poll?recipient=<b64>`  | Drain queued messages             |
//! | `GET  /health`       | Liveness check                            |
//!
//! This is intentionally small and dependency-light. TLS termination is expected
//! to be handled by a reverse proxy in front of the relay.

use std::sync::Arc;

use tiny_http::{Method, Request, Response, Server};

use crate::protocol::{
    b64, unb64, unb64_key, BundleResponse, PollResponse, PublishRequest, SendRequest,
};
use crate::store::RelayStore;
use clarity_core::PreKeyBundle;

/// Run the relay HTTP server on `addr` (e.g. `"0.0.0.0:8080"`), blocking forever.
pub fn serve(store: Arc<RelayStore>, addr: &str) -> std::io::Result<()> {
    let server = Server::http(addr).map_err(|e| std::io::Error::other(e.to_string()))?;
    eprintln!("clarity-relay listening on http://{addr}");
    serve_on(server, store);
    Ok(())
}

/// Drive the request loop on an already-bound [`Server`]. Useful when the caller
/// needs the bound address first (e.g. binding to port 0 in tests).
pub fn serve_on(server: Server, store: Arc<RelayStore>) {
    for request in server.incoming_requests() {
        handle(&store, request);
    }
}

fn handle(store: &RelayStore, mut request: Request) {
    let method = request.method().clone();
    let url = request.url().to_string();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (url.clone(), String::new()),
    };

    let result = match (&method, path.as_str()) {
        (Method::Get, "/health") => respond_text(request, 200, "ok"),
        (Method::Post, "/publish") => handle_publish(store, &mut request).and_then(|_| respond_text(request, 200, "ok")),
        (Method::Get, "/bundle") => handle_bundle(store, request, &query),
        (Method::Post, "/send") => handle_send(store, &mut request).and_then(|_| respond_text(request, 200, "ok")),
        (Method::Get, "/poll") => handle_poll(store, request, &query),
        _ => respond_text(request, 404, "not found"),
    };

    if let Err(e) = result {
        eprintln!("relay request error: {e}");
    }
}

fn handle_publish(store: &RelayStore, request: &mut Request) -> std::io::Result<()> {
    let req: PublishRequest = read_json(request)?;
    let bundle_bytes = unb64(&req.bundle).map_err(std::io::Error::other)?;
    let bundle = PreKeyBundle::decode(&bundle_bytes)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut one_time = Vec::with_capacity(req.one_time.len());
    for otp in req.one_time {
        let key = crate::protocol::unb64_key(&otp.public).map_err(std::io::Error::other)?;
        one_time.push((otp.id, key));
    }
    store.publish(bundle, one_time);
    Ok(())
}

fn handle_bundle(store: &RelayStore, request: Request, query: &str) -> std::io::Result<()> {
    let identity = match query_param(query, "identity").and_then(|s| unb64_key(&s).ok()) {
        Some(id) => id,
        None => return respond_text(request, 400, "missing identity"),
    };
    match store.fetch_bundle(&identity) {
        Some(bundle) => {
            let body = BundleResponse {
                bundle: b64(&bundle.encode()),
            };
            respond_json(request, 200, &body)
        }
        None => respond_text(request, 404, "unknown identity"),
    }
}

fn handle_send(store: &RelayStore, request: &mut Request) -> std::io::Result<()> {
    let req: SendRequest = read_json(request)?;
    let recipient = unb64_key(&req.recipient).map_err(std::io::Error::other)?;
    let message = unb64(&req.message).map_err(std::io::Error::other)?;
    store.enqueue(recipient, message);
    Ok(())
}

fn handle_poll(store: &RelayStore, request: Request, query: &str) -> std::io::Result<()> {
    let recipient = match query_param(query, "recipient").and_then(|s| unb64_key(&s).ok()) {
        Some(id) => id,
        None => return respond_text(request, 400, "missing recipient"),
    };
    let messages = store
        .poll(&recipient)
        .into_iter()
        .map(|m| b64(&m))
        .collect();
    respond_json(request, 200, &PollResponse { messages })
}

// --- small helpers ---------------------------------------------------------

fn read_json<T: serde::de::DeserializeOwned>(request: &mut Request) -> std::io::Result<T> {
    let mut body = String::new();
    std::io::Read::read_to_string(request.as_reader(), &mut body)?;
    serde_json::from_str(&body).map_err(|e| std::io::Error::other(e.to_string()))
}

fn respond_json<T: serde::Serialize>(
    request: Request,
    status: u16,
    body: &T,
) -> std::io::Result<()> {
    let json = serde_json::to_string(body).map_err(|e| std::io::Error::other(e.to_string()))?;
    let header = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("valid header");
    request.respond(Response::from_string(json).with_status_code(status).with_header(header))
}

fn respond_text(request: Request, status: u16, text: &str) -> std::io::Result<()> {
    request.respond(Response::from_string(text).with_status_code(status))
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        if it.next() == Some(key) {
            let raw = it.next().unwrap_or("");
            return Some(url_decode(raw));
        }
    }
    None
}

/// Minimal percent-decoding sufficient for base64 query values (`+`, `/`, `=`).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte as char);
                    i += 3;
                    continue;
                }
                out.push('%');
                i += 1;
            }
            b'+' => {
                out.push(' ');
                i += 1;
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}
