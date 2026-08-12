//! A minimal synchronous HTTP front-end over [`RelayStore`] using `tiny_http`.
//!
//! Endpoints (all JSON, see [`crate::protocol`]):
//!
//! | Method & path        | Purpose                                   |
//! |----------------------|-------------------------------------------|
//! | `POST /publish`      | Upload a bundle + one-time prekeys        |
//! | `GET  /bundle?identity=<b64>` | Fetch a bundle (consumes one OPK) |
//! | `POST /send`         | Queue an opaque message for a mailbox     |
//! | `GET  /poll?recipient=<b64>`  | Drain queued messages             |
//! | `GET  /health`       | Liveness check                            |
//!
//! This is intentionally small and dependency-light. TLS termination is expected
//! to be handled by a reverse proxy in front of the relay.
//!
//! ## Abuse guards
//!
//! Request bodies are capped at 4 MiB, oversized messages get `413`, and an
//! optional fixed-window per-IP rate limit returns `429` when exceeded. This is
//! a single-node abuse guard, not DoS protection — a real deployment still
//! wants network-level filtering in front. After each request the server
//! opportunistically flushes the store snapshot and, once an hour, sweeps
//! expired mail.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tiny_http::{Method, Request, Response, Server};

use crate::protocol::{
    b64, unb64, unb64_key, BundleResponse, PollResponse, PublishRequest, SendRequest,
};
use crate::store::{RelayStore, StoreError};
use clarity_core::PreKeyBundle;

/// Largest accepted request body. Bundles with a full one-time-prekey batch
/// and padded sealed envelopes are far below this.
const MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;
/// How often the expired-mail sweep runs, at most.
const SWEEP_INTERVAL_SECS: u64 = 60 * 60;

/// Server options beyond the store's own limits.
#[derive(Debug, Clone, Copy, Default)]
pub struct ServeOptions {
    /// Per-IP request budget per minute; `None` disables rate limiting.
    pub rate_limit_per_min: Option<u32>,
}

/// Fixed-window per-IP request counter.
struct RateLimiter {
    limit: u32,
    windows: HashMap<IpAddr, (u64, u32)>,
    started: Instant,
}

impl RateLimiter {
    fn new(limit: u32) -> Self {
        RateLimiter {
            limit,
            windows: HashMap::new(),
            started: Instant::now(),
        }
    }

    fn allow(&mut self, ip: IpAddr) -> bool {
        let minute = self.started.elapsed().as_secs() / 60;
        // Drop stale windows so the map tracks only currently-active peers.
        if self.windows.len() > 10_000 {
            self.windows.retain(|_, (w, _)| *w == minute);
        }
        let entry = self.windows.entry(ip).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        entry.1 += 1;
        entry.1 <= self.limit
    }
}

/// Run the relay HTTP server on `addr` (e.g. `"0.0.0.0:8080"`), blocking forever.
pub fn serve(store: Arc<RelayStore>, addr: &str) -> std::io::Result<()> {
    serve_with(store, addr, ServeOptions::default())
}

/// [`serve`] with explicit [`ServeOptions`].
pub fn serve_with(store: Arc<RelayStore>, addr: &str, options: ServeOptions) -> std::io::Result<()> {
    let server = Server::http(addr).map_err(|e| std::io::Error::other(e.to_string()))?;
    eprintln!("clarity-relay listening on http://{addr}");
    serve_on_with(server, store, options);
    Ok(())
}

/// Drive the request loop on an already-bound [`Server`]. Useful when the caller
/// needs the bound address first (e.g. binding to port 0 in tests).
pub fn serve_on(server: Server, store: Arc<RelayStore>) {
    serve_on_with(server, store, ServeOptions::default())
}

/// [`serve_on`] with explicit [`ServeOptions`].
pub fn serve_on_with(server: Server, store: Arc<RelayStore>, options: ServeOptions) {
    let mut limiter = options.rate_limit_per_min.map(RateLimiter::new);
    let mut last_sweep = Instant::now();
    for request in server.incoming_requests() {
        if let Some(limiter) = limiter.as_mut() {
            let ip = request.remote_addr().map(|a| a.ip());
            if let Some(ip) = ip {
                if !limiter.allow(ip) {
                    let _ = respond_text(request, 429, "rate limited");
                    continue;
                }
            }
        }
        handle(&store, request);
        if last_sweep.elapsed().as_secs() >= SWEEP_INTERVAL_SECS {
            store.sweep_expired();
            last_sweep = Instant::now();
        }
        if let Err(e) = store.maybe_flush() {
            eprintln!("relay state flush failed: {e}");
        }
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
        (Method::Post, "/publish") => match handle_publish(store, &mut request) {
            Ok(()) => respond_text(request, 200, "ok"),
            Err(e) => respond_error(request, e),
        },
        (Method::Get, "/bundle") => handle_bundle(store, request, &query),
        (Method::Post, "/send") => match handle_send(store, &mut request) {
            Ok(()) => respond_text(request, 200, "ok"),
            Err(e) => respond_error(request, e),
        },
        (Method::Get, "/poll") => handle_poll(store, request, &query),
        _ => respond_text(request, 404, "not found"),
    };

    if let Err(e) = result {
        eprintln!("relay request error: {e}");
    }
}

/// A request failure with the HTTP status it should map to.
struct RequestError {
    status: u16,
    message: String,
}

impl RequestError {
    fn bad(message: impl Into<String>) -> Self {
        RequestError {
            status: 400,
            message: message.into(),
        }
    }
}

impl From<std::io::Error> for RequestError {
    fn from(e: std::io::Error) -> Self {
        RequestError {
            status: 400,
            message: e.to_string(),
        }
    }
}

fn respond_error(request: Request, e: RequestError) -> std::io::Result<()> {
    respond_text(request, e.status, &e.message)
}

fn handle_publish(store: &RelayStore, request: &mut Request) -> Result<(), RequestError> {
    let req: PublishRequest = read_json(request)?;
    let bundle_bytes = unb64(&req.bundle).map_err(RequestError::bad)?;
    let bundle =
        PreKeyBundle::decode(&bundle_bytes).map_err(|e| RequestError::bad(e.to_string()))?;
    let mut one_time = Vec::with_capacity(req.one_time.len());
    for otp in req.one_time {
        let key = unb64_key(&otp.public).map_err(RequestError::bad)?;
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

fn handle_send(store: &RelayStore, request: &mut Request) -> Result<(), RequestError> {
    let req: SendRequest = read_json(request)?;
    let recipient = unb64_key(&req.recipient).map_err(RequestError::bad)?;
    let message = unb64(&req.message).map_err(RequestError::bad)?;
    store.enqueue(recipient, message).map_err(|e| match e {
        StoreError::MessageTooLarge => RequestError {
            status: 413,
            message: "message too large".to_string(),
        },
    })
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
    std::io::Read::read_to_string(
        &mut std::io::Read::take(request.as_reader(), MAX_BODY_BYTES),
        &mut body,
    )?;
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
