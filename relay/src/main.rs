//! Clarity relay server binary.
//!
//! Usage: `clarity-relay [BIND_ADDR]` (default `0.0.0.0:8080`).
//! Put a TLS-terminating reverse proxy in front of it in production.

use std::sync::Arc;

use clarity_relay::{serve, RelayStore};

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:8080".to_string());
    let store = Arc::new(RelayStore::new());
    if let Err(e) = serve(store, &addr) {
        eprintln!("clarity-relay fatal error: {e}");
        std::process::exit(1);
    }
}
