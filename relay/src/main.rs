//! Clarity relay server binary.
//!
//! ```text
//! clarity-relay [BIND_ADDR] [--state FILE] [--ttl-days N] [--rate-limit N]
//!
//!   BIND_ADDR       address to listen on          (default 0.0.0.0:8080)
//!   --state FILE    persist mailboxes + prekeys to FILE (atomic snapshots);
//!                   omit for a memory-only relay
//!   --ttl-days N    drop queued mail older than N days   (default 30)
//!   --rate-limit N  per-IP requests per minute, 0 = off  (default 240)
//! ```
//!
//! Put a TLS-terminating reverse proxy in front of it in production.

use std::sync::Arc;

use clarity_relay::{serve_with, RelayStore, ServeOptions, StoreLimits};

fn main() {
    let mut addr = "0.0.0.0:8080".to_string();
    let mut state_path: Option<String> = None;
    let mut limits = StoreLimits::default();
    let mut rate_limit: u32 = 240;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--state" => state_path = Some(expect_value(&arg, args.next())),
            "--ttl-days" => {
                let days: u64 = parse_value(&arg, args.next());
                limits.mail_ttl_secs = days * 24 * 60 * 60;
            }
            "--rate-limit" => rate_limit = parse_value(&arg, args.next()),
            "--help" | "-h" => {
                eprintln!(
                    "usage: clarity-relay [BIND_ADDR] [--state FILE] [--ttl-days N] [--rate-limit N]"
                );
                return;
            }
            flag if flag.starts_with("--") => {
                eprintln!("unknown flag: {flag}");
                std::process::exit(2);
            }
            positional => addr = positional.to_string(),
        }
    }

    let store = match &state_path {
        Some(path) => match RelayStore::open(path, limits) {
            Ok(store) => {
                eprintln!("clarity-relay state file: {path}");
                store
            }
            Err(e) => {
                eprintln!("clarity-relay fatal error: {e}");
                std::process::exit(1);
            }
        },
        None => RelayStore::with_limits(limits),
    };

    let options = ServeOptions {
        rate_limit_per_min: (rate_limit > 0).then_some(rate_limit),
    };
    if let Err(e) = serve_with(Arc::new(store), &addr, options) {
        eprintln!("clarity-relay fatal error: {e}");
        std::process::exit(1);
    }
}

fn expect_value(flag: &str, value: Option<String>) -> String {
    value.unwrap_or_else(|| {
        eprintln!("{flag} requires a value");
        std::process::exit(2);
    })
}

fn parse_value<T: std::str::FromStr>(flag: &str, value: Option<String>) -> T {
    expect_value(flag, value).parse().unwrap_or_else(|_| {
        eprintln!("{flag} requires a numeric value");
        std::process::exit(2);
    })
}
