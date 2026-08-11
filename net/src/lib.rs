//! # clarity-net
//!
//! Relay transport with first-class **Tor** support. This is the recommended
//! way for a client to reach a relay, because it hides the client's IP address
//! from both the relay operator and the network — the biggest metadata win
//! available without inventing a new anonymity network.
//!
//! Two modes:
//!
//! * [`RelayTransport::direct`] — plain HTTP(S), for development or when an
//!   outer VPN/Tor is already in place.
//! * [`RelayTransport::over_tor`] — routes every request through a Tor SOCKS5
//!   proxy (system `tor` on `127.0.0.1:9050`, or Orbot on mobile). Because the
//!   proxy resolves the hostname, this also reaches relays published as
//!   **`.onion` hidden services**, so neither side ever learns a network
//!   address for the other.
//!
//! The wire protocol is identical to the clearnet relay (see `clarity-relay`);
//! only the transport changes. That is exactly why Tor is the *fastest* secure
//! transport to adopt — no protocol changes, no NAT traversal, and offline
//! delivery keeps working.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use clarity_core::PreKeyBundle;
use clarity_relay::protocol::{
    BundleResponse, OneTimePrekey, PollResponse, PublishRequest, SendRequest,
};

/// A transport pointed at one relay, optionally via Tor.
pub struct RelayTransport {
    base_url: String,
    agent: ureq::Agent,
}

impl RelayTransport {
    /// Talk to the relay directly (no proxy). Use HTTPS in production, or wrap
    /// the whole app in a system-wide Tor/VPN.
    pub fn direct(base_url: impl Into<String>) -> Self {
        RelayTransport {
            base_url: base_url.into(),
            agent: ureq::AgentBuilder::new().build(),
        }
    }

    /// Route all traffic through a Tor SOCKS5 proxy.
    ///
    /// `socks_addr` is typically `"127.0.0.1:9050"` (system tor) or
    /// `"127.0.0.1:9150"` (Tor Browser / Orbot). `base_url` may be a `.onion`
    /// address; the proxy performs resolution, so no DNS or IP ever leaks to the
    /// local network.
    pub fn over_tor(base_url: impl Into<String>, socks_addr: &str) -> Result<Self, NetError> {
        // socks5h: hostname resolution happens at the proxy (required for .onion
        // and to avoid DNS leaks).
        let proxy = ureq::Proxy::new(format!("socks5://{socks_addr}"))
            .map_err(|e| NetError::Config(e.to_string()))?;
        Ok(RelayTransport {
            base_url: base_url.into(),
            agent: ureq::AgentBuilder::new().proxy(proxy).build(),
        })
    }

    /// Publish a base bundle plus the pool of one-time prekeys.
    pub fn publish(
        &self,
        base_bundle: &PreKeyBundle,
        one_time: &[(u32, [u8; 32])],
    ) -> Result<(), NetError> {
        let req = PublishRequest {
            bundle: b64(&base_bundle.encode()),
            one_time: one_time
                .iter()
                .map(|(id, public)| OneTimePrekey {
                    id: *id,
                    public: b64(public),
                })
                .collect(),
        };
        self.agent
            .post(&self.url("/publish"))
            .send_json(serde_json::to_value(&req)?)
            .map_err(boxed)?;
        Ok(())
    }

    /// Fetch a contact's bundle (consumes one one-time prekey server-side).
    /// Returns `None` if the relay has no bundle for that identity.
    pub fn fetch_bundle(&self, identity: &[u8; 32]) -> Result<Option<PreKeyBundle>, NetError> {
        let result = self
            .agent
            .get(&self.url("/bundle"))
            .query("identity", &b64(identity))
            .call();
        let resp = match result {
            Ok(resp) => resp,
            Err(ureq::Error::Status(404, _)) => return Ok(None),
            Err(e) => return Err(boxed(e)),
        };
        let body: BundleResponse = resp.into_json()?;
        let bytes = unb64(&body.bundle)?;
        Ok(Some(PreKeyBundle::decode(&bytes).map_err(|e| NetError::Decode(e.to_string()))?))
    }

    /// Queue an encrypted message for a recipient.
    pub fn send(&self, recipient: &[u8; 32], message: &[u8]) -> Result<(), NetError> {
        let req = SendRequest {
            recipient: b64(recipient),
            message: b64(message),
        };
        self.agent
            .post(&self.url("/send"))
            .send_json(serde_json::to_value(&req)?)
            .map_err(boxed)?;
        Ok(())
    }

    /// Drain queued messages for a recipient.
    pub fn poll(&self, recipient: &[u8; 32]) -> Result<Vec<Vec<u8>>, NetError> {
        let resp = self
            .agent
            .get(&self.url("/poll"))
            .query("recipient", &b64(recipient))
            .call()
            .map_err(boxed)?;
        let body: PollResponse = resp.into_json()?;
        body.messages.iter().map(|m| unb64(m)).collect()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>, NetError> {
    STANDARD.decode(s).map_err(|e| NetError::Decode(e.to_string()))
}

fn boxed(e: ureq::Error) -> NetError {
    NetError::Http(e.to_string())
}

/// Errors from the relay transport.
#[derive(Debug)]
pub enum NetError {
    /// Proxy/agent configuration error.
    Config(String),
    /// Network or non-2xx HTTP error.
    Http(String),
    /// Response body could not be decoded.
    Decode(String),
    /// JSON (de)serialization error.
    Json(String),
    /// I/O error reading a response body.
    Io(String),
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NetError::Config(m) => write!(f, "transport config error: {m}"),
            NetError::Http(m) => write!(f, "relay request failed: {m}"),
            NetError::Decode(m) => write!(f, "response decode error: {m}"),
            NetError::Json(m) => write!(f, "json error: {m}"),
            NetError::Io(m) => write!(f, "io error: {m}"),
        }
    }
}

impl std::error::Error for NetError {}

impl From<serde_json::Error> for NetError {
    fn from(e: serde_json::Error) -> Self {
        NetError::Json(e.to_string())
    }
}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests;
