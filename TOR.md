# Tor transport

Clarity's recommended transport routes all relay traffic over **Tor**. This is
the safest option and the fastest to adopt: it reuses the existing relay
protocol unchanged, keeps offline delivery working, and — unlike raw
peer-to-peer — never exposes your IP address to the person you're talking to.

## What it protects

| Observer | Without Tor | With Tor |
|----------|-------------|----------|
| Relay operator | sees your IP + contact graph | sees neither your IP nor a network address |
| Local network / ISP | sees you talking to the relay | sees only that you use Tor |
| The person you message | (relay-mediated: nothing) | (relay-mediated: nothing) |

It does **not** hide message content (that's already end-to-end encrypted) and
it does not by itself hide the contact graph *from a relay that logs identity
lookups* — pair it with the rotating-inbox-ID plan in `ARCHITECTURE.md` for that.

## Client usage (`clarity-net`)

```rust
use clarity_net::RelayTransport;

// Development / clearnet:
let t = RelayTransport::direct("http://127.0.0.1:8080");

// Over Tor (system tor on 9050, or Orbot on 9150). base_url may be a .onion:
let t = RelayTransport::over_tor("http://<relay>.onion", "127.0.0.1:9050")?;
```

The proxy resolves the hostname, so `.onion` relays work and no DNS leaks to the
local network. Every method (`publish`, `fetch_bundle`, `send`, `poll`) is
identical across both modes.

### Per-platform Tor
- **Linux/desktop:** run the system `tor` daemon; SOCKS5 on `127.0.0.1:9050`.
- **Android:** bundle/require **Orbot**; SOCKS5 on `127.0.0.1:9150`. (A future
  build can embed [Arti](https://gitlab.torproject.org/tpo/core/arti), Tor in
  Rust, to avoid the Orbot dependency.)
- **iOS:** embed Tor (Arti, or `Tor.framework`); point the transport at its
  local SOCKS port.

## Running the relay as a hidden service

Publishing the relay as a Tor **onion service** means clients reach it without it
ever having a public IP, and the connection is end-to-end between Tor circuits.

Add to your `torrc`:

```
HiddenServiceDir /var/lib/tor/clarity-relay/
HiddenServicePort 80 127.0.0.1:8080
```

Start the relay bound to localhost and reload Tor:

```bash
cargo run -p clarity-relay -- 127.0.0.1:8080
sudo systemctl reload tor
cat /var/lib/tor/clarity-relay/hostname   # your <relay>.onion address
```

Hand that `.onion` to clients as the `base_url` for `RelayTransport::over_tor`.

## Why not raw peer-to-peer?

Direct P2P (WebRTC/QUIC hole-punching) removes the relay but **reveals your IP to
the peer**, needs signaling + NAT traversal (weeks of fiddly work), and still
falls back to relays when a peer is offline. Tor gives stronger anonymity for far
less code. Direct P2P remains a possible *optional* mode later, for users who
explicitly accept the IP-exposure trade-off on a trusted local network.
