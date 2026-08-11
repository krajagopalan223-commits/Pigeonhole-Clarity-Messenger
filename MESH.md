# Bluetooth mesh transport

Clarity can deliver messages **without any internet, cell service, or servers**,
by hopping them phone-to-phone over Bluetooth in a store-carry-forward mesh. This
is the transport for network blackouts, censorship, disasters, and remote areas —
the scenario where a relay simply isn't reachable.

Implemented and tested in the [`mesh/`](mesh) crate (`clarity-mesh`).

## When to use it (and when not to)

| | Bluetooth mesh | Tor relay |
|---|----------------|-----------|
| Works with no infrastructure | ✅ | ❌ (needs a reachable relay) |
| Hides your location / presence | ❌ **broadcasts it** | ✅ |
| Range / throughput | ~10–100 m, low | internet-wide |
| Best for | blackouts, censorship, off-grid | everyday private messaging |

**This is a deliberate trade, not a strict upgrade.** Joining a Bluetooth mesh
announces "a Clarity user is here" and, by proximity, roughly *where* you are —
the opposite of what Tor buys you. So the app treats it as **explicitly opt-in**,
per the honest UX rule: use Tor to hide *who and where* you are; use the mesh when
the network is *down or blocked* and reachability matters more than concealment.

Message **content is always safe**: payloads are end-to-end encrypted by
`clarity-core`, so the couriers relaying your message physically cannot read it.
The tests prove exactly this — a courier node in the middle forwards ciphertext
and never sees plaintext.

## How the routing works

- Each message is a `MeshFrame`: a random `msg_id`, the `recipient` identity, a
  hop-limited `ttl`, and the opaque encrypted `payload`.
- **Flood + dedup:** nodes offer frames to every peer they meet but process each
  `msg_id` once, so frames don't loop.
- **Carry-forward:** nodes store frames and re-offer them to each newly met peer,
  so a message reaches a recipient who was never directly connected to the sender
  — physically carried across the mesh by intermediaries.
- **Bounds:** `ttl` limits hop distance; a bounded seen-set and frame store cap
  memory against floods.

Tests cover multi-hop delivery, dedup, TTL limits, carry-forward across a
*disconnected* mesh, and a genuine clarity-core session end-to-end over the mesh.

## What's built vs. what the app wires up

`clarity-mesh` is **pure routing logic** — no radio, no threads, fully unit
tested. The app supplies the actual Bluetooth I/O and pumps it into the node:

```rust
use clarity_mesh::{MeshNode, MeshTransport};

let transport = MeshTransport::new(MeshNode::new(my_identity));

// Sending is the same MessageTransport seam as the relay/Tor transport:
transport.send(&recipient_id, &encrypted_payload)?;

// The radio layer bridges the airwaves:
for frame_bytes in radio.received_frames() {
    transport.ingest(&frame_bytes)?;          // feed inbound frames in
}
radio.broadcast(transport.pending_broadcast()); // push carry-forward store out

// Delivered messages for us:
let mine = transport.receive(&my_identity)?;
```

Because `MeshTransport` implements the same `clarity_core::MessageTransport` trait
as the relay/Tor transport, the app can hold `Box<dyn MessageTransport>` and pick
per conversation — or even run several at once.

### Platform radios
- **Android:** BLE GATT + the **Nearby Connections** / Wi-Fi Direct APIs
  (`flutter` plugins such as `nearby_connections`). Most capable; background
  operation is workable within OS limits.
- **iOS:** **MultipeerConnectivity** (Bluetooth + peer Wi-Fi) or Core Bluetooth.
  Background BLE is heavily restricted, so the mesh is strongest in the
  foreground.
- **Linux/desktop:** BlueZ.

### Privacy hardening (roadmap)
The `recipient` field is visible to couriers (metadata). A production build should
route to **rotating inbox IDs** (`BLAKE3(identity ‖ epoch)`) instead of raw
identities, add cover traffic, and randomize BLE timing — the same
metadata-minimization track described in `ARCHITECTURE.md`.
