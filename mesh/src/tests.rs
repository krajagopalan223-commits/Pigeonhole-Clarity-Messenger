//! In-process simulation of a Bluetooth mesh: several `MeshNode`s wired by an
//! adjacency list, gossiping in discrete rounds. Proves multi-hop delivery,
//! dedup, TTL bounding, carry-forward across a disconnected mesh, and a real
//! end-to-end clarity-core message travelling over the mesh.

use clarity_core::identity::Account;
use clarity_core::{Message, Session};

use crate::{MeshNode, Reception, DEFAULT_TTL};

/// Deliver one discrete gossip round over undirected `edges`. Returns how many
/// frames were newly accepted this round (0 ⇒ the network has quiesced).
fn gossip_round(nodes: &mut [MeshNode], edges: &[(usize, usize)]) -> usize {
    // Snapshot every node's outbound set at the start of the round.
    let outbound: Vec<Vec<crate::MeshFrame>> = nodes.iter().map(|n| n.outbound()).collect();
    let mut accepted = 0;
    for &(a, b) in edges {
        for frame in &outbound[a] {
            if let Reception::Accepted { .. } = nodes[b].handle_incoming(frame.clone()) {
                accepted += 1;
            }
        }
        for frame in &outbound[b] {
            if let Reception::Accepted { .. } = nodes[a].handle_incoming(frame.clone()) {
                accepted += 1;
            }
        }
    }
    accepted
}

/// Run gossip until the network quiesces or a round cap is hit.
fn run_to_quiescence(nodes: &mut [MeshNode], edges: &[(usize, usize)]) {
    for _ in 0..64 {
        if gossip_round(nodes, edges) == 0 {
            break;
        }
    }
}

fn id(n: u8) -> [u8; 32] {
    [n; 32]
}

#[test]
fn delivers_across_multiple_hops() {
    // Line topology: 0 — 1 — 2 — 3. Node 0 messages node 3.
    let mut nodes = vec![
        MeshNode::new(id(0)),
        MeshNode::new(id(1)),
        MeshNode::new(id(2)),
        MeshNode::new(id(3)),
    ];
    let edges = [(0, 1), (1, 2), (2, 3)];

    nodes[0].originate(id(3), b"reach the far end".to_vec());
    run_to_quiescence(&mut nodes, &edges);

    assert_eq!(nodes[3].take_inbox(), vec![b"reach the far end".to_vec()]);
    // Intermediaries carried it but did not receive it as their own.
    assert!(nodes[1].take_inbox().is_empty());
    assert!(nodes[2].take_inbox().is_empty());
}

#[test]
fn duplicate_frames_are_ignored() {
    let mut node = MeshNode::new(id(9));
    let frame = {
        let mut origin = MeshNode::new(id(1));
        origin.originate(id(9), b"once".to_vec())
    };
    assert!(matches!(
        node.handle_incoming(frame.clone()),
        Reception::Accepted { for_me: true, .. }
    ));
    assert_eq!(node.handle_incoming(frame), Reception::Duplicate);
    // Delivered exactly once despite two receipts.
    assert_eq!(node.take_inbox(), vec![b"once".to_vec()]);
}

#[test]
fn ttl_bounds_reach() {
    // ttl = 2 can't cross three hops (0→1→2→3).
    let mut nodes = vec![
        MeshNode::with_ttl(id(0), 2),
        MeshNode::with_ttl(id(1), 2),
        MeshNode::with_ttl(id(2), 2),
        MeshNode::with_ttl(id(3), 2),
    ];
    let edges = [(0, 1), (1, 2), (2, 3)];
    nodes[0].originate(id(3), b"too far".to_vec());
    run_to_quiescence(&mut nodes, &edges);
    assert!(nodes[3].take_inbox().is_empty(), "ttl=2 should not reach hop 3");

    // But an adjacent node (one hop) does get it.
    let mut nodes = vec![MeshNode::with_ttl(id(0), 2), MeshNode::with_ttl(id(1), 2)];
    let edges = [(0, 1)];
    nodes[0].originate(id(1), b"next door".to_vec());
    run_to_quiescence(&mut nodes, &edges);
    assert_eq!(nodes[1].take_inbox(), vec![b"next door".to_vec()]);
}

#[test]
fn carry_forward_across_a_disconnected_mesh() {
    // 0 and 2 are never directly connected. 1 is a courier that first meets 0,
    // carries the message, then later meets 2 and delivers it.
    let mut nodes = vec![MeshNode::new(id(0)), MeshNode::new(id(1)), MeshNode::new(id(2))];

    nodes[0].originate(id(2), b"carried by a courier".to_vec());

    // Phase 1: only 0 and 1 are in range.
    run_to_quiescence(&mut nodes, &[(0, 1)]);
    assert!(nodes[2].take_inbox().is_empty());
    assert!(nodes[1].stored() >= 1, "courier should be carrying the frame");

    // Phase 2: the courier (1) moves and now meets 2.
    run_to_quiescence(&mut nodes, &[(1, 2)]);
    assert_eq!(nodes[2].take_inbox(), vec![b"carried by a courier".to_vec()]);
}

#[test]
fn real_clarity_session_over_the_mesh() {
    // A genuine end-to-end encrypted message travels the mesh; the courier in
    // the middle relays ciphertext it cannot read.
    let alice = Account::generate_with_prekeys(5);
    let mut bob = Account::generate_with_prekeys(5);
    let bob_id = bob.identity_public();

    // Alice needs Bob's bundle; in a pure-mesh setting bundles are exchanged on
    // contact. Here we hand it over directly for the test.
    let bundle = bob.bundle();
    let mut alice_session = Session::initiate(&alice, &bundle).unwrap();
    let wire = alice_session.encrypt(b"mesh secret").unwrap().encode();

    // Route Alice → (courier) → Bob, keyed by Bob's identity.
    let mut nodes = vec![
        MeshNode::new(alice.identity_public()),
        MeshNode::new(id(200)), // courier, unrelated identity
        MeshNode::new(bob_id),
    ];
    nodes[0].originate(bob_id, wire);
    run_to_quiescence(&mut nodes, &[(0, 1), (1, 2)]);

    // The courier relayed but never received a deliverable payload.
    assert!(nodes[1].take_inbox().is_empty());

    // Bob pulls the ciphertext off the mesh and decrypts it.
    let inbox = nodes[2].take_inbox();
    assert_eq!(inbox.len(), 1);
    let incoming = Message::decode(&inbox[0]).unwrap();
    let (_bob_session, plaintext) = Session::respond(&mut bob, &incoming).unwrap();
    assert_eq!(plaintext, b"mesh secret");
}

#[test]
fn frame_encode_decode_roundtrip() {
    let mut origin = MeshNode::with_ttl(id(1), DEFAULT_TTL);
    let frame = origin.originate(id(2), b"blob".to_vec());
    let bytes = frame.encode();
    let back = crate::MeshFrame::decode(&bytes).unwrap();
    assert_eq!(frame, back);
}
