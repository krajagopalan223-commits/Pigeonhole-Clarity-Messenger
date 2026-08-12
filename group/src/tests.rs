//! Multi-party group tests driven entirely through the public API.

use super::*;

/// Deliver `blob` to each member's group and assert what each one observes.
fn deliver(blob: &[u8], to: &mut [(&GroupClient, &mut Group)]) -> Vec<GroupEvent> {
    to.iter_mut()
        .map(|(client, group)| group.process(client, blob).expect("process"))
        .collect()
}

#[test]
fn three_member_group_messaging() {
    let alice = GroupClient::generate(b"alice").unwrap();
    let bob = GroupClient::generate(b"bob").unwrap();
    let carol = GroupClient::generate(b"carol").unwrap();

    // Alice creates the group and adds Bob.
    let mut a_group = alice.create_group(b"team-clarity").unwrap();
    let add_bob = a_group.add_member(&alice, &bob.key_package().unwrap()).unwrap();
    let mut b_group = bob.join_group(&add_bob.welcome).unwrap();
    assert_eq!(a_group.members().len(), 2);
    assert_eq!(b_group.members().len(), 2);

    // Alice adds Carol; the commit goes to Bob, the welcome to Carol.
    let add_carol = a_group
        .add_member(&alice, &carol.key_package().unwrap())
        .unwrap();
    assert_eq!(
        deliver(&add_carol.commit, &mut [(&bob, &mut b_group)]),
        vec![GroupEvent::MembershipChanged]
    );
    let mut c_group = carol.join_group(&add_carol.welcome).unwrap();
    assert_eq!(a_group.members().len(), 3);
    assert_eq!(b_group.members().len(), 3);
    assert_eq!(c_group.members().len(), 3);

    // Alice broadcasts; Bob and Carol decrypt, attributing it to Alice.
    let msg = a_group.send(&alice, b"ship it").unwrap();
    let events = deliver(&msg, &mut [(&bob, &mut b_group), (&carol, &mut c_group)]);
    for event in events {
        assert_eq!(
            event,
            GroupEvent::Application {
                sender: b"alice".to_vec(),
                plaintext: b"ship it".to_vec(),
            }
        );
    }

    // Carol replies; Alice and Bob decrypt.
    let reply = c_group.send(&carol, b"already shipping").unwrap();
    let events = deliver(&reply, &mut [(&alice, &mut a_group), (&bob, &mut b_group)]);
    for event in events {
        assert_eq!(
            event,
            GroupEvent::Application {
                sender: b"carol".to_vec(),
                plaintext: b"already shipping".to_vec(),
            }
        );
    }
}

#[test]
fn removed_member_cannot_read_new_messages() {
    let alice = GroupClient::generate(b"alice").unwrap();
    let bob = GroupClient::generate(b"bob").unwrap();
    let carol = GroupClient::generate(b"carol").unwrap();

    let mut a_group = alice.create_group(b"g").unwrap();
    let add_bob = a_group.add_member(&alice, &bob.key_package().unwrap()).unwrap();
    let mut b_group = bob.join_group(&add_bob.welcome).unwrap();
    let add_carol = a_group
        .add_member(&alice, &carol.key_package().unwrap())
        .unwrap();
    deliver(&add_carol.commit, &mut [(&bob, &mut b_group)]);
    let mut c_group = carol.join_group(&add_carol.welcome).unwrap();

    // Alice removes Bob; Carol applies the commit.
    let bob_index = a_group.member_index(b"bob").expect("bob present");
    let remove = a_group.remove_member(&alice, bob_index).unwrap();
    assert_eq!(
        deliver(&remove, &mut [(&carol, &mut c_group)]),
        vec![GroupEvent::MembershipChanged]
    );
    assert_eq!(a_group.members().len(), 2);
    assert!(!a_group.members().contains(&b"bob".to_vec()));

    // A post-removal message from Alice reaches Carol but NOT Bob: Bob's group
    // can no longer process it (he was removed at the last commit).
    let after = a_group.send(&alice, b"members only").unwrap();
    assert_eq!(
        c_group.process(&carol, &after).unwrap(),
        GroupEvent::Application {
            sender: b"alice".to_vec(),
            plaintext: b"members only".to_vec(),
        }
    );
    assert!(
        b_group.process(&bob, &after).is_err(),
        "removed member must not decrypt post-removal traffic"
    );
}

#[test]
fn client_state_survives_export_import() {
    let alice = GroupClient::generate(b"alice").unwrap();
    let bob = GroupClient::generate(b"bob").unwrap();

    let mut a_group = alice.create_group(b"persist-me").unwrap();
    let add_bob = a_group.add_member(&alice, &bob.key_package().unwrap()).unwrap();
    let mut b_group = bob.join_group(&add_bob.welcome).unwrap();

    // Exchange one message so there is live ratchet state to preserve.
    let m = a_group.send(&alice, b"before restart").unwrap();
    assert!(matches!(
        b_group.process(&bob, &m).unwrap(),
        GroupEvent::Application { .. }
    ));

    // "Restart" Bob: export his whole client, drop it, import from bytes, and
    // reload the group from his restored store.
    let saved = bob.export_state().unwrap();
    drop(b_group);
    drop(bob);
    let bob = GroupClient::import_state(&saved).unwrap();
    assert_eq!(bob.identity(), b"bob");
    let mut b_group = bob
        .load_group(b"persist-me")
        .unwrap()
        .expect("group restored from store");

    // The conversation continues across the restart, both directions.
    let m2 = a_group.send(&alice, b"after restart").unwrap();
    assert_eq!(
        b_group.process(&bob, &m2).unwrap(),
        GroupEvent::Application {
            sender: b"alice".to_vec(),
            plaintext: b"after restart".to_vec(),
        }
    );
    let back = b_group.send(&bob, b"still here").unwrap();
    assert_eq!(
        a_group.process(&alice, &back).unwrap(),
        GroupEvent::Application {
            sender: b"bob".to_vec(),
            plaintext: b"still here".to_vec(),
        }
    );
}

#[test]
fn garbage_and_foreign_messages_are_rejected() {
    let alice = GroupClient::generate(b"alice").unwrap();
    let bob = GroupClient::generate(b"bob").unwrap();
    let outsider = GroupClient::generate(b"outsider").unwrap();

    let mut a_group = alice.create_group(b"g").unwrap();
    let add_bob = a_group.add_member(&alice, &bob.key_package().unwrap()).unwrap();
    let mut b_group = bob.join_group(&add_bob.welcome).unwrap();

    // Structurally invalid input is rejected at the API boundary, not panicked.
    assert!(b_group.process(&bob, b"not an mls message").is_err());
    assert!(b_group.process(&bob, &[]).is_err());
    let mut truncated = a_group.send(&alice, b"authentic").unwrap();
    truncated.truncate(truncated.len() / 2);
    assert!(b_group.process(&bob, &truncated).is_err());

    // An outsider's separate group — same id, different epoch and secrets —
    // cannot inject a message into this group.
    let mut o_group = outsider.create_group(b"g").unwrap();
    let foreign = o_group.send(&outsider, b"intrusion").unwrap();
    assert!(b_group.process(&bob, &foreign).is_err());

    // And the authentic message it was cloned from still works, proving the
    // rejections above were about validity, not a wedged group.
    let good = a_group.send(&alice, b"authentic").unwrap();
    assert_eq!(
        b_group.process(&bob, &good).unwrap(),
        GroupEvent::Application {
            sender: b"alice".to_vec(),
            plaintext: b"authentic".to_vec(),
        }
    );
}
