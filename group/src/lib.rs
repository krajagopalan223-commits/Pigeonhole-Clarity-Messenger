//! # clarity-group
//!
//! Group messaging for Clarity, built on **MLS (RFC 9420)** via the audited
//! [OpenMLS](https://openmls.tech) library — deliberately *not* a bespoke
//! TreeKEM. The source specification proposed a hand-rolled group protocol that
//! signed every message while claiming deniability (contradictory) and would
//! have been unaudited home-grown group cryptography. MLS is the standard that
//! solves this problem correctly, with forward secrecy and post-compromise
//! security across membership changes, so this crate wraps it rather than
//! reinventing it. See `STATUS.md` and `SECURITY.md`.
//!
//! ## Model
//!
//! A [`GroupClient`] is one user's long-lived MLS identity plus its key store
//! (an OpenMLS provider). It publishes [`GroupClient::key_package`] bytes the
//! way 1:1 identities publish prekey bundles, and its whole state persists via
//! [`GroupClient::export_state`] / [`GroupClient::import_state`] for
//! encrypted-at-rest storage.
//!
//! A [`Group`] is one conversation. The creator calls [`Group::create`]; adding
//! a member yields a **commit** (fan out to existing members) and a **welcome**
//! (send to the newcomer). Every inbound blob — application message or membership
//! change — goes through [`Group::process`], which returns a [`GroupEvent`].
//!
//! All bytes crossing these APIs are opaque, transport-ready TLS-serialized MLS
//! messages: they ride the same sealed-envelope + relay path as 1:1 traffic, so
//! the relay learns nothing new. Fan-out (delivering each commit/message to
//! every member) is the caller's job — MLS is delivery-agnostic.
//!
//! ## Scope
//!
//! This crate is the tested protocol foundation. Wiring it through the FFI and
//! into the Flutter app (group creation UI, member management, group chat, and
//! commit fan-out over the relay) is deliberately left to follow-up work.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

/// The MLS ciphersuite Clarity uses: X25519 + AES-128-GCM + SHA-256 + Ed25519.
/// The mandatory-to-implement suite, matching the classical half of the 1:1
/// stack. (A post-quantum MLS suite is future work, as it is for the ratchet.)
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

const MLS_VERSION: ProtocolVersion = ProtocolVersion::Mls10;

/// Everything that can go wrong in this crate. Coarse on purpose.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("MLS operation failed: {0}")]
    Mls(String),
    #[error("serialization failed: {0}")]
    Codec(String),
    #[error("group state is corrupt or incompatible")]
    State,
    #[error("no such group")]
    UnknownGroup,
}

pub type Result<T> = std::result::Result<T, Error>;

fn mls<T, E: std::fmt::Debug>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| Error::Mls(format!("{e:?}")))
}

fn codec<T, E: std::fmt::Debug>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| Error::Codec(format!("{e:?}")))
}

/// One user's MLS identity and key store. Persist with [`export_state`].
///
/// [`export_state`]: GroupClient::export_state
pub struct GroupClient {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    identity: Vec<u8>,
}

impl GroupClient {
    /// Create a fresh MLS identity named `identity` (an application-level name
    /// or, in Clarity, the user's Ed25519 identity key bytes).
    pub fn generate(identity: &[u8]) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = mls(SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()))?;
        mls(signer.store(provider.storage()))?;
        let credential = BasicCredential::new(identity.to_vec());
        let credential = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        Ok(GroupClient {
            provider,
            signer,
            credential,
            identity: identity.to_vec(),
        })
    }

    /// This client's identity bytes.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// A fresh key package to publish, so others can add this client to a group.
    /// Each should be consumed once, like a one-time prekey.
    pub fn key_package(&self) -> Result<Vec<u8>> {
        let bundle = mls(
            KeyPackage::builder().build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            ),
        )?;
        codec(bundle.key_package().tls_serialize_detached())
    }

    /// Start a new group with `group_id`, with this client as the sole member.
    pub fn create_group(&self, group_id: &[u8]) -> Result<Group> {
        let config = MlsGroupCreateConfig::builder()
            // Carry the ratchet tree in the group info / welcome so a newcomer
            // can join without a separate tree fetch.
            .use_ratchet_tree_extension(true)
            .build();
        let mls_group = mls(MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential.clone(),
        ))?;
        Ok(Group { mls_group })
    }

    /// Join a group from a `welcome` produced by [`Group::add_member`].
    pub fn join_group(&self, welcome: &[u8]) -> Result<Group> {
        let message = codec(MlsMessageIn::tls_deserialize(&mut &welcome[..]))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(Error::Mls("expected a welcome message".into())),
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = mls(StagedWelcome::new_from_welcome(
            &self.provider,
            &config,
            welcome,
            None,
        ))?;
        let mls_group = mls(staged.into_group(&self.provider))?;
        Ok(Group { mls_group })
    }

    /// Re-open a group this client already belongs to, by id. Returns `None`
    /// if the client's store has no such group.
    pub fn load_group(&self, group_id: &[u8]) -> Result<Option<Group>> {
        let loaded = mls(MlsGroup::load(
            self.provider.storage(),
            &GroupId::from_slice(group_id),
        ))?;
        Ok(loaded.map(|mls_group| Group { mls_group }))
    }

    /// Serialize the whole client (identity, signer, key store, and every group
    /// it belongs to) for encrypted-at-rest persistence. The result is SECRET.
    ///
    /// The key store is the provider's `MemoryStorage`, whose `values` map is
    /// serialized directly — no dependency on OpenMLS test-only helpers.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::State)?;
        let mut store_bytes = Vec::new();
        store_bytes.extend_from_slice(&(values.len() as u32).to_le_bytes());
        for (k, v) in values.iter() {
            store_bytes.extend_from_slice(&(k.len() as u32).to_le_bytes());
            store_bytes.extend_from_slice(k);
            store_bytes.extend_from_slice(&(v.len() as u32).to_le_bytes());
            store_bytes.extend_from_slice(v);
        }
        let public = self.signer.public().to_vec();
        Ok(frame(&[&self.identity, &public, &store_bytes]))
    }

    /// Restore a client from [`export_state`] bytes.
    ///
    /// [`export_state`]: GroupClient::export_state
    pub fn import_state(bytes: &[u8]) -> Result<Self> {
        let parts = unframe(bytes, 3).ok_or(Error::State)?;
        let identity = parts[0].to_vec();
        let public = parts[1];

        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider.storage().values.write().map_err(|_| Error::State)?;
            let store_bytes = parts[2];
            let mut cur = Cursor::new(store_bytes);
            let count = cur.read_u32().ok_or(Error::State)?;
            for _ in 0..count {
                let k = cur.read_bytes().ok_or(Error::State)?;
                let v = cur.read_bytes().ok_or(Error::State)?;
                values.insert(k.to_vec(), v.to_vec());
            }
            if !cur.is_done() {
                return Err(Error::State);
            }
        }

        let signer =
            SignatureKeyPair::read(provider.storage(), public, CIPHERSUITE.signature_algorithm())
                .ok_or(Error::State)?;
        let credential = BasicCredential::new(identity.clone());
        let credential = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        Ok(GroupClient {
            provider,
            signer,
            credential,
            identity,
        })
    }
}

/// Bytes to send to existing members (`commit`) and to the newcomer (`welcome`)
/// after [`Group::add_member`].
pub struct AddResult {
    /// Commit to fan out to every existing member; apply locally already done.
    pub commit: Vec<u8>,
    /// Welcome to send to the newly-added member only.
    pub welcome: Vec<u8>,
}

/// What an inbound message turned out to be, after [`Group::process`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupEvent {
    /// A decrypted application message and its sender's identity bytes.
    Application { sender: Vec<u8>, plaintext: Vec<u8> },
    /// A membership change (add/remove/update) was applied to the group.
    MembershipChanged,
    /// A bare proposal was received and staged; nothing to show yet.
    Proposal,
}

/// One MLS group conversation. Operations take the owning [`GroupClient`] so
/// they can reach its key store and signer.
pub struct Group {
    mls_group: MlsGroup,
}

impl Group {
    /// This group's id.
    pub fn group_id(&self) -> Vec<u8> {
        self.mls_group.group_id().as_slice().to_vec()
    }

    /// Identity bytes of every current member.
    pub fn members(&self) -> Vec<Vec<u8>> {
        self.mls_group
            .members()
            .filter_map(|m| basic_identity(&m.credential))
            .collect()
    }

    /// Add a member from their published key-package bytes. Returns the commit
    /// (for existing members) and welcome (for the newcomer). The change is
    /// merged into this local group before returning.
    pub fn add_member(&mut self, client: &GroupClient, key_package: &[u8]) -> Result<AddResult> {
        let kp_in = codec(KeyPackageIn::tls_deserialize(&mut &key_package[..]))?;
        let kp = mls(kp_in.validate(client.provider.crypto(), MLS_VERSION))?;
        let (commit, welcome, _group_info) = mls(self.mls_group.add_members(
            &client.provider,
            &client.signer,
            &[kp],
        ))?;
        mls(self.mls_group.merge_pending_commit(&client.provider))?;
        Ok(AddResult {
            commit: codec(commit.tls_serialize_detached())?,
            welcome: codec(welcome.tls_serialize_detached())?,
        })
    }

    /// Remove the member at `member_index` (see [`Group::member_index`]).
    /// Returns the commit to fan out; merged locally before returning.
    pub fn remove_member(&mut self, client: &GroupClient, member_index: u32) -> Result<Vec<u8>> {
        let (commit, _welcome, _group_info) = mls(self.mls_group.remove_members(
            &client.provider,
            &client.signer,
            &[LeafNodeIndex::new(member_index)],
        ))?;
        mls(self.mls_group.merge_pending_commit(&client.provider))?;
        codec(commit.tls_serialize_detached())
    }

    /// The leaf index of the member with the given identity, if present — the
    /// handle [`Group::remove_member`] takes.
    pub fn member_index(&self, identity: &[u8]) -> Option<u32> {
        self.mls_group.members().find_map(|m| {
            (basic_identity(&m.credential).as_deref() == Some(identity)).then_some(m.index.u32())
        })
    }

    /// Encrypt an application message for the group. Returns transport-ready
    /// bytes to fan out to every other member.
    pub fn send(&mut self, client: &GroupClient, plaintext: &[u8]) -> Result<Vec<u8>> {
        let out = mls(
            self.mls_group
                .create_message(&client.provider, &client.signer, plaintext),
        )?;
        codec(out.tls_serialize_detached())
    }

    /// Process an inbound message — application data or a membership commit —
    /// applying any membership change to the local group.
    pub fn process(&mut self, client: &GroupClient, message: &[u8]) -> Result<GroupEvent> {
        let msg = codec(MlsMessageIn::tls_deserialize(&mut &message[..]))?;
        let protocol = mls(msg.try_into_protocol_message())?;
        let processed = mls(self.mls_group.process_message(&client.provider, protocol))?;
        let sender = basic_identity(processed.credential()).unwrap_or_default();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(GroupEvent::Application {
                sender,
                plaintext: app.into_bytes(),
            }),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                mls(self.mls_group.merge_staged_commit(&client.provider, *staged))?;
                Ok(GroupEvent::MembershipChanged)
            }
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => Ok(GroupEvent::Proposal),
        }
    }
}

/// Extract the identity bytes from a basic credential, if it is one.
fn basic_identity(credential: &Credential) -> Option<Vec<u8>> {
    BasicCredential::try_from(credential.clone())
        .ok()
        .map(|b| b.identity().to_vec())
}

/// Length-prefix each field as `[u32-le len][bytes]` and concatenate.
fn frame(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// Inverse of [`frame`]; returns exactly `count` fields or `None` if malformed.
fn unframe(bytes: &[u8], count: usize) -> Option<Vec<&[u8]>> {
    let mut cur = Cursor::new(bytes);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(cur.read_bytes()?);
    }
    cur.is_done().then_some(out)
}

/// A tiny forward-only reader for `[u32-le len][bytes]` framing.
struct Cursor<'a> {
    bytes: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, i: 0 }
    }

    fn read_u32(&mut self) -> Option<u32> {
        let end = self.i.checked_add(4)?;
        let v = u32::from_le_bytes(self.bytes.get(self.i..end)?.try_into().ok()?);
        self.i = end;
        Some(v)
    }

    fn read_bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.read_u32()? as usize;
        let end = self.i.checked_add(len)?;
        let out = self.bytes.get(self.i..end)?;
        self.i = end;
        Some(out)
    }

    fn is_done(&self) -> bool {
        self.i == self.bytes.len()
    }
}

#[cfg(test)]
mod tests;
