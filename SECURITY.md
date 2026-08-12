# Security Model & Notes

This document is deliberately blunt about what Clarity Messenger protects, what
it does not, and where the original specification was wrong.

## Threat model

**In scope — defended:**

- A **network eavesdropper** reading all traffic: sees only ciphertext and
  routing metadata; cannot read content.
- A **malicious or compromised relay/prekey server**: stores only public keys
  and ciphertext; cannot read, forge, or undetectably modify messages, and
  cannot MITM the key exchange (bundles are identity-signed and client-verified).
- An **active attacker** injecting/replaying/modifying packets: AEAD
  authentication rejects tampering; the ratchet and associated-data binding
  reject replays into the wrong session.
- **Future quantum adversaries** doing "harvest now, decrypt later": the
  ML-KEM-1024 leg of the handshake keeps recorded sessions confidential.
- **Long-term key compromise**: forward secrecy protects past messages; break-in
  recovery protects future ones after the next ratchet step.

**Out of scope — not defended (be honest with users):**

- **Endpoint compromise.** Malware or a physically seized, unlocked device
  reads plaintext. No messenger can prevent this.
- **Metadata / traffic analysis at the relay.** Absent a Tor-style transport,
  the relay operator learns the contact graph, timing, and message sizes. See
  `ARCHITECTURE.md`.
- **Coercion.** Rubber-hose key disclosure is a legal/physical problem, not a
  cryptographic one.
- **Denial of service.** A hostile relay can drop messages (it just can't read
  them). Availability is not guaranteed by a single relay.

## Corrections made to the source specification

The original spec contained several claims that are false or unsound. They were
fixed, not implemented as written:

1. **"ChaCha20-Poly1305 is nonce-misuse resistant."** False — nonce reuse leaks
   the Poly1305 key and breaks integrity. We use **XChaCha20-Poly1305** and
   derive a **unique key+nonce per message** from the ratchet, so reuse cannot
   occur by construction.
2. **Deriving the nonce from a timestamp.** Timestamps collide. Nonces here come
   from HKDF over the unique per-message ratchet key.
3. **A redundant `HMAC-SHA3-256` over every packet on top of the AEAD.** The
   AEAD tag already authenticates. The extra MAC adds key-management surface and
   bugs, not security — removed.
4. **Signing every group message while also claiming deniability.** Signatures
   give *non-repudiation*, the opposite of deniability. Group messaging is
   deferred to MLS, which handles this deliberately.
5. **Fabricated audits, a token economy, and "MI6-grade / unbreakable"
   marketing.** Removed. This code is **unaudited**; it says so plainly.
6. **A bespoke onion network and steganographic transports.** These are worse
   than reusing Tor and are deferred; see `ARCHITECTURE.md`.

## Cryptographic choices

| Purpose | Primitive | Notes |
|---------|-----------|-------|
| Identity signatures | Ed25519 | Signs prekeys; basis of the safety number |
| Classical KEX | X25519 | Four-DH X3DH |
| Post-quantum KEX | ML-KEM-1024 (FIPS 203) | Hybrid; handshake only |
| AEAD | XChaCha20-Poly1305 | Per-message derived key + 192-bit nonce |
| Root/session KDF | HKDF-SHA256 | Domain-separated context strings |
| Chain KDF | HMAC-SHA256 | `0x01` → message key, `0x02` → next chain key |
| Account at rest | OS keystore | Keychain / Android Keystore / libsecret |

All primitives come from the RustCrypto and dalek ecosystems. The core is
`#![forbid(unsafe_code)]`; the only `unsafe` in the project is the thin FFI
boundary, whose contract is documented in `ffi/src/lib.rs`.

## Known limitations (v0.1)

- **Not independently audited.** Do not protect at-risk users with it yet.
- **Metadata**: relay mail now travels in sealed-sender envelopes addressed to
  rotating inbox IDs, so the relay stores no sender and no stable recipient
  identifier. What it can still observe: network addresses and timing (run
  over **Tor** to remove the address linkage), message counts/sizes (padding
  and cover traffic are future work), and identity-keyed prekey *directory*
  fetches, which are inherent to looking up a new contact.
- **Sealed envelopes are not forward-secret for sender metadata**: compromise
  of a recipient's long-term identity DH key lets recorded envelopes be opened
  to reveal *who wrote to them* (message content keeps forward secrecy from
  the ratchet). This matches Signal's sealed-sender trade-off.
- **1:1 only**; no group messaging.
- The relay is **in-memory** (no durable storage, no auth/rate-limiting) — a
  reference implementation, not a hardened production service.

## Reporting a vulnerability

This is a pre-release project. If you find a security issue, please open a
private report to the repository maintainers rather than a public issue. A real
deployment would publish a dedicated security contact and PGP key here.
