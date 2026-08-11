# Original Clarity source documents

These are the two documents that kicked off this project, preserved **verbatim**
as extracted text so every engineering decision in this repo can be traced back
to what was originally asked for.

| File | What it is |
|------|-----------|
| [`clarity-technical-specification-v1.0.txt`](clarity-technical-specification-v1.0.txt) | *Clarity Messenger — Technical Architecture & Security Specification v1.0* (16 pages, 14 sections) |
| [`clarity-mi6-grade-overview.txt`](clarity-mi6-grade-overview.txt) | *Clarity Messenger: MI6-Grade Encrypted Communication* — the positioning/architecture overview deck |

> ⚠️ **Handling.** The specification carries the marking
> *"CONFIDENTIAL — Internal Technical Distribution Only"*, and the closing page
> asserts confidential and proprietary status. This repository is currently
> **private**, which is why these documents are committed here. **Do not make
> this repository public without first removing `docs/source/` or clearing the
> documents for release.**

## Why they are kept

The specification is a genuinely ambitious and, in places, well-informed
document — the hybrid post-quantum key exchange, the untrusted prekey server,
the three-tier key hierarchy, and the rotating inbox identifiers are all sound
ideas that this implementation adopts. It is also, in places, factually wrong
about cryptography, and it presents audits, a token economy, and shipped
platforms that do not exist.

Keeping the originals in-tree means:

1. **Traceability** — [`../../STATUS.md`](../../STATUS.md) maps every one of the
   spec's 14 sections to what was built, deferred, or corrected.
2. **Accountability** — the corrections in [`../../SECURITY.md`](../../SECURITY.md)
   quote real claims from a real document rather than a paraphrase.
3. **Honesty** — the gap between the document and the code is the most useful
   artifact this project has. It should stay visible.

## Important: these documents are not a specification of what was built

Read them as **product intent**, not as a description of this codebase. Where
the two disagree, the code and [`../../SECURITY.md`](../../SECURITY.md) are
authoritative. In particular the source documents contain claims that are
**false, unverified, or aspirational**:

- Cryptographic errors (e.g. "Poly1305 … provides strong integrity guarantees
  even under nonce reuse" — it does not; see `SECURITY.md` §Corrections).
- **Audits that have not happened.** The spec lists completed Trail of Bits,
  NCC Group, Cure53, and Quarkslab audits with finding counts and report URLs.
  No audit of this code has taken place.
- **Infrastructure and adoption that do not exist** — a 500–5,000 node relay
  network, a CLR utility token, published bug-bounty payouts, shipped iOS /
  Android / Web / macOS / Windows / Linux clients, a status page, and
  `clarity.app` endpoints.
- **Competitive claims** presented as fact, including characterizations of
  Signal's group forward secrecy and audit history.

None of these should be repeated in marketing, investor, or user-facing material
on the strength of these documents.
