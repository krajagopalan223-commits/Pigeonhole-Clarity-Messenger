# Running Clarity in a Trusted Execution Environment

You asked for the core to run "at the kernel level." The security-correct way to
get that property is **not** to put the messenger *in* the kernel (that maximizes
attack surface at the highest privilege — see `SECURITY.md`), but to isolate the
secrets *from* the kernel inside a **Trusted Execution Environment (TEE)**. This
document explains the boundary Clarity implements and how it maps onto each
platform's real hardware.

## The boundary (implemented + tested)

`clarity-core::enclave::Enclave` is a **stateless** trusted core:

- It holds one secret in trusted memory: a **sealing key**.
- Every operation takes **sealed state in** and returns **sealed state out**.
- The untrusted host only ever sees `Sealed` blobs (opaque AEAD) and ciphertext
  — never plaintext keys or ratchet state.

```
   host (untrusted)                    enclave (trusted)
   ────────────────                    ─────────────────
   Sealed account  ─────initiate────►  open→run→re-seal
   Sealed session  ◄───────────────    (seal key never leaves)
   Message (ct)    ◄──────encrypt───   open→advance→re-seal
```

This is exactly the marshalling shape of an SGX `ECALL`, a TrustZone secure-world
call, or a Secure Enclave / StrongBox key operation. Because `clarity-core` is
`#![forbid(unsafe_code)]` and builds `no_std`, the *same* code compiles inside
an enclave with no changes.

The tests in `core/src/tests.rs` drive an entire two-party conversation through
the sealed ABI and assert that sealed blobs are opaque, enclave-bound, and
tamper-evident.

## Two levels of integration

| Level | What it protects | Effort | Where the seal key lives |
|-------|------------------|--------|--------------------------|
| **1. Hardware-sealed keys** | Secrets at rest are bound to the device's secure hardware; a rooted OS can't extract them | Modest, available on all targets today | Secure Enclave / StrongBox / TPM |
| **2. Full in-enclave execution** | The ratchet itself runs isolated from the OS kernel; even a kernel compromise can't read live session state | Larger, platform SDK required | Inside SGX / TrustZone |

The `Enclave` type is written so you can adopt Level 1 now and Level 2 later
without changing the protocol code.

## Per-platform mapping

### iOS / macOS — Secure Enclave (SEP)
Generate the sealing key as a **Secure Enclave key**
(`kSecAttrTokenIDSecureEnclave`, non-extractable, optionally gated by Face ID /
Touch ID). `clarity-core` runs in the app process, but `Enclave`'s seal/unseal
delegates to the SEP-resident key, so account and session blobs are bound to
hardware. (Apple does not allow arbitrary code inside SEP, so Level 2 is not
available on iOS — Level 1 is the ceiling here, and it's strong.)

### Android — StrongBox Keystore / TrustZone
- **Level 1:** hold the sealing key in the **StrongBox** Keystore
  (`setIsStrongBoxBacked(true)`), a dedicated secure element; hardware-bound,
  non-extractable.
- **Level 2:** compile `clarity-core` (`no_std`) into a **Trusty TA** (TrustZone
  trusted application); the `Enclave` API becomes the TA's IPC surface.

### Linux / desktop — TPM 2.0, SGX, or SEV
- **Level 1:** seal the key with a **TPM 2.0** (`TPM2_Create` under the storage
  hierarchy); the key only unseals on the same machine/PCR state.
- **Level 2:** run `clarity-core` **inside an Intel SGX enclave** via
  [Gramine](https://gramineproject.io/), [Occlum](https://occlum.io/), or
  [Fortanix EDP](https://edp.fortanix.com/) (`x86_64-fortanix-unknown-sgx`
  target). The `Enclave` methods are the `ECALL` boundary verbatim. AMD **SEV-SNP**
  is the VM-level alternative.

## What's built here vs. what a device build adds

- **Built + tested (portable):** the enclave boundary, the sealing discipline,
  the "secrets never cross unsealed" invariant, and session serialization.
- **Per-device (not buildable in CI, needs the target + SDK):** binding the
  sealing key to SEP/StrongBox/TPM (Level 1), and producing the enclave binary
  for SGX/TrustZone (Level 2). Follow the platform notes above.

> Honest caveat: a TEE raises the bar a lot, but it is not magic. Side-channel
> attacks against SGX/TrustZone are an active research area, and Level 1 still
> runs the ratchet in app memory. Treat this as defense in depth, not a
> guarantee, and keep the plan for an independent audit.
