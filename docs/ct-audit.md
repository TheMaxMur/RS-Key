<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Constant-time / timing side-channel audit

This is a source-level constant-time and timing side-channel audit of the
RS-Key firmware (Rust, `no_std`, RP2350 / Cortex-M33). Its scope is every
secret-dependent comparison, branch, memory access, and private-key arithmetic
operation that an attacker holding the device can probe over USB (CCID /
ISO-7816 APDUs and CTAPHID / CTAP2): PIN/PUK/password verifiers, the FIDO
`pinUvAuthToken` MAC, OATH and OTP access codes, RSA private operations, and the
hand-written `rsk-rsa` keygen primitives.

> **What this is and isn't.** This is a *source/disassembly* audit: it
> establishes that the generated machine code has no secret-dependent
> branch / early-exit / index on the audited paths. It is **not** a *measured*
> timing study and does not replace an instrumented hardware harness (TVLA /
> Welch t-test). See [Coverage & limits](#coverage--limits).

## Summary

42 candidate sites were examined. **3 were real findings, all fixed** (no
high/critical). The core authentication surface is sound. The project's
hand-rolled constant-time comparison is genuinely constant-time as compiled for
the production target. The PIN/MAC/verifier paths compare one-way derived
verifiers, not raw secrets. The defects were concentrated in two places the
canonical helper did not reach: an unblinded RSA private-exponent
exponentiation on an OpenPGP fallback path, and two raw short-circuiting
comparisons of the OTP slot access code with no rate limit.

## Methodology

Six analysis lenses were applied across the workspace. Each candidate was then
put through **adversarial verification** (default-to-false; a finding survives
only if a concrete secret → observable path is demonstrated at exact
`file:line` with the exploitation model stated), and a **completeness critic**
pass caught sites a single lens would miss. Several constant-time refutations
were corroborated by **disassembling the actual on-device LTO firmware ELF** and
by standalone `thumbv8m` compiles at the production `opt-level=s` and at
`opt-level=3`.

1. Hand-rolled constant-time comparator definitions.
2. Secret-vs-attacker comparisons that bypass the comparator.
3. Secret-dependent control flow / variable work between match and mismatch.
4. Secret-indexed memory access / data-dependent arithmetic.
5. Crypto-primitive usage (are the CT-by-design RustCrypto primitives wrapped
   non-CT? is the hand-written modexp safe?).
6. Status-word / error-path / response-latency oracles.

## Findings (fixed)

| Severity | Location | Issue | Fix |
|---|---|---|---|
| Medium | `crates/rsk-rsa/src/pkcs1v15.rs` (`rsa_raw`; was `rsk-openpgp/src/keys.rs`) | **Unblinded RSA private-exponent modexp.** `rsa_sign` fell through to a raw `m^d mod n` for any input that is not a recognized DigestInfo or standard-length hash (reachable via PSO:CDS and INTERNAL AUTHENTICATE). Unlike the mainline sign/decipher paths, this fallback applied no blinding. A Marvin-class private-key timing path the documented residual did not cover. | The raw operation is now **base-blinded** `(m·rᵉ)ᵈ·r⁻¹ mod n` with a fresh random `r`, so the variable-time exponentiation runs on a base unrelated to caller input. A unit test pins `rsa_raw == m^d mod n` and proves the result is independent of the blinding factor. |
| Medium | `crates/rsk-otp/src/lib.rs` (`cmd_configure`) | **Non-constant-time compare of the 6-byte OTP slot access code** via slice `!=`, a position-of-first-mismatch leak. Reachable over CCID and HID with no PIN gate and **no retry counter**, so the leak collapses brute force from ~2⁴⁸ to ~6·256 probes. The access code authorizes overwriting a slot's key material. | Replaced with the constant-time `rsk_crypto::ct_eq`. |
| Medium | `crates/rsk-otp/src/lib.rs` (`cmd_update`) | Second, byte-identical instance of the same non-CT access-code compare on the slot-update path. | Same fix. |

## Constant-time confirmed

The assurance result. Sites checked and found **correct**:

- **The canonical comparator `rsk_crypto::ct_eq` is constant-time.** Public
  length-equality early-return, then a full-width OR-accumulate with no in-loop
  branch on the accumulator. Verified in the on-device LTO ELF: the inlined
  copies lower to a loop whose only branch is governed by the *public* length
  counter. The secret accumulator is reduced branchlessly. Reproduced from
  source at `opt-level=s` and `opt-level=3`.
- **PIN/PUK/password verifier compares are CT and structurally
  non-amplifiable.** Every verifier site compares 32-byte HKDF/HMAC-**derived**
  verifiers, not raw secret bytes. Even a hypothetical position oracle would
  reveal avalanche-hash bytes, not PIN digits, and the "10ᵏ → k·10"
  counter-defeat does not apply.
- **The `pinUvAuthToken` MAC verify, OATH access-code/HOTP verifies, and PIV
  mutual-auth** all route through the constant-time comparator (PIV against a
  single-use per-session challenge, not the persistent management key).
- **The RSA sign/decipher mainline is blinded** (verified through `rsa`
  0.9.10's `blind`/`unblind` around the secret-exponent CRT modexp), and with
  the fix above, so is the raw fallback.
- **RustCrypto primitives are CT-by-library and not wrapped non-CT:** k256,
  ed25519-dalek, x25519-dalek, ML-KEM/ML-DSA, and the HMAC/HKDF/SHA-2 KDF.
- **Keygen primality primitives are not an attacker oracle:** they operate on
  RNG-generated, single-use, never-disclosed candidates. Production keygen uses
  the branchless incremental sieve.

## Defense-in-depth applied

The five hand-rolled comparators (one canonical plus four byte-identical
duplicates across the applet crates) were **consolidated onto the single
`rsk_crypto::ct_eq`**, and a `core::hint::black_box` barrier was added before its
final reduction. The comparator was already constant-time on the audited
toolchain. The barrier pins that property so a future LLVM/rustc cannot fold the
accumulate into an early-exit branch. It does not change the code generated
today.

## Documented residuals

- **RUSTSEC-2023-0071 "Marvin"** timing channel in the `rsa` crate, accepted as
  mitigated by per-operation base blinding on **all** private-key paths (the
  finding above closed the one path the blinding did not previously cover). See
  [threat-model.md](threat-model.md).
- **`rsk-rsa` keygen modexp secret-indexed window lookup**: a genuine
  secret-dependent *memory-access pattern* over bits of the generated prime, but
  it is **keygen-only, one-shot, and not USB-timing-observable**. On the
  cacheless Cortex-M33 there is no microarchitectural channel. Exploitable only
  via physical EM/power capture of a single keygen event, already out of scope
  ([threat-model.md](threat-model.md)). Optional hardening: build the asm with a
  constant memory-access pattern.

## Coverage & limits

**Covered:** all hand-rolled comparator definitions and call sites; every
PIN/PUK/password/MAC/verifier comparison across FIDO, PIV, OpenPGP, OATH; OTP
slot access-code compares; HOTP/TOTP; RSA private sign/decrypt/raw paths; the
`rsk-rsa` C/asm modexp, sieve, and primality primitives; secret-indexed
lookups; and status-word/error-path oracles.

**What a source/disassembly audit cannot prove:**

- **No measured timing distributions.** This shows the *code* has no
  secret-dependent branch/early-exit/index. It cannot rule out a
  *microarchitectural* channel (e.g. XIP-flash stall variance, data-dependent
  multiplier latency). A definitive statement needs an **instrumented timing
  harness on hardware** with a statistical leakage test (TVLA / Welch t-test).
- **Compiler stability is empirical, not contractual.** The comparator is
  constant-time under the audited toolchain. The `black_box` barrier pins it,
  but the guarantee remains "verified on this build."
- **Physical side channels (power/EM/fault) are explicitly out of scope** and
  unverified here, including the keygen access pattern and any DPA on the
  secure-boot AES, both already noted in the threat model.
- **Third-party crate internals** (RustCrypto, `rsa`/`num-bigint-dig`) were
  audited only at the *usage* boundary. Their own CT properties are inherited
  from upstream and the documented RUSTSEC residual.
