<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Constant-time / timing side-channel audit

This is a source-level constant-time and timing side-channel audit of the
RS-Key firmware (Rust, `no_std`, RP2350 / Cortex-M33). Its scope is every
secret-dependent comparison, branch, memory access, and private-key arithmetic
operation that an attacker holding the device can probe over USB (CCID /
ISO-7816 APDUs and CTAPHID / CTAP2): PIN/PUK/password verifiers, the FIDO
`pinUvAuthToken` MAC, OATH and OTP access codes, RSA private operations, and the
hand-written `rsk-rsa` modexp, sieve and primality primitives — the modexp on
both of its callers, the prime search and the `rsa_private_exp_crt` that PIV
GENERAL AUTHENTICATE and OpenPGP PSO:CDS / INTERNAL AUTHENTICATE / DECIPHER
reach over USB against a long-lived key.

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
| Medium | `crates/rsk-rsa/src/pkcs1v15.rs` (`rsa_raw`; was `rsk-openpgp/src/keys.rs`) | **Unblinded RSA private-exponent modexp.** `rsa_sign` fell through to a raw `m^d mod n` for any input that is not a recognized DigestInfo or standard-length hash (reachable via PSO:CDS and INTERNAL AUTHENTICATE). Unlike the mainline sign/decipher paths, this fallback applied no blinding. A Marvin-class private-key timing path the documented residual did not cover. | The raw operation is now **base-blinded** `(m·rᵉ)ᵈ·r⁻¹ mod n` with a fresh random `r`, so the variable-time exponentiation runs on a base unrelated to caller input. A unit test pins `rsa_raw == m^d mod n` and proves the result is independent of the blinding factor. Since 0x0A4F neither exists: `rsa_raw` went with the full-key `rsa_sign` that fell back to it, once PIV stopped writing certificates. The raw private operation left, PIV GENERAL AUTHENTICATE's over a host-padded block, runs on the blinded asm CRT core. |
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
- **The RSA sign/decipher mainline is blinded** — one helper inside `rsk-rsa`
  draws a fresh `r` around every secret-exponent modexp, asm CRT and software
  alike, and with the fix above so was the raw fallback, until 0x0A4F removed
  it. (Re-checked at 0.4.12, when the operation moved off `rsa` 0.9.10's own
  `blind`/`unblind`.)
- **RustCrypto primitives are CT-by-library and not wrapped non-CT:** k256,
  ed25519-dalek, x25519-dalek, ML-KEM/ML-DSA, and the HMAC/HKDF/SHA-2 KDF.
- **Keygen primality primitives are not an attacker oracle:** they operate on
  RNG-generated, single-use, never-disclosed candidates. Production keygen uses
  the branchless incremental sieve.

## What the image says

<!-- ct-sites:start -->
<!-- Generated by scripts/ct_gate.py --write; do not edit. -->

Read out of `target/thumbv8m.main-none-eabihf/release/firmware` with `arm-none-eabi-objdump -d -l --inlines`, built by clang LLVM (rustc version 1.96.0 (ac68faa20 2026-05-25)). A site's verdict is `constant-time` when no conditional branch inside any address run the inline chain attributes to it reads flags set from a buffer load; the callers are the first-party frames those chains name, so a surface that stops routing through the site leaves this table.

| Site | Class | Verdict | Surfaces that inline it |
|---|---|---|---|
| `rsk_crypto::mac::ct_eq` | comparator | constant-time | CTAP pinUvAuthProtocol MAC verify, FIDO device-local PIN verify, FIDO's forwarder onto the canonical comparator, FIDO device-PIN hash verify, FIDO clientPIN hash verify, panel path, FIDO clientPIN hash verify, FIDO credential key-handle verify, vendor device-PIN gate, pad path, vendor device-PIN gate, OATH SET CODE, OATH VALIDATE, OATH PIN match helper, OATH PIN-gated code match, OATH's forwarder onto the canonical comparator, OpenPGP default reset-code neutralisation, OpenPGP PW1/PW3/RC verify, OpenPGP's forwarder onto the canonical comparator, OTP slot configure access code, OTP command dispatch access code, OTP slot swap access code, OTP slot swap access code, inner, OTP slot update access code, OTP access-code sweep, PIV slot metadata default-value check, PIV mutual authenticate, PIV single authenticate, PIV PIN/PUK reference verify, PIV's forwarder onto the canonical comparator |

<!-- ct-sites:end -->

**What holds which half of this page.** Only the table above is derived:
`scripts/ct_gate.py` rebuilds it from the image on every gate run, and the row
goes red when a surface stops routing through the comparator or a new one starts.
The prose around it is held by almost nothing — `claims_gate` fires only on a
sentence naming a registered `SEC-…` id, and this page names none. Measured with
a refuted scope sentence in place: the claims, run-count and constant-time gates
and `docs.sh check` were all exit 0, and the citation gate, red that day over
line drift in other files, said nothing about this page. The single exception is
the scope paragraph at the top of this page. `ct_gate` anchors on its `rsk-rsa`
clause and asks three things of the paragraph that carries it: it must name the
modexp and the `rsa_private_exp_crt` that reaches it over USB, it may not
re-scope them to key generation, and it may not be one of two paragraphs
carrying the anchor, because an earlier one would shield it. Anchored instead on
a sentence five lines above the clause and refusing one spelling of one word,
the rule was walked past thirteen ways — a synonym, eight spellings, the clause
moved into a list, a decoy paragraph, and an editor inserting a blank line.
Nothing holds the findings table, the residuals, or this sentence.

## Defense-in-depth applied

The five hand-rolled comparators (one canonical plus four byte-identical
duplicates across the applet crates) were **consolidated onto the single
`rsk_crypto::ct_eq`**, and a `core::hint::black_box` barrier was added before its
final reduction. The comparator was already constant-time on the audited
toolchain. The barrier pins that property so a future LLVM/rustc cannot fold the
accumulate into an early-exit branch. It does not change the code generated
today.

## Documented residuals

- **The RSA private operation is now entirely in-tree.** The `rsa` crate left in
  0.4.12 and RUSTSEC-2023-0071 ("Marvin") with it, so that residual is closed as
  a dependency question — but the mitigation it named is what remains load-bearing:
  every private-key path, asm CRT and software alike, is base-blinded per
  operation, and none of them is exempt. See [threat-model.md](threat-model.md).
- **`rsk-rsa` modexp secret-indexed window lookup**: the window index is a secret
  nibble — of the candidate in the keygen prime search, and of `dP`/`dQ` in
  `rsa_private_exp_crt`, which both reach the same
  `bignum_modexp_private_exponent_internal`. It folds into the table's base
  pointer instead of steering a branch, so the instruction sequence per nibble is
  the same whatever the nibble is and only the *address* changes
  (`crates/rsk-rsa/csrc/bignum_high_level.c`, the `#else` arm that
  `CONSTANT_MEMORY_ACCESS_PATTERN 0` in `crates/rsk-rsa/csrc/bignum_config.h`
  selects).

  *There is no XIP-cache channel — and not because the core is cacheless.* The
  RP2350 does put a cache in front of its QSPI flash, and it is load-bearing
  enough that hot loops were moved out of XIP to escape it
  ([architecture.md](architecture.md), [limitations.md](limitations.md),
  [testing.md](testing.md)). That cache sits on the *flash* path, and neither end
  of this access is on it. The table is the `temp` array the Rust caller declares
  as a stack local (`crates/rsk-rsa/src/lib.rs`, `modexp_priv` and `sign_crt`),
  and every stack it can sit on is SRAM: core0's, which the linker bounds with
  `_stack_end` and `_stack_start`, and — for the keygen half, which core1 runs
  too — core1's `CORE1_STACK` (`firmware/src/core1.rs`), a `.bss` static outside
  that pair and SRAM by the same script. The code that reads it is SRAM-resident
  by link section: the C carries `BIGNUM_RAMFUNC`, which is
  `section(".data.bignum_hl")`, and the `bignum_mulacc` that performs the load
  has `.section .data.bignum_asm` for its whole translation unit. Confirmed in
  the on-device ELF rather than inferred from the sections: both symbols resolve
  to RAM addresses, while `bignum_modexp_public_exponent` resolves to flash. That
  is not a property of the one image read: `crates/rsk-rsa/build.rs` compiles the
  C and the asm unconditionally for `target_os = "none"` with no feature gate,
  and neither of the crate's two features reaches a firmware image, so every
  shipped flavour links the same sections. The CRT path is worth reading in the
  image and not in the source, because `rsa_private_exp_crt` itself stays in
  flash and only the inner modexp it shares with keygen is moved. "The
  Cortex-M33 is cacheless" was true of the core's own data path and false as a
  statement about the SoC, which is why it disagreed with every other page here.

  *What that does not settle.* An SRAM access is not a cache access, but it is
  not nothing. Two mechanisms could still turn the address into a time, and this
  audit measures neither: SRAM banking, and data-dependent multiplier latency
  inside `bignum_mulacc`. The banking half is an assumption and not a finding —
  *if* the bank a cycle touches follows the address, then a secret nibble picks
  it, and nothing in this tree establishes that. It is the conservative reading
  of the SoC's memory organisation; the nearest in-tree note
  (`firmware/src/core1.rs`, the core1-stats counters) is about cross-core
  XIP/bus contention rather than SRAM banks, and citing it here would be citing
  the wrong thing. Deciding either mechanism needs the instrumented hardware
  harness [Coverage & limits](#coverage--limits) asks for, and both are
  unmeasured here in both directions. Physical EM/power capture stays out of
  scope ([threat-model.md](threat-model.md)). What is no longer claimed is the
  bound: the CRT path is reached over USB and runs on a long-lived `dP`/`dQ`, so
  this is not a one-shot keygen event, and the base blinding above does not
  answer it — blinding randomizes the base, not the exponent nibbles that choose
  the window. Concurrency belongs to the keygen half alone: the prime filter
  races this modexp on both cores, and core1 takes nothing but keygen jobs
  (`firmware/src/core1.rs`), so the USB-reachable sign/decrypt path runs it
  single-core. Hardening: build the asm with `CONSTANT_MEMORY_ACCESS_PATTERN 1`,
  which selects the branchless `bignum_table_select` over the whole table —
  proposed, not tested. Nothing in this tree ever compiles that arm: the vendored
  header defines it `0` and recommends that value for Cortex-M, no build
  overrides it, `bignum_table_select` is absent from the image, and the same
  switch pulls in an in-place table transpose that has never been built either.

  *Severity: LOW, recorded rather than left pending.* It is registered as
  `PLAT-CRYPTO-002` in [platform-assumptions.md](platform-assumptions.md) with
  the four surfaces, the blinding gap, the absent cache channel and the triggers
  that re-open it. What makes it low is the OBSERVATION and not the code:
  recovering the window sequence needs a time-resolved look inside one operation,
  and no in-scope observer has one. On all four surfaces the private operation
  runs to completion before any response byte leaves, and the 61xx / GET RESPONSE
  chaining that may follow is transport-level (`crates/rsk-device/src/ccid.rs`)
  over a buffer already computed — so a host measures a single end-to-end
  latency, and the exponent is fixed for the life of the key, so that latency is
  the same scalar for every signature and carries nothing about which nibble sat
  where. The observer that would hold a time-resolved trace is the power/EM
  prober [threat-model.md](threat-model.md) §4 puts out of scope. Two things keep
  this a residual rather than a non-issue. Nothing has measured whether an RP2350
  SRAM read's cycle count follows its address at all — the paragraph above says
  so, in both directions. And the arithmetic that stands in for that measurement
  is a bound and not a result: the sixteen entries are `temp + k·half` with
  `half` a multiple of 32 bytes, so they share every address bit below 32 and
  each read is a contiguous multiple-of-32-byte run, which no stripe whose period
  divides 32 bytes can tell apart and which a high-bit-selected bank holds whole
  at ≤ 4 KiB.

  *The hardening is DEFERRED, not declined.* `CONSTANT_MEMORY_ACCESS_PATTERN 1`
  is registered as `PLAT-BUILD-005` with its price, and the price is why it is
  not simply flipped. It has never been built here and cannot be validated here:
  `crates/rsk-rsa/build.rs` compiles the C and the asm only for
  `target_os = "none"`, so no host test and no `tools/emu` run reaches that arm,
  and the transpose it pulls in is exercised by an on-card RSA sign at each of
  the three widths and by nothing else. The Bellcore check makes a wrong
  transpose a refused signature rather than a bad one, so a passing on-card sign
  IS the proof — and a failing one is a key that stops working. Cost, counted
  from the instruction mix and not measured: `bignum_table_select` reads
  16 × `half` bytes per window where the shipped arm reads `half`, against a
  window that already spends four squarings and one multiply, so the overhead is
  of the order of a tenth of the private operation and larger at RSA-2048 than at
  RSA-4096 — the multiply grows quadratically in the width and the scan only
  linearly. It costs SRAM and not only flash: the C half is `BIGNUM_RAMFUNC`
  (`section(".data.bignum_hl")`) and the asm's whole translation unit is
  `.section .data.bignum_asm`. What would settle it: one firmware build with the
  flag defined, then a board run of the three widths and a before/after timing of
  one PIV GENERAL AUTHENTICATE.

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
  unverified here — physical capture of the modexp window-lookup access pattern,
  and any DPA on the secure-boot AES, both already noted in the threat model.
  What is out of scope is the *capture*. The lookup itself is not keygen-only:
  its USB-reachable half stands open and unmeasured under
  [Documented residuals](#documented-residuals), not excluded.
- **Third-party crate internals** (RustCrypto, `num-bigint-dig`) were audited
  only at the *usage* boundary. Their own CT properties are inherited from
  upstream — `num-bigint-dig`'s exponentiation is variable-time, which is what
  the blinding above exists to answer for.
