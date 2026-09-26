<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Assurance case

One argument, in four parts, for why RS-Key's security claims hold: what it
promises, what it is defending against, where the trust boundaries run, and why
the design and the implementation are expected to survive contact with each.

This page argues; it does not carry the evidence. Every claim below points at
the page that does, and those pages are where a disagreement should be settled.
It is deliberately short on adjectives and explicit about what it cannot
justify — a residual named here is worth more than a claim nobody can check.

## What is claimed

1. **Secrets do not leave.** The FIDO master seed, resident passkeys, OpenPGP
   and PIV private keys, OATH and OTP secrets, and the PINs never cross the USB
   boundary, and no protocol command exists that exports them — except the one
   deliberate exception, [seed backup](guides/seed-backup.md), which is an
   owner-initiated ceremony and is argued separately in
   [threat-model.md](threat-model.md#seed-backup-the-deliberate-exception).
2. **Use is gated on a human.** Operations that consume a key require the
   authorizations their protocol defines — PIN or UV, physical touch, an
   OpenPGP UIF, a PIV management key — and the gates are spent and enforced
   before the key is touched, not after.
3. **A hostile host cannot corrupt the device.** Every byte arriving over USB is
   parsed by memory-safe code that either answers or refuses; no input sequence
   produces memory corruption, a wedged transport, or a state the next boot
   comes up softer for.
4. **Interruption does not weaken it.** A power cut lands wherever the host
   aims it, and what the device owes across one is that nothing comes back
   weaker: an interrupted write leaves the old value or the new one, a committed
   record still reads back, and no gate is softer on the next boot than it was
   before.
5. **At rest, flash alone is not enough.** On a device whose OTP master key is
   burned, a full flash image does not yield the secrets it stores.
6. **The build is the source.** A published release is reproducible from this
   repository and cryptographically tied to it.

Claim 5 is conditional on purpose: before the OTP burn the seal root derives
from on-chip state an attacker with the chip can reconstruct
([production.md](production.md), [otp-fuses.md](otp-fuses.md)).

## The threat model, in brief

The full statement is [threat-model.md](threat-model.md); it defines four
attackers and the defences compose in tiers, each assuming the ones before it.

| Attacker | Position | Treatment |
|---|---|---|
| Hostile host | Drives every byte over USB, picks when the power dies | Defended: memory safety, protocol gates, write ordering |
| Thief with the powered-off device | Full flash image, no PIN | Defended after the OTP burn: at-rest sealing |
| Attacker who can flash firmware | Replaces the image | Defended by secure boot + anti-rollback; undefended on an unfused board |
| Physical / lab attack | Decapping, glitching, probing | **Out of scope** — the RP2350 is not a secure element |
| Network | — | No network interface exists |

Two boundaries of the model are worth restating here because the rest of this
page leans on them. A compromised, *unlocked* host can drive any operation the
owner has already authorized — a security key attests presence and possession,
not the intent of every byte — and touch requirements bound the rate rather
than eliminate the class. And physical attacks are not merely unmitigated but
architecturally out of reach: the claim is never "the key survives a lab", it
is "the key survives the cable".

## Trust boundaries

Six places where data or execution changes trust level. Each is a place where a
mistake is a vulnerability rather than a bug.

**B1 — the USB cable.** Everything inbound is attacker-controlled: CTAPHID
frames, the CCID bulk stream, ISO-7816 APDUs, CTAP2 CBOR. Crossing inward means
parsing; crossing outward means a status word or a signature, never key
material. This is the boundary every fuzz target sits on.

**B2 — transport to worker.** USB and the transports run on a high-priority
interrupt executor; applet dispatch runs in a single *worker* task on the
thread executor that owns the flash and the TRNG outright
([architecture.md](architecture.md#the-big-picture)). Ownership is the
synchronization — there are no mutexes to get wrong — and the transports cannot
reach persistent state except by handing the worker a request.

**B3 — RAM to flash.** Secrets are sealed before they are stored, at one
chokepoint rather than at each call site: `kbase = HKDF(serial_hash,
otp_master_key)` keys the at-rest seals
([architecture.md](architecture.md#flash-layout)). Crossing this boundary
outward without a seal is the defect class the chokepoint exists to make
visible.

**B4 — the boot chain and the partition table.** The bootrom verifies the
signed image before it runs; the shipped image then carries a partition table
that denies the USB bootloader read and write over the KV range, while secure
code keeps it ([build.md](build.md#the-partition-table)). The firmware's own
provisioning and recovery complete *before* the USB pull-up, so a host never
sees a half-initialized device ([architecture.md](architecture.md#boot-sequence)).

**B5 — the owner.** Touch, the PIN, and on a display build the trusted screen,
are the one channel a hostile host cannot drive. Everything that depends on
"the human agreed" crosses here, which is also why the trusted display is where
a display build's promises concentrate ([guides/display.md](guides/display.md)).

**B6 — source to artifact.** The gate, the release pipeline and the signing keys
sit between a commit and a firmware image someone flashes. Provenance is
published and verifiable ([supply-chain.md](supply-chain.md),
[releases.md](releases.md)).

## Secure design principles, and where each one lands

Saltzer and Schroeder's list, against what the tree actually does. The point of
the exercise is the mismatches it would expose, so a principle that is only
partly honoured says so.

**Economy of mechanism.** `no_std`, no mutexes; one worker owning flash and
TRNG; the async executor supplying the concurrency an earlier design needed a
second core and hand-rolled queues for. Less machinery is fewer states to get
wrong. Partly honoured: there is one heap, which RSA's big integers and FIDO's
boxed ML-DSA keys need and nothing else uses, and it wipes each block it frees.

**Fail-safe defaults.** `alwaysUv` ships on. The harder rule is the one learned
from a defect: a flash read that *fails* must never be laundered into an
absence, because absence is how this tree spells *no PIN set* and *not
provisioned*. A probe whose absent arm would open a gate is answered fallibly
or resolved to the restrictive arm ([threat-model.md](threat-model.md)).

**Complete mediation.** Authorization is re-checked at use, not cached into a
capability: a private-key operation re-reads its slot's algorithm attribute
every time, and a PIN retry is *spent before* the comparison, so a power cut
during verification cannot buy a free guess.

**Open design.** AGPL-3.0-only, a published threat model, a published wire
protocol ([protocol.md](protocol.md)), the formal models and their failures in
the repository ([formal.md](formal.md)). The keys are the only secret; nothing
rests on an unpublished mechanism.

**Separation of privilege.** Distinct authorities gate distinct things —
OpenPGP PW1 and PW3, the PIV management key against the PIV PIN, touch against
knowledge. The irreversible steps (secure-boot signing, OTP fuse burns) are a
separate ceremony under separate keys, performed by a person, never by a build.

**Least privilege.** The partition table denies the USB bootloader access to
the KV store; applets own disjoint file-id ranges and a reset wipes exactly its
own predicate; no applet crate may name another — the count is zero and
`cargo deny` keeps it there ([architecture.md](architecture.md#crates)); CI
workflows declare minimal permissions.

**Least common mechanism.** The per-operation counters live in their own KV
partition so their churn never forces compaction of long-lived records; the
crate graph is tiered with every edge pointing strictly downward, generated and
gated rather than asserted.

**Psychological acceptability.** The LED and the touch button say what the
device is waiting for; the trusted display says what is being signed. A gate
whose reason is invisible gets clicked through, so the visible half is part of
the mechanism, not decoration.

## Common implementation weaknesses, and what stops them

| Weakness | Why it does not happen here | Evidence |
|---|---|---|
| Memory corruption (CWE-119/125/787) | Safe `no_std` Rust; every `unsafe` site enumerated and justified | [unsafe.md](unsafe.md), fuzzing + Miri ([testing.md](testing.md)) |
| Improper input validation (CWE-20) | Every external parser is a fuzz target, with a floor in the gate so the set cannot quietly empty | [testing.md](testing.md) |
| Authentication / authorization bypass (CWE-287/862/863) | Gates spent before use; retry counters and lockout; sequence properties model-checked | [formal.md](formal.md), [assurance-matrix.md](assurance-matrix.md) |
| Weak randomness (CWE-330/338) | RP2350 hardware TRNG with health checks seeding an HMAC-DRBG; no language-default RNG in the image | [threat-model.md](threat-model.md) |
| Cleartext storage of secrets (CWE-312) | One seal chokepoint before anything reaches the store | [architecture.md](architecture.md#flash-layout) |
| Timing side channels (CWE-208) | Constant-time comparisons and blinded private-key paths, audited against the built image | [ct-audit.md](ct-audit.md) |
| Secrets left in memory (CWE-226) | Zeroization on the paths that hold key material | [threat-model.md](threat-model.md#zeroization) |
| Torn write / interrupted state (CWE-367 family) | Per-operation write ordering, stated where the code does it; refinement proofs over the store and reset | [store-refinement.md](store-refinement.md), [reset-refinement.md](reset-refinement.md) |
| Downgrade and rollback (CWE-757) | Secure boot plus the OTP anti-rollback epoch; `bcdDevice` names the build precisely | [anti-rollback.md](anti-rollback.md) |
| Hardcoded credentials (CWE-798) | Test keys exist only behind explicit build knobs; `gitleaks` runs in the pre-commit hook and in the one CI job no change can skip | [build.md](build.md) |
| Vulnerable dependencies (CWE-1395) | `cargo audit`, `cargo deny` and `cargo vet` in the gate; pinned lockfiles; git dependencies restricted | [threat-model.md](threat-model.md#supply-chain--process) |

The argument these rows share is structural rather than per-bug: each weakness
is tied to a gate row that fails, so the countermeasure is checked on every
change instead of being asserted once on this page. Where that is not true —
and the next section is the list — it is said plainly.

## Residuals

What this case does **not** justify:

- **Physical and lab attacks.** Out of scope by construction; the RP2350 is not
  a secure element ([limitations.md](limitations.md)).
- **A compromised unlocked host.** It can use what you have authorized. Touch
  bounds the rate; nothing eliminates the class.
- **Before the OTP burn**, at-rest sealing is not worth much: the root derives
  from on-chip state a chip-level attacker can reconstruct.
- **Hand-written cryptography.** `rsk-mldsa`'s constant-time posture is a
  source-level claim — branch-free reductions, masked norm checks, no secret
  division — not proven at machine code, and none of the post-quantum code has
  had a third-party audit.
- **Platform assumptions are assumptions.** What the silicon owes this design is
  registered, and some entries are still pending a board measurement rather than
  discharged ([platform-assumptions.md](platform-assumptions.md)).
- **Per-site disciplines cannot be gated.** The fallible-probe rule above is
  held by tests at each site and by review, not by a mechanical property; the
  tree carries far more collapsing probes than fallible ones, and which class a
  site belongs to is a judgment.
- **One maintainer.** Review by a second pair of eyes is not a property this
  project can currently claim
  ([GOVERNANCE.md](https://github.com/TheMaxMur/RS-Key/blob/main/GOVERNANCE.md)).

## Checking it yourself

The gate is one command and CI runs exactly it, so the evidence behind this page
is reproducible without special access: [testing.md](testing.md) for the layers,
[reproducing.md](reproducing.md) for the evidence artifacts,
[formal.md](formal.md) for the models and what they do and do not cover. A claim
here that you cannot reproduce is a bug in this page; report it under
[SECURITY.md](https://github.com/TheMaxMur/RS-Key/blob/main/SECURITY.md) if it
is exploitable, and as an issue if it is not.
