# Threat model

What RS-Key defends against, what it deliberately does not, and the honest
residuals in between. The defenses compose in tiers: each one assumes the
ones before it.

![What RS-Key defends and what is out of scope — attacker-controlled USB bytes enter the RP2350 and pass through three composing tiers: memory-safe parsers (safe Rust plus fuzzing), then protocol gates (PIN/UV, touch, management key), then the key material, which is additionally protected by an at-rest seal meaningful after the OTP master-key burn; physical and lab attacks and a compromised, unlocked host are explicitly out of scope and reach the device undefended, since the RP2350 is not a secure element](images/threat-tiers.svg)

## Assets

The FIDO master seed (every non-resident credential derives from it),
resident passkeys, OpenPGP private keys and their DEK chain, PIV private
keys, OATH secrets, OTP slot secrets, PINs.

## Attackers, strongest defense first

### 1. A hostile host (malware on the computer)

Everything arriving over USB is attacker-controlled: CTAPHID frames, the CCID
bulk stream, ISO-7816 APDUs, CTAP2 CBOR. Defenses:

- **Memory safety.** `no_std` Rust end to end. The parsers and applet
  dispatch are safe code. The handful of `unsafe` sites are enumerated and
  justified in [unsafe.md](unsafe.md).
- **Fuzzing.** Every parser and every applet's full dispatch path has a
  `cargo-fuzz` target (30+). See [testing.md](testing.md).
- **Protocol gates.** PINs/UV with retry counters and lockout, physical-touch
  requirements on FIDO operations and OpenPGP UIF, OATH access codes, PIV
  management-key auth.
- What a hostile host **can** do: drive any operation you have authorized
  while the device is plugged in and unlocked (sign, decrypt, assert). A
  security key authenticates *presence and possession*, not the intent of
  every byte the host sends. Touch requirements bound the rate.
- **Device config is UNGATED on the default build.** The shipped default is the
  full-ykman/YubiKey-compatible admin surface: a hostile USB host can silently
  rewrite the DeviceInfo / enabled-applications / USB identity — over CCID
  Management `WRITE CONFIG`, the FIDO vendor `CONFIG_WRITE`, and the CTAPHID
  (`0x43`) and OTP-HID (`0x15`) transport writes — with **no** touch or PIN, and
  can trigger a device-wide factory reset (that one keeps a presence gate). The
  USB *identity* (serial, strings) is cosmetic — never proof a device is genuine,
  attestation is (§3). The **enabled-applications mask is enforced**, though: a
  disabled application's applet stops answering (PIV/OpenPGP/OATH/OTP over CCID,
  FIDO2/U2F over CTAPHID, the OTP keyboard), so a hostile host can turn one off.
  That is a **reversible denial-of-service**, not a confidentiality or integrity
  break — the Management applet, the FIDO vendor command, and the OTP-HID
  identify/config slots are never gated, so any single transport can re-enable it,
  and no secret is exposed. If you need config writes gated on the operator,
  build/flash **`firmware-strict-config`**, which restores the presence/PIN gates
  and refuses the ungated transport writes ([build.md](build.md)). It is not the
  runtime flash flag `EF_HARDENED`.
- **The residual gap is *intent*. The trusted-display flavor closes it.** Because
  a standard key attests presence and possession, a malicious page can silently
  drive an authorized key over WebUSB to phish a real sign-in ([demonstrated
  against YubiKeys in Chrome](https://www.wired.com/story/chrome-yubikey-phishing-webusb/)).
  The [trusted-display flavor](guides/display.md) paints the true `rpId` on the
  device's own screen and gates each signature on a tap there, so a compromised
  host cannot fake what you approve. [Qubes OS's CTAP proxy](https://doc.qubes-os.org/en/latest/user/security-in-qubes/ctap-proxy.html#the-qubes-approach-to-ctap)
  tackles the same gap in software, mediating CTAP through a trusted VM.

### 2. A thief with the powered-off device (at-rest)

- All key material is sealed in flash: FIDO seed, PIV keys and OATH records
  (secrets plus the access-code key) under AES-256-CBC/GCM keyed by a device key
  (`kbase` = HKDF of the chip serial and the OTP master key once provisioned),
  OpenPGP keys under the PIN-wrapped DEK chain.
- **OTP master key** ([production.md](production.md) stage 1): with the MKEK
  fused and page-58 hard-locked, a flash dump (even with BOOTSEL access and
  the chip id) does not reproduce the sealing key. Without the burn, the
  sealing key derives from on-chip state an attacker with full flash + chip
  access could reconstruct. The burn is what makes at-rest real.
- **The seals give confidentiality, not authenticity.** Records written before
  the burn are keyed from the public chip serial alone, and those pre-OTP arms
  stay readable afterwards so a provisioned device keeps working across the
  upgrade. So an attacker who can *write* flash (BOOTSEL) can forge a record
  that opens under one, and the boot migration then re-seals it under the fused
  root. Reading the flash still tells them nothing. Closing this needs a
  fuse-rooted latch on the migration window; audit run-27 #8 has the analysis.
- **Soft-lock** ([guides/soft-lock.md](guides/soft-lock.md)): optionally, the
  seed at rest is additionally wrapped with ChaCha20-Poly1305 under a 32-byte
  key only you hold (BIP-39/SLIP-39 words). A stolen device (even running
  genuine firmware) refuses every FIDO operation until that key is presented
  over an encrypted channel at power-up. Device + words, two factors.
- Caveat: superseded records linger. The flash log is append-only, so
  re-sealing or deleting a secret leaves the old copy on flash until its page
  is reclaimed. Two cases differ in how much that matters:
  - The **OTP-burn migration** supersedes the *pre-OTP* seed, which was sealed
    under the chip-serial-only root (no fuse secret). Left alone, a flash dump
    plus the chip id would recover it, bypassing the burn. So it is **not**
    left to lazy healing: the first boot after provisioning runs a one-shot
    compaction (`Fs::compact`, gated by the `EF_HARDENED` marker, crash-safe)
    that drives a full GC lap over the credential partition and physically
    erases every superseded pre-OTP record before the device re-attaches to USB.
  - The **soft-lock** transition leaves the same kind of lingering record, but
    on a provisioned device it is already sealed under the fused root (moot
    against anything short of a fused-key compromise), so soft-lock's at-rest
    guarantee simply hardens over time as natural compaction overwrites it.
- The FIDO seed is **never PIN-wrapped at rest** (a deliberate design
  decision). UP-only operations (`ssh ed25519-sk`, U2F, no-PIN assertions)
  must work from a cold boot with no PIN presented. So a PIN-keyed at-rest
  copy adds no protection an attacker couldn't bypass via the always-loadable
  copy, while breaking those flows. At-rest strength is the kbase (tier
  above), not the PIN.

### 3. An attacker who can flash their own firmware

- **Secure boot** ([production.md](production.md) stage 2): the bootrom
  refuses unsigned images, so no foreign code ever runs to read the OTP key
  in secure mode. Glitch detectors are fused on along the way.
- **Anti-rollback** ([anti-rollback.md](anti-rollback.md), optional): with
  `ROLLBACK_REQUIRED` fused, images below your board's rollback floor (or
  carrying no version at all, i.e. anything sealed before the feature) no
  longer boot. A kept copy of an old signed release with a since-fixed bug
  stops being a downgrade path.
- Before secure boot is enabled, this attacker wins against the OTP tier:
  their firmware reads the MKEK exactly like ours does. That is why the
  production page calls the two stages one story.
- The **USB/smartcard identity** (VID/PID, manufacturer, product, OpenPGP AID
  vendor) is fully host-configurable at runtime via the phy record and is not an
  authenticity signal: a phy write that sets the Yubico VID makes a stock key
  present a full Yubico identity, and the manufacturer/product strings are also
  settable outright (phy tags `0x0F` / `0x09`), so any VID can carry any vendor
  name. On the **default build these config writes are ungated** (no touch, no
  PIN — see §1); `firmware-strict-config` re-gates them. Treat the identity as
  cosmetic, never as proof a device is genuine — attestation (device-key / org
  cert) is the authenticity mechanism, and it is unaffected by any config write.

### 4. Physical / lab attacks — OUT OF SCOPE

Decapping, microprobing, advanced fault injection beyond the RP2350's glitch
detectors, power/EM side channels, and the **XIP TOCTOU**: interposing on the
QSPI bus to serve the genuine image to secure boot's verifier and a tampered one
to the CPU, since nothing binds checked bytes to executed bytes and the image is
too large to verify-in-place from SRAM. An in-package-flash part (RP2354) leaves
no discrete flash chip to tap, raising a reliable swap to decap-class effort. The
RP2350 is not a secure element and RS-Key does not pretend otherwise. If your
threat model includes a funded lab, buy a certified key.

### 5. Network

None. The device speaks USB only. There is no radio and no IP stack.

## Flash snapshot rollback (the PIN-counter reset)

Reported by Token2 ([issue #37](https://github.com/TheMaxMur/RS-Key/issues/37),
[advisory PDF](https://github.com/user-attachments/files/30152894/T2-SA-RP2350-Dec2025.pdf)).
An attacker with brief physical access and BOOTSEL runs `picotool save` to snapshot the
whole flash, guesses PINs until the wrong-PIN counter locks, then `picotool load`s the old
snapshot to reset the counter and repeats. That is unlimited offline PIN guessing. It
defeats every applet's retry counter — FIDO clientPIN, PIV PIN/PUK, OpenPGP PW1/PW3, OATH —
since all are ordinary flash records with no external freshness binding.

The gap is **freshness**, not confidentiality or authenticity. Secure boot accepts the
restored image (it is genuine and signed); the at-rest seal decrypts it (same chip). Neither
notices a rollback. RS-Key's firmware anti-rollback ([anti-rollback.md](anti-rollback.md))
versions the firmware *image*, not the flash *data*, so it is blind to the swap too. The clean
fix is a monotonic counter in tamper-resistant NVM that the firmware checks on boot — exactly
what a secure element has and the RP2350 lacks. Its OTP is write-once antifuse (a few dozen
one-way bits for the board's whole life), so it cannot back a retry counter that must reset to
eight on every correct PIN. We cannot close the rollback itself on this silicon; we fence the
store and raise the cost of getting past the fence:

- **Partition table** (always on since `0x0871`). The shipped image embeds an RP2350
  partition table that fences the KV store off from the USB bootloader. `picotool save` and
  `picotool load` over that range answer `permission failure` — enforced by the bootrom, not
  by us — while the running firmware keeps `secure: rw` and full access to its own data. The
  snapshot/restore above no longer works as written.

  **What that is worth depends on secure boot.** The table sits inside the signed image, so
  where secure boot is on it cannot be swapped without your signing key: a byte flipped
  anywhere in the table fails the image hash *and* the signature. Where it is off, the fence
  is friction rather than a barrier — the firmware partition has to stay bootloader-writable
  or updates would not work at all, so an attacker flashes an image carrying a permissive
  table and is back where they started. Read this as "the attack now needs a reflash first,
  and secure boot is what denies the reflash", not as "rollback fixed".

  It is worth doing precisely because this is the one gap secure boot does **not** close by
  itself: secure boot verifies *executable* images, and writing the data region is not
  execution. Until this change a fully provisioned board was still snapshot/restore-able.
- **OTP-seeded PIN verifier** (always on after the OTP burn). The stored verifier is
  `HKDF(serial_hash, HMAC(kbase, pin))`, with `kbase` rooted in the fused OTP master key
  ([production.md](production.md) stage 1). A flash dump does not contain that key, so it
  cannot brute-force the PIN *offline* — the guessing must run on the device, one try at a
  time.
- **`strong-pin` / `fips-profile` builds** (opt-in). Raise the clientPIN floor to six code
  points and refuse the most guessable PINs (a repeated digit, a `123456`-style run), so the
  on-device search space is at least a million. By Token2's estimate an automated attack runs
  ~34 days at six digits and ~10 years at eight, against ~8 hours at four
  ([build.md](build.md)).
- **Soft-lock** (opt-in). The FIDO seed is wrapped under a key only you hold
  ([guides/soft-lock.md](guides/soft-lock.md)), so a brute-forced PIN yields nothing until you
  present it. It covers the FIDO seed; the PIV, OpenPGP and OATH counters stay
  rollback-resettable.

The durable defense on a general-purpose MCU is PIN entropy, plus the soft-lock second factor
for the FIDO seed. A device left in an attacker's hands, protected only by a short PIN, is not
safe here. This is the same boundary as ["anyone with the device and your PIN is
you"](limitations.md).

## Platform silicon: the RP2350 security challenges

Raspberry Pi has publicly stress-tested the RP2350 die. The results bound
RS-Key's physical-attack posture.

**Challenge 1 broke the A2 stepping** ([results][c1]). The task was to extract an
OTP secret from a board running secure boot. The winning attacks:

- **Aedan Cullen**: voltage glitch on the `USB_OTP_VDD` rail, reading OTP
  secrets out of the guarded path (erratum E16) ([writeup][cullen], [talk][c38c3]).
- **Marius Muench**: a glitch plus a boot-ROM flaw, bypassing secure boot to run
  unsigned code.
- **Kévin Courdesses**: laser fault injection corrupting the boot-time signature
  check (erratum E24) ([writeup][courk]).
- **IOActive**: focused-ion-beam (FIB) plus passive voltage contrast (PVC),
  reading the antifuse array directly: the bitwise OR of two physically paired
  bitcell rows ([writeup][ioactive]).

The first three are comparatively cheap fault / boot-ROM attacks. The IOActive
readout needs FIB-class lab equipment (a tool worth hundreds of thousands of
dollars, one to two days per target) and applies to *every* device built on the
Synopsys `dwc_nvm_ts40*` antifuse IP on TSMC's 40 nm node, an antifuse property,
not an RP2350-specific defect.

**The A4 stepping fixes the fault and boot-ROM attacks in silicon, but not the
antifuse readout** ([announcement][a4]). A4 closes the boot-ROM errata
(E20/E21/E24, including the laser signature bypass) in a new boot ROM, the OTP
power-glitch (E16) through changes to the wrapper circuitry around the OTP macro,
and the GPIO errata (E9, E3). The antifuse-array PVC readout is explicitly **not**
fixed in A4. Raspberry Pi's guidance is to mitigate it by how secrets are stored
in OTP, the chaffing RS-Key applies (see [otp-fuses.md](otp-fuses.md)). A third
challenge (power side-channel analysis of the secure-boot AES) is open with no
break reported ([challenge 2][c2]).

**What this means for RS-Key.** Our development boards are **A2**: the broken
stepping, kept as the conservative worst case. The firmware is **A4-compatible**,
and A4 is recommended for the fault / boot-ROM attacks above. Against the antifuse
readout (which no stepping fixes), RS-Key applies the chaffing mitigation
directly ([otp-fuses.md](otp-fuses.md)). What remains out of scope is unchanged: a
funded lab with FIB/PVC, laser fault injection, or power/EM analysis against a
device in hand. No software or provisioning choice on a general-purpose die closes
those. That is what a dedicated secure element is for ([limitations.md](limitations.md)).

[c1]: https://www.raspberrypi.com/news/security-through-transparency-rp2350-hacking-challenge-results-are-in/
[a4]: https://www.raspberrypi.com/news/rp2350-a4-rp2354-and-a-new-hacking-challenge/
[c2]: https://www.raspberrypi.com/news/rp2350-hacking-challenge-2-less-randomisation-more-correlation/
[cullen]: https://github.com/aedancullen/hacking-the-rp2350
[c38c3]: https://media.ccc.de/v/38c3-hacking-the-rp2350
[courk]: https://courk.cc/rp2350-challenge-laser
[ioactive]: https://www.ioactive.com/raspberry-pi-2350-hacking-challenge/

## Seed backup (the deliberate exception)

A FIDO authenticator's pitch is non-exportable keys. The wallet-style backup
is a conscious trade for recoverability, gated accordingly. Export moves the
seed over an ephemeral encrypted channel (P-256 ECDH → HKDF →
ChaCha20-Poly1305), and requires (all at once) physical touch, the FIDO
PIN/UV token when a PIN is set, and the **one-time setup window**: after an
explicit `finalize`, export is refused until a full reset regenerates a new
seed. Malware cannot exfiltrate the seed silently or later. Restore re-seals
the seed under the *destination* chip's root. The host driving a backup
necessarily sees the seed plaintext. Do it on a machine you trust.
Scope: the deterministic identity only (resident passkeys, OpenPGP, PIV are
not covered).

On the **trusted-display flavor** the host need not be in that trust path: the
device can render its BIP-39 recovery phrase **on its own screen** (the seed is
turned into words on-device and never crosses USB), so a backup can be taken
without trusting any host. That trades the host-observation surface for a
physical/visual one. The words are briefly on the panel (shoulder-surf, camera).
It is gated to keep that surface small: it requires a **device PIN** set and
re-entered, a deliberate hold past an explicit "no one watching" warning, runs
only inside the same one-time window (and seal closes it), is disabled on the
`fips-profile` (non-exportable) build, zeroizes the seed/words from RAM on exit,
and auto-clears the panel after a short idle.

```mermaid
sequenceDiagram
    participant U as You
    participant H as Host
    participant D as Device
    U->>D: touch + PIN/UV (when set)
    H->>D: ephemeral P-256 ECDH
    D-->>H: seed over HKDF → ChaCha20-Poly1305 channel
    Note over H: the host necessarily sees the seed in the clear
    H-->>U: BIP-39 / SLIP-39 words
    U->>D: finalize → export refused until a full reset
```

## Zeroization

Key-grade material in RAM is wiped (`zeroize`, volatile writes) when its use
ends: session state and PIN/UV tokens on drop, transient key copies at end of
scope including error paths, and the transport/exchange buffers as soon as a
message completes (requests carry PINs and imported keys). Accepted
residuals: `Copy` temporaries inside RustCrypto curve arithmetic, digest
internals, and heap temporaries inside the `rsa` crate. Short-lived,
library-internal, not wipeable without forking the crates.

A WebAuthn **large-blob key is obtainable without user interaction**. CTAP 2.1
§12.3 puts no UP/UV precondition on the `largeBlobKey` extension output — unlike
§12.5, which mandates refusing `hmac-secret` on a silent `up:false` probe — and
§6.2.2 step 5 scopes `alwaysUv` to requests where `up` is present and true. RS-Key
implements both as written, so a host process can obtain a credential's large-blob
key, and the ungated `authenticatorLargeBlobs get` alongside it, with no touch and
no PIN, on a device with `alwaysUv` enabled. Per §6.10 the confidentiality of that
data is a function of the credential's protection policy, so a relying party that
needs it gated should set `credProtect` accordingly. Deviating unilaterally would
fail conformance; the asymmetry belongs upstream.

The reboot to BOOTSEL is presence-gated but takes no PIN, so "one touch, then
dump RAM" is a real attacker move. `worker::reboot` wipes the live key material
before dropping, and the stack — which carries the deepest secrets, RSA primes
and EC scalars — is *not* wiped. That is deliberate, and measured rather than
assumed: on RP2350 A4 the platform clears main SRAM across the drop. All 520 KiB
read back as zeros while a pattern written through picoboot read straight back,
so the zeros are the memory and not a refused read
([`tests/54_sram_residue.py`](https://github.com/TheMaxMur/RS-Key/blob/main/tests/54_sram_residue.py),
2026-08-05, secure boot off). This is a property of the silicon revision and boot
configuration, so it is re-measured when either moves; the explicit wipes stay as
depth in case a future one keeps SRAM.

## Supply chain & process

- `cargo audit` + `cargo deny` (advisories, license allow-list, source
  policy) and `gitleaks` run in `scripts/check.sh` and the pre-commit hook.
- Dependencies are pinned (`Cargo.lock`). The git dependencies are restricted
  to the embassy organization.
- One known-unfixed advisory is accepted deliberately: RUSTSEC-2023-0071
  (Marvin timing side channel in `rsa`), the OpenPGP RSA backend. It is
  mitigated by per-operation base blinding on **every** private-key path
  (PKCS#1 v1.5 sign, decipher, and the raw fallback `rsa_raw`). Rationale in
  `deny.toml`. The [constant-time audit](ct-audit.md) verified that this
  blinding leaves no unblinded private-exponent path.

## Post-quantum notes

ML-DSA-44 (COSE −48) and ML-DSA-65 (COSE −49) FIDO2 credentials (both the
in-tree `rsk-mldsa` crate) with hedged signing (32 fresh DRBG bytes
per signature; the hedge and expanded keys are zeroized). `rsk-mldsa` streams
the FIPS 204 matrix A on the fly so ML-DSA-65's keygen+sign fit the RP2350
stack. It is hand-written, so its constant-time posture is a source-level
claim (branch-free reductions, masked norm checks, no secret division), not
proven at machine code. It is checked byte-for-byte against NIST ACVP KATs,
with Kani proofs over the reductions and rounding. ML-DSA-87 (−50) is out of
reach on this chip (keygen overflows the stack; its makeCredential response
also overruns the CTAPHID message ceiling). ML-KEM-768 is compiled in as
scaffolding but nothing calls it until a CTAP PQC PIN/UV protocol exists.
None of these has a third-party audit yet, the same standing as the rest of
the RustCrypto stack, tracked via cargo-audit/deny.

## Reporting

This is an experimental hobby project. If you find a security issue, please
report it privately to the maintainer rather than opening a public issue.
