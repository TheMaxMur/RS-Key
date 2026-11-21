# Limitations — what RS-Key does not do, and why

RS-Key is experimental firmware. Its security review is project-led.
The [threat model](threat-model.md) describes the security boundary, and
[Testing](testing.md) describes the checks and their scope.

## Cryptography

- **RSA side-channel coverage has limits.** `rsk-rsa` uses base blinding
  and checks CRT results before returning them. In the optimized CRT
  path, the private exponent still selects a table address during
  modular exponentiation. A host observing whole-operation timing and
  a lab observing activity inside one operation are different cases.
  See the [constant-time audit](ct-audit.md) and the residual and deferred
  hardening in `PLAT-CRYPTO-002` and `PLAT-BUILD-005`.

### Flash storage

- **Integrity depends on the root.** Storage v2 authenticates expected
  records and detects damaged or missing values. Before OTP provisioning,
  its root derives from the public chip serial. A raw flash writer can
  forge authority under that root. Secure startup closes the public-root
  path when migration and the fresh flash scrub finish and page 58 is
  sealed. See [OTP fuses](otp-fuses.md).
- **Freshness is limited to a live backend instance.** The main directory
  and counter banks retain the latest authority they have accepted in
  RAM. Replacing both counter banks with an older copy during a live mount
  is rejected, including for PIN retries. Reads authenticate the
  requested value, so unrelated damage may surface only at mutation or
  recovery. After a cold boot, replaying older valid flash state can
  restore old records and counters. The BOOTSEL partition table limits
  access to the store. Firmware anti-rollback applies to images. See
  [Flash snapshot rollback](threat-model.md#flash-snapshot-rollback-the-pin-counter-reset).
- **Legacy import has a trust boundary.** A verified newer publication
  takes precedence over an older import manifest. If all v2 evidence
  is lost and the surviving media looks like a valid legacy layout, boot
  can admit it as legacy. Import can preserve readable bytes and check
  their layout. The integrity of data written by the legacy store
  depends on that store's own guarantees.
- **Mirroring consumes erase cycles.** In a software NOR run of 20,000
  updates to one four-byte counter, v2 programmed 1,941,056 bytes and
  erased each of its ten counter sectors 47 times. The legacy backend
  programmed 320,628 bytes and erased each of its 32 sectors once or
  twice. The v2 run left the main payload and directory unchanged. This
  measures one write pattern. Physical endurance depends on the flash
  chip and use pattern. See [Storage and failure injection](testing.md#storage-and-failure-injection).

### Seals and PINs

- **Page 58 and the records it protects.** After the latch closes,
  device-sealed records covered by migration require the fused MKEK. An
  unreadable MKEK blocks migration at boot and prevents those records
  from opening under the public root. A legacy lock can deny BOOTSEL
  reads while the latch still awaits completion. See
  [Production setup](production.md#stage-1--otp-master-key).
- **Legacy PIN verifiers remain readable by the applets.** The verifier
  format permits a fallback to the old root after the latch closes.
  Substituting a verifier also requires flash state that the
  authenticated store will accept. A substituted verifier does not
  unwrap the original OpenPGP data-encryption key (DEK).
- **PIN-dependent migration needs the PIN.** Present each existing PIN
  or update its reference as directed during provisioning. This includes
  the PIV PUK and the OpenPGP admin PIN and resetting code, which ordinary
  use may never present. A legacy OpenPGP DEK copy can remain reachable
  through an offline guess against the old root, even after another
  reference migrated. See `PLAT-THREAT-002` in
  [Platform assumptions](platform-assumptions.md) and the
  [production procedure](production.md#stage-1--otp-master-key).
- **PIV data objects can be visible in a flash dump.** The card requires
  PIN verification to read Cardholder Fingerprints (`5FC103`), Facial
  Image (`5FC108`), Printed Information (`5FC109`) and Iris Images
  (`5FC121`) through PIV. The objects are authenticated in storage and
  their contents are plaintext. The per-object limit is 3063 bytes.
  The card stores data supplied by the host. See the [PIV guide](guides/piv.md).

### Algorithms and implementations

The `fips-profile` build applies algorithm and PIN restrictions.
The [FIPS-style profile guide](guides/fips.md) covers its validation status.

- **OpenPGP curves.** The applet supports brainpoolP256r1 and brainpoolP384r1.
  Its supported set excludes brainpoolP512r1, X448 and Ed448. The
  advertised algorithm list reflects the implemented curves.
- **RSA decryption exposes a padding result.** A host that can drive
  OpenPGP `PSO:DECIPHER` with PW1 verified can distinguish a successful
  PKCS#1 v1.5 decrypt from a refusal. That provides a padding oracle to
  an authorized caller. The unpadding code uses masks for its checks.
  Returning plaintext on success still exposes its length.
- **On-card RSA generation can be slow.** The prime search dominates
  RSA-3072 and RSA-4096. Both cores can search with the hot path in SRAM.
  Latency varies with board, build and the number of candidates rejected.
  The firmware sends keepalives while supported transports wait. See
  [RSA on core1](architecture.md#rsa-on-core1).
- **ML-DSA needs client support.** RS-Key supports ML-DSA-44, -65 and -87
  for FIDO2. `advertise-pqc` enables their advertisement in getInfo. A
  client can request the algorithms with that flag off. Unknown-algorithm
  parsing and ML-DSA credential creation are separate compatibility issues.
  Mozilla documents the former fix in `authenticator-rs` and tracks the
  latter separately. See [Build options](build.md#cargo-features) and
  [Firefox's ML-DSA issue](https://bugzilla.mozilla.org/show_bug.cgi?id=2064183).
- **ML-KEM scope.** The vendor MSE channel can combine P-256 with
  ML-KEM-768 when the host supplies an encapsulation key. Standard CTAP
  PIN/UV protocols still use P-256. See the
  [MSE protocol](protocol.md#91-the-mse-channel-0x41--0x01).

## Backup & migration

- **Seed backup recovers the deterministic FIDO identity.** Restoring
  the seed can recover non-resident credentials when the client or
  relying party still has their credential IDs. Resident passkeys,
  OpenPGP and PIV private keys, OATH credentials and OTP slots require
  separate migration or re-enrolment.
- **Finalizing closes the export window.** Retain the phrase or enough
  SLIP-39 shares before finalizing. A factory reset reopens the window
  for a new identity. The `fips-profile` build blocks seed export.
  See the [seed backup guide](guides/seed-backup.md).
- **Flash geometry is part of the upgrade contract.** Keep `FLASH_SIZE`
  and `KVMAIN` when updating a provisioned key. Changing either can move
  the partitions away from existing data. See [Build options](build.md#flash-size-and-the-memory-map).

## Hardware / physical

- **Physical and lab attacks.** The security boundary is the
  general-purpose RP2350 family. A4 addresses the original A2 boot ROM
  and OTP power-glitch findings. Direct antifuse imaging remains a
  concern, and a separate lab attack recovered a challenge secret after
  restoring Secure debug on a decapped A4. RS-Key uses chaff for the
  demonstrated paired-row readout. It still relies on Secure reads of
  page 58. The application of the debug attack to those rows is an
  inference from their access policy. See the [threat model](threat-model.md#platform-silicon-the-rp2350-security-challenges)
  and [Ledger Donjon's experiment](https://donjon.ledger.com/blog/rp2350-secure-debug-laser-fault-injection/).
- **TRNG health checks and entropy.** The firmware leaves the RP2350's
  continuous health checks enabled. Their success does not quantify
  entropy from a degraded source. A raw-source measurement under desk
  conditions is pending in `PLAT-TRNG-002`. Qualification across supply,
  temperature and process is an accepted gap in `PLAT-TRNG-003`. See
  [Platform assumptions](platform-assumptions.md).
- **Flash failures can look like absence to callers.** The storage API
  has both lossy reads and probes that distinguish absence from failure.
  Security-sensitive provisioning and authorization paths use fallible
  probes or take a restrictive path. The effect of a real interrupted
  program or erase is a separate hardware question. The supply-cut
  assumption in `PLAT-FLASH-001` is pending. See the
  [threat model](threat-model.md#1-a-hostile-host-malware-on-the-computer).
- **External-flash XIP has a time-of-check gap.** Secure Boot verifies
  the image, then the CPU fetches instructions from flash. An interposer
  on the external flash bus can serve different bytes at those stages.
  The combined firmware and its working memory exceed the available
  SRAM. RP2354 puts flash inside the package, which removes the exposed
  external flash chip from that attack path. The FIDO2 demonstration on
  Romu used Bitmerse's RS-Key port. See [Hardware](hardware.md) and the
  [RP2350 datasheet](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf).
- **TrustZone separates USB framing from Secure services.** Secure owns
  the USB controller and lifecycle, applets, storage and OTP. Non-secure
  code sees plaintext that crosses its transport, including a host PIN
  sent in a plain CCID APDU. Secure applets share one trust domain. See
  [Architecture](architecture.md#trustzone) for the boundary and
  [Testing](testing.md#trustzone-on-hardware) for the scope of board results.
- **Anti-rollback is an image policy.** The OTP version floor has 48
  one-way steps. The boot ROM checks a versioned image against the floor.
  `ROLLBACK_REQUIRED` requires a rollback version on signed images.
  See [Anti-rollback](anti-rollback.md).
- **Firmware images are signed for production and execute from flash.**
  RS-Key uses signed XIP images. The RP2350's encrypted-boot mechanism
  loads a payload into SRAM. See the
  [RP2350 datasheet](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf).
- **The display build runs beyond the nominal clock ratings.** It sets
  the RP2350 to 160 MHz, above the 150 MHz rating. The write-only PIO link
  clocks the panel at 80 MHz. The ST7789T3 specifies a minimum serial
  write cycle of 16 ns (62.5 MHz). The driver cannot read back pixels to
  detect a panel transfer error. Measurements apply to the clock and
  board used. See the [trusted display guide](guides/display.md) and
  [ST7789T3 datasheet](https://files.waveshare.com/wiki/2inch%20Capacitive%20Touch%20LCD/ST7789T3_SPEC_V1.0.pdf).

## Protocol / compatibility

- **USB identity affects discovery.** The default identity is
  `0x1209:0xF1D2` with the RS-Key reader name. `ykman` and Yubico
  Authenticator look for the Yubico reader name and use the opt-in
  `VIDPID=Yubikey5` build for interop. Linux device permissions and CCID
  driver recognition are separate from application discovery. See
  [Build options](build.md) and [Linux setup](linux.md).
- **FIDO attestation can identify the device.** Ordinary packed basic
  attestation carries a stable per-device certificate. A client that
  receives that certificate can correlate registrations. A CTAP client
  can request `attestationFormatsPreference: ["none"]` to omit the
  statement when enterprise attestation is not performed. An eligible
  enterprise request can return the provisioned organization's chain.
  See [Attestation](guides/attestation.md).
- **PIV attestation uses a device-generated identity.** Host import into
  slot `f9` and replacement of object `5FFF01` are refused after
  management authentication, with `6A80`. `ATTEST` uses the device's
  identity. See the [PIV guide](guides/piv.md).
- **OpenPGP attestation uses a device-generated identity.** Its
  certificate is self-signed. Host writes to attributes `DA` or
  certificate `FC` return `6B00`. Import and generation requests for
  the attestation slot return `6A80`. See the [OpenPGP guide](guides/openpgp.md).
- **PIV retry budgets must be nonzero.** With PIN and management
  authentication in place, `SET RETRIES` returns `6A80` for a zero
  PIN or PUK budget and leaves the counters intact.
- **SELECT by AID accepts `P2 = 04`.** RS-Key accepts it alongside
  `P2 = 00` for clients such as PicoForge.
- **OpenPGP secure messaging is unavailable.** OpenPGP commands use
  ordinary APDUs. Access still depends on the command's PIN and presence
  policy.
- **The available presence input depends on the board.** Ordinary builds
  use BOOTSEL or a configured GPIO. The display adds on-device PIN entry
  and a named prompt for operations that require confirmation. The
  shipped builds use PINs for user verification and offer no biometric
  reader. See [Hardware](hardware.md) and the [threat model](threat-model.md).

## Operational

- **A logical deletion can leave old flash bytes.** Superseded records
  can remain until compaction or a scrub reclaims their sectors. OTP
  migration schedules a scrub of superseded weak-root copies and
  requires a fresh successful scrub before sealing page 58.
- **Using a stolen key depends on its remaining gates.** Someone with
  the device and its PIN can authorize the operations that PIN covers
  when they also satisfy the operation's other gates. FIDO soft-lock
  protects the seed with a separate off-device key. See
  [Soft-lock](guides/soft-lock.md) and the [threat model](threat-model.md).
