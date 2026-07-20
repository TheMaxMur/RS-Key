<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Changelog

All notable changes to RS-Key are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and **releases** are
versioned with [SemVer](https://semver.org/).

Two other version numbers live in the firmware and are deliberately **not** this
tag: the USB `bcdDevice` build counter (bumped on every behavior change), and
`FW_VERSION` — the YubiKey-compatibility version reported to host tools (5.7.4).

## [Unreleased]

### Added

- **`strict-config` cargo feature** — restores the strict admin-write
  authorization that used to be the shipped default (device-config writes
  presence/PIN-gated, ungated transport writes refused). OFF by default now; see
  the "default posture flipped" Changed entry. Build/ship the strict image with
  `--features strict-config` (release flavor `firmware-strict-config`). Distinct
  from the runtime flash flag `EF_HARDENED`.
- **Build-time AAGUID override.** `AAGUID=<uuid-or-32-hex> cargo build` bakes a
  custom FIDO2 AAGUID (the authenticator-model id in getInfo / attestation): the
  value is validated in `crates/rsk-fido/build.rs` and const-parsed in `consts.rs`
  (baked as `PK_AAGUID`), defaulting to RS-Key's reproducible UUIDv5. It is meant
  for a fork that ships its own metadata — a non-default AAGUID makes the
  checked-in metadata statement no longer match, and advertising a real vendor's
  AAGUID would be an attestation forgery that fails to chain anyway. The default
  build's AAGUID is unchanged and its image is **byte-for-byte identical**
  (compile-time const parse, no runtime code) — **no bcdDevice bump.**
- **The USB manufacturer/product strings are runtime-configurable via the phy
  record, and a Yubico VID now auto-fills the whole identity.** A new phy tag
  `0x0F` (USB_MANUFACTURER) sets the iManufacturer string; `rsk hw` gains
  `--manufacturer` / `--product`. Precedence per string: an explicit phy tag wins,
  else the effective VID picks a default (a Yubico VID `0x1050` fills in both
  `Yubico` and `YubiKey RSK OTP+FIDO+CCID`, so a VID-only repoint via PicoForge /
  `rsk hw` now "just works" for `ykman` / Yubico Authenticator — previously the
  manufacturer followed the VID but the product did not), else the build const.
  The default build still presents its own RS-Key identity; nothing masquerades
  unless you set it. ⚠️ an explicit manufacturer/product lets any VID carry any
  vendor name — the identity stays cosmetic, never an authenticity signal
  (docs/threat-model.md). Forward-compatible: an old phy record without `0x0F`
  falls back to the VID/build default. **bcdDevice → 0x083D.**
- **PIV serves a default CHUID, so a freshly flashed card works under Windows
  CAPI.** The Windows PIV minidriver enumerates a card's containers from the Card
  Holder Unique Identifier (CHUID, object `5FC102`); a card that had none answered
  `6A82`, and CryptoAPI sign / auth then stayed "pending" on slots `9A`/`9C`. The
  applet now synthesizes a default CHUID when none is provisioned — the well-known
  non-federal FASC-N plus a device-stable GUID (`sha256(serial)[..16]`), the same
  shape `ykman piv objects generate chuid` writes. A host-written CHUID still
  overrides it (flash is read first). RSA/EC signing itself was always correct
  (verified byte-for-byte against a real YubiKey 5.7.4); this is the enumeration
  half of the issue #44 PIV-under-CAPI reports. **bcdDevice → 0x0839.**
- **OpenPGP brainpoolP256r1 and brainpoolP384r1** (ECDSA on the sign / auth slots,
  ECDH on the decrypt slot). gpg can now `key-attr` / `generate` / `keytocard` a
  brainpool key, matching the curves a real YubiKey 5.7.4 advertises in the
  algorithm-information DO (`0xFA`). brainpoolP512r1 stays absent — no Rust
  arithmetic for the 512-bit brainpool curve exists yet. The applet keys off the
  `bp256` / `bp384` crates (fiat-crypto backend), checked byte-for-byte against
  OpenSSL test vectors. **bcdDevice → 0x0836.**
- **`rsk bench` — an on-device crypto-latency harness that survives XIP-cache
  noise.** Steady-state EC latency on the RP2350 shifts ±~30 ms with code layout
  (the hot working set overflows the 16 KB XIP cache), so a host-timed mean fakes
  regressions. The new `bench` firmware feature (vendor command, never shipped —
  like `keygen-bench`) times a primitive with the device's own timer and returns a
  robust median / MAD plus a separate cold-cache sample; `rsk bench --compare`
  gives an A/B verdict between two saved runs. The summary is computed on-device by
  the new host-tested, Kani-proved `rsk-bench` crate. Feature is off by default, so
  the shipped image is byte-for-byte unchanged — **no bcdDevice bump.**
- **Default firmware images for 2 MB and 16 MB boards.** The signed release now
  ships `firmware-2mb` (`FLASH_SIZE=2M KVMAIN=896K`) and `firmware-16mb`
  (`FLASH_SIZE=16M`) alongside the 4 MB default — the flash-geometry siblings of
  the default image, same feature set and RS-Key identity, for boards whose chip
  is not the 4 MB default (Seeed XIAO RP2350 / Waveshare RP2350-Zero-CM at 2 MB;
  TenStar RP2350-USB at 16 MB). PR CI smoke-builds both so a 2 MB link/fit
  regression is caught early. Build/release wiring only; the 4 MB default image is
  byte-for-byte unchanged — **no bcdDevice bump.**

### Changed

- **Faster PIV RSA signing** (~3.1× on RSA-2048, ~2.9× on RSA-4096; on-device
  medians — 0.13 s / 0.86 s — now beat a real YubiKey 5.7's 0.18 s / 1.39 s).
  Slot private-key operations now run the
  CRT modexp through the vendored UMAAL assembly (`rsk_rsa_asm::sign_crt`) instead
  of the pure-Rust `num-bigint-dig` 4-bit-window path, and the two full-width
  public-exponent modexps around it — the blinding factor `rᵉ` and the fault
  check `sigᵉ` — now use the asm too (`rsk_rsa_asm::modexp_pub`). The sealed key
  caches the CRT parameters (`P‖Q‖dP‖dQ‖qInv`) so a signature no longer rebuilds
  `d`/`dP`/`dQ`/`qInv` (two modular inversions) every time. Base blinding and the
  Bellcore fault check (`sigᵉ ≡ c mod n`) are kept — the fault check also means a
  faulted CRT half or an asm/marshaling bug can never emit a valid signature.
  Forward-compatible: keys sealed by an older firmware (`P‖Q` only) still load and
  sign — they get the fast modexp but recompute the CRT parameters once per
  signature until re-provisioned. OpenPGP RSA is unchanged (separate seal path).
- **⚠️ Default security posture flipped: device-config writes are now UNGATED by
  default (full YubiKey/ykman parity).** On the default build the CCID Management
  WRITE CONFIG (`0x1C`) and the FIDO vendor CONFIG_WRITE (`0x0C`) no longer require
  operator presence / a PIN `pinUvAuthToken` — any USB host can rewrite the
  reported DeviceInfo. The previous presence/PIN-gated behaviour is now opt-in via
  `--features strict-config`. This deliberately weakens the DEFAULT threat model
  (docs/threat-model.md); build/ship `firmware-strict-config` for the strict
  posture. Part of a broader default→permissive flip: the default build also now
  serves ykman's CTAPHID vendor WRITE CONFIG (`0x43`) and the OTP-HID
  SET_DEVICE_INFO (`0x15`) DeviceInfo writes — both ungated, persisting the same
  `EF_DEV_CONF` every READ CONFIG echoes — and the remaining OTP-HID admin slots:
  SCAN_MAP (`0x12`, functional — a stored custom scancode map remaps typed OTP
  output for non-US hosts) plus DEVICE_CONFIG (`0x11`) and NDEF (`0x08`/`0x09`) as
  accept+store (inert on this USB-only board, no NFC radio). Management RESET
  (INS `0x1E` / ykman's `0x1F`) is a device-wide factory reset in the default build
  — presence-gated even here, since an ungated one-APDU wipe would be a footgun —
  wiping all flash but the org attestation and rebooting to re-provision; it stays
  `6D00` under strict-config. **bcdDevice → 0x0841.**
- **The USB manufacturer string and OpenPGP AID vendor now follow the effective
  (phy-overridden) VID at runtime.** Previously only the *build-time* VID chose them
  (`VIDPID=Yubikey5`), so a runtime Yubico-VID repoint via PicoForge kept the
  manufacturer `RS-Key` and the OpenPGP AID vendor unmanaged; both now switch with
  the effective VID for a consistent identity (fixes the "manufacturer stays RS-Key"
  report, picoforge#102). ⚠️ this lets a phy-repointed default key present a full
  Yubico identity at runtime — a deliberate masquerade capability, previously
  build-time-only (see docs/threat-model.md). **bcdDevice → 0x083B.**
- **A FIDO PHY config-write now warm-reboots the device by default**, so a
  VID/PID/product/interface change applies without a manual replug (RS-Key#33). The
  phy `DISABLE_POWER_RESET` option bit (clear by default) turns it off; a `CONFIG_READ`
  never reboots.
- **The `flow` and `sparkle` LED effects honour the configured status colour**
  instead of a fixed yellow→red gradient / random RGB, so a per-status colour set
  via PicoForge or `rsk led` is actually shown.
- **Faster PIN: the clientPIN key-agreement key is generated at power-up and its
  public key is cached.** The first PIN entry after plugging the key in used to be
  noticeably slower than the rest (a one-time elliptic-curve key generation on the
  first `clientPIN` command); it now happens at boot, off the critical path. And
  because every `getKeyAgreement` was needlessly re-deriving the same public key,
  caching it speeds up *every* PIN operation, not just the first. Measured on the
  RP2350: first PIN ~162 → ~64 ms and each subsequent PIN ~106 → ~62 ms (a real
  YubiKey, for reference, is ~166 first / ~98 steady). The wire behaviour is
  unchanged (same key, same protocol). **bcdDevice → 0x0838.**
- **The elliptic-curve stack moved from RustCrypto 0.13 to 0.14** (`p256` / `p384`
  / `p521` / `k256`, with `elliptic-curve` 0.14 and `ecdsa` 0.17), so brainpool and
  the NIST curves share one arithmetic generation instead of two — cutting ~138 KB
  of flash. EC signatures are byte-for-byte unchanged (host KATs prove it), so
  keys provisioned before the upgrade keep working. **bcdDevice → 0x0836.**
- **P-384 and secp256k1 FIDO signatures now sign through the fixed-base comb**
  (as P-256 and P-521 already did), skipping 0.14's slower generic scalar
  multiplication: on the RP2350, P-384 `getAssertion` drops ~570 → ~230 ms and
  secp256k1 ~86 → ~50 ms. The signatures stay byte-identical to the crate signer,
  secp256k1's low-S normalization included. **bcdDevice → 0x0837.**

### Fixed

- **A partial PicoForge config write no longer resets the fields it didn't touch.**
  The FIDO `CONFIG_WRITE` (`0x0C`, target PHY) and CCID rescue `WRITE 0x1C` used to
  *replace* the whole `EF_PHY` record with a parse of the incoming blob, so any tag a
  host omitted (product name, LED order/count, VID/PID) reverted to the build
  default. Both paths now do a read-modify-write merge (`phy::merge_save`): only the
  TLV tags in the blob are updated, the rest are preserved. Closes the firmware half
  of picoforge#102 / RS-Key#33. **bcdDevice → 0x083A.**
- **A YubiKey-masquerade product string can no longer crash Yubico Authenticator on
  Windows.** `ykman` derives a YubiKey PID from the PC/SC reader name; a name with
  `Yubico YubiKey` but no `OTP`/`FIDO`/`CCID` token makes it build the non-existent
  PID `YK4_` and raise `KeyError`, aborting the whole card scan. The firmware now
  appends ` OTP+FIDO+CCID` to a runtime product that looks like a YubiKey but omits
  the `CCID` token (`normalize_usb_product`).
- **"Steady / keep-LED-on" now works on the addressable (WS2812) backend.** The
  animated effects (vapor/flow/bounce/sparkle) ignored `LED_STEADY` — only the legacy
  on/off renderer read it — so on the default build the LED kept animating; the render
  loop now shows the status colour solidly when steady is set.
- **Plain single-colour LEDs now dim, and the `LED_DIMMABLE` bit is honoured.** The
  `gpio` backend was on/off only, so brightness (and PicoForge's "LED Dimmable") did
  nothing on a plain LED; it now uses software PWM (~500 Hz). The phy `LED_DIMMABLE`
  option bit gates the global boot-brightness override. **bcdDevice → 0x083C.**
- **Four small YubiKey-conformance nits surfaced by a full differential against a
  real YubiKey 5.7.4.** None broke tooling, but each now matches the YubiKey
  byte-for-byte: (1) standalone GET DATA of the OpenPGP General Feature Management
  DO (`7F74`) returned the bare flag `20` instead of the `81 01 20` sub-DO a real
  card returns — the primitive-DO unwrap no longer strips this constructed DO;
  (2) the OpenPGP algorithm-information DO (`FA`) advertised the DEC slot's NIST /
  secp256k1 curves as ECDSA (`0x13`) instead of ECDH (`0x12`) — the applet already
  accepted ECDH decryption keys, only the advertisement was wrong; (3) the CCID OTP
  status was 7 bytes (a stray trailing `0x00`) instead of the canonical 6; (4) the
  OATH device id / PBKDF2 salt (SELECT tag `71`) was the raw chip-id hex text,
  making it predictable from the semi-public serial — it is now an opaque one-way
  hash of the device seed, stable across boots like a YubiKey's. **A device with an
  OATH access code set must re-set it once after this change** (the salt moved).
  **bcdDevice → 0x0835.**

- **The OpenPGP card serial now matches the rest of the device identity.** The
  OpenPGP application AID (GET DATA `0x4F`) spliced in the *raw* chip-id bytes, so
  hosts rendered a serial unrelated to the one PIV (`INS 0xF8`), Management READ
  CONFIG and OTP GET SERIAL report — visible on Windows / Kleopatra as an OpenPGP
  serial with no bearing on the PIV one (issue #44). OpenPGP now carries the
  8-digit device serial as packed BCD, matching a real YubiKey (whose OpenPGP AID
  holds e.g. `37 36 50 93` for device serial 37365093), so `gpg` renders the same
  decimal across all applets. Persistent keys and PINs are unaffected: the PIN/DEK
  derivation roots on `sha256` of the full 8-byte chip id, not the serial. On an
  already-provisioned device GnuPG's scdaemon sees the card under its corrected
  serial once and re-adopts it (a one-time reconnect, no re-provisioning).
- **OpenPGP now reports the device firmware version and an identity-consistent
  manufacturer.** The vendor VERSION command (INS `0xF1`, read by `ykman openpgp
  info` as "Application version") returned a hardcoded `4.6.0` inherited from the
  upstream project; it now returns the shared `FIRMWARE_VERSION` (default `5.7.4`,
  `FW_VERSION`-overridable at build time) that FIDO / OATH / OTP / Management
  already report, matching a real YubiKey where the OpenPGP applet version equals
  the firmware version. The OpenPGP AID manufacturer id (bytes 8-9) now follows the
  USB identity: `0x0006` (Yubico) on the `VIDPID=Yubikey5` interop build so hosts
  show the same vendor as a real YubiKey, `0xFFFE` (unmanaged range) on the default
  RS-Key identity, which is not Yubico.
- **The OpenPGP Key Information DO (`0xDE`) is now spec-conformant.** It was emitted
  as a bare child of the application-related-data (`0x6E`) with 0-indexed key
  references (`00/01/02`); the OpenPGP Card 3.4 spec nests it inside the `0x73`
  discretionary DOs with references `01/02/03` for SIG/DEC/AUT. `ykman >= 5.2` reads
  the DO from the discretionary set and keys on those references, so with the
  firmware version now reporting 5.7.4, `ykman openpgp info` used to crash
  (`KeyError`); it now reads the card. **bcdDevice → 0x0834.**

## [0.3.10] - 2026-07-20

### Fixed

- **`authenticatorReset` could hang the device on a heavily-provisioned key.** The
  FIDO factory reset wiped its files with `Fs::delete`, which skips the backend
  removal when its in-RAM present-cache reads the key as absent. A torn-migration
  false-absent key (live in flash, present bit clear) was therefore never removed,
  yet the reset's `for_each_key` pass — which reads the backend directly — kept
  re-finding it, so the wipe looped forever and the authenticator wedged until a
  power cycle (the on-device LED froze). Reset now removes each FIDO file
  unconditionally (`Fs::force_delete`, as the trusted-display factory wipe already
  did) and aborts on a backend error rather than retrying it, so the wipe always
  terminates. Surfaced on a well-worn test key; a fresh key was unaffected.
  **bcdDevice → 0x0830.**

### Security

- **A `getAssertion` that matches no credential now asks for a touch before
  reporting "no credentials".** Previously the authenticator returned
  `CTAP2_ERR_NO_CREDENTIALS` immediately — the CTAP 2.1 §6.2.2 reference order,
  which lists the disclosure before the user-presence step — so anyone holding the
  plugged-in (PIN-locked) device could probe whether a credential exists for a
  given RP, or for a specific credential id, without any user gesture: a fast
  `0x2e` meant "absent", a touch prompt meant "present". An interactive request
  (`up` true) now polls the button before disclosing the miss, for both
  discoverable and allowList lookups, matching a genuine YubiKey (which does the
  same and passes FIDO conformance). The platform's silent `up:false` pre-flight
  (WebAuthn / ssh-sk credential discovery) stays touch-free and still fast-fails,
  so login latency and ssh-sk are unaffected. **bcdDevice → 0x082F.**
- **The FIDO `pinUvAuthToken` now expires instead of living for the whole power
  cycle.** A minted PIN/UV auth token carried no usage timer (CTAP 2.1 §6.5.5.7
  was unimplemented), so once issued it stayed valid until the next reboot. It
  now runs the spec's usage timer, checked before every CBOR command: a **30 s
  rolling inactivity window** — each token-authorized command (`makeCredential`,
  `getAssertion`, `credentialManagement`, `largeBlobs` write, `authenticatorConfig`,
  the vendor MSE channel) pushes the deadline out — bounded by a **10-minute
  absolute cap** from issuance that fires even under constant use. Impact was low
  — the token is RAM-only (a reboot always cleared it), it cannot be minted
  without the PIN, and `makeCredential`/`getAssertion` still require a fresh
  physical touch regardless; the practical exposure was a host that had already
  captured the token driving touch-free `credentialManagement` enumeration or
  deletion — but a bounded lifetime closes the gap. Found comparing the FIDO
  clientPIN state machine against the upstream lineage's own token-expiry fix.
  **bcdDevice → 0x082E.**
- **`rsk lock enable --key-out` no longer leaves the lock key briefly
  world-readable.** The key file was `chmod 0600`-ed only *after* the write
  finished and the descriptor closed, so the 32-byte host lock key (it wraps the
  FIDO seed) sat at the umask default in between, and the `chmod` followed a
  symlink swapped in during the window. The file is now created `0600` atomically
  with `O_EXCL`. Host-only (`rsk` → 0.3.13); `--key-out` is a test-only flag and
  the normal flow only prints the key to stdout, so exposure was minor.

## [0.3.9] - 2026-07-19

### Fixed

- **KV store no longer rolls a key back to an older value on a power-cut mid-delete.**
  The vendored `sequential-storage`'s `remove_item` erased a key's page copies starting
  from `find_first_page(PartialOpen).unwrap_or_default()`, which falls back to page 0
  whenever there is no partial-open page (the normal steady state: a closed frontier page
  plus an open buffer page). That inverted the intended oldest-first erase order, so a
  power loss during a delete could erase the newest copy first and leave an older copy
  live — which the next read then returned (a rollback past the committed value). The
  remove path now computes the newest page the same way the read path does, so the two
  agree. On RS-Key this was fail-closed (every stored value is AEAD-sealed and read past a
  length/tag gate, so a resurfaced stale/short blob is rejected, not used), but it is a
  real durability defect in the store that holds all sealed secrets. Found by the
  `kv_durability` fuzz target; an upstream `sequential-storage` bug (fix confined to the
  vendored fork, `third_party/sequential-storage.patch` item 3). **bcdDevice → 0x082D.**

## [0.3.8] - 2026-07-19

### Added

- **`strong-pin` build feature — stronger PIN policy for the FIDO clientPIN.** A new
  opt-in cargo feature that raises the clientPIN minimum to **6** code points (from
  CTAP's default 4) and refuses trivially guessable PINs — a single repeated digit, or
  a ±1 run like `123456` / `654321` — on both the host `setPIN`/`changePIN` path and the
  trusted-display PIN pad. Off by default; the default build is unchanged. `fips-profile`
  now bundles this same PIN policy. Motivated by the RP2350 BOOTSEL flash snapshot/restore
  that rolls back the wrong-PIN counter ([#37](https://github.com/TheMaxMur/RS-Key/issues/37)):
  with the retry ceiling removed, PIN entropy is the practical brute-force bound. See
  [docs/build.md](docs/build.md) and [docs/threat-model.md](docs/threat-model.md).
- **`LED_POWER_PIN` build knob — support boards whose LED is power-gated.** A new
  compile-time env knob names an optional GPIO the firmware drives **high at boot**
  to power a gated LED rail, then holds for the device's lifetime. This is what the
  **Seeed Studio XIAO RP2350** needs: its onboard WS2812 data is on GP22 but its
  power sits behind GP23, so the LED stayed dark ([#36](https://github.com/TheMaxMur/RS-Key/issues/36)).
  Build it `LED_PIN=22 LED_ORDER=grb LED_POWER_PIN=23`. Off by default; the pin
  must differ from `LED_PIN` and a GPIO `PRESENCE_PIN` (rejected at compile time).
  See [docs/hardware.md](docs/hardware.md) and [docs/build.md](docs/build.md).
- **`USR_LED_PIN` build knob — park a nuisance onboard LED off at boot.** A new
  compile-time env knob names an optional GPIO wired to an onboard user/status LED
  that comes up lit; the firmware drives it to the LED's **off** level at boot and
  holds it. This is the **Seeed Studio XIAO RP2350**'s active-low USR LED on GP25,
  which the board's weak pull-down otherwise keeps on ([#36](https://github.com/TheMaxMur/RS-Key/issues/36)).
  Build it `USR_LED_PIN=25` (add `USR_LED_ACTIVE_HIGH=1` for an active-high LED).
  Off by default and independent of the addressable LED, so it also works on a
  `LED_KIND=none` build; the pin must differ from `LED_PIN`, `LED_POWER_PIN`, a GPIO
  `PRESENCE_PIN`, and the display `WAKE_PIN` (rejected at compile time). See
  [docs/hardware.md](docs/hardware.md) and [docs/build.md](docs/build.md).
- **`KVMAIN` build knob — fit the firmware on a 2 MB flash.** The KV main partition
  size is now a compile-time knob (default 1408K, the checked-in layout). A **2 MB**
  board (Seeed XIAO RP2350, Waveshare RP2350-Zero-CM) can't fit the ~900K image under
  the default KV store, so shrink it: `FLASH_SIZE=2M KVMAIN=896K` (896K creds + 128K
  counters + 1024K code) ([#36](https://github.com/TheMaxMur/RS-Key/issues/36)). build.rs
  bakes the size into both `memory.x` and `flash_storage.rs` so the two partitions
  never drift, and rejects a split that leaves under 1 MB for code with a fix hint.
  A fully provisioned key needs only a few hundred KB. See [docs/build.md](docs/build.md).

### Changed

- **Faster `authenticatorCredentialManagement` enumeration with many distinct RPs.**
  `enumerateCredentials` re-read every resident-credential slot on each per-RP call,
  so listing a store of *N* credentials spread over *N* distinct RPs was O(N²) flash
  reads — on hardware a 256-passkey / 256-RP store took ~13 s (a store of the same
  256 passkeys under one RP took ~1.3 s). The applet now builds a small in-RAM
  slot→rpId-hash-prefix index once per enumeration (invalidated by a new `Fs`
  mutation counter, so any add/delete rebuilds it) and reads flash only for the
  target RP, making the walk O(N). Enumeration results and order are unchanged; a
  4-byte prefix hit is still confirmed by the full rpId-hash compare. bcdDevice bump
  only (no wire change).

### Fixed

- **Post-quantum ML-DSA-65 `makeCredential` no longer hard-faults the device.**
  Requesting an ML-DSA-65 (COSE alg `-49`) credential wedged the FIDO worker on the
  RP2350: the compute worker ran nested under `main`'s ~95 KiB one-time init stack
  frame (it was `await`ed at the tail of `#[embassy_executor::main]`), which left
  ML-DSA-65's ~92 KiB keygen chain flush against the shared main-stack ceiling — the
  next USB/keepalive interrupt overran it into the heap and halted the core. (ML-DSA-44
  fit with ~27 KiB to spare and was unaffected, which is why only the larger parameter
  set failed.) The worker now runs as its own thread-executor task, so `main` returns
  and that init frame is reclaimed, restoring ~90 KiB of headroom. Firmware-only; no
  wire-format or at-rest change. Latent in shipped builds (ML-DSA is not advertised
  without `advertise-pqc`, so no platform requested it).
- **`always-uv` and `strict-up` built together no longer break `ssh-sk`.** With both
  features on, `ssh -i` failed with "device not found": the platform's silent
  `up:false` pre-flight (credential discovery) was refused with `CTAP2_ERR_PUAT_REQUIRED`
  because the alwaysUv gate keyed on the `strict-up`-forced presence flag rather than the
  request's raw `up` option. It now keys on `up` (CTAP 2.1 §6.2.2 step 5), so the probe is
  exempt from the PUAT refusal regardless of `strict-up`. `strict-up` still polls the
  button on the probe (its deliberate two-touch behavior); only the spurious refusal is
  gone. Reported for v0.3.7 ([#34](https://github.com/TheMaxMur/RS-Key/issues/34)).
- **`strict-up` no longer weakens `alwaysUv` for the `up:false` pre-flight.** On a
  `strict-up` build with alwaysUv enabled, the silent `up:false` discovery probe was
  returned as a *usable* assertion with the user-presence (UP) flag **set** — because
  `strict-up` forces the button poll and the emitted UP flag followed that poll rather
  than the request's `up` option. A relying party that does not require user verification
  would accept it, so a stolen key could authenticate without the PIN, defeating the
  alwaysUv guarantee (a plain `always-uv` build was unaffected — it returns the probe with
  UP clear). The emitted UP flag now follows the request's raw `up`, so the probe stays
  inert (UP=0) even while `strict-up` still polls the button, and `ssh-sk` keeps working
  (the platform discards the pre-flight regardless). No shipped flavor enabled this by
  default (`firmware-strict-up` ships with alwaysUv off); found by an internal security
  review — a follow-up to the [#34](https://github.com/TheMaxMur/RS-Key/issues/34) fix above.
- **PIV stays detectable by OpenSC after the OpenPGP applet has been used.** The
  PIV `SELECT` application property template placed the NIST RID directly under
  tag `79` instead of the required nested `4F`. OpenSC's `piv_match_card` then
  failed to re-detect PIV whenever another applet was selected first (e.g. by
  `gpg`/`scdaemon`), so `p11tool` / Chrome mTLS saw only OpenPGP until a
  `ykman piv info` forced PIV back — a real YubiKey re-detects PIV fine. The
  template now matches NIST SP 800-73-4 (and a YubiKey's response) for tags
  `4F` / `79`.
- **OpenPGP RSA key import can no longer halt the device on a zero-valued prime.**
  A `PUT DATA` key import (admin/PW3) whose `P` or `Q` prime MPI was present but
  numerically zero (a non-empty `00` that the applet's `is_empty()` check let
  through) reached `RsaPrivateKey::from_p_q`, where computing `(p-1)(q-1)`
  underflowed num-bigint's unsigned subtraction and panicked. Under `panic-halt`
  that wedged the authenticator until replug. `rsa_from_pqe` now rejects a
  degenerate prime as a bad key (`EXEC_ERROR`). Found by the new `openpgp_key_load`
  fuzz target.
- **The TUI cockpit can no longer be hung by a counterfeit device.** `rsk-tui`'s CCID
  `get_data_full` chained `61xx` GET RESPONSE with no bound, so a device that answered
  every GET RESPONSE with a bare `61 00` spun the synchronous event loop forever (and a
  data-carrying variant grew memory without limit) — reached unauthenticated on startup
  and on every 5 s refresh. The chaining is now bounded by a round and byte cap.
  Host-tool only (`tools/tui` → 0.3.1); found by an internal security review.

## [0.3.7] - 2026-07-17

### Added

- **`rsk-tui` cockpit — richer applet reads, a passkey count, LED preview, and
  scrollable output (`0.3.0`).** Four host-only additions, no firmware change:
  the FIDO section can **count resident passkeys** over credMgmt
  `getCredsMetadata` (PIN-gated — the count needs the FIDO2 PIN, but not the
  enumeration); OpenPGP and PIV surface real metadata pulled in the same gather —
  OpenPGP parses its `6E` DO (card serial, PW1/RC/PW3 retry counters, populated
  key slots) and PIV reads the PIN GET METADATA (retries + default-PIN flag); the
  LED section paints a live colour swatch per state; and long **message modals**
  (audit journal, verify report) now scroll (arrows / `PgUp` / `PgDn` / `Home` /
  `End`). The new fields also appear in `rsk-tui --once` / `--json`. See
  [docs/guides/tui.md](docs/guides/tui.md).
- **Differential interop harness — diff RS-Key against a real YubiKey.** New
  `tests/interop/{capture,diff,divergences,normalize,parity}.py`: capture a
  read-only snapshot of each key (both can stay plugged; an identity guard keys
  off the `RSK` marker and the FIDO AAGUID), then classify every field against a
  known-divergence allow-list so a fidelity gap stands out from the ~160 fields
  that legitimately differ. Host-testable engine (`python -m pytest
  tests/interop/test_diff.py`). A first macOS run against a YubiKey 5C NFC found
  85 identical / 76 expected-divergence / 1 unexpected field (see
  [docs/interop.md](docs/interop.md) → "Differential against a real YubiKey").

### Changed

- **Faster PIV SELECT — skip the redundant default-file scan after the first.**
  `scan_files` provisions the PIV defaults (PIN/PUK/retry/management/attestation)
  on the first SELECT and re-probed all five on every subsequent SELECT. Those
  files only ever go away by a path that recreates them (PIV reset) or reboots
  (trusted-display factory wipe), and `authenticatorReset` leaves them, so a RAM
  guard now runs the scan once per power-cycle and the wire response (the APT) is
  byte-identical. Shaves the five flash probes off every re-SELECT (`ykman`,
  OpenSC, `age-plugin-yubikey`, PIV sign).
- **Faster SHA-512 on the Cortex-M33 (the FIDO key-derivation ratchet).** SHA-512
  and SHA-384 now come from a new `rsk-sha512` crate instead of the `sha2`
  soft backend, leaving every digest **byte-for-byte unchanged** — the compression
  function is the only thing swapped, so `hmac`/`hkdf` compose over it identically
  and no stored credential key changes. On-device profiling had found the FIDO
  getAssertion ratchet (8× HKDF-SHA512, ~96 SHA-512 blocks) dominating every
  assertion at ~191 ms of ~241 ms: `sha2` fully unrolls SHA-512 into a ~28 KB
  straight-line body that overflows the RP2350 XIP cache and re-fetches over QSPI
  flash on every block. The replacement compiles to an ~866-byte rolled loop that
  fits the cache. Output identity is gated on the host by a randomized differential
  against `sha2`/`hmac`/`hkdf` plus NIST/RFC 4231 KATs; SHA-256/SHA-1 stay on
  `sha2` (already fast on the M33) and Ed25519 (dalek) is unaffected.
  `bcdDevice` → `0x0820`.

- **Faster P-256 ECDSA signing (fixed-base comb + no wasted public-key derivation).**
  Two changes to the P-256 credential path, both leaving the RFC 6979 deterministic
  signature **byte-for-byte unchanged** (a KAT test pins the result to the `p256`
  crate's output), so this is a pure speedup with no wire or behaviour change:
  (1) the ephemeral `k·G` now uses a precomputed width-4 Lim–Lee comb table — the
  fixed-base technique already used for P-521 — instead of the crate's generic
  `mul_by_generator`; (2) a P-256 credential key is held as the bare scalar (like
  P-521), so getAssertion no longer builds a `SigningKey` that eagerly derives the
  public key `d·G` — a second fixed-base mul it never uses when only signing (the
  public key it does need, at makeCredential, comes from the same comb). Measured on
  the RP2350: a silent `up:false` P-256 assertion drops from ~303 ms to ~241 ms
  (about 20 % — the removed `d·G` was ~40 ms, the comb ~22 ms). Costs ~1 KB of flash
  for the table (`build.rs`-generated). P-384 / secp256k1 / P-521 are unchanged
  (P-521 keeps its comb + random nonce). `bcdDevice` → `0x081F`.

- **FIDO2 signature counters are now per-credential (privacy).** Each resident
  credential (passkey) keeps its own counter in a new packed `EF_CRED_CTR` flash
  file, starting at 0 and advancing only on its own assertions — colluding relying
  parties can no longer read a shared global counter to correlate how much the key
  is used across sites (WebAuthn §6.1.1). Non-resident (second-factor) credentials
  keep no device state and report signCount 0; legacy U2F keeps its global monotonic
  counter. Migration is forward-safe for passkeys: a credential created before
  `EF_CRED_CTR` seeds its counter from the frozen global value on first use, so the
  reported count never decreases. A pre-existing non-resident credential now reports
  0, which a site that strictly enforced counter monotonicity may treat as reason to
  re-register. Found by the RS-Key ↔ YubiKey differential harness (finding #4:
  RS-Key's shared counter at ~105 vs a real YubiKey's per-credential counter).
  `bcdDevice` → `0x081D`.

- **getInfo no longer advertises `U2F_V2` while `alwaysUv` is on.** CTAP 2.1 §7.2.4
  disables the CTAP1/U2F interface whenever alwaysUv is enabled (via the `always-uv`
  build feature or the runtime `toggleAlwaysUv`), and the `versions` list now drops
  `U2F_V2` to match — a platform is no longer told CTAP1 is available while every U2F
  request is refused. The CTAP2 versions and the default (alwaysUv-off) advertisement
  are unchanged.

### Fixed

- **`alwaysUv` no longer breaks the silent credential-discovery pre-flight (fixes
  `ssh -i` "device not found" on an `always-uv` build).** `getAssertion` rejected
  every request without a `pinUvAuthParam` under `alwaysUv` with
  `CTAP2_ERR_PUAT_REQUIRED` — including the platform's silent `up:false` probe that
  OpenSSH's `ssh-sk` middleware (and WebAuthn platforms) use to locate which
  credential/device to sign with. CTAP 2.1 §6.2.2 step 5 guards that error on the
  `up` option being *present and true*, so the silent probe must be exempt (it
  returns a silent assertion or `NO_CREDENTIALS`); a real YubiKey and pico-fido do
  exactly that. The `alwaysUv` gate now keys on `want_up` (honoring `up:false`,
  and — under the `strict-up` build — still demanding UV on every call), so a
  silent pre-flight succeeds while an interactive `up:true` request without UV is
  still refused. The real assertion then correctly prompts for the PIN each use
  (`alwaysUv` as designed). `makeCredential` is unchanged: registration can't be
  silent (§6.1.2 has no `up` guard). Reported in
  [#34](https://github.com/TheMaxMur/RS-Key/issues/34). `bcdDevice` → `0x0823`.

- **`EF_CRED_CTR` per-credential counter now churns the counter partition, not the
  secret one.** The per-credential signature counter file (`0xC001`) is rewritten on
  every getAssertion, but `is_counter_fid` routed only the global `EF_COUNTER`
  (`0xC000`) to the dedicated counter partition, so the new file appended to the
  **main** partition — the one holding sealed credentials and keys, which the
  two-partition split deliberately keeps off the per-operation hot path to avoid a
  multi-second cold-migration stall during authentication. Adding `0xC001` to the
  predicate restores that isolation. Internal routing only (no wire, key, or
  signCount change), and fixed before the per-credential counter shipped, so no
  provisioned device re-seeds. `bcdDevice` → `0x0821`.

- **`rsk-tui` starts in the Linux dev shell again.** The dev-shell launcher is a
  bare `cargo run` of `tools/tui`, whose binary carries no nix RPATH, so its
  `DT_NEEDED` `libudev.so.1` / `libpcsclite.so.1` were only satisfied at build
  time (pkg-config) and missing at run time — `error while loading shared
  libraries: libudev.so.1`. The shell now also exports `systemd` (libudev) and
  `pcsclite` on `LD_LIBRARY_PATH` on Linux. Host-only; `nix run .#rsk-tui` was
  unaffected. Reported in [#31](https://github.com/TheMaxMur/RS-Key/issues/31).

- **READ CONFIG now clamps `USB_ENABLED` to the supported capabilities.** The
  management DeviceInfo (`0x1D`) echoed a host-written `EF_DEV_CONF` blob verbatim,
  so a persisted enabled-applications mask wider than `SUPPORTED_CAPS` (e.g. a newer
  `ykman` that knows capability bits this firmware lacks) was reported as-is —
  `enabled ⊄ supported`, which a real YubiKey never does. `config_tlv` now masks the
  `USB_ENABLED` TLV down to `SUPPORTED_CAPS` on read, healing already-persisted
  devices without a rewrite. Found by the new RS-Key ↔ YubiKey differential harness
  (`enabled = 0x3A3B` vs `supported = 0x023B` on a live board). `bcdDevice` → `0x081C`.

## [0.3.6] — 2026-07-16

### Added

- **`always-uv` build feature — ship with CTAP 2.1 `alwaysUv` on by default.** A new
  opt-in cargo feature (`cargo build --release -p firmware --features always-uv`) bakes
  the `alwaysUv` option on, so the key demands user verification for every
  makeCredential / getAssertion out of the box — no post-flash `ykman fido config
  toggle-always-uv`. OFF by default; the shipped image is unchanged (its alwaysUv still
  starts off until a platform toggles it). The stored state is now tri-state — an
  explicit `toggleAlwaysUv` override (`EF_ALWAYS_UV` = `[1]`/`[0]`, survives reboots,
  cleared by `authenticatorReset`) over the compile-time default — so the feature build
  stays fully runtime-toggleable and a reset returns alwaysUv to the compiled default.
  On a normal build the on/off representation is the same `[1]`/absent pair as before
  (no on-flash change). With alwaysUv on and no PIN set, FIDO operations return
  `CTAP2_ERR_PUAT_REQUIRED` until a PIN is configured — the standard cue for the platform
  (Windows, Chrome) to prompt for one. Whenever alwaysUv is on (via this default or a
  runtime `toggleAlwaysUv`) the **CTAP1/U2F interface is now disabled** (CTAP 2.1 §7.2.4):
  U2F only proves presence, so leaving it live would bypass the always-require-UV
  guarantee — register / authenticate return `CONDITIONS_NOT_SATISFIED`, matching a
  YubiKey. WebAuthn / CTAP2 is unaffected. bcdDevice → `0x081A`. See docs/build.md.

### Changed

- **`sequential-storage` 7.2.0 → 8.0.0.** The flash key/value backend's cache API was
  restructured upstream into a single composite `Cache` of three sub-caches (page
  states + page pointers + key pointers); `flash_storage.rs` and the fuzz harnesses
  are migrated to it. The release is on-flash-compatible with 7.x, so a provisioned
  device upgrades with no migration. The crate is vendored under
  `third_party/sequential-storage/` and wired via `[patch.crates-io]` because it
  carries one local change (below) that has no public API; the single-function diff is
  kept in `third_party/sequential-storage.patch`.
- **Higher, decoupled credential/key capacity.** All applets shared one 256-entry
  dynamic-file budget, so filling PIV key slots shrank the passkey ceiling — a HW
  stress test hit `KEY_STORE_FULL` at ~80 passkeys (not the logical 256) once ~48 PIV
  files were provisioned, and `remainingDiscoverableCredentials` over-reported the
  free slots. The shared budget (`MAX_DYNAMIC_FILES`) is raised 256 → 1280 to exceed
  the union of every applet's own cap, and the storage key-pointer cache
  (`MAIN_CACHE_KEYS`) is raised 512 → 1280 in lockstep so the freed capacity stays on
  the O(1) read/migrate path instead of falling off the flash-scan cliff. getInfo
  `remainingDiscoverableCredentials` (0x14) and credMgmt `getCredsMetadata` (0x02) now
  report an honest estimate clamped by the true free shared-file budget, so the host
  is no longer promised slots the store can't back. RAM cost ~8 KiB; no on-flash
  format change (the indexes are rebuilt from flash on boot, so provisioned devices
  upgrade transparently). bcdDevice → `0x0811`.

### Fixed

- **Run-20 audit hardening (no exploitable defect; defense-in-depth on the perf delta
  above).** Three follow-ups from the security review:
  - The boot cache-warm no longer trusts a partial walk after a flash *read* fault. The
    vendored `sequential-storage` page-advance loop swallowed a page-state error and
    still cleared the "dirty" flag at the walk's end, so a read fault that skipped a
    live page could leave a stale key→address entry marked clean. It now skips only an
    interrupted-erase page (always a fully-migrated source, so enumeration stays
    complete) and aborts the walk on any other error, leaving the cache dirty for the
    existing `is_dirty` guard to discard. No observable change on RP2350 (in-range flash
    reads don't fault); the update is in `third_party/sequential-storage.patch`, and the
    vendored tree is verified byte-identical to published 8.0.0 apart from that one file.
  - `MAIN_CACHE_KEYS` is raised 1280 → 1281 (`MAX_DYNAMIC_FILES + 1`) so the one live
    main-partition key the dynamic-file budget does not count (`EF_META`) can never fall
    off the key-pointer cache on a fully-provisioned device.
  - PIV MOVE to the `0xFF` delete sentinel no longer writes an unread `0xD4FF` orphan
    public-point file: the per-slot pubkey carry is skipped when there is no destination
    slot (the source slot's cache is still dropped).
  No wire or on-flash change. bcdDevice → `0x0819`.
- **The first credential enumeration after a power-cycle is no longer slow: the boot
  scan warms the flash key-pointer cache it was already reading.** `sequential-storage`
  keeps a RAM cache mapping each key to its flash address so a read is O(1); it starts
  empty after every boot, so the first `fetch_item` of each key did a cold backward
  ring-scan — listing 256 passkeys right after plug-in measured ~9 s (vs ~2.6 s warm).
  The boot `scan` already walks the whole store once (via `fetch_all_items`) but threw
  the addresses away. The vendored `sequential-storage` (see Changed) now seeds the
  key-pointer cache from that existing walk, so the cache is warm before USB even
  enumerates and the first list is as fast as a warm one — no extra flash reads. The
  warm is completion-gated: the cache is held "dirty" during the walk and cleared only
  when the iterator runs to the end, so a walk that errors partway self-invalidates via
  the existing dirty guard rather than caching a stale pointer (power-cut-safe — the
  cache is RAM-only, rebuilt each boot). Adds ~30–120 ms of pre-USB boot bookkeeping at
  a full store. Measured on a 100-passkey device: first list after a power-cycle
  3044 ms → 1023 ms (the slowest single-cred read 2044 ms → 23 ms), now identical to a
  warm list. bcdDevice → `0x0818`.
- **OATH LIST / CALCULATE ALL are faster on a full store: the occupied-slot map is
  read from the in-RAM present index instead of scanning flash.** Enumerating
  accounts sorted the live OATH slots with a whole-partition `for_each_key` walk on
  every LIST (`0xA1`) and CALCULATE ALL (`0xA4`) — and PUT re-paid it to find a free
  slot — so a busy store (a parity fill measured `ykman oath accounts list` ~1.6×
  slower than a hardware YubiKey) spent tens of ms per call on the scan. `Fs` already
  keeps an authoritative in-RAM present index (seeded at boot by `scan`, kept live by
  every put/delete), so the slot gather (`present_creds`) and free-slot search now
  read occupancy from it in O(255) bit tests with no flash access — the same fix
  applied to FIDO `slot_map` and PIV. Occupancy-equivalent to the old `for_each_key`
  pass (same torn-migration semantics) and ascending by construction, so LIST /
  CALCULATE ALL output — including its `61xx` paging — is byte-identical. No wire or
  on-flash change. bcdDevice → `0x0817`.
- **PIV GET METADATA is fast at any slot count: each slot's public point is cached
  in its own flash file instead of a shared, capacity-bound record.** The earlier
  cache packed every EC slot's point into one EF_META blob (≤768 B for points), so
  past ~10 populated EC slots the rest kept only a bare head and GET METADATA
  recomputed the software point (`d·G`, ~30 ms) on every read — `ykman piv info` over
  24 slots measured ~1.0 s (~3× a hardware YubiKey), ~400 ms of it that d·G. Each
  slot now caches its point in a private per-slot file (`0xD4xx`, unsealed — the
  point is public) written at key generate/import and read O(1) by GET METADATA at
  any slot count; a slot without one (pre-upgrade, or a failed import derive) falls
  back to the old EF_META cache, then to deriving the point, so provisioned devices
  upgrade transparently. The redundant per-slot `has_key` probe GET METADATA did on
  top of the existing `meta_find` gate is dropped. No wire change; GET METADATA
  output is byte-identical. bcdDevice → `0x0816`.
- **credMgmt enumeration and makeCredential are much faster on a full store: the
  occupied-slot map is read from the in-RAM present index instead of scanning
  flash.** `slot_map` — run on every getCredsMetadata / enumerateRPs /
  enumerateCredentials / getNext and on every makeCredential (dedup + free-slot) —
  walked the whole flash partition each call (~84 ms on a 256-passkey device), so
  listing every credential paid it ~289 times (~24 s of a measured ~34 s walk) and
  each registration re-paid it (~336 → 480 ms as the store filled). `Fs` already
  keeps an authoritative in-RAM present index (seeded at boot by `scan`, kept live
  by every put/delete), so `slot_map` now reads occupancy from it in sub-ms with no
  flash scan and no new state — occupancy-equivalent to the old `for_each_key` pass
  (same torn-migration under-count semantics). The FIDO HID poll interval is also
  tightened 5 ms → 1 ms so a multi-frame enumerate/assertion response drains faster.
  No wire or on-flash change. bcdDevice → `0x0814`.
- **credMgmt enumeration is O(n), not O(n²): getNextRP / getNextCredential resume
  from a slot cursor instead of re-scanning from slot 0.** With the per-call flash
  scan removed (above), the remaining full-walk cost was each getNext re-reading the
  store from the first slot to the N-th match — quadratic in the credential count.
  `CredMgmtState` now carries a per-enumeration slot cursor (separate cursors for the
  RP and credential walks, each reset by its Begin and advanced by each getNext), so a
  getNext reads only the gap to the next match. On a full 256-passkey device the warm
  per-credential enumeration cost flattens (~10 ms, matching a hardware YubiKey)
  instead of climbing with slot position. No wire change; enumerate output is
  byte-identical. bcdDevice → `0x0815`.
- **OATH LIST / CALCULATE ALL now page through a full store instead of silently
  truncating.** A device holding many accounts (up to the 255 the applet stores)
  built each enumeration response into a single ~2 KiB CCID frame and stopped when
  it filled, returning `9000` — so `ykman oath accounts list` / Yubico
  Authenticator saw only the ~135 (LIST) / ~94 (CALCULATE ALL) that fit, and the
  rest were invisible even though stored and individually usable (HW-found on a
  255-account fill). LIST (`0xA1`) and CALCULATE ALL (`0xA4`) now implement the
  YubiKey-OATH `61xx` + SEND REMAINING (`0xA5`) chaining they had stubbed out: when
  a frame fills they return `61 00` and resume the sorted-credential sweep on the
  next `0xA5`, so every account surfaces. ykman / Yubico Authenticator already speak
  this and need no change; a host that ignores `0xA5` still gets the first frame
  exactly as before (no regression). bcdDevice → `0x0813`.
- **getAssertion no longer wedges the device after the capacity bump.** The
  credential-key builder (`CredKey::from_raw`) and signer (`CredKey::sign`) folded
  the lattice (ML-DSA) key-expansion / streaming-sign frames — ~106 KiB and ~50 KiB —
  into their own stack frames, so **every** assertion, including a P-256 one that
  never touches ML-DSA, reserved that ~106 KiB on the worker stack. With the capacity
  bump's extra ~16 KiB of static RAM shrinking that stack, a getAssertion overflowed
  it into the adjacent USB/IRQ wakers and hung the device hard (still USB-enumerated
  but unresponsive on HID and CCID, recoverable only by replug). The ML-DSA build/sign
  arms are moved behind `#[inline(never)]` helpers so their large frames stay off the
  EC path; a P-256 getAssertion's builder/signer frames are now negligible.
  HW-verified on the full capacity build. bcdDevice → `0x0812`.
- **PIV GET METADATA is faster: a key slot's public point is now cached in its
  metadata record** instead of being recomputed on every probe. `ykman piv info`
  and the Yubico Authenticator read `GET METADATA` (INS 0xF7) for every slot, and
  for a populated EC slot that recomputed the public key (`d·G`, ~tens of ms in
  software) every time. Key generation and import already derive that point, so
  the slot's metadata record now carries it (appended after `[algo, pin policy,
  touch policy, origin]`) and GET METADATA emits it directly. RSA slots are
  unchanged (their modulus rebuild is cheap). Keys generated by earlier firmware
  keep working and derive the point on the fly (the bare record has no trailer).
  The cached point is **best-effort**: the shared `EF_META` store reserves room for
  every slot's essential 4-byte head, so when it is near full (many populated EC
  slots) a new key stores just the head and GET METADATA derives its point on the
  fly — provisioning never fails or leaves a key without metadata because of the
  cache, and `EF_META` stays bounded regardless of how many slots are used.
  bcdDevice → `0x0810`.
- **Passkey enumeration is much faster: the credential's public key is now cached
  in its resident record** instead of being recomputed on every
  `authenticatorCredentialManagement` enumerate call. On this MCU a software
  P-256 public-key derivation (`d·G`) costs ~150–250 ms, so listing passkeys — as
  the Yubico Authenticator "Passkeys" tab does — spent that per credential every
  time (a measured ~1.2 s for four passkeys). makeCredential already computes the
  point for authData, so the record now carries it (a length-prefixed trailer on
  a new **v3** resident record) and enumeration emits it directly, dropping the
  per-credential cost to a flash read. The one-time clientPIN unlock (an ECDH, not
  cacheable) is unchanged. Records already on a device (v1/v2) keep deriving on
  the fly and stay byte-for-byte compatible; passkeys created by this firmware get
  the cache. EC curves (P-256/384/521, secp256k1, Ed25519) are cached; the lattice
  schemes derive as before (their public keys exceed the record). bcdDevice → `0x080E`.

## [0.3.5] — 2026-07-14

### Changed

- **`makeCredential` now ships `fmt:"none"` attestation by default**, fixing
  `ssh-keygen -t ed25519-sk` enrollment on Windows / OpenSSH 10.0p2 (issue #26).
  RS-Key previously returned packed **self**-attestation, so an Ed25519 credential
  carried an Ed25519 self-attestation signature. OpenSSH 10.0 added
  `fido_cred_verify_self`, and the Windows WebAuthn API does not round-trip that
  EdDSA signature faithfully, so the verify failed with `FIDO_ERR_INVALID_SIG` and
  the enroll aborted with "Key enrollment failed: invalid format" (ES256 self-att
  round-trips fine, so `ecdsa-sk` worked; a genuine YubiKey uses basic ES256 x5c
  attestation and never hits the path). Self-attestation conveys no trust beyond
  "none" (WebAuthn §6.5.2), so shipping "none" loses nothing and is more private.
  An explicitly-requested **enterprise** attestation still emits its full x5c
  statement, and the `fido-conformance` profile keeps packed self-attestation (its
  MakeCredential tests cryptographically verify it). `getInfo.attestationFormats`
  is now `["none","packed"]`. Firmware `bcdDevice` `0x080C` → `0x080D`.

### Fixed

- **A wrong PIN in `rsk fido set-pin` / `list-passkeys` now prints a clean error,
  not a Python traceback.** python-fido2 raises `CtapError` when the device
  rejects a clientPIN operation; `change_pin`, `set_pin` and `get_pin_token` left
  it uncaught, so mistyping the current PIN while changing it dumped a stack trace
  instead of "wrong PIN". These now map the CTAP 2.1 §6.5.5 status to an operator
  message — a wrong PIN reports how many attempts remain before it blocks, and the
  blocked / auth-blocked / policy statuses get actionable text — via a shared
  `common.die_ctap_pin_error`. `rsk` `0.3.10` → `0.3.11`; host-only, no firmware
  change.
- **`rsk` now finds the FIDO HID on Linux hosts where hidapi doesn't report a
  usage page (issue #28).** `ctaphid.find()` matched a device solely by its HID
  `usage_page == 0xF1D0`, but some Linux `hidapi` builds (the libusb backend, and
  older hidraw) enumerate the device with `usage_page` left `0`, so `rsk status`
  (and every command behind it) reported `FIDO HID : not found` even with the key
  plugged in. It now keeps the `usage_page` fast path and, when that field is
  unset, confirms the FIDO usage page straight from each device's report
  descriptor — VID/PID-agnostic, so it works for every build (the default
  `0x1209:0x0001` identity and each `VIDPID` preset), unlike hard-coding a single
  vendor's VID/PID. `rsk` `0.3.9` → `0.3.10`; host-only, no firmware change.
- **New passkey registration no longer hangs on the touch after a PIN is set.**
  A zero-length `pinUvAuthParam` is the CTAP 2.1 §6.1.2 / §6.2.2 step-1 selection
  probe: the authenticator takes a device-selection touch and then reports the PIN
  state through the returned error. With a PIN configured it must return
  `CTAP2_ERR_PIN_INVALID` (0x31) — the code a platform managing device selection
  (Chrome) reads to advance from that touch to PIN entry. `makeCredential` and
  `getAssertion` returned `CTAP2_ERR_PIN_AUTH_INVALID` (0x33) instead, so once a
  PIN was set a fresh registration showed "press the button" and the press never
  advanced (the no-PIN `PIN_NOT_SET` code was already correct, which is why
  registering *before* setting a PIN worked). Both now return `PIN_INVALID`.
  Firmware `bcdDevice` `0x080B` → `0x080C`.

### Security

- **A counterfeit FIDO device can no longer inject terminal escapes through the
  clientPIN retry count.** The wrong-PIN message added above reads the remaining
  attempts from python-fido2's `get_pin_retries()`, which returns the device's
  CBOR-encoded value without type-checking it. A hostile authenticator could
  return that field as a text string of ANSI/OSC/bidi escapes instead of an
  integer, and `pin_error_message` embedded it into the `error:` line that `die()`
  prints to the terminal **without** the CLI's `sanitize()` filter — an operator
  running `rsk fido set-pin`/`list-passkeys` with a wrong PIN against the device
  would get those escapes interpreted (window-title spoof, OSC-52 clipboard write,
  Trojan-Source bidi). The retry count is now embedded only when it is really an
  `int`; anything else falls back to a plain `wrong PIN`. LOW (needs a malicious
  device + a wrong-PIN attempt); same class as the run-11/12 host-tooling escapes.
  Found by security-audit run-18. `rsk` `0.3.11` → `0.3.12`; host-only, no firmware
  change.

## [0.3.4] — 2026-07-12

### Fixed

- **OpenPGP decrypt no longer breaks after a `VERIFY` of both PW1 modes (issue
  #25).** `gpg`/`scdaemon` verifies one PIN entry into both PW1 modes
  back-to-back — mode `82` (DECIPHER/INTERNAL AUTH) then mode `81` (signing) —
  before a decrypt. `check_pin` cleared **both** PW1 latches on every successful
  verify and re-raised only the current one, so the trailing mode-`81` verify
  silently dropped the mode-`82` authorization the next `PSO:DECIPHER` needs,
  which then returned `6982` and surfaced to the user as `Bad PIN` with the
  correct PIN (typically after a replug, once `scdaemon` re-ran the full verify
  sequence). PW1.81, PW1.82 and PW3 are now treated as the independent access
  latches the card spec requires — a successful `VERIFY` raises only its own.
  Session-only state; no wire or on-flash format change. Firmware `bcdDevice`
  → `0x0809`.
- **A `put` past the dynamic-file cap no longer strands its value on flash.** A
  new runtime file (e.g. a resident credential) written once the dynamic set is
  full committed its bytes to flash *before* the cap check rejected it, so the
  caller saw `NoMemory` while the value stayed on flash — readable yet
  unregistered, and re-dropped by every reboot rescan at the same cap. The cap
  is now enforced before the write, so an over-cap `put` fails atomically and
  leaves no trace. Latent (it needs 256 dynamic files to trigger); no wire or
  on-flash format change. Firmware `bcdDevice` → `0x07FD`.
- **OpenPGP `PUT DATA` for the PW-status DO (`C4`) can no longer overwrite the
  PIN retry counters.** `put_pw_status` capped the copy at the full 7-byte
  record, so a ≥5-byte field wrote host bytes over the live PW1/RC/PW3 retry
  counters — its own doc comment says they are preserved; they were not. A host
  (malicious or a buggy 7-byte read-modify-write) could zero them and block
  every PIN across a power cycle, recoverable only by a key-destroying
  `TERMINATE DF`. The copy is now capped at the writable prefix (flag + the
  three max-length bytes); the retry counters are read-only. PW3-gated, so no
  privilege change. Firmware `bcdDevice` → `0x07FE`.
- **PIV `MOVE KEY` onto a key's own slot (`p1 == p2`) no longer destroys it.**
  A self-move wrote the sealed key/cert/metadata back into the slot and then
  unconditionally deleted the *source* — the same slot — leaving it empty while
  returning `0x9000`, silently erasing the (possibly only) key. Same-slot moves
  are now rejected with `INCORRECT_P1P2` before any write, matching real
  hardware. Management-key-gated, so no privilege change. Firmware `bcdDevice`
  → `0x07FF`.
- **OpenPGP empty-data `VERIFY` in PW2 mode (`P2=0x82`) reports PW1's retries
  again.** The `EF_RC → EF_PW1` remap was gated on a non-empty data field, so a
  status query (`00 20 00 82 00`) probed the reset-code EF instead of the shared
  PW1 verifier — answering `6A88`, or a spurious `PIN_BLOCKED` when a reset code
  was configured and blocked. The remap now applies to the status query too.
  Firmware `bcdDevice` → `0x0800`.
- **FIDO `getAssertion` no longer over-reports `numberOfCredentials`.** With more
  than `MAX_ASSERTION_CREDS` (16) discoverable credentials for one RP, the count
  reported the full match total while the `getNextAssertion` queue caps at 16, so
  a platform was told to fetch more than the device could serve and hit a
  premature `NOT_ALLOWED`. The count is now clamped to the servable queue size.
  Firmware `bcdDevice` → `0x0801`.
- **FIDO `getAssertion` binds an unscoped `pinUvAuthToken` to the request rpId on
  first use (CTAP 2.1 §6.2.2).** A token minted without an rpId (legacy
  `getPinToken`, or `0x09` with `ga` permission and no rpId) was reusable across
  arbitrary RPs for its whole lifetime — `makeCredential` bound it but
  `getAssertion` did not. It now binds on first use, so a later cross-RP
  assertion fails `PinAuthInvalid`. Firmware `bcdDevice` → `0x0802`.
- **CCID `XfrBlock` responses can no longer be silently truncated.** The applet
  response buffer (`RESP_CAP`) was sized to the full 2048-byte CCID message
  rather than its 2038-byte payload budget (message − 10-byte header), so a large
  response (e.g. a long OATH `LIST`) overran one frame and `run_xfr` dropped the
  trailing bytes including the status word. The buffer now matches the frame
  payload budget. Firmware `bcdDevice` → `0x0803`.
- **RSA keygen ignores a stale core1 prime when it did not engage the second
  core.** When the core1 entry gate timed out (`engaged=false`), the search still
  drained core1's find slots, which could hold a prime from the *previous*
  (possibly different-size) keygen — combining it would yield a malformed modulus
  with a weak factor. The search now consumes core1's finds only when it actually
  engaged core1 this keygen; stale finds are scrubbed at wind-down. Astronomically
  rare, but a real undefended race. Firmware `bcdDevice` → `0x0804`.
- **LED breathing effect no longer flickers dark at its peak.** `effect_vapor`
  divided the falling ramp by `period/2` (floor) over `half+1` steps, so for an
  odd `speed` the brightness could exceed `peak` at the apex and wrap to a dark
  value through the `u8` cast. The value is clamped to `peak` before the cast.
  Firmware `bcdDevice` → `0x0805`.
- **`updateUserInformation` no longer breaks a passkey by rotating its keys.**
  Editing a resident credential's user name (CTAP2.1 `authenticatorCredential
  Management` 0x07) reseals the credential box with a fresh IV. The signing key,
  hmac-secret and largeBlobKey were all derived from that box, so they rotated on
  every update — the relying party's stored public key stopped verifying and the
  passkey was effectively bricked. New resident credentials now stamp a **v2
  version byte** into their 42-byte resident id (a reserved header byte, outside
  the id's HMAC chain) and derive those three keys from the **stable** id instead
  of the box, so they survive the reseal. The credential id itself was already
  preserved; this extends that stability to the keys. Forward-compatible: resident
  credentials from older firmware carry an implicit v1 marker and keep deriving
  from the box, so an already-provisioned device is unaffected. No box or
  on-flash format change. Firmware `bcdDevice` → `0x0806`.
- **PIV `SET PIN RETRIES` (INS `0xFA`) now requires the PIN, not just the
  management key.** The handler gated only on the management key, then reset the
  PIN and PUK to their public defaults ("123456" / "12345678"). Because the
  default management key is public and the `9B` slot is touch-`NEVER`, a host
  that authenticated it could reset an *unknown* cardholder PIN without knowing
  it — locking the legitimate user out, and (for a touch-`NEVER` key slot) using
  their PIN-protected keys after verifying the now-default PIN. It now demands
  the current PIN as well, matching YubiKey's `set-pin-retries`. Reachable only
  by an already-management-authenticated caller, so no new privilege for a
  legitimate admin. Firmware `bcdDevice` → `0x0807`.
- **FIDO vendor `AUDIT_READ` (`0x41 / 0x07`) now requires a touch on a device
  with no PIN.** With no clientPIN the PIN gate is a no-op, so any local process
  could export the tamper-evident journal, whose per-entry `detail` is a 64-bit
  `rpIdHash` prefix — short enough to dictionary-match back to the relying
  parties a no-PIN device had been used with (the entries are only weakly
  pseudonymous, not anonymous). A physical touch is now required in that case,
  matching the sibling `AUDIT_CHECKPOINT`; a PIN-backed device is unchanged.
  Privacy hardening — no key material is exposed. The `rsk` CLI (`0.3.9`) and TUI
  (`0.2.9`) clients now prompt for that touch and map its denial. Firmware
  `bcdDevice` → `0x0808`.

### Security

- **Dual-core RSA keygen rejects a wrong-size prime at the inter-core handoff.**
  `RsaKeygen::offer_le` — the byte-transport entry the core0 drain feeds core1's
  finds through — converted whatever length it was handed, so a stale prime from
  a prior different-size keygen would have corrupted the assembled modulus. The
  mailbox is scrubbed on engage and keygens are serialized on the worker, so this
  never fires today; the length check is a belt-and-suspenders backstop that fails
  a mismatched find closed even if a future refactor reopened the handoff window.
  Defense-in-depth (found in the run-16 audit); no wire or on-flash format change.
  Firmware `bcdDevice` → `0x080B`.
- **PIV `GENERAL AUTHENTICATE` rejects a key slot with a truncated metadata
  record.** The handler read the PIN- and touch-policy bytes without checking the
  meta record was at least the 3-byte `[algo, pin, touch]` header, unlike
  `info::read_slot`; a sub-header record would have read policy from the zero-fill
  and skipped the touch gate. Every metadata writer emits ≥ 3 bytes, so no slot
  can reach this state — the guard is a defense-in-depth backstop (found in the
  run-16 audit) matching the sibling reader. No wire or on-flash format change.
  Firmware `bcdDevice` → `0x080A`.

### Changed

- **`rsk` CLI and `rsk-tui` harden their handling of device-controlled data.** A
  counterfeit or malfunctioning USB device that returned non-string/absent
  getInfo fields (`versions`, `aaguid`, `clientPin`) or a malformed soft-lock
  state could crash `rsk status` / `rsk inventory list` / `rsk lock` with an
  uncaught `TypeError`, or inject ANSI/OSC/bidi escapes into the operator's
  terminal via unsanitized `clientPin`/lock-state strings; `rsk-tui --json` left
  DEL/C1/bidi bytes unescaped. All device-controlled display values now route
  through the shared sanitizer or a type-guarded join, bool-coerced where
  appropriate, and the TUI `--json` writer escapes every control and non-ASCII
  char. Host-only (`rsk` `0.3.8`, `rsk-tui` `0.2.8`); no firmware change.

## [0.3.3] — 2026-07-10

### Added

- **ML-DSA-65 (FIPS 204, COSE `-49`) FIDO credentials.** A second post-quantum
  signature set alongside ML-DSA-44, negotiable via `pubKeyCredParams` and — like
  -44 — advertised in getInfo only under the `advertise-pqc` build; under
  `PREFER_PQC` it outranks -44. It is backed by a new in-tree, stack-optimized
  ML-DSA implementation (`crates/rsk-mldsa`, `no_std`/no-alloc, no `unsafe`) that
  **streams the FIPS 204 matrix A** on the fly instead of materializing it, so
  keygen+signing fit the RP2350's ~222 KiB main stack (~84 KiB host floor) where
  the by-value `fips204` crate's -65 (~192 KiB) overflowed it — the reason -65
  was previously dropped. ML-DSA-44 signing runs on the same crate too, and the
  `fips204` dependency has been dropped from the tree entirely. The
  implementation is checked byte-for-byte against NIST ACVP KATs (both parameter
  sets) with Kani proofs over the reductions and rounding. ML-DSA-87 (`-50`)
  remains unsupported (its response overruns `maxMsgSize`). Firmware
  `bcdDevice` → `0x07FB`.

### Security

- **CHANGE REFERENCE DATA no longer half-writes the OpenPGP reset code, and
  CTAPHID drops short reads (audit run-14 hardening).** `INS 0x24` with
  `P2=0x82` (the resetting code) verified the current RC and rewrote its verifier
  *before* the command's own `P2` check rejected it, desyncing the RC verifier
  from the `EF_DEK_RC` seal it unlocks — a self-inflicted, admin-recoverable
  state (the caller already needs the current RC), now closed by rejecting the
  unsupported `P2` before any write. Separately, the CTAPHID frame loop now
  requires a full 64-byte report instead of accepting `≥5`-byte short reads,
  whose stale buffer tail would otherwise be parsed as payload. Neither was
  exploitable; both were non-findings the run-14 audit flagged for hardening.
  Firmware `bcdDevice` → `0x07FC`.

- **Host tools neutralise terminal escapes from a counterfeit device on every
  path.** The earlier escape hardening reached only `rsk-tui --once`, and even
  there stripped only C0/C1 controls. The Python `rsk` CLI had no sanitizer at
  all, so a hostile device's USB product descriptor, getInfo `versions`, or a
  resident credential's rpId / `user.name` could inject ANSI/OSC sequences
  (screen repaint to forge a "genuine device" banner, `OSC 0` window-title,
  `OSC 52` clipboard write) into the operator's terminal on `rsk inventory` /
  `rsk status` / `rsk fido list-passkeys`. And the TUI's `char::is_control()`
  filter let Unicode bidi/format overrides (U+202E and the isolates) through,
  leaving a Trojan-Source reordering of the printed identity line. Both tools now
  route every device-controlled string through a shared sanitizer that maps C0/C1
  controls **and** Cf bidi/format characters to U+FFFD. Terminal-display integrity
  only — no device secret, PIN, or presence is involved. (`tools/rsk` 0.3.7,
  `tools/tui` 0.2.7)
- **Trusted display: the passkey manager keeps the registrable-domain suffix on
  every screen.** The earlier anti-phishing fix reached only the getAssertion/
  add-passkey ceremonies and the Confirm-Delete card; the passkey **list** row and
  the **service-detail title** still head-truncated an over-long relying-party id,
  hiding the real domain behind the ellipsis on the very screens used to review and
  delete credentials. They now head-ellipsize (`...registrable.domain`) when showing
  the rpId — a look-alike such as `accounts.google.com.attacker.com` can no longer
  read as a legitimate Google passkey. A user-set device-local nickname still keeps
  its head. bcdDevice `0x07F7` → `0x07F8`.
- **`rsk` / `rsk-tui` can no longer be hung or crashed by a hostile device.** The
  earlier host-tooling hardening bounded only the withheld-continuation-frame case;
  a malicious device could still (a) stream `CTAPHID_KEEPALIVE` frames forever to
  hang `rsk` and freeze the synchronous TUI, (b) send short continuation frames that
  made no progress, (c) return over-nested or non-UTF-8 CBOR to crash the decoder,
  (d) answer `rsk hw --transport fido`'s `CONFIG_READ` with a non-byte value to
  crash it, and (e) embed terminal escape sequences in getInfo/identity text that
  `rsk-tui --once` printed raw. The keepalive waits are now deadline-bounded, the
  CBOR decoder is depth- and UTF-8-hardened, the PHY `CONFIG_READ` path validates
  the value type (matching the LED path), and `--once` strips control bytes from
  device-controlled strings. (`tools/rsk` 0.3.6, `tools/tui` 0.2.6)
- **OpenPGP: the resetting code is no longer pre-set to the public default
  `12345678`.** Initialisation seeded the reset code (`EF_RC`) to the well-known
  admin default with an active retry counter, so an unauthenticated host could
  `RESET RETRY COUNTER` (P1=0) with `"12345678" || new-PW1` to reset the user PIN
  and then sign/decrypt with the victim's OpenPGP keys. The reset code now ships
  **deactivated** (per OpenPGP Card 3.4 §4.3.4) and is enabled only when an admin
  sets a real code via `PUT DATA 0xD3`; boot also neutralises any already-
  provisioned card still carrying the default reset code.
- **OATH: `VALIDATE` no longer fails open on an unreadable access code.** A stored
  access code longer than the read buffer made `seal_read` fail and (previously)
  unlocked the applet without the code. Reading a present-but-unreadable code now
  keeps the applet **locked**, and `SET CODE` bounds the code length.
- **OATH: `VERIFY CODE` now honours a credential's touch flag.** A touch-required
  primary HOTP credential could be exercised as a presence-free code-guessing
  oracle; `VERIFY CODE` now requests the same physical press as `CALCULATE`.
- **U2F: a `credProtect=userVerificationRequired` credential is refused on the
  U2F authenticate path**, which performs no user verification — only CTAP2
  `getAssertion` (with a PIN/UV) may exercise such a credential. Level 1/2
  credentials are unaffected.
- **Secure-PIN entry (trusted display): the on-pad PIN can no longer be diverted
  into an attacker-chosen command.** The CCID `PC_to_RDR_Secure` VERIFY template's
  class byte is now forced to `0x00` instead of copied from the host, so a host
  cannot set the ISO 7816-4 command-chaining bit to make the dispatcher buffer the
  typed PIN as a chain segment; the secure path also resets any incoming chaining
  state before dispatch.
- **Seed-moving vendor commands now name themselves on the trusted display.**
  `BACKUP_EXPORT` / `BACKUP_LOAD` and attestation import/clear were all approved
  behind a generic "Vendor config?" prompt; the master-seed export now reads
  "Export secret seed to host?" so a host cannot phish the approval for a full
  identity export behind a benign-looking touch.
- **OpenPGP GET DATA no longer over-reads the scratch buffer** for the fingerprint,
  CA-fingerprint and timestamp DOs: a present-but-short slot is zero-padded to its
  fixed width, so the DO's declared length matches what was written and no stale
  bytes from a prior command leak to an unauthenticated reader.
- **The trusted-display sign-in and add-passkey ceremonies now keep the
  registrable-domain suffix of an over-long relying-party id visible** instead of
  truncating it head-first. A relying party id is kept from the tail
  (`Label::clamp_domain`) and head-ellipsized (`...registrable.domain`), so a
  look-alike such as `accounts.google.com.attacker.com` can no longer hide the real
  domain behind the ellipsis while showing trusted-looking bait in the prefix.
- **The on-device passkey manager applies the same domain-suffix rule.** The
  earlier fix reached only the host-driven ceremonies; the passkey list, service
  detail and the destructive Confirm-Delete card still truncated the relying-party
  id head-first. They now keep the registrable-domain suffix
  (`Label::clamp_domain` + suffix-ellipsis), so a look-alike passkey cannot
  impersonate a service on the screen used to review and delete credentials.

### Fixed

- **A crafted phy record can no longer permanently brick USB.** The boot interface
  guard now falls back to enabling all interfaces unless a *management-capable* one
  (CCID or HID) survives — a keyboard-only mask previously slipped past it and
  stranded the device with no software path to rewrite the record.
- **The boot path no longer panics on a host-written LED pin.** A `led_gpio` from
  the phy record that collides with a GPIO presence pin is now ignored (the build
  default is used) instead of panicking every boot; a build whose own LED/presence
  pins collide is caught at compile time.
- **`rsk` no longer hangs against a hostile device** that announces an inflated
  CTAPHID response length and then withholds the continuation frames.
- **`rsk led --transport fido` no longer crashes** on a device that answers the
  ungated LED `CONFIG_READ` with a non-byte-string CBOR value.

## [0.3.2] — 2026-07-08

### Added

- **Releases now build and publish the trusted-display flavor** as
  `rs-key-<tag>-display.uf2` — reproducibility-gated, signed and attested like the
  other flavors (for the Waveshare RP2350-Touch-LCD-2.8; see
  [docs/guides/display.md](docs/guides/display.md)). CI also packages it as a
  build-smoke `firmware-display.uf2` artifact.

### Fixed

- **The trusted-display power button now sleeps the device from *every* on-device
  screen.** The PIN pad, the hold-to-confirm gestures, the "PIN blocked" notice,
  the success pop, and the host Approve/Deny and "Save passkey?" prompts didn't
  poll the sleep/wake button, so pressing it there did nothing (the reported case:
  the PIN-entry screen). Every blocking on-device loop now honors the button —
  sleeping blanks and, when a device PIN is set, auto-locks; a host ceremony
  interrupted this way is aborted (declined/cancelled), never approved.

- **A management-key mutual auth wrongly cleared the PIN verification, breaking
  `age-plugin-yubikey`'s first-run.** The 9B management key stores pin-policy
  ALWAYS, and a successful GENERAL AUTHENTICATE re-locked the session PIN even for
  the management key — but that re-lock should only follow an actual key-slot sign
  (it already gates the *check* on `is_key`). A client that verifies the PIN,
  mutually authenticates the management key, then signs with a pin-policy=ONCE slot
  key (age-plugin's generate order) hit `6982` on the sign. Now only an `is_key`
  slot sign re-locks the PIN, matching a real YubiKey.

- **PIV certificates over 256 bytes were invisible to `yubikey.rs`-based tools
  (e.g. `age-plugin-yubikey`).** A Case-3 `GET DATA` (command data, no `Le` — how
  `yubikey.rs` reads slot certificates) returned an oversized body whole instead
  of chaining it with `61xx` / `GET RESPONSE`. Clients with a short-APDU receive
  buffer dropped the read, so a retired-slot age identity showed as "(Empty)"
  right after it was generated. The CCID dispatcher now caps a no-`Le` response at
  256 and chains the remainder, matching a real YubiKey (`docs/protocol.md` §1.1).
  `ykman` / OpenSC were unaffected (they read with an extended `Le`).

## [0.3.1] — 2026-07-06

### Added

- **PicoForge hardware config over FIDO.** `authenticatorConfig`'s vendorPrototype
  (`0xFF`) arm now accepts PicoForge's physical-config command IDs (`PhysicalVidPid`,
  `PhysicalLedGpio`, `PhysicalLedBrightness`, `PhysicalOptions`), writing the phy
  record — so PicoForge can set VID/PID, LED and options over FIDO with no PC/SC.
  Gated by an `acfg` pinUvAuthToken. Details in `docs/protocol.md` §11.
- **Device configuration over FIDO (CTAPHID), PIN + touch gated.** A new
  `authenticatorVendor 0x41` subcommand `CONFIG_WRITE (0x0C)` writes device config
  over the FIDO HID transport — for hosts where PC/SC / pcscd can't read or write
  the CCID interface. Targets: the management enabled-apps TLV (`EF_DEV_CONF`) and
  the phy record (`EF_PHY` — VID/PID, USB interfaces, LED wiring, presence-timeout)
  and the LED config block (`EF_LED_CONF`, applied **live**); each lands in the same
  record the CCID read path echoes. Gated by a physical touch and, when a PIN is
  set, a `pinUvAuthToken` (`acfg` permission) — stronger than the CCID path's
  presence-only, since CTAPHID is reachable by any unprivileged host process.
  `CONFIG_READ (0x0D)` returns the phy / LED record (ungated) so a host can
  read-modify-write it over FIDO with no PC/SC at all; `rsk hw --transport fido`
  and `rsk led --transport fido` use this. Wire format in `docs/protocol.md` §9.
- **Firmware flash-size ratchet in the gate.** `check.sh` fails if the shipping
  image grows past a ceiling that hugs the current size (well under the 2560K
  code region) — a runaway dependency or surprise growth trips it early. Ratchet
  it down when the image shrinks; bump `FIRMWARE_FLASH_BUDGET_KIB` for a
  legitimate feature.
- **Host-crate coverage floor.** `deep-checks` gained an `llvm-cov` job that
  floors host-crate line coverage (a regression alarm; the embedded image is
  not host-measurable).
- **Cognitive-complexity ratchet in `deep-checks`.** `scripts/complexity_gate.sh`
  fails if any crate-library function crosses a cognitive-complexity ceiling — a
  daily regression alarm for new hotspots, the coverage floor's sibling. Lower
  the ceiling as the peak falls. rust-code-analysis is pulled ad-hoc, so it
  never joins the pinned dev shell.
- **`scripts/metrics.sh`** — advisory refactor reconnaissance (function
  complexity, firmware size, generic monomorphization). Not a gate; the tools
  are pulled ad-hoc so they never join the pinned dev shell.

### Changed

- **`deep-checks` runs daily** rather than weekly (Miri, fuzz, Kani, repro,
  coverage, complexity).

## [0.3.0] — 2026-07-03

### Added

- **Trusted-display build (experimental, opt-in).** A screen-and-touch RS-Key
  variant for the Waveshare RP2350-Touch-LCD-2.8, behind the `display` cargo
  feature (`firmware-display` nix flavor). The screen turns the key into a
  *trusted display* — the operations that matter happen on the device's own glass,
  not on the host:
  - **Approve / Deny** paints the *real* relying party for every touch-gated
    operation, so a signature can't be produced without a physical tap on a screen
    showing the true `rpId` (refuse → `OPERATION_DENIED`); a registration shows a
    *Save new passkey?* card. A look-alike id too long for the box is clipped with
    a truncation marker so its prefix can't masquerade.
  - **On-screen PIN entry** — built-in user verification (getInfo `options.uv`; a
    `pinUvAuthToken` minted from the on-screen pad against the same `EF_PIN`), and
    a CCID **pinpad** (`bPINSupport` / `PC_to_RDR_Secure`) so GnuPG and OpenSC
    collect the OpenPGP / PIV PIN on the panel — the PIN never crosses USB. Every
    PIN screen names which credential it collects, an eye toggle reveals the
    digits, and "N tries remaining" is shown up front.
  - A dedicated **device PIN** (separate from the FIDO clientPIN) gating the
    on-device UI, with **lock / unlock**, display **sleep** (image-retention
    guard + wake button), and set / change PIN on the panel.
  - **Passkeys** — browse resident credentials, **rename** (a device-local
    nickname that never re-seals the box) and **delete** on-device.
  - **Apps** — a read-only browser of OpenPGP / PIV / OATH state (no PIN, no
    secret, no OATH code — the device has no clock), plus on-device **PIV key
    generation** (EC P-256/P-384, Ed25519, X25519, RSA 2048/3072/4096) into empty
    retired slots.
  - **Settings** — device & FIDO PINs; a PIV PIN / PUK / unblock / **protect
    management key** (ykman `--protect`) sub-menu; on-screen **BIP-39 / SLIP-39
    recovery** export (derived on-device, never over USB) and backup-window status;
    an **audit log**; **factory reset**; a **Firmware** screen that reboots to
    BOOTSEL for an over-USB update; and live brightness / display-sleep /
    touch-timeout that persist across reboots.
  - A standard **screenless key compiles none of it** — the whole UI stack
    (`rsk-ui`, `embedded-graphics`, `u8g2-fonts`) is `dep:`-gated and the build
    asserts it absent from the default image, so an ordinary build is
    byte-for-byte unaffected. The UI model, geometry and glyphs live in the
    host-tested + Kani-proved `rsk-ui` crate. See
    [`docs/guides/display.md`](docs/guides/display.md). Built up across bcdDevice
    `0x0784`–`0x07D5`.

- **PIV: RSA-3072 and RSA-4096 keys.** Generate, import, sign / decrypt,
  attestation and metadata gained RSA-3072/4096 (the applet buffers were lifted
  off their RSA-2048 ceiling); on a display build the on-device **Generate key**
  chooser offers RSA via a 2048 / 3072 / 4096 sub-picker. RSA-1024 stays disabled.
  bcdDevice `0x07C4` → `0x07C6`.

- **PIV: Ed25519 and X25519 keys** (algorithm ids `0xE0` / `0xE1`, Yubico 5.7
  PIV). Generate (Ed25519 with an RFC 8410 self-signed cert; X25519 is
  key-agreement-only), import (raw seed / scalar, yubikit tags `0x07` / `0x08`),
  sign / key-agree, metadata and attestation — interoperating with `ykman` /
  `yubico-piv-tool` (an imported X25519 scalar is byte-flipped to the little-endian
  form standard tooling sends, so the slot's public key matches). bcdDevice
  `0x07C3` → `0x07C4`.

- **Configurable multi-LED effects engine.** Boards with a chain of addressable
  WS2812 LEDs light the whole strip with per-status animated effects (`vapor`,
  `bounce`, `flow`, `sparkle`, `legacy`) via `rsk led --effect/--speed`; the
  connected count is a runtime phy setting (`rsk hw --led-num`, TLV tag `0x0E`)
  bounded by the `MAX_LEDS` build ceiling (a value over it saturates, never
  panics). `EF_LED_CONF` grows to 17 bytes; older blocks still load. Thanks to
  @Curious-r. bcdDevice `0x0780` → `0x0783`.

- **Configurable GPIO presence button (`PRESENCE_PIN`).** The user-presence input
  can move from BOOTSEL to a dedicated GPIO at compile time (`PRESENCE_PIN=<0..=29>`,
  active-low with a pull-up by default, or `PRESENCE_ACTIVE_HIGH=1` for a touch
  sensor / button-to-VCC); the pin is guarded against colliding with the LED and is
  rejected on a `display` build. One new documented `unsafe`. Thanks to @lpiob
  ([#17](https://github.com/TheMaxMur/RS-Key/pull/17)). bcdDevice `0x0791` → `0x0793`.

- **`rsk-tui` can export the seed as SLIP-39 shares** (tools/tui 0.2.4). The Backup
  section gains "Export seed (SLIP-39)" beside the BIP-39 export, revealing the seed
  as a 2-of-3 Shamir share set (via the in-tree `rsk-slip39` crate) that recombines
  with `rsk backup restore --scheme slip39`.

### Changed

- **Touch timeout is configurable; phy tag `0x08` now follows pico-fido.** Tag
  `0x08` (previously an unused presence-button GPIO) now means `PresenceTimeout` —
  the touch-wait in seconds — matching pico-fido / PicoForge, so a PicoForge config
  or `rsk hw --touch-timeout <secs>` sets it (absent / `0` keeps the 30 s default).
  bcdDevice `0x0783` → `0x0784`.

- **`rsk-tui` gets a curated colour theme** (tools/tui 0.2.3). On truecolor / 256-
  colour terminals the cockpit uses a fixed brand palette with rounded borders and
  an explicit selection bar; a 16-colour terminal keeps the adaptive named-ANSI
  colours. Override with `RSK_TUI_TRUECOLOR=1|0`. No `--once` / `--json` change.

- **`rsk-tui` status labels are single-sourced** (tools/tui 0.2.2). The `--once`
  printer and the cockpit now share the model's label mappings, which changes three
  `--once` labels (seed lock "… disabled until unlock", secure boot "ENABLED (not
  locked)", un-probed applets "not probed").

### Fixed

- **Maximal credential requests now fit the credential box.** A registration
  within every advertised limit (a 253-byte `rpId`, a 64-byte user.id, 64-byte
  name / displayName and a 127-byte credBlob) could overflow the sealed credential
  box or its resident bookkeeping and be rejected (`CTAP2_ERR_OTHER` /
  `KEY_STORE_FULL` / `REQUEST_TOO_LARGE`), and a large credential that did register
  could then never assert. The three ceilings are now **derived** from the field
  maxima so they can't drift below what the device advertises: `CRED_BOX_MAX` (748)
  sizes create / assert / reseal, `RP_REC_MAX` (314) the resident `EF_RP` record,
  and `MAX_RAW_SUBPARA` (384) a maximal `updateUserInformation`; getInfo's
  `maxCredentialIdLength` and the published metadata report the real 748, and
  over-maximum inputs are rejected explicitly with `INVALID_LENGTH`. Older records
  load unchanged. bcdDevice `0x07E7` → `0x07EC`.

### Security

- **Additional defense-in-depth hardening** (four items, none independently
  exploitable; bcdDevice `0x07DD` → `0x07DE`):
  - **credProtect is now range-checked.** makeCredential rejected nothing for a
    credProtect value outside `{1,2,3}` and stored it verbatim; `getAssertion`
    enforces protection by exact match, so an out-of-range value silently meant
    *no* protection. It now returns `CTAP2_ERR_INVALID_OPTION` (§12.1).
  - **hmac-secret-mc empty-salt parity.** makeCredential now rejects an
    hmac-secret-mc request with an empty salt up front (`MissingParameter`),
    matching the existing `getAssertion` hmac-secret guard (previously this was
    only caught later by the length check in `hmacsecret::eval`).
  - **credentialManagement enumeration counters widened to `u16`.** The `skip` /
    `total` / begin-next counters were `u8` and saturated at 255, so on a fully
    provisioned store (`MAX_RESIDENT_CREDENTIALS = 256`) the 256th RP/credential
    was invisible to (and undeletable via) enumeration. The wire encoding is
    unchanged for ≤255 (canonical CBOR).
  - **RSA-keygen fast path resets the incoming command chain.** The CCID keygen
    fast path already dropped a stale GET RESPONSE tail (`clear_pending`); it now
    also resets a half-accumulated CLA-`0x10` command chain (`clear_chaining`,
    scrubbing it) so an interrupted chain cannot prepend onto a later command.
- **Missing-authorization fixes in the Yubico-management and rescue applets**
  (two defects in never-before-audited utility applets; bcdDevice `0x07DC` →
  `0x07DD`):
  - **Rescue OTP-fuse writes now require an on-device user-presence confirmation.**
    The two irreversible fuse burns — page-58 access lock (`INS 0x1B` `P1=0x58`,
    `"LOCK58"`) and `ROLLBACK_REQUIRED` (`P1=0x48`, `"ROLLBK"`) — were the only
    privileged rescue commands without the `require_presence` gate every sibling
    op (attestation sign, cert/phy write, reboot-to-BOOTSEL) enforces. Their magic
    payload is a source-visible constant, not authentication, so an unauthenticated
    USB host could permanently burn a fuse with no operator consent. Both now
    prompt (`6985` if declined); idempotent no-ops still return `OK` without a
    prompt. (`crates/rsk-rescue/src/lib.rs`.)
  - **Management WRITE CONFIG (`INS 0x1C`) now requires user presence.** It was
    entirely unauthenticated and the `CONFIG_LOCK` byte it stores was never
    enforced, so a USB host could persistently spoof the reported DeviceInfo. The
    write now prompts for on-device confirmation (`6985` if declined), matching
    every sibling applet's write path. (`crates/rsk-mgmt/src/lib.rs`.)
- **PIV and CCID defense-in-depth hardening** (no exploitable vulnerability
  found; three items; bcdDevice `0x07DB` → `0x07DC`):
  - **PIV `GENERAL AUTHENTICATE` challenge is now bound to its issuing
    algorithm.** A 9B mutual/single-auth challenge issued under one algorithm
    (3DES `chal_len` 8 vs AES `chal_len` 16) could structurally be answered under
    the other; AES-192 and 3DES share a 24-byte key, so the key-length gate alone
    did not separate them. This was **not** exploitable (the witness always
    requires knowledge of the management key, and every replay failed closed with
    `has_mgm` staying false), but the `Session` now records `chal_algo` at issue
    and refuses a step-2 whose algorithm differs.
  - **PIV GET DATA / MOVE KEY clamp the stored object length.** `get_data` and
    `move_key` sliced a `MAX_OBJECT` (1900-byte) buffer by the full length
    `Storage::read` returns, which would panic on a stored value longer than the
    buffer. Every host writer already caps at `MAX_OBJECT` (so this was reachable
    only by a raw flash write — a stronger attacker than the USB host), but the
    readers now clamp with `n.min(MAX_OBJECT)`, returning the prefix instead of
    panicking. Matches the existing `EF_PIVMAN_DATA` clamp pattern.
  - **CCID RSA-keygen fast path clears the GET RESPONSE remainder.** The dual-core
    `try_rsa_keygen` / `try_piv_rsa_keygen` fast paths bypass
    `Dispatcher::process`, which is what normally drops a stale chained-response
    tail, so a host interleaving `chained-response → GENERATE → GET RESPONSE` was
    re-served its own prior tail. This crossed no trust boundary (same principal;
    a SELECT to another applet clears the buffer first), but the fast paths now
    call `Dispatcher::clear_pending()` to match ordinary dispatch.

- **PIV and OATH authentication fixes** (bcdDevice `0x07DA` → `0x07DB`):
  - **PIV management-key authentication bypass via an encryption oracle
    (critical).** `GENERAL AUTHENTICATE` had a symmetric-algorithm tag-`0x81`
    ("internal authenticate") branch for slot `9B` that returned
    `E(mgm_key, caller_bytes)` with no `has_mgm`, no PIN (`9B` is not a key slot,
    so the PIN gate was skipped) and no touch (default `9B` policy is
    `TOUCHPOLICY_NEVER`). Because the management-key cipher is deterministic ECB,
    an unauthenticated USB host could chain it with the applet's own single-auth
    challenge — request a plaintext challenge `R`, ask the oracle for `E(mgm,R)`,
    submit that as the response — and the card's `D(mgm,·)==R` check would pass,
    setting `has_mgm` with **zero knowledge of the management key**. That grants
    full, persistent PIV takeover (generate/import/overwrite slot keys, `PUT DATA`,
    rotate the management key, reset PIN/PUK counters). It is a distinct-mechanism
    sibling of the earlier mgmt-key bypass, whose `ChallengeKind` binding did not
    cover it. **Fix:** the symmetric tag-`0x81` branch (which has no legitimate PIV
    client) is removed, so the only sanctioned `9B` flows are mutual-witness
    (tag `0x80`) and single-auth (tag `0x81`-empty challenge → tag `0x82` verify).
    A class-invariant test asserts no `GENERAL AUTHENTICATE` path reachable without
    prior auth can set `has_mgm`.
  - **OATH `CHANGE PIN` unlimited OTP-PIN guessing at the retry floor (medium).**
    `cmd_change_otp_pin` decremented the OTP-PIN retry counter with a saturating
    subtraction but, unlike `cmd_verify_otp_pin`, did not refuse at the floor —
    once the counter reached 0 it stayed 0 and the PIN comparison kept running on
    every request, an unlimited online brute-force of the store-unlocking OTP-PIN
    (a residual sibling of the earlier `CHANGE PIN` finding). **Fix:** both `VERIFY`
    and `CHANGE` now go through a single `spend_and_match_otp_pin` chokepoint that
    refuses at `rec[0]==0`; legitimate recovery after lock-out is `RESET` (which
    wipes the store), not more guesses. **Behavior change:** a correct old-PIN no
    longer recovers a locked-out OTP-PIN via `CHANGE`; use `RESET`.
- **OTP, OpenPGP, U2F and audit-journal hardening** (bcdDevice `0x07D9` →
  `0x07DA`):
  - **OTP `SLOT_SWAP` access-code bypass (high).** `cmd_swap` was the only
    slot-mutating OTP command that did not check the per-slot access code that
    `cmd_configure`/`cmd_update` enforce: it unsealed both target slots (the seal
    read never compares the access code) and relocated/deleted them unconditionally.
    An unauthenticated USB host (CCID or the HID keyboard frame, no PIN/code/touch)
    could `SLOT_SWAP` a programmed, access-code-protected slot to **silently delete
    or relocate** it — persistently breaking a challenge-response credential used
    for LUKS / KeePassXC / pam_yubico. An unbounded swap offset could also orphan
    the slot at an FID outside the addressable 1..=4 range. `cmd_swap` now requires
    the access code of every non-empty slot it touches (an unprotected slot's code
    is all-zero, so a plain `ykman otp swap` of unprotected slots is unchanged) and
    rejects out-of-range offsets; the same offset bound is applied to
    `cmd_configure`/`cmd_update`/`cmd_calculate`. Integrity/availability only — the
    config stays GCM-sealed (no secret exfiltration).
  - **OpenPGP `read_public` unclamped stored length (hardening).** `read_public`
    returned the value's full `Fs::read` length without `n.min(out.len())` — the
    6th member of the OpenPGP stored-length family. Latent only (`EF_PB_*` is not
    host-writable beyond its bound), now clamped like every other reader.
  - **U2F attestation-chain read (hardening).** The org-attestation branch sliced
    `cert[..n]` on the full stored length with only a size margin; now clamps
    `n.min(cert.len())`, matching the sibling `EF_EE_DEV` branch.
  - **Audit-journal meta window (hardening).** `load_meta` now fails closed to
    genesis when a persisted `EF_AUDIT_META` claims a window wider than
    `AUDIT_RING_SLOTS`, so a flash-corrupted meta can't overrun the export buffer.
  - **`BACKUP_EXPORT` docstring corrected** to match behavior (only
    `BACKUP_FINALIZE` seals the window; repeat export before finalize is safe).
- **FIDO, OpenPGP and OATH fixes** (bcdDevice `0x07D8` → `0x07D9`):
  - **FIDO `getNextAssertion` user-presence bypass (high).** `getAssertion` armed
    the multi-credential `getNextAssertion` queue during resident discovery
    *before* its user-presence gate, and no path tore the queue down when that gate
    failed; `getNextAssertion` performs no presence check of its own. So on a
    device holding ≥2 discoverable credentials for one RP, after the user
    **declined or ignored** the touch, a host could still pull valid `UP=1`
    assertions for credentials #2..N with no touch — defeating the test of user
    presence. `get_assertion` now calls `gna.reset()` on any error return (CTAP 2.1
    §6.3: getNextAssertion only continues a *successful* getAssertion).
  - **OpenPGP `GENERATE` OOB panic on a short algorithm attribute (medium).** A
    PW3-written 1–2 byte `C1/C2/C3` DO (`PUT DATA` caps no minimum length) made
    `GENERATE ASYMMETRIC KEY PAIR` index the RSA modulus-size bytes past the slice
    → panic/reset on every `GENERATE` for that slot. The earlier clamp only bounded
    the *over*-long case; both `generate` and `rsa_generate_params` now reject an
    attribute shorter than 3 bytes, matching the guarded sibling `info::slot_algo`.
  - **OATH OTP-PIN counter glitch-hardening (defense-in-depth).** `VERIFY PIN` /
    `CHANGE PIN` now persist and read back the retry-counter decrement *before* the
    PIN compare (mirroring the FIDO clientPIN gate), so a fault-injected or failed
    flash program can't widen the 3-try OTP-PIN limiter.
  - **FIDO `verify_pin_hash` self-guards the retry decrement (defense-in-depth).**
    Added an in-function `retry == 0` check before `pin_data[0] -= 1` (matching
    `verify_pin_at`), so no future caller can underflow the PIN retry budget in a
    release build without overflow-checks.
- **OpenPGP, OATH and FIDO fixes; `rsk` receipt binding** (bcdDevice `0x07D8`;
  `rsk` 0.3.1; `rsk-tui` 0.2.1):
  - **OpenPGP `GET DATA` unclamped length → OOB brick (high, ×2 sites).** Both the
    generic top-level Flash DO (`login`/`url`/private DOs) and the `C1/C2/C3`
    algorithm-attribute path returned the value's full stored length, so an
    over-long PW3-written object panicked the device on every read (persistent
    DoS reached by `gpg --card-status`). `get_data` now clamps `data_len` to the
    scratch buffer at the single chokepoint, plus a defensive clamp at the extend.
  - **OATH access-code / OTP-PIN bypasses (high, ×2).** `SET PIN` now requires a
    validated session (an unauthenticated host could mint the unlock secret on a
    locked applet); `CHANGE PIN` now spends a retry on a wrong old-PIN (it was an
    unlimited brute-force oracle that recovered the OTP-PIN and unlocked the store).
  - **FIDO `setMinPINLength` truncation (medium).** A `newMinPINLength` above the
    max PIN length is now rejected before the `as u8` store, which otherwise
    truncated (e.g. 256 → 0) and silently defeated the monotonic enterprise floor.
  - **`rsk offboard` receipt binding (medium).** The signed wipe receipt is now
    bound to the journal window it presents (recompute + compare the head, hard-fail
    a missing RESET), matching `rsk audit`; the verify ceremonies also validate
    device-supplied checkpoint fields instead of raising a traceback.
  - **Defense-in-depth (low).** Clamped five remaining `Fs::read` readers
    (`phy`/`largeblobs`/vendor `unlock`/`makeCredential` att-chain/OpenPGP DEK) to
    their buffers; fixed the OpenPGP `GET DATA 0x7A` stale-scratch over-read;
    rejected the 2-byte TLV tag form in OATH `PUT`; hardened the `rsk-tui` audit
    view and `rsk led` against malformed device responses.

- **Full-tree audit fixes.** Found and fixed:
  - **PIV management-key authentication bypass (critical).** `GENERAL
    AUTHENTICATE` shared one session challenge field between the single-auth
    (plaintext challenge) and mutual-auth (encrypted witness) handshakes, so a
    host could read the plaintext single-auth challenge and replay it as the
    mutual-auth witness to authenticate as the card administrator with no
    knowledge of the management key — no PIN, no touch. The challenge is now
    tagged with the flow that issued it and can only be consumed by that same
    flow.
  - **OpenPGP `GET DATA` over-long-DO brick (two more sites).** The cardholder
    certificate (`7F21`) read-out and the generic `DoWriter` flash-DO builder
    sliced/advanced a fixed 1024-byte buffer by the value's *full* stored length;
    a PW3 host can `PUT DATA` an over-long cardholder cert/name, so a later `GET
    DATA 65/6E/7F21` (issued by `gpg --card-status`) panicked — a persistent
    brick. Both are now clamped to the buffer, matching the earlier `info.rs` fix.
  - **OATH `VERIFY CODE` (INS `0xB1`) now honours the access code.** It lacked the
    `validated` gate every other stored-data command has, so a locked applet
    answered it — a replayable oracle on the primary credential's current OTP
    across the access-code boundary. Now gated.
  - **Trusted-display delete-confirmation clips the identity.** The
    delete-passkey confirmation drew the untrusted rpId/account unclipped with no
    truncation marker, unlike the approve/add ceremonies; a padded look-alike
    rpId could overflow the card silently. Now ellipsized + marked to the card.
  - **OpenPGP private keys are AES-256-GCM-sealed with a fresh nonce.** The DEK
    seal used one fixed (key, IV) AES-CFB across every key slot, so the block-0
    keystream repeated and a flash-dump attacker could recover the XOR of two
    same-format scalars' first bytes; CFB was also unauthenticated. Sealing now
    uses AES-256-GCM under a synthetic per-record nonce (`HMAC(dek, fid ‖ key)`),
    adding authentication and eliminating the reuse. Keys in the old CFB format
    still load (trial-decrypt fallback) and are re-sealed to the new format the
    first time they are used — no reprovisioning needed.
  - **The release pipeline no longer ships the `no-touch` firmware.** The release
    workflow built and published four `no-touch` flavors (user-presence bypass,
    marked "never ship") as signed, SLSA-provenanced public assets. It now builds
    and publishes only the four touch-required flavors, with a guard that fails
    the release if any `no-touch` asset is present.

- **FIDO master seed sealed with authenticated ChaCha20-Poly1305.** The device
  master seed and the org attestation scalar (`EF_KEY_DEV` / `EF_ATT_KEY`) were
  sealed with AES-256-CBC under one fixed serial-hash IV shared across both
  slots, and carried no MAC — the same fixed-IV / no-authentication class as the
  OpenPGP DEK above, but at the root of the FIDO identity. They are now
  ChaCha20-Poly1305-sealed (new tags `0x02` pre-OTP / `0x12` OTP-arm) under a
  synthetic per-record nonce (`HMAC(HMAC(nonce_key, fid), value)`), so the seed
  and the attestation key never share a nonce and a flash fault or tamper is
  detected rather than silently decrypting to a corrupted seed. Records in the
  legacy CBC (`0x01`/`0x11`) and PIN-wrapped (`0x03`/`0x13`) formats still load
  and are re-sealed forward at boot / the first PIN verify — no reprovisioning,
  and every passkey survives the upgrade.

- **Pre-release cross-review hardening.** An adversarial re-review of the two
  unreleased hardening commits (the trusted-display arc and the pico-keys
  carry-over below) — the ones that had not yet been cross-reviewed before a
  release tag — found and fixed:
  - **OpenPGP over-long-DO brick, two remaining sites.** `GENERATE`,
    `rsa_generate_params` and key `IMPORT` read the algorithm-attribute DO into a
    fixed 16-byte buffer and sliced it by the value's *full* stored length; a
    PW3 host can `PUT DATA` an over-16-byte `C1/C2/C3`, so the slice panicked
    (device brick). Clamped to the buffer, matching the earlier `info.rs` fix.
  - **OTP slots and OATH credentials now survive a later OTP-MKEK burn.** Both
    seal under the device root key, which changes when the fuse MKEK is burned;
    neither had the pre-OTP recovery arm the FIDO seed / PIV / attestation key
    already use, so a secret provisioned *before* a burn became unreadable (OTP)
    or was double-encrypted and destroyed (OATH) on the first post-burn boot. The
    boot migrations now trial-decrypt under the pre-OTP arm and re-seal under the
    OTP arm.
  - **OATH OTP-PIN survives an OTP-MKEK burn.** The new OTP-rooted verifier gained
    the same `without_otp()` match-and-re-store fallback the PIV / OpenPGP / FIDO
    PINs use, so a PIN set before a burn still verifies afterwards — restoring the
    burn-immunity the legacy serial-only hash happened to have.
  - **The reboot-to-BOOTSEL user-presence gate can no longer be bypassed.** The
    vendor applet exposes the same reboot verb as the (gated) rescue applet, over
    both the CCID and CTAPHID transports; its `1F/01` (BOOTSEL) is now gated
    identically. A warm restart (`1F/00`) stays ungated.
  - **Trusted-display: the Add-passkey (enrollment) screen marks a truncated
    relying-party id.** The makeCredential screen dropped the truncation marker
    for a clamped look-alike id whose prefix fit the box — the phishing vector the
    Approve screen already closed. It now forces the marker like the Approve path.
  - **`rsk-wipe` rejects a degenerate `FLASH_SIZE`.** `FLASH_SIZE=0` passed the
    remaining build asserts and made the erase a silent no-op that still signalled
    success; a lower bound now rejects it.

  bcdDevice 0x07D3 → 0x07D4. Host CLI (`tools/rsk`) 0.2.0 → 0.3.0: `rsk hw` and
  `rsk reboot bootsel` now prompt for the on-device approval the firmware requires
  and explain a `6985` decline instead of failing cryptically.

- **Carry-over hardening from a pico-keys upstream audit.** A review of the upstream
  pico-keys C firmware surfaced design flaws; each was re-verified against the RS-Key
  Rust source. The overwhelming majority were already handled by the port (OATH gate,
  PIV key sealing + admin-auth gates, parser totality, HMAC-DRBG, constant-time
  compares), and this wave closes the remaining gaps:
  - **Yubico OTP slot secrets are now sealed at rest.** The 52-byte slot config —
    which carries the AES-128 key, private UID and the HMAC-SHA1 / OATH-HOTP secret —
    was the one applet still written to flash in the clear. It now goes through the same
    `KeyFid` AES-256-GCM chokepoint as FIDO / PIV / OpenPGP / OATH; a boot pass re-seals
    any pre-existing plaintext slot, so a flash-dump thief no longer recovers the token
    secrets.
  - **The OATH OTP-PIN verifier is OTP-rooted, not a fast serial-only hash.** The
    Nitrokey-style OTP PIN now stores `pin_derive_verifier` (rooted in the OTP MKEK,
    exactly like the OpenPGP / PIV PINs) instead of the legacy `double_hash_pin`; a
    legacy record still verifies and is upgraded on the next successful use.
  - **The device attestation key is AEAD-sealed.** `EF_DEVCERT_KEY` moved from raw
    AES-256-CBC under a public fixed IV with no MAC to AES-256-GCM (random nonce, auth
    tag); a bit-flip in the sealed scalar is now detected rather than silently accepted,
    and legacy CBC records are re-sealed at boot.
  - **Privileged rescue commands require user presence.** Attestation signing over a
    host-chosen digest, attestation-cert overwrite, phy/identity write and
    reboot-to-BOOTSEL now need an on-device confirmation (a touch, or an on-screen
    Approve on the trusted-display build), so a hostile USB host can no longer drive
    them silently. Read-only status and a plain restart stay ungated.
  - **OpenPGP MSE touch policy follows the repointed slot.** The UIF (touch) check for
    PSO:DECIPHER / INTERNAL AUTHENTICATE now follows an MSE key-reference repoint, so a
    cross-wired DEC↔AUT key can no longer be used under the wrong slot's touch policy.
  - **FIDO credMgmt `updateUserInformation` requires an exact userId match** (CTAP 2.1
    §6.8.3), closing a min-length-prefix compare where a prefix (or empty id) matched.
  - **`rsk-wipe` erases the whole target flash.** It reads the same `FLASH_SIZE` build
    knob as the firmware instead of assuming 4 MB, so a 16 MiB board is fully wiped.

  bcdDevice 0x07D2 → 0x07D3. (`rsk-wipe` is a separate binary and carries no bcdDevice.)

## [0.2.8] — 2026-06-21

### Changed

- **A WebAuthn login is a single touch by default.** RS-Key now honors the
  platform's silent pre-flight probe — a `getAssertion` with the `up` option set
  to `false` — by returning the credential-discovery assertion **without**
  polling the button and with the UP flag clear, as the CTAP2 spec and YubiKey
  do. Previously the `up` option was ignored and every assertion polled the
  button, so an `allowCredentials` (non-resident) login — the common security-key
  second-factor flow — cost **two** touches: one for the browser's silent
  pre-flight, one for the real assertion. Resident-credential / passkey logins
  were, and remain, a single touch. A new `strict-up` cargo feature (off by
  default) restores the touch-on-every-assertion behavior for anyone who wants an
  explicit gesture per assertion; `fido-conformance` enables it implicitly so the
  conformance image keeps its validated behavior. See
  [build.md](https://github.com/TheMaxMur/RS-Key/blob/main/docs/build.md).
  bcdDevice 0x077F → 0x0780.
- **Requiring a touch is the unconditional default, not a cargo feature.** The
  `up-button` feature (which was on by default) is gone — the shipped image
  demands a BOOTSEL touch for FIDO / OpenPGP-UIF operations with no flag. The
  no-touch test image, for the automated suites that cannot press a button, is
  now the explicit opt-in **`--features no-touch`** (previously
  `--no-default-features`). The secure default no longer depends on a feature
  being left enabled; the default firmware binary is unchanged.

## [0.2.7] — 2026-06-21

### Security

- **A pre-OTP seed remnant survived OTP provisioning, readable from a flash
  dump without the fused key — now physically scrubbed at the first OTP boot.**
  RS-Key seals the FIDO seed under the device root (`kbase`): chip-serial-only
  before OTP provisioning, the fused MKEK after. Burning OTP re-seals the seed
  from the weaker root to the fused one (`migrate_keydev_boot`), but the
  `sequential-storage` flash log is append-only — an overwrite leaves the prior
  value in place and `remove_item` only flips a header CRC, so the superseded
  *chip-serial-sealed* copy lingered in flash until natural compaction (rare on
  the cold credential partition). Because that root derives from the chip id
  alone — no fuse secret — an attacker with a flash dump plus the chip id could
  recover the seed, and with it every derived FIDO credential, **bypassing the
  OTP hardening entirely.** This is the same class of issue as the upstream
  pico-fido/pico-keys-sdk `flash_clear_file` finding (their "clear" zeroes only
  the length field, leaving the payload); here `sequential-storage`'s logical
  delete is the equivalent, and the device-root seal is the only thing that made
  the steady state safe. Fix: the first boot with the OTP key present now runs a
  one-shot `Fs::compact` — a full garbage-collection lap over the credential
  partition that migrates live records forward and sector-erases every page,
  physically destroying the superseded pre-OTP copies. It is gated by a new
  `EF_HARDENED` flash marker (runs once, before USB attach) and is crash-safe
  (an interrupted lap leaves the marker unset and re-runs next boot). A device
  provisioned OTP-first never creates the remnant and the pass finds nothing to
  scrub. A host-side proof on the real `sequential-storage` + mock-flash stack
  scans raw flash to confirm the remnant is present before the lap and gone
  after (`fuzz/tests/churn_compaction.rs`, mutation-checked). `production.md`
  now documents the pass and recommends burning OTP before enrolling; the
  threat-model/limitations caveats are corrected (the lingering record was
  described as "moot against anything but a fused-key compromise", true only for
  the already-fused soft-lock case, not this one). bcdDevice 0x077E → 0x077F.

## [0.2.6] — 2026-06-21

### Fixed

- **ML-DSA-44 (COSE `-48`) FIDO `getAssertion` hard-wedged the device — the
  post-quantum credential key is now heap-boxed off the worker stack.** The
  optional ML-DSA-44 signature scheme (negotiable from a request's
  `pubKeyCredParams`, unadvertised by default) held fips204's ~16.6 KiB of
  NTT-form keys *inline* on the worker stack, directly below the stack-heavy
  rejection-sampling `sign`. A `.bss` growth since v0.2.5 (the power-cut
  tri-state present-cache + the hybrid ML-KEM-768 seed-backup) had lowered the
  RP2350 worker-stack ceiling from ~238 KiB to ~222 KiB, so an ML-DSA-44
  `getAssertion` overflowed it → memory corruption → `panic-halt`, leaving FIDO
  dark until a USB replug. Reachable as a denial of service: an explicit `-48`
  `makeCredential` followed by `getAssertion` wedges the authenticator even
  though `-48` is unadvertised. `makeCredential` survived because key generation
  is a shallower frame than signing. The keypair is now `Box`-ed onto the
  firmware heap — idle during a FIDO request, since applet keys are reconstructed
  per-operation — freeing ~16.6 KiB at signing depth and restoring a measured
  32–64 KiB of stack margin (verified on hardware by flashing deliberately
  stack-starved builds: passes at −32 KiB, wedges at −64 KiB). The heap stays
  128 KiB, so there is no RSA impact, and a `size_of::<CredKey>()` guard fails
  the build if the key ever regresses back inline. HW-verified on RP2350
  (`tests/60` raw CTAPHID + `tests/61` python-fido2/OpenSSL, ML-DSA-44
  register+login). `bcdDevice` `0x077D` → `0x077E`.

- **`ssh-keygen -t ed25519-sk` (and any Ed25519 FIDO2 credential) failed on
  Windows — EdDSA is now advertised in `authenticatorGetInfo`.** The device has
  always *supported* EdDSA (COSE `-8`): `makeCredential` negotiates it from a
  request's `pubKeyCredParams` and signs with Ed25519. But `-8` was omitted from
  the advertised `algorithms` (0x0A) list, kept out alongside ES256K (`-47`) so
  the FIDO Conformance tool — whose `verifySignatureCOSE` only maps `-7/-35/-36` —
  wouldn't fail trying to verify an EdDSA self-attestation. The Windows WebAuthn
  API (the path Windows OpenSSH takes) **intersects the requested algorithms with
  the advertised list**, so it silently dropped `-8` and the credential create
  failed; macOS/Linux OpenSSH go through libfido2, which sends `-8` directly, so
  it worked there. The shipping/default build now advertises `-8`. The capability
  is unchanged — only the advertisement was added. ES256K (`-47`) stays
  unadvertised (still negotiable from a request). For the conformance run, the new
  `fido-conformance` build feature suppresses `-8` again and
  `metadata/rs-key.conformance.metadata.json` is the matching EdDSA-free Metadata
  Statement (verified by `tests/62` to be the shipping statement minus EdDSA).
  `bcdDevice` `0x077C` → `0x077D`.

- **Two power-cut data-durability bugs in the flash file system, both surfaced by
  the `power_cut` / `fs_ops` fuzz targets (deep-checks) and latent since the
  present-cache landed in v0.2.3.** Neither affects the shipped, verified v0.2.5
  artifacts — both are power-cut-edge, not artifact-integrity.
  - **`delete` orphaned metadata.** `Fs::delete` dropped a file's `EF_META`
    record only when the file's *own* data was present, so a file given metadata
    (`meta_add`) but never written (`put`) kept its metadata after deletion — the
    record read back alive across a reboot, diverging the live key set from the
    model. `delete` now drops metadata unconditionally (O(1) when there is none),
    and `meta_delete` skips the `EF_META` rewrite when the FID had no record, so
    the absent-slot reset sweep stays write-free.
  - **The present-cache could go false-absent after a torn migration.** The boot
    `scan` seeds its negative cache from a bulk `for_each_key`, which can silently
    under-count a key when a power-cut interrupts a `sequential-storage` page
    migration — while the per-key `fetch_item` still recovers it. A clear cache
    bit was trusted as "absent", so committed data/metadata read back lost, and a
    `meta_add` over a false-absent `EF_META` wiped every existing record. The
    cache is now tri-state (`present` + a `decided` authority bit): a clear bit is
    trusted only once a backend probe confirms it, otherwise the reliable
    `fetch_item` decides and the answer is memoised — a false-absent is now
    impossible. Cost: a one-time-per-boot first probe per absent FID (the PIV-tab
    lag returns once after a plug-in, then stays O(1)). `fetch_item` durability is
    pinned by a new `kv_durability` fuzz target (the storage layer in isolation);
    `power_cut` and `fs_ops` now run clean. `bcdDevice` `0x077B` → `0x077C`.

## [0.2.5] — 2026-06-20

### Added

- **Runtime LED hardware config — pin, driver, and wire order are now set at
  runtime via the `phy` record (`rsk hw` / PicoForge), no reflash.** The
  `LED_KIND` / `LED_PIN` / `LED_ORDER` build knobs (below) become *boot
  defaults*: a non-`none` build now compiles all three backends and, at boot,
  applies the data pin (`led_gpio`), driver (`led_driver` — 1=gpio / 2=pimoroni /
  3=ws2812, matching pico-fido / PicoForge), and an RS-Key vendor wire-order tag
  (`led_order`, `0x0D`) from `EF_PHY` — the same record that already drives the
  USB identity. The pin reaches the PIO state machine through a `match` over GPIO
  `0..=29` (embassy has no `PioPin for AnyPin`, but doesn't need one); the wire
  order is a runtime red/green swap, so one binary serves both RGB- and GRB-wired
  parts. New **`rsk hw`** command (`--led-pin` / `--led-driver` / `--led-order` /
  `--get`) does a read-modify-write of only the LED fields (any USB identity is
  preserved) and warm-reboots to apply. A `none` build stays headless and ignores
  the phy LED fields. `bcdDevice` `0x077A` → `0x077B`.

- **Selectable LED backend (`LED_KIND` build knob) — the indicator is no longer
  WS2812-only.** The status engine (boot/processing/touch/idle blink + the
  runtime-configurable colour/brightness in `EF_LED_CONF`) was already
  backend-agnostic; only the render half was hard-wired to the Waveshare's
  addressable WS2812. The render is now chosen at build time: `ws2812` (default —
  the addressable RGB on `LED_PIN`), `gpio` (a plain on/off LED on `LED_PIN`;
  hue/brightness collapse to lit/unlit, but the blink *pattern* still tells the
  statuses apart — so RS-Key now runs on boards with a simple LED, e.g. a bare
  RP2350 or Pico 2), `pimoroni` (a 3-pin PWM common-anode RGB, Pimoroni Tiny 2350)
  or `none` (headless). Only the selected driver and its PIO/PWM dependencies are
  compiled. `bcdDevice` `0x0778` → `0x0779`.

- **`LED_ORDER` build knob — the WS2812 wire byte order is now selectable.** The
  reference Waveshare RP2350-One is unusually **RGB**, the project default; but
  standard WS2812B parts (e.g. the TenStar RP2350-USB) are **GRB**, and driving
  one with the wrong order swaps red↔green (blue is unaffected). `LED_ORDER=grb`
  picks the standard order for such boards; `rgb` (default) keeps the Waveshare
  behaviour. Verified on a TenStar RP2350-USB (16 MB, WS2812 on GP22):
  `LED_KIND=ws2812 LED_ORDER=grb LED_PIN=22 FLASH_SIZE=16M`. `bcdDevice` `0x0779`
  → `0x077A`.

- **Hybrid post-quantum seed-backup channel — the vendor MSE key agreement is now
  P-256 + ML-KEM-768.** The seed-backup channel (`authenticatorVendor` `0x41`,
  `MSE`) is the one place the device hands out a normally non-exportable key — the
  32-byte master seed — so a recorded exchange is the prime harvest-now-decrypt-
  later target: break the ephemeral P-256 ECDH with a future quantum computer and
  the wrapped seed falls out. The handshake now accepts an optional ML-KEM-768
  (FIPS 203) encapsulation key in subCommandParams key 2; when present the device
  encapsulates to it and derives the channel key as
  `HKDF-SHA256("RSK-MSE-PQ-v1", z ‖ ss_mlkem, dev_pub ‖ ct)`, returning the
  ciphertext as response key 2. Both shared secrets feed the KDF, so the channel
  stays confidential unless *both* P-256 and ML-KEM-768 are broken (defense in
  depth — never PQC-only). Only the cheap `encapsulate` direction runs on-device;
  the host keeps the ML-KEM keypair and decapsulates. A host that sends no key 2
  gets the classical channel byte-for-byte, so existing hosts keep working.
  `bcdDevice` `0x0777` → `0x0778`.

- **`alwaysUv` (always require user verification) is supported.** `getInfo`
  advertises the `options.alwaysUv` flag (reflecting its state, `false` at reset)
  and the `toggleAlwaysUv` (`0x02`) `authenticatorConfig` subcommand. While enabled
  (flipped via `authenticatorConfig` toggleAlwaysUv, gated on a pinUvAuthToken with
  the `acfg` permission), every `makeCredential` / `getAssertion` requires a verified
  pinUvAuthToken — an up-only (touch) request is refused with
  `CTAP2_ERR_PUAT_REQUIRED`, even when no PIN is configured. The state persists until
  `authenticatorReset`, which clears it. Completes the FIDO conformance "featureful"
  CTAP2.3 profile's authenticatorConfig requirement. `bcdDevice` `0x0774` → `0x0775`.

- **`getInfo` advertises five optional informational members.** `transports`
  (0x09, `["usb"]`), `maxRPIDsForSetMinPINLength` (0x10, `8`),
  `remainingDiscoverableCredentials` (0x14, the live free resident-key-slot count),
  `attestationFormats` (0x16, `["packed"]`) and `maxPINLength` (0x1D, `63`). Purely
  informational — no behaviour change — and mirrored in the metadata statement (the
  FIDO conformance Authr-Generic test strict-compares each member to it).
  `bcdDevice` `0x0776` → `0x0777`.

### Fixed

- **CTAPHID: an init-type frame received mid-transaction is rejected as
  `ERR_INVALID_SEQ` regardless of its length field.** The `bcnt > maxMsgSize`
  check ran first, so a continuation frame whose sequence byte had the INIT bit
  set — the FIDO Conformance Tools' `HID-1 F-4` corrupts the last frame's seq to
  `CTAPHID_PING + 1` (0x82), leaving random payload bytes as the "bcnt" — usually
  tripped the length guard and returned `ERR_INVALID_LEN` (0x03) instead of the
  required `ERR_INVALID_SEQ` (0x04). The out-of-sequence check now precedes the
  length check. `bcdDevice` `0x0767` → `0x0768`.
- **U2F authenticate resolves the key handle before requesting a touch.** An
  unknown handle (wrong AppID / not minted by us) and a check-only (`P1=0x07`)
  request must be answered immediately — `0x6A80` and `0x6985` respectively —
  without user presence; we prompted for a touch first on `P1=0x03`, so a
  conformance negative test (`U2F-Authenticate F-2`) hung on the button and the
  stream of `UPNEEDED` keepalives desynced the tool's response reader (seen as
  "sequence out of order"). Shares the `0x0768` bump.
- **No `PROCESSING` keepalive before a fast U2F response.** U2F (CTAPHID_MSG) is
  quick apart from the touch wait, but the worker runs on a lower-priority
  executor, so the 100 ms keepalive timer could fire once before a near-instant
  reply (check-only, unknown handle) — and U2FHID hosts, including the FIDO
  Conformance Tool, read that stray `PROCESSING` frame as the response's first
  frame and desync (`U2F-Authenticate P-3`/`F-2`: "sequence out of order"). MSG
  now stays silent unless a touch is pending (`UPNEEDED`); CBOR keeps
  `PROCESSING` for its genuinely slow operations. `bcdDevice` `0x0768` →
  `0x0769`.
- **`CTAPHID_CANCEL` aborts an in-flight request's user-presence wait.** While
  the worker blocked on the touch wait the transport never read further frames,
  so a `CANCEL` sat unread until the (up to 30 s) wait ended — the FIDO
  Conformance Tool's `HID-1 P-10` (cancel during `makeCredential`) and `P-15`
  (cancel during `authenticatorSelection`) timed out. The transport now watches
  for a `CANCEL` on the active channel concurrently with the worker and signals a
  cross-executor abort; the cancelled command returns `CTAP2_ERR_KEEPALIVE_CANCEL`
  (0x2D). A `CANCEL` is also no longer acknowledged with its own frame (per the
  CTAPHID spec).
- **`authenticatorMakeCredential` input validation.** A non-text `rp.name`
  (`Req-2 F-2`) and a `pubKeyCredParams` entry missing its `alg` (`Req-4 F-4`)
  are now rejected instead of accepted.
- **`authenticatorMakeCredential` accepts `options.up=true`.** An explicit
  `up=true` is the default and now succeeds (`Req-6 P-3`); only `up=false`
  remains an `INVALID_OPTION` (`F-1`).
- **getAssertion withholds user name/displayName without user verification.** On
  a multi-credential discovery the response `user` map now carries only `id`
  unless `uv` is set (CTAP §6.2.2 privacy rule, `Discoverable P-2`); the full
  identity is returned once the user is verified. Applies to
  `authenticatorGetNextAssertion` too.
- **credentialManagement enumerateCredentials always reports `credProtect`.** The
  `0x0A` field was emitted only when a non-default level was set; it now always
  appears, defaulting to level 1 (`userVerificationOptional`)
  (`CredMgmt-EnumerateCredentials P-1`).
- **largeBlobs accepts `get=0`.** A read of zero bytes is valid and returns an
  empty fragment instead of `CTAP2_ERR_INVALID_PARAMETER` (`LargeBlobs-1 P-2`).
- **credentialManagement updateUserInformation keeps the credentialId stable.**
  Resealing a credential draws a fresh IV (nonce reuse is forbidden), so the box —
  and the resident id previously re-derived from it — changed, staling the
  platform's stored credentialId; a later `deleteCredential` with that id then
  returned `CTAP2_ERR_NO_CREDENTIALS` (`CredMgmt-UpdateAndDelete P-2`). The update
  now rewrites the credential in place, preserving its stored 42-byte resident id,
  and `getAssertion` returns that stored id instead of re-deriving it (CTAP2.1
  §6.8.5). The signing key / hmac-secret / largeBlobKey are still box-derived, so
  they rotate on an update — full stability needs a per-credential nonce and is
  deferred. `bcdDevice` `0x076F` → `0x0770`.
- **A `pinUvAuthToken` request while a forced PIN change is pending now returns the
  correct per-subcommand error.** With `forcePINChange` set (via `setMinPINLength`
  subcommand param `0x03`), both `getPinToken` (0x05) and
  `getPinUvAuthTokenUsingPinWithPermissions` (0x09) refuse to issue a token until the
  PIN is changed. The FIDO conformance ClientPin forcePINChange tests assert a
  *different* code for each: legacy `getPinToken` (0x05) → `CTAP2_ERR_PIN_INVALID`
  (0x31) (`ClientPin1-NewPin F-1`, `ClientPin2-GetPinToken F-5`); the
  permissions-based `getPinUvAuthTokenUsingPinWithPermissions` (0x09) →
  `CTAP2_ERR_PIN_POLICY_VIOLATION` (0x37)
  (`ClientPin2-GetPinUvAuthTokenUsingPinWithPermissions F-1`). Previously both
  returned `PIN_POLICY_VIOLATION`. The PIN verify itself still succeeds first, so the
  retry counter is untouched. `bcdDevice` `0x0773` → `0x0774` (0x05 fix); the 0x09
  branch followed at `0x0776`.

### Changed

- **Enterprise attestation: `ep` advertised + reflects state, type-1 eligibility
  enforced.** `getInfo` and the metadata statement carry the `ep` option (`false`
  until `authenticatorConfig` enableEnterpriseAttestation flips it `true`), so
  platforms and the conformance tool exercise the enterprise profile. EA is now
  performed only when warranted — platform-managed (type 2) for any RP,
  vendor-facilitated (type 1) only for an RP on a built-in list (empty in shipping
  firmware). Any enterpriseAttestation request now yields a basic_full (x5c)
  attestation: the org/EP cert + `epAtt` when EA is performed, or a non-enterprise
  basic_full with the device's own cert and no `epAtt` for a non-listed type-1 RP
  (CTAP2.1 §6.1.3, conformance Enterprise-Attestation F-6, which requires x5c). A
  request without enterpriseAttestation keeps the default self-attestation. The FIDO
  conformance test RPID is added to the type-1 list **only** under the
  conformance-only `ea-conformance-rpid` build feature, never in a shipped image.
  The metadata `upv` gains `{1,2}` and `{1,3}` and drops the non-MDS3
  `legalHeader`. `bcdDevice` `0x0770` → `0x0772`.
- **EdDSA (-8) and ES256K (-47) are no longer advertised in `getInfo.algorithms`
  or the metadata.** The FIDO conformance tool's shared `verifySignatureCOSE` maps
  only `-7`/`-35`/`-36` for elliptic curves, so it throws "hashFunction missing"
  verifying a packed self-attestation over an EdDSA or secp256k1 credential
  (`MakeCred-Resp P-06`). Both stay fully implemented — makeCredential negotiates
  `-8`/`-47` from a request's `pubKeyCredParams` — only the advertisement is dropped
  (the same approach as ML-DSA-44), leaving the advertised set at the
  tool-verifiable NIST curves ES256/ES384/ES512. getInfo, `authenticationAlgorithms`
  and `authenticatorGetInfo.algorithms` kept in sync (`tests/62`). `bcdDevice`
  `0x0772` → `0x0773`.
- **`getInfo` advertises the `authenticatorConfigCommands` member (`0x1F`).** It
  lists the supported `authenticatorConfig` (0x0D) subcommands —
  `enableEnterpriseAttestation` (0x01), `toggleAlwaysUv` (0x02) and `setMinPINLength`
  (0x03). The FIDO conformance AuthenticatorConfig suite requires it (the
  enable-enterprise-attestation test asserts the array contains `0x01`, the
  "featureful" CTAP2.3 profile requires `0x02`, and the suite's `before` hook reads
  it). Mirrored in the metadata statement. Shares the `0x0774` bump (`0x02` arrived
  with alwaysUv at `0x0775`, below).

## [0.2.4] — 2026-06-19

### Added

- **The `rsk` CLI can run without Nix.** A `tools/pyproject.toml` packages the
  CLI so it installs from any Python ≥ 3.9 toolchain —
  `uvx --from ./tools rsk …`, `uv tool install ./tools`, `pipx install ./tools`,
  or plain `pip`. The Nix dev shell stays the primary, pinned path; this mirrors
  its CLI runtime deps (`hidapi`, `cryptography`, `pyscard`, `fido2`,
  `mnemonic`, `shamir-mnemonic`) for hosts without Nix. See
  [tools/README.md](tools/README.md). Host-tool only; no `bcdDevice` bump.

### Changed

- **FIDO2 PIN entry is now uniform across the CLI.** Commands disagreed on how
  to take a PIN: most accepted only `--pin` (and aborted on a PIN-protected
  device when it was omitted), while `fido list-passkeys` and `fido set-pin`
  prompted interactively with no flag at all. Every PIN-gated command (`backup
  export`/`restore`, `audit log`/`verify`, `lock enable`/`disable`, `inventory
  verify`, `fido list-passkeys`/`set-pin`/`attestation import`/`clear`) now
  accepts the PIN **either** way — `--pin` flag **or** an interactive prompt —
  through one chokepoint (`rsk.common.resolve_pin`) that only prompts when the
  device actually has a PIN, so touch-only devices are never asked. Host-tool
  only; no `bcdDevice` bump.
- **The `rsk-tui` cockpit now routes PIN entry through one chokepoint too.** Its
  four per-action PIN steps collapsed into a single `App::gate_pin` +
  `Step::PinThenRun`, so "prompt for the FIDO2 PIN iff the device has one, else
  run" lives in exactly one place (mirroring the CLI's `resolve_pin`). PIN-vs-
  phrase collection in the modal flow is now explicit instead of a catch-all (a
  stray text input can no longer land in the PIN buffer), and the four
  `device requires a PIN` strings were unified. No behaviour change for users;
  host-tool only, no `bcdDevice` bump.

### Fixed

- **`rsk secure-boot` no longer refuses provisioning on a chip with a benign
  `LOCK_NS`.** `pages_locked()` read the whole OTP lock row, so a pre-set
  non-secure-page lock (`LOCK_NS=1`, `0x040404`) looked like a bootloader lock
  and wrongly blocked `load-key`; it now masks `LOCK_BL` specifically. Host-tool
  only; a mutation-proven regression test was added.

### Security

- **Transparency-log monitoring for our release signing identity.** A scheduled
  GitHub Action (`sigstore/rekor-monitor`) watches the Rekor log for entries
  signed under our release workflow's OIDC identity, so illegitimate use of it —
  a signature we did not produce — becomes detectable, complementing the SLSA
  Build L3 provenance. CI only; see `docs/supply-chain.md`.
- **OATH credential secrets are now sealed at rest.** Every other applet
  (FIDO, PIV, OpenPGP, rescue) AES-encrypts its keys before they reach flash;
  OATH alone stored its TOTP/HOTP shared secrets — and the SET CODE key — as
  plaintext TLV. They are now AES-256-GCM-sealed under the device `kbase`
  (`HKDF(serial_hash, kbase, "OATH/KEYS")`), the same device-seal the PIV slot
  keys use. A one-time boot migration re-seals any credential enrolled before
  this release, so existing accounts keep working. With the OTP MKEK burned, an
  extracted flash image no longer reveals OATH secrets. `bcdDevice` `0x0765` →
  `0x0766`.
- **The at-rest seal path is now enforced by types, not convention.** A slot
  that holds a sealed secret is a `KeyFid`, distinct from a plaintext `u16` file
  id, and the only writer that accepts one is `Fs::put_key(KeyFid, Sealed)` —
  where `Sealed` is produced only by a seal routine. A stray
  `fs.put(key_fid, raw_secret)` no longer compiles (asserted by a `compile_fail`
  doctest). This is the chokepoint whose absence let OATH ship its secrets in
  the clear; every applet's key FIDs were moved onto it.
- **Resident-credential RP domains are now boxed at rest.** A discoverable
  credential's `EF_RP` record stored the relying-party id (the site's domain)
  in cleartext, so a flash dump revealed the *list of sites you hold passkeys
  for* — a privacy leak, even though the keys themselves were sealed. The domain
  is now ChaCha20-Poly1305-boxed under the device seed (the same seal the
  credential body uses), with the rpId **hash** kept in cleartext as the O(1)
  lookup key. A boot migration re-boxes records enrolled before this release.
  Honest residual: the rpId hash remains, so a dump can still *dictionary-attack*
  guessable domains — but the plaintext site list is gone. `bcdDevice` `0x0766`
  → `0x0767`.

## [0.2.3] — 2026-06-18

### Changed

- **LED turns green (idle) as soon as the host configures the device**, instead
  of staying on the red boot status until the first applet command arrives. A
  healthy, enumerated key that nothing is talking to yet — e.g. a Linux host with
  no PC/SC daemon running — used to look dead (red) even though it was ready. A
  device-level USB `Handler::configured` callback now flips the status on
  configuration. `bcdDevice` `0x0764` → `0x0765`.

### Fixed

- **~90 s boot stall (LED stuck on the red BOOT status) on some RP2350 boards.**
  `FidoRng::new` seeds the HMAC-DRBG with 48 bytes from the hardware TRNG, and
  the embassy driver runs an autocorrelation health-check on every generated
  block — on a failed check it soft-resets and re-samples in a loop. At the
  default `sample_count` of 25, consecutive ROSC samples on a marginal unit are
  too correlated, so the check failed almost every time and seeding blocked a
  variable 30–105 s on **every** boot (init runs before the USB pull-up, so the
  device was simply absent from the bus that whole time — looked dead, worst on
  strict hosts). Raising `sample_count` to 1000 decorrelates the samples so the
  check passes first try: **~1.5 s boot, HW-verified** on the affected board.
  Entropy quality is unchanged — the NIST health checks stay enabled and the
  source is the same; the seed is just gathered reliably. `bcdDevice` `0x0763`
  → `0x0764`.

- **PIV tab *still* slow after the present-cache fix below: `GET METADATA` over
  empty key slots.** That bitmap guarded `read` and `size`, but `has_data` — a
  third absent-probe method — still called the backend directly, so a missing
  FID scanned the whole partition. PIV `GET METADATA` checks `has_data(slot)`
  first, and `ykman piv info` / Yubico Authenticator's PIV tab read metadata for
  ~24 mostly-empty slots (`9A/9C/9D/9E` + 20 retired), so each tab switch paid
  ~24 full scans ≈ 4 s of green-blinking even though every individual APDU
  answered in ~30 ms. `has_data` now consults the same bitmap → `O(1)` for an
  absent slot; measured `ykman piv info` **4.16 s → 0.26 s** (~16×) on hardware.
  `bcdDevice` `0x0762` → `0x0763`.

- **Slow applet listing (PIV especially), seen as long green-blinking when
  switching tabs in Yubico Authenticator.** A backend `read`/`size` of an
  *absent* file scanned the entire ~1.4 MB KV partition to confirm absence, so
  enumerating a sparse object range was `O(slots · flash)` — opening the
  Certificates tab probes ~25 mostly-empty PIV certificate slots, each a full
  scan. (OATH had the same class of bug, fixed earlier; PIV/others did not.) The
  filesystem now keeps a fixed present/absent bitmap of all FIDs (rebuilt on
  boot, maintained on every write/remove), so an absent `read`/`size` returns
  without touching the backend — `O(1)` instead of a full scan. `bcdDevice`
  `0x0761` → `0x0762`.

- **USB enumeration race at boot (first field report).** On a Waveshare RP2350
  the device would "blink red and not be recognised," recovering only after
  several replugs. `builder.build()` asserts the bus pull-up, so the host begins
  enumerating the moment the device attaches — but the task that answers control
  transfers (`usb_task`) was spawned only after a block of per-boot init (seed +
  attestation cert + OpenPGP DEK + flash writes, heaviest on a fresh device). The
  host enumerated into an attached-but-mute device and timed out the first
  descriptor request; a lenient host (macOS) usually won, a strict one often did
  not. Boot now completes all that init **before** attaching, and spawns
  `usb_task` immediately after `build()`, so enumeration is serviced with no
  blocking gap. `bcdDevice` `0x0760` → `0x0761`.

## [0.2.2] — 2026-06-15

No firmware change — `bcdDevice` stays `0x0760` and the eight `.uf2` images are
bit-identical to 0.2.0. This release ships the fixed, hardened release pipeline:
0.2.0 published its GitHub Release without provenance, because the SLSA
generator's "append the provenance to the release" model is incompatible with
GitHub's immutable releases (the late asset upload is rejected — even on a draft).

### Changed

- Build provenance now uses GitHub's native `attest-build-provenance`, generated
  from inside a **reusable workflow** (`release-build.yml`). Running the build
  and the attestation in an isolated, identity-bound reusable workflow raises the
  release to **SLSA v1 Build Level 3** (an inline attestation step alone is only
  Build L2). Each `.uf2` is attested keyless (Sigstore/Fulcio + the Rekor log)
  into the **attestation API** instead of being uploaded as a release asset, so
  it stays compatible with immutable releases. Verify with
  `gh attestation verify --signer-workflow …` (`docs/supply-chain.md`).
- All GitHub Actions bumped to their current major versions (off the deprecated
  Node 20 runtime).

## [0.2.0] — 2026-06-15

The cycle since 0.1.0. USB `bcdDevice` is now `0x0760` (incremented once per
firmware change along the way).

### Added

- **Own AAGUID + FIDO Metadata Statement.** The authenticator reports its own
  model identity (`2479c7bf-6b30-5683-9ec8-0e8171a918b7`, a reproducible UUIDv5)
  instead of the inherited pico-fido one, and ships a self-published FIDO
  Metadata Statement (`metadata/rs-key.metadata.json`) with a drift guard.
- **Supply-chain provenance.** Releases now carry SLSA build provenance
  (slsa-github-generator, keyless) and pass a release-time reproducibility gate
  that rebuilds all eight flavors bit-identical before anything is published.
- **Dependency review.** A `cargo-vet` gate (Mozilla / Google / ISRG / Zcash
  audits + recorded exemptions) blocks new unreviewed crates; a new
  `docs/supply-chain.md` documents the whole chain.
- **Versioned documentation site** — `main`, `develop` and tagged versions are
  published side by side with a switcher.
- **Kani proofs** that the OpenPGP import (BER) parser is panic-free and
  terminating, plus a CI guard that `flake.lock` stays in sync with `flake.nix`.

### Changed

- Every GitHub Action is pinned to a commit SHA, kept fresh by Dependabot.
- The physical-attack posture docs are reframed around the published RP2350
  hacking challenges (threat model / OTP fuses / limitations).

### Fixed

- **U2F routing.** A vendor-AID SELECT over CTAPHID_MSG no longer leaves a sticky
  applet selection that routed later U2F REGISTER / AUTHENTICATE / VERSION into
  `0x6D00`; the MSG selection is dropped on every CTAPHID_INIT.
- **OATH performance.** RESET / LIST / CALCULATE-ALL / lookup probed all 255
  credential slots, and each absent slot rescanned flash; they now touch only
  present credentials — OATH RESET dropped from ~39 s to ~0.5 s.
- **USB transport wedge.** Bounding the CTAPHID/CCID IN-endpoint writes stops an
  abandoned transaction from wedging the interface until a replug.
- The OpenPGP card-status self-test now follows GET DATA response chaining.

### Security

- **Constant-time audit fixes** — RSA base blinding on the raw path and
  constant-time OTP access-code comparisons (`docs/ct-audit.md`).
- **Fault-injection fences** on the PIN and secure-boot gates, so a glitched
  single comparison can't skip the check.

## [0.1.0] — 2026-06-13

First public release — an open-source security-key firmware for the Raspberry Pi
RP2350 (Cortex-M33), a behavioral reimplementation of the AGPL-3.0 pico-keys
family that keeps the "enterprise" features in the open tree.

### Security keys / protocols

- **FIDO2 / WebAuthn / U2F** — passkeys (discoverable credentials), second-factor,
  `ssh -t ed25519-sk`, hmac-secret and largeBlobs; user presence gated on the
  BOOTSEL button (the default touch build).
- **OpenPGP card 3.4** — sign / decrypt / authenticate; EC (Ed25519, NIST, brainpool)
  and on-card RSA keygen (2048/3072/4096) accelerated across both cores.
- **PIV** — X.509 slots, attestation, the Yubico management extensions; works
  through PKCS#11 / OpenSC and the OS-native stacks.
- **OATH (YKOATH)** — TOTP / HOTP credential store.
- **Yubico OTP** — slot programming and challenge-response over CCID, plus the
  HID-keyboard typing path.

### Enterprise features, in the open tree

- forceChangePin enforcement, a SHA-256-chained signed audit trail, an opt-in
  `fips-profile`, organizational attestation (import key + chain), and host-side
  fleet inventory / verification / offboarding tooling.

### Hardening

- Secure boot + anti-rollback (RP2350 OTP), keys sealed under an OTP-burned
  device root, and an at-rest soft-lock of the FIDO seed.

### Tooling

- The `rsk` CLI and the `rsk-tui` ratatui dashboard; guided primary + backup
  device pairing; secure-boot key-rotation tooling. Run without the dev shell via
  `nix run .#rsk`, `.#rsk-tui`, and a one-command flasher `.#flash`.

### USB identity

- The default build presents this project's **own** pid.codes identity
  (`0x1209:0x0001`, "RS-Key Security Key") — not a YubiKey masquerade. An opt-in
  `VIDPID=Yubikey5` flavor borrows the YubiKey identity for `ykman` / Yubico
  Authenticator interop.

### Assurance

- 39 fuzz targets, Kani proofs, a Miri pass, power-cut torture, bit-reproducible
  `nix build` images (per platform, per `flake.lock`), and a hardware-verified
  interop matrix ([docs/interop.md](docs/interop.md)).

### Release artifacts

- Eight firmware flavors (`up-button` × `advertise-pqc` × `fips-profile`), each a
  reproducible **unsigned** `.uf2` — on a secure-boot device, seal it with your
  own key before flashing (`nix run .#flash`, or see
  [docs/production.md](docs/production.md)).
- `SHA256SUMS` over every artifact, a keyless [cosign](https://docs.sigstore.dev/)
  signature of it, and a CycloneDX SBOM. See
  [docs/releases.md](docs/releases.md) to verify a download.

[Unreleased]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.10...HEAD
[0.3.10]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.9...v0.3.10
[0.3.9]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/TheMaxMur/RS-Key/compare/v0.2.8...v0.3.0
[0.1.0]: https://github.com/TheMaxMur/RS-Key/releases/tag/v0.1.0
