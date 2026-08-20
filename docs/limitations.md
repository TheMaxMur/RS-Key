# Limitations — what RS-Key does not do, and why

Each gap below comes with its reasoning. "Not yet" and "never" are marked. The
project as a whole is experimental and unaudited. The [threat model](threat-model.md)
covers the security boundary. This page covers feature and hardware gaps.

## Cryptography

- **brainpoolP512r1 (OpenPGP)**: not offered. brainpoolP256r1 and P384r1 are
  supported (advertised in DO `0xFA`, generate / keytocard / sign / decrypt), but
  no Rust arithmetic for the 512-bit brainpool curve exists yet, so the applet
  neither advertises nor generates it. *Status: until a crate exists.*
- **X448 / Ed448 (OpenPGP)**: not offered, same reason. RustCrypto coverage
  of Curve448 is thin and unaudited. Cv25519/Ed25519 plus the NIST curves and
  secp256k1 cover practical use. *Status: until a serious crate exists.*
- **RSA decryption timing (OpenPGP PSO:DECIPHER)**: the `rsa` crate carries
  RUSTSEC-2023-0071 (the Marvin attack) and no fixed release exists — OSV marks
  every version affected. Most private-RSA work never reaches it: PIV GENERAL
  AUTHENTICATE, PSO:CDS and INTERNAL AUTHENTICATE all sign through
  `rsk_rsa_asm::sign_crt`, blinded and Bellcore-fault-checked. Two paths do.
  PIV certificate signing runs once at key generation over a digest the device
  built itself, so there is no chosen-ciphertext oracle to drive. PSO:DECIPHER
  is the real one — it PKCS#1 v1.5-decrypts a ciphertext the host chose. It goes
  through the crate's blinded API over a constant-time unpad, so what is left is
  `num-bigint-dig`'s variable-time arithmetic, behind the PW1 gate.

  Separately, and regardless of timing: DECIPHER answers malformed padding with
  a distinct status word and well-formed padding with plaintext. That is a
  padding oracle by response code, and it is inherent to the command — the card
  must either hand back a session key or report failure — not specific to this
  implementation. Assume a host that can drive DECIPHER at will with PW1
  verified can mount Bleichenbacher-class attacks on ciphertexts of its
  choosing. *Status: accepted; revisit if DECIPHER moves onto `rsk_rsa_asm`.*
- **RSA-3072/4096 on-card generation is slow.** The prime search dominates the
  cost: *rejecting* hundreds of composite candidates, each one asm-modexp-bound.
  Both cores run the search with the modexp hot path in SRAM
  ([architecture](architecture.md)). Typical timings, measured on the
  reference board (single-core → dual-core):

  | key | before | after |
  |---|---|---|
  | RSA-2048 | ~8.9 s | ~4–6 s |
  | RSA-3072 | ~35 s | ~22 s |
  | RSA-4096 | ~65 s | ~50 s |

  The total is set by how many candidates a given draw happens to need, which is
  random. The per-keygen spread is wide (17 s to 124 s seen at 4096) because
  that count varies, not because the silicon does. Per candidate the throughput
  is ~6.9 ms across both cores.

  **These are reference-board numbers and do not carry to every board.** A
  Waveshare RP2350-Zero measures RSA-2048 at a median of ~9.7 s where the
  reference board does 4–6 s. Budget for the board you ship, not for this table.

  Both halves of the hot path — the asm modexp, and the small-prime sieve loop
  with its prime table — are held in SRAM rather than run from XIP flash. That
  is not a micro-optimization: while the sieve was still in flash it and the
  surrounding code evicted each other from the small XIP cache, and *which* of
  them won depended on where the linker happened to put things, so an unrelated
  1.7 KB of image growth moved RSA-2048 keygen by 1.36× (9.7 s → 12.7 s, three
  and four batches of 12, no overlap between them). Keep new hot loops out of
  XIP if you want a timing that survives the next commit.

  The lever is *fewer candidates reaching the modexp*: a deeper small-prime
  sieve. (The Baillie–PSW that confirms a survivor, asm strong Miller–Rabin
  plus a software Lucas test, runs only a handful of times per keygen, so it
  doesn't move the total.) Depth is set by the measured cost ratio: one
  strong-MR modexp is ~35 ms (1024-bit) / ~239 ms (2048-bit) against ~11 µs /
  ~23 µs for one trial division, so it pays to sieve by every prime up to
  ~3.1k / ~10.5k, far past the old flat 256-prime (≤1619) sieve. Depth now
  scales with key size (448 primes at RSA-2048 ... 1280 at RSA-4096), and the
  sieve runs *incrementally*: a candidate stream `n, n+2, n+4, …` from a random
  odd start, each residue `n mod pᵢ` stepped by one add instead of re-derived by
  a Horner pass (OpenSSL/GMP do the same). The primality decision is untouched,
  so key strength is unchanged. Same-device A/B (per-candidate cost, which
  divides out the prime-search-luck variance): depth-scaling took **RSA-2048
  7.84 → 6.48 ms/candidate and RSA-4096 36.0 → 26.2 ms** versus the old flat
  256-prime sieve, and the incremental step took those a further **6.48 → 5.28
  ms (−18.5%) and 26.2 → 20.9 ms (−20.4%)**. The device streams keepalives
  throughout, so tools wait it out. Import is fast. *Status: inherent to the
  hardware class; the parallel-scan share is at the two-core limit, the sieve
  at the measured modexp:division ratio and now incremental.*
- **ML-KEM is scaffolding**: compiled, tested, unused. No CTAP PIN/UV
  protocol number for PQC key agreement exists yet to implement.
  *Status: waiting on standards.*
- **PQC interop is limited by client support**: ML-DSA-44 (COSE −48),
  ML-DSA-65 (−49) and ML-DSA-87 (−50) credentials work and verify on-device.
  Their signatures verify under OpenSSL and Yubico's python-fido2, but no browser
  or mainstream WebAuthn library *negotiates* these COSE ids against security keys
  yet. Released Firefox versions abort getInfo if the algorithm is *advertised*
  (hence the `advertise-pqc` build flag, default off; capability stays on
  regardless). These are the ML-DSA schemes, not a FIPS-validated module.
  *Status: waiting on clients.*

## Backup & migration

- **The seed backup covers the deterministic identity only.** Non-resident
  credentials (`ssh ed25519-sk`, most 2FA registrations) derive from the
  master seed and survive a restore onto a new board. **Not covered:**
  resident passkeys (stored records, not derivable), OpenPGP private keys,
  PIV private keys, OATH secrets, OTP slots, all sealed to the source
  chip. A board swap means re-enrolling those. *Status: by design; a full
  at-rest export would gut the at-rest story.*
- **A finalized backup window stays closed** until a factory reset
  regenerates the seed. Lost words cannot be re-exported. Pick a generous
  SLIP-39 share count. *Status: by design (anti-exfiltration gate).*

## Hardware / physical

- **No secure element.** The RP2350's OTP fuses, glitch detectors and secure
  boot are real, and RS-Key adds anti-imaging OTP chaffing on top. But decap,
  microprobing, FIB imaging, advanced fault injection and power/EM side channels
  remain out of scope. The public RP2350 hacking challenge broke the **A2**
  stepping. The **A4** stepping fixes the boot-ROM and OTP power-glitch attacks
  in silicon, but **not** the antifuse-array readout (mitigated only by how
  secrets are stored: the chaffing RS-Key applies). Our development boards are
  A2. The firmware is A4-compatible and A4 is recommended. *Status: never. These
  are silicon properties, not firmware ones; closing them fully is what a
  dedicated secure element is for.*
- **The at-rest seals are not authenticated against a flash writer.** They keep a
  flash *dump* from yielding key material, which is what the OTP burn buys. They
  do not stop someone who can *write* flash over BOOTSEL from planting a record:
  the pre-OTP key base derives from the public chip serial, and those arms stay
  readable after the burn so an already-provisioned device survives the upgrade.
  The boot migration then re-seals the planted record under the fused root.
  *Status: needs a fuse-rooted latch that closes the migration window once the
  device is provisioned; the analysis is audit run-27 #8, the decision is the
  maintainer's because it makes `lock-page58` load-bearing for boot correctness.*
- **PIV data objects are access-gated, not sealed.** SP 800-73-4 pt1 Table 3
  gives four of them a read condition of PIN — Cardholder Fingerprints
  (`5FC103`), Facial Image (`5FC108`), Printed Information (`5FC109`) and Iris
  Images (`5FC121`) — and RS-Key enforces exactly those four at the APDU layer.
  It does not back them at rest: the seal rule covers key material, so a flash
  dump of a provisioned device yields whatever a host put in them. Their names
  are the standard's, not a capability of this firmware — there is no sensor, no
  enrolment and no matching here, and the 1900-byte object ceiling is far under a
  real FIPS 201 biometric template, so what they hold is whatever the owner chose
  to store. *Status: won't fix. The read condition is an access rule, not a
  confidentiality promise, and the device cannot produce the content a seal here
  would be protecting.*
- **XIP TOCTOU residual**: secure boot verifies the image in external QSPI
  flash, then executes from it. Nothing binds the bytes that were hashed to the
  bytes later fetched, so hardware interposing on the QSPI bus can serve the
  genuine image to the verifier and a tampered one to the CPU. The clean fix
  (copy the image into SRAM, verify, run verified-in-place) does not fit: the
  ~1.7 MB image plus working RAM far exceeds the 520 KB SRAM. There is also no
  runtime flash authentication in hardware. Part selection is the real lever: an
  in-package-flash device (**RP2354**) stacks the flash die on the QSPI bus
  inside the package, so there is no discrete flash chip to clip an emulator
  onto and a reliable interposer needs decap-class access. RS-Key is developed
  and tested on external-flash RP2350 boards, so RP2354 is a recommendation here,
  not a configuration the project has validated. *Status: never on an
  external-flash board; decap-class effort on RP2354.*
- **No TrustZone-M secure/non-secure split.** Considered and rejected: the
  embassy ecosystem has no TrustZone support, so it would mean hand-rolling
  SAU/IDAU configuration, NSC veneers and dual images (the project's
  single biggest item) to defend mainly against parser memory corruption,
  which safe Rust plus fuzzing already address. Physical attacks are
  orthogonal to TrustZone. *Status: revisit only with ecosystem support.*
- **Anti-rollback is opt-in and coarse**: `picotool seal --rollback`
  plus the `ROLLBACK_REQUIRED` fuse ([anti-rollback.md](anti-rollback.md)). The
  OTP thermometer has 48 steps for the board's life, so the rollback floor is
  raised for security-relevant releases only. Until the fuse is set, any
  previously-signed image still boots. *Status: shipped (optional).*
- **No image encryption**: pointless for open-source code (no secrets in
  the image; secrets live sealed in flash), and the RP2350 has no
  transparent XIP decryption anyway. *Status: never.*

## Protocol / compatibility

- **The default USB identity is RS-Key's own** (`0x1209:0x0001` on the
  pid.codes FOSS VID, manufacturer `RS-Key`, product `RS-Key Security Key`,
  reported firmware 5.7.4), *not* a YubiKey masquerade. We no longer ship
  Yubico's identifiers by default. A YubiKey identity (`0x1050:0x0407`,
  reader name `Yubico YubiKey …`) exists only as the opt-in `VIDPID=Yubikey5`
  build flavor ([build.md](build.md)), built for local interop testing and
  never distributed. Distributing hardware with Yubico's identifiers is not
  OK. The trade-off: `ykman`, Yubico Authenticator and the stock Yubico udev
  rules gate on the `Yubico YubiKey` reader name / VID `0x1050`, so on the
  default RS-Key build they do not see the device. Use them against the
  `VIDPID=Yubikey5` flavor, or add a udev rule matching VID `0x1209`.
  FIDO2/WebAuthn, `ssh -sk`, `gpg`/OpenPGP, OpenSC/PKCS#11 and the project's
  own `rsk`/`rsk-tui` tools are identity-independent and work on the default
  build.
- **The attestation certificate is per-device, so it identifies the key.** Every
  `makeCredential` carries packed basic attestation whose `x5c` leaf is this
  board's own certificate ([guides/attestation.md](guides/attestation.md)), and
  it is the same certificate for every relying party. A batch certificate shared
  across devices would avoid that, but it would have to ship inside open-source
  firmware, where anyone could extract it. Browsers hide the leaf unless a site
  asks for `attestation: "direct"`; native CTAP clients such as `ssh-keygen` see
  it. A factory reset regenerates the seed and with it the certificate.
- **The PIV attestation identity cannot be replaced by a host.** A YubiKey lets
  one load its own chain — `IMPORT` into slot `f9` for the key,
  `PUT DATA 5FFF01` for the certificate — and that is a documented enterprise
  feature there. RS-Key refuses both (`6A86` and `6A80`). The `f9` key is
  generated by the device at first boot and never leaves it, so accepting those
  two commands would let anyone holding the management key swap the device's
  attestation identity irreversibly, over a single APDU, for a key they control.
  The cost of the other choice is on the record: one probe pass in this project
  destroyed a real YubiKey's factory attestation chain with a single
  `PUT DATA 5FFF01`, and no reset brings it back. `ATTEST` and `GET METADATA` at
  `f9` work normally, and a factory reset regenerates the identity.
  *Status: never — deliberate.*
- **`SET RETRIES` will not set a zero budget.** `00 FA 00 00` on a YubiKey
  answers `9000` and leaves the card at `0/0` tries, permanently blocked, with
  only a factory reset — which destroys every key — to recover. RS-Key answers
  `6A80` and changes nothing. The project matches a YubiKey everywhere except
  where matching would lose user data, and this is that exception.
  *Status: never — deliberate.*
- **OpenPGP secure messaging** is not implemented (rarely used by clients;
  PINs gate everything in practice).
- **One physical button on the base build.** Touch = the BOOTSEL button, and
  there is no fingerprint reader, so UV is the PIN and "number matching" style
  UV is impossible. The trusted-display flavor
  ([guides/display.md](guides/display.md)) adds a screen for on-device PIN entry
  and per-signature relying-party approval, but still no biometric UV.

## Operational

- **The flash log heals lazily**: deleting/superseding a record (e.g.
  enabling the soft-lock) leaves the old record in the log until compaction
  naturally overwrites it, so most at-rest guarantees harden over time rather
  than instantly. *(On a provisioned device the superseded copy is sealed to
  the fused root.)* The one record that is **not** left to lazy healing is the
  pre-OTP seed superseded by the OTP-burn migration. It is sealed under the
  chip-serial-only root, so the first boot after provisioning scrubs it eagerly
  with a one-shot full-GC-lap compaction.
- **The board is the security boundary**: anyone with the device and your
  PIN is you. Same as every security key.
