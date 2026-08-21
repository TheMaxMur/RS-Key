# Architecture

How the firmware is put together, for contributors and the curious. For what
the design does and does not defend against, see the
[threat model](threat-model.md).

## The big picture

A composite USB device with three interfaces, seven smart-card applets and
one storage layer. Day to day everything runs on one RP2350 core. The
second wakes only to parallelize RSA keygen (below):

```mermaid
flowchart TD
    subgraph irq["Interrupt executor"]
      fido["FIDO HID<br/>(0xF1D0, CTAPHID)"]
      ccid["CCID<br/>(class 0x0B, APDU)"]
      kbd["Boot keyboard<br/>(OTP typing)"]
    end
    fido --> worker
    ccid --> worker
    kbd --> worker
    subgraph thread["Thread executor"]
      worker["worker task<br/>owns flash + TRNG"]
      worker --> applets["Applets<br/>FIDO2/U2F · OpenPGP · PIV · OATH<br/>OTP · mgmt · vendor + rescue"]
    end
    applets --> fs["flash KV store<br/>(rsk-fs over sequential-storage)"]
```

**Two executors.** USB and the transports live on a high-priority
`InterruptExecutor`. The applet dispatch lives on the low-priority thread
executor, in a single *worker* task that owns the flash and the TRNG outright.
Long synchronous work (on-card RSA generation, flash compaction, a touch
wait) blocks only the worker, while the interrupt executor keeps the bus
enumerated, streams CCID/CTAPHID keepalives, and animates the LED. No
mutexes: ownership does the synchronization.

**Why (mostly) one core.** The async executor provides the *concurrency* that
the upstream design used a second core and hand-rolled queues for. Core 1 is
kept out of the transport path and has exactly one job: during on-card RSA
generation both cores race the prime search. Independent random candidates,
each core with its own DRBG stream, feed one shared two-prime pool
(`firmware/src/core1.rs`). Measured, RSA-2048 generation drops from ~8.9 s to
~4.3 s mean (2.07×).

Three details make that work:

- The Fermat-filter modexp (C + asm) executes from SRAM. Two cores running it
  from XIP throttle each other on the shared flash cache (~40% per core,
  measured).
- The key returns the moment the pool completes; core1's last candidate
  finishes in the background.
- A core1 that ever stops answering latches the engine into single-core mode
  rather than stalling the worker (on a `--features core1-stats` build, `INS 0x12`
  on the vendor applet reads the engine's counters and flags; a shipped image
  answers `6D00` — they time the prime search).

Outside keygen, core1 parks in WFE, and embassy-rp pauses it around every flash
erase/program, so its XIP fetches never collide with flash writes.

## Boot sequence

Getting to that runtime state has a strict order. The bootrom verifies the
signed image, then the firmware provisions and recovers **all** persistent state
(OTP keys, the KV store, the phy record, the TRNG, the seal migrations and the
one-shot at-rest scrub) *before* it asserts the USB pull-up. That ordering is
load-bearing: `builder.build()` starts host enumeration, and the task that
answers control transfers must be spawned with no blocking work in between, or
the host enumerates a mute device and times out. That is the "blink red / not
recognised until several replugs" report that motivated attaching to the bus
only after everything else is ready.

![Boot sequence — bootrom secure-boot verify, then a provision-and-recover phase (OTP keys, KV mount, phy record, TRNG seed, seal migrations, at-rest scrub) that completes before the USB pull-up, then attach-and-serve (build, spawn usb_task, transports live, worker dispatches applets)](images/boot-flow.svg)

## Crates

The workspace splits along a strict dependency gradient: the `firmware` binary
is thin glue over the applet crates, which build on a handful of host-tested
platform libraries. The per-crate detail is in the table. The shape is:

![Crate dependency layers — the firmware binary on top, then the seven applet crates (fido, openpgp, piv, oath, otp, mgmt, rescue), then the platform libraries (sdk, fs, crypto, usb, rsa, led); each tier depends on the one below, with piv→openpgp and openpgp/piv→rsa as the cross-edges](images/crate-graph.svg)

| Crate | Contents |
|---|---|
| `firmware` | the only crate that touches the HAL: board bring-up, USB descriptors, executors, the worker, OTP fuse access, LED, BOOTSEL touch |
| `rsk-sdk` | APDU parsing (cases 1–4, short + extended), BER-TLV, status words, the `Applet` trait + dispatcher, and the seams a board hands every applet: `Rng`, `UserPresence`/`Presence` |
| `rsk-fs` | the flash filesystem: 16-bit file ids over two `sequential-storage` KV partitions (main + high-churn counters), ACLs, metadata records |
| `rsk-crypto` | one wrapper over RustCrypto: hashes, HMAC/HKDF, AES-CBC/CFB/GCM, ChaCha20-Poly1305, PIN KDFs, HMAC-DRBG, ML-DSA-44/-65/-87 (`rsk-mldsa`) / ML-KEM, base64url, CRC |
| `rsk-mldsa` | stack-optimized ML-DSA (FIPS 204) for all three parameter sets: streams the matrix A on the fly (one polynomial resident, not the full k×l) so even ML-DSA-87 fits the RP2350 stack where the by-value `fips204` crate's -65 overflowed it. `no_std`, no alloc, no `unsafe`; checked byte-for-byte vs NIST ACVP KATs, with Kani proofs over the reductions and rounding |
| `rsk-usb` | the CTAPHID reassembler/framer and the CCID state machine, transport-agnostic and fully host-testable |
| `rsk-fido` | FIDO2 (CTAP 2.1) + U2F: credentials, clientPIN (protocols 1+2), credManagement, extensions (hmac-secret, credProtect, credBlob, largeBlobs, minPinLength), enterprise attestation, seed backup + soft-lock vendor commands |
| `rsk-openpgp` | OpenPGP card 3.4: DO model, PW1/RC/PW3, import/generate, PSO, AES PSO, certs — EC + RSA-2048/3072/4096 |
| `rsk-piv` | PIV: 24 key slots + F9 attestation, management-key auth, generate/import/sign/ECDH, on-card X.509 via a hand-rolled backward DER writer |
| `rsk-oath` | YKOATH protocol: TOTP/HOTP, touch-required accounts, access codes |
| `rsk-otp` | Yubico OTP slots ×4: CCID command surface + the keyboard frame protocol and typed-ticket generation |
| `rsk-mgmt` | the YubiKey management applet: the CCID command surface for READ/WRITE CONFIG and the device-wide reset (the record itself is `rsk-devconf`), served over both CCID and CTAPHID |
| `rsk-rescue` | recovery/provisioning applet: identity, the phy config record (codec in `rsk-phy`), flash info, secure-boot status, attestation key, reboot, the one OTP-lock write |
| `rsk-store` | the `rsk_fs::Storage` backend the device runs: two `sequential-storage` map partitions (credentials vs. the hot counters), the counter-FID routing, and the scrub lap that physically destroys superseded secrets — generic over the flash, so the fuzzer can cut its power and the emulator can mount a file |
| `rsk-device` | the applet wiring both the firmware and the emulator run: which applets exist, what capability gates each, and how a CTAPHID or CCID message reaches one — the board's own parts behind a `Hooks` trait. Also the presence-scope arbitration (`presence`): which transport owns the one button, whose cancel may end its wait, and the `spent` latch, with the button and clock behind a `Board` seam |
| `rsk-vendor` | the vendor AID: the persisted test counter, SET/GET LED, the reboot request, and — gated out of every shipped image — core1 stats and the measurement benches; the hardware behind a `Platform` the firmware fills in |
| `rsk-rsa` | the RSA family: the key type, key generation, the sealed CRT layout and its blinded, fault-checked private operation, PKCS#1 v1.5, the `7F49` public-key DO — over vendored C/ARM-asm modular exponentiation behind one FFI fn (host build uses a pure-Rust fallback). The OpenPGP and PIV applets add only their own framing and seal I/O |
| `rsk-led` | the `EF_LED_CONF` codec for the status-LED config block, shared by the firmware and the `rsk led` host tool |
| `rsk-devconf` | the `EF_DEV_CONF` codec: the Yubico DeviceInfo record — which applications are enabled, the capability vocabulary, the validate/merge/trim write path and the READ CONFIG response built around it. Written by four command surfaces (CCID, the OTP keyboard slots, CTAPHID, the FIDO vendor config-write), so it sits below all of them rather than inside the management applet |
| `rsk-phy` | the `EF_PHY` codec: the PicoForge-compatible device-config TLV record — USB identity, LED wiring, the interface mask — plus its clamped load and its read-modify-write save. Read by the rescue and FIDO applets, `rsk-device`, `rsk-display` and the boot path, so it sits below all of them rather than inside one |
| `rsk-ui` | the trusted-display UI model (operation prompts, untrusted relying-party-string sanitizing, Allow/Deny button geometry); compiled only into the `display` build |
| `rsk-display` | the trusted display's *flow* — which screen is shown when, the PIN pad, the browse modals, the Approve/Deny wait — over a panel and a touch controller it takes as type parameters, so the firmware drives an ST7789 and the emulator a window; `display` build only |

Everything except `firmware` is hardware-agnostic and runs the full test
suite on the host ([testing.md](testing.md)).

## Flash layout

![RP2350-One flash map — a signed code region above two KV partitions (main store + counters) that survive a reflash](images/flash-map.svg)

Two KV partitions at fixed offsets (`firmware/memory.x`): the main store, and
a small separate partition for the per-operation counters so their churn
never forces compaction of long-lived records. Files are 16-bit ids. Each
applet owns disjoint ranges (FIDO `0x10xx/0xCxxx/0xCFxx/0xD0xx`, OpenPGP DO
mirrors, PIV `0xD1xx/0xD2xx`, OTP slots `0xBBxx`, phy/rescue `0xE0xx`) and a
reset wipes exactly its own predicate, never a range shared with another
applet.

Both regions sit behind one RP2350 **partition table** entry carried in the
shipped image: the USB bootloader is denied read and write over
`__kvmain_start..__kvcnt_end`, while secure code — the running firmware,
`rsk-wipe`, the rescue applet — keeps `rw`. The table is derived from those
linker symbols rather than restated, so it follows `FLASH_SIZE`/`KVMAIN` on its
own ([build.md](build.md#the-partition-table)). What it is and is not worth:
[threat-model.md](threat-model.md#flash-snapshot-rollback-the-pin-counter-reset).

Key sealing at rest: `kbase = HKDF(serial_hash, otp_master_key)` keys
AES-CBC for the FIDO seed (tagged formats: plain vs OTP-rooted generation)
and AES-GCM for PIV keys. OpenPGP keys sit under the PIN-wrapped DEK chain.
When the OTP master key gets provisioned later in a device's life, a boot
pass and lazy PIN-verify hooks migrate every sealed object to the new root
without losing data. Until that burn the root derives from on-chip state
alone, which an attacker with full flash and chip access could reconstruct.
[threat-model.md](threat-model.md) covers what at-rest sealing does and does
not buy before provisioning.

One sealed object worth spelling out is the FIDO credential box. It doubles as
the opaque credential ID a relying party stores, so its size caps the reported
`maxCredentialIdLength` (748):

![FIDO credential box — proto(4) iv(12) then a variable CBOR body, poly1305 tag(16) and silent tag(16); the four framing pieces are 48 bytes and the whole box is at most 748. Below it, the 42-byte resident id returned to the relying party](images/cred-box.svg)

The 42-byte resident id carries a **version byte** at offset 8, a reserved
header byte outside the `[10..42]` HMAC chain, so it never changes the id's
entropy. It is `1` (v2) for every resident credential created since RS-Key
`0x0806`: a v2 credential derives its signing key, hmac-secret and largeBlobKey
from this **stable** id, so an `updateUserInformation` reseal (which draws a
fresh box IV) no longer rotates them and the relying party's stored public key
keeps verifying. Resident credentials from older firmware carry an implicit `0`
(v1) and keep deriving from the box, so an already-provisioned device stays
compatible across the upgrade.

## Capacity — why the flash is mostly empty

The KV store is 1.5 MB by default whatever the `FLASH_SIZE`, so a larger flash only
grows the code region, most of which no firmware writes ([build.md](build.md)). That
is deliberate. (A 2 MB board is the one exception: it shrinks the main partition via
`KVMAIN` to leave room for code — still far more than a key ever fills.) A security key's maximum *logical* state is small and hard-capped:
`MAX_RESIDENT_CREDENTIALS` (256 passkeys), `MAX_DYNAMIC_FILES` (1280 files, one
budget shared by every applet), `MAX_OATH_CRED` (255), plus a handful of
OpenPGP/PIV slots. The passkeys dominate the bytes — a file-count ceiling is not
a size ceiling — so a fully provisioned device fills only a few hundred KB, well
under the 1408 KB main partition. Growing the store to "fill" a 16 MB board would buy nothing usable: it
lengthens the `sequential-storage` scan behind every cold boot and absent-key
probe (the present cache exists to dodge exactly that full-partition ~0.2 s cost),
and forces the logical caps (and the RAM/stack buffers sized to them) up for
capacity no one reaches. Empty flash here is headroom, not waste.

## Device identity

USB VID/PID, product strings and the reported firmware version are
compile-time knobs ([build.md](build.md)). The default is RS-Key's own
identity: VID:PID `0x1209:0x0001` (pid.codes), manufacturer "RS-Key",
product "RS-Key Security Key" (the `RSKey` preset). An opt-in `VIDPID=Yubikey5`
preset builds the Yubico interop flavor (`0x1050:0x0407`, reader name "Yubico
YubiKey") for the tools that auto-recognize the device purely by that reader
name. A flash-resident *phy* record can override VID/PID and the product
string at boot (the store mounts before the USB builder runs for exactly this
reason). FIDO tools find the device by HID usage page, CCID tools by the
reader name.

## User presence

One presence button (BOOTSEL by default, or `PRESENCE_PIN`), shared by all
applets through `rsk_sdk::UserPresence`, which the firmware implements once:
FIDO operations, OpenPGP UIF, PIV touch policies, OATH touch accounts, and OTP
slot typing (1–4 presses select the slot) all gate on it. The trait has two
asks, because a screen answers them differently: `request` for a smartcard
touch policy, one per signature, and `request_ceremony` for a ceremony a host
raised — a CTAP2 command, or the pinpad's "Allow host PIN entry?" gate — which
alone can be cancelled mid-wait (`CTAPHID_CANCEL`) and so alone can answer
`Presence::Cancelled`. The no-touch build (`--features no-touch`)
auto-confirms. For test rigs, not for daily use.

## Provenance

RS-Key reimplements the applet behaviour, file layouts and protocol surface
of [pico-keys](https://github.com/polhenarejos) (AGPL, see
[NOTICE](https://github.com/TheMaxMur/RS-Key/blob/main/NOTICE)) in Rust,
replacing the C HAL/runtime/transport stack with embassy and RustCrypto:

| was (C) | is (Rust) |
|---|---|
| pico-sdk runtime + TinyUSB | `embassy-rp` + `embassy-usb` |
| mbedTLS | RustCrypto (`p256/p384/p521/k256`, `ed25519-dalek`, …) + our own `rsk-rsa` |
| TinyCBOR | `minicbor` |
| bespoke wear-leveled flash writer | `sequential-storage` |
| core0/core1 + queues | one async executor pair; core1 = a keygen math engine only |

Where the two implementations deliberately differ (at-rest sealing, seed
PIN-wrapping, OTP provisioning policy, several upstream bugs not carried
over), the divergence is a documented design decision. See
[threat-model.md](threat-model.md) and the crate docs.
