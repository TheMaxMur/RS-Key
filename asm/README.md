<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# asm/ — the parallel assembly rewrite track

Hand-written RP2350 assembly for the RS-Key authenticator, built and verified
**outside** the firmware tree. It is a parallel track: `asm/` must never touch
`firmware/`. The shipping Rust+embassy firmware remains the product; this
directory is a ground-up rewrite of selected pieces — boot image, CTAPHID
reassembly kernel, USB device driver — to prove the register facts and framing
contract independently of the Rust implementation.

Everything is host-verified: the stateful logic is differentially tested against
the shipping Rust code, and the `firmware/` tree is not modified by anything in
here. No file here is linked into a firmware binary.

## Layout

| File | What |
|---|---|
| `boot.S` | M2 boot image: vector table, reset handler (.data/.bss copy), pad/FUNCSEL + GPIO blink. Publishes a `__image_def` block byte-identical to the shipping `image_def` at `0x10000114` — the pre-`pt.sh`, unpartitioned form. |
| `link.ld` | M3 memory map, region-for-region with the shipping `firmware/memory.x` default 4 MB layout: code 2560K, `KVMAIN` 1408K, `KVCNT` 128K, RAM 512K — plus the `__kvmain_start`/`__kvcnt_end` fence symbols (the exact spellings `scripts/pt.sh` reads) and ASSERTs that the map is one contiguous 4 MB with the image's own footprint out of the store. |
| `build.sh` | asm → ELF → `.bin`, then the store fence: the SAME `scripts/pt.sh` the shipping image runs over the SAME symbols, producing the flashable `boot-pt.elf`/`.uf2`. Verifies the emitted table against the symbols (the gate's `partition_table_fences_the_store` row, run against the asm image) and diffs the parsed table against the shipping firmware's — same script, same JSON, same bounds, so they must agree line for line. Deterministic; dumps `target/asm/ref.disasm` for the audit trail. Requires the `nix develop` devshell (`arm-none-eabi-gcc`, `picotool`). |
| `ctaphid.S` | CTAPHID reassembly kernel (CTAP 2.1 §11.2.9). Pure: no hardware, no allocator; parses host-controlled framing and emits events (busy/done/error/ignored). The differentially tested core. |
| `ctaphid_tx.S` | CTAPHID transmission framing kernel — the mirror of `ctaphid.S`: splits one outgoing message into 64-byte reports (an INIT then CONTs, always at least the INIT). The `cmd` byte is stored verbatim, matching the shipping `TxFrames` contract. |
| `ctaphid_init.S` | CTAPHID INIT allocation kernel (CTAP 2.1 §11.2.9.4): a persistent `next_cid` counter plus the 17-byte reply composition (nonce‖newcid LE‖iface‖version‖capabilities). The allocator wrap rule is spec-pinned (cited from the shipping tests); the values are differentially cross-checked against `CidAllocator` + `init_capabilities` + `rsk_sdk::FIRMWARE_VERSION`. |
| `ctaphid_ctrl.S` | CTAPHID transport-control predicates: the keepalive 2×2, cancel-frame detection (with the `n ∈ [5,63]` threshold the shipping tests leave unpinned), and the per-channel lock (u64 strict-expiry arithmetic, owner-only release, broadcast-INIT carve-out) with the caller supplying `now_ms` — clock-free, like the firmware feeds it. |
| `ctaphid_dispatch.S` | CTAPHID dispatcher verdicts (CTAP 2.1 §11.2.9): the pure leaves the transport consults per reassembled command — LOCK's length/`LOCK_MAX_SECONDS` clamp, WINK's capability gate, the empty-CBOR refusal, the unknown-command verdict. No framing of its own; the caller frames the error reply through `ctaphid_tx.S` and arms the lock through `ctaphid_ctrl.S`. |
| `ctaphid_wait.S` | CTAPHID worker-wait state machine (CTAP 2.1 §11.2.9): what the transport does while the compute worker runs a reassembled MSG/CBOR. The keepalive cadence (a `KEEPALIVE_MS` deadline chain, clock supplied by the caller like the lock's `now_ms`) and the mid-flight frame disposition — queued off the touch wait, dropped or cancel-signalled on it. The cancel check reuses the M8 `ctaphid_is_cancel` twin. |
| `ccid.S` | CCID message core (USB CCID 1.1): the smart-card transport's pure halves — `xfr_apdu`/`secure_apdu` payload ranging, the 10-byte response header, and `process_message`'s slot-state machine (power on/off with ATR presentation and cap clamp, slot status echo, the T=1 params block, the data-rate reply). XfrBlock/Secure earn no reply here either — they belong to the async worker in the shipping `Ccid::run`, exactly as MSG/CBOR do on the FIDO side. |
| `difftest.S` | Linux user-mode entry for the differential harness: raw EABI syscalls, no libc. |
| `difftest.c` | Differential harness driver: one 64-byte report per stdin line → `ctaphid_feed`, prints the event stream in the oracle's exact format; `T <cid> <cmd> <payload-hex>` lines drive `ctaphid_tx.S`, `I <can_wink> <nonce-hex>` lines drive `ctaphid_init.S`, `K`/`C`/`L` lines drive `ctaphid_ctrl.S`, `Q <can_wink> <cmd> <cid> <body-hex>` lines drive `ctaphid_dispatch.S` over the live lock state, `W start/up/tick/frame/done` lines drive `ctaphid_wait.S` over the live cadence, and `A`/`N`/`H`/`X`/`E`/`M` lines drive `ccid.S` (ATR select, slot-status seed, header composition, payload ranging, whole messages against a caller-sized out slice) — the frame/predicate outputs share one stream. Streams input line-by-line so no input size is truncated. |
| `difftest.sh` | Builds the ARM side + Rust oracle, then requires byte-identical event streams over the spec vectors and seeded random frames. |
| `gen_vectors.py` | Spec/reassembly vectors (CTAP 2.1 §11.2.9): single/multi-packet, gaps, cross-channel, broadcast, cap-overflow, maximum 7609-byte message; plus TX framing cases with boundary lengths. |
| `gen_random.py` | Seeded random frames for the fuzz differential: `noise` (uniform garbage around the framing), `mixed` (valid transactions with noise interleaved on live state), `tx` (random response-framing and INIT-allocation lines), `ctrl` (random keepalive/cancel/lock lines, including expiry-crossing `now_ms` sequences), `dispatch` (random command/cid/body verdict lines over a live lock, so the channel-busy guard and its carve-outs fuzz), `wait` (random cadence/touch-flag/frame sequences, so the deadline chain and the queue/drop/cancel disposition fuzz together) and `ccid` (random ATR/status drift, header composition, XfrBlock/Secure ranging with dwLength at and past the bytes present, and whole messages against caps around every reply size). |
| `oracle/` | Rust differential oracle over rsk-usb's `Reassembler`, `TxFrames` and `ccid` — the **shipping** implementations. A detached cargo workspace (the `tools/emu` pattern); links `rsk-usb` from `../../crates/rsk-usb` for host execution only. |
| `usb.S` | USB device-side driver for the RP2350 USBCTRL block: chapter-9 EP0 control transfers (device/config/string/report descriptors) plus the EP1 interrupt endpoints that carry CTAPHID. Plain MMIO, one event per `usb_task`; register facts cite pico-sdk 2.2.0 headers. |
| `usbtest.c` | Model-level USB harness: maps the USBCTRL register file + DPSRAM as plain memory under qemu-user and runs the driver against a datasheet-derived SIE model. Includes end-to-end exchanges: a CTAPHID echo through both EP1 endpoints, the INIT transaction (broadcast demand → allocation → reply field-checked: nonce echo, assigned cid, iface, versions, capabilities), and the full transport stack — dispatcher verdicts (LOCK arm/reply, WINK and empty-CBOR refusals, CHANNEL_BUSY on a locked channel) and the worker-wait cadence (PROCESSING/UPNEEDED keepalives out EP1, the touch-window CANCEL dispositions, the cancelled CBOR response) all framed through the TX kernel into EP1 IN. |
| `usbtest.sh` | Builds `usb.S` + the SIE-model harness into a static ARM ELF and runs it under `qemu-arm`. |

## Running it

Everything builds inside `nix develop` — `arm-none-eabi-gcc` and `picotool`
live only in the devshell. `qemu-arm` does **not**; the devshell does not ship
it (flakes are maintainer-only). Point `QEMU=` at any `qemu-arm`, e.g. the
store path.

### Boot image

```
nix develop -c ./asm/build.sh
```

Outputs `target/asm/boot.{bin,elf}` (the bare pre-`pt.sh` form) plus
`boot-pt.{elf,uf2}` (the flashable, fenced image), `boot.disasm`/`ref.disasm`.
The build is deterministic: two runs produce byte-identical artifacts (buried
timestamps and build paths are none). The boot image's `__image_def` block
matches the shipping `image_def` byte-for-byte; `ref.disasm` backs the pad/SIO
register facts the source cites. The fence step verifies the emitted table
against the ELF's own symbols and — when the shipping firmware ELF is present
— diffs it against the shipping partition table, which it must match exactly:
same script, same JSON, same 0x280000..0x400000 bounds, NSBOOT denied over the
store.

### CTAPHID differential

```
QEMU=/nix/store/m4qamr94ba84viib1l2wskzwr90hbmmn-qemu-10.2.4/bin/qemu-arm \
nix develop -c ./asm/difftest.sh [frames_per_seed]
```

Default 700 frames/seed × 5 seeds × {noise, mixed, tx, ctrl, dispatch, wait,
ccid}; spec vectors always run
first. The oracle builds with an explicit host target triple (`HOST_TARGET`,
defaulting to the current `rustc` host). Green means the ARM kernels and the
shipping `rsk-usb` implementations emit **byte-identical** streams — a
divergence is an asm bug or a spec reading to adjudicate, never noise. The
RX and TX kernels also round-trip: frames emitted by `ctaphid_tx.S` fed back
into `ctaphid.S` reassemble to the original payload (verified at the
7609-byte maximum: 1 INIT + 128 CONTs).

### USB model tests

```
QEMU=... nix develop -c ./asm/usbtest.sh
```

204 checks: chapter-9 EP0 enumeration (device/config/HID-report/string
descriptors, wLength clamp, SET_ADDRESS latch + §9.6.2 overflow stall,
GET_STATUS/interface, unknown-request stall, bus-reset address/pid clearing),
the EP1 CTAPHID data path (single/multi-packet, out-of-sequence abort,
short-packet tail zeroing, IN data-toggle tracking), an end-to-end echo
through both EP1 endpoints (request in → reassembly → TX framing → DPRAM
byte-compare, multi-frame with seq + toggle tracking, interleaved channels),
the INIT transaction end to end (broadcast demand, nonce echo, sequential
cid allocation, reply fields independently asserted), and the full transport
stack end to end (LOCK arms and answers empty, a second host earns
CHANNEL_BUSY, WINK and empty-CBOR refusals framed as CTAPHID_ERROR, the
worker-wait cadence streaming PROCESSING then UPNEEDED keepalives, the
touch-window CANCEL dispositions, the cancelled CBOR response, and the
IN data-toggle accounting across the whole section).
Fails if a wrong-register poll would hang the driver (guarded by `timeout 60`).

## Verification status

- **Store fence — differentially identical to the shipping table.** `build.sh`
  runs the shipping `scripts/pt.sh` over the asm image's own
  `__kvmain_start`/`__kvcnt_end` symbols and diffs the parsed table against
  the shipping firmware's: identical, because the layout is region-for-region
  the same and the script and JSON are literally the same files. Mutation-
  verified through the build row: decoupling `__kvmain_start` from its region
  links clean and passes the symbol self-check but is caught by the shipping
  diff; breaking the map's contiguity is caught by the linker's own ASSERTs.
- **CTAPHID kernels — differentially tested.** All seven kernels byte-identical
  to the shipping Rust implementations over the spec vectors and over four
  million seeded random frames cumulatively (deepest single runs: 750 k and
  1 M frames; the transport-control expiry boundary, the dispatcher's LOCK
  clamp / empty-CBOR refusal / WINK gate, and the worker-wait's cadence
  boundary and queue/drop/cancel disposition are mutation-verified — flipping
  each guard's branch is caught by the differential). The oracle links the
  shipping `rsk-usb` `Reassembler`, `TxFrames`, `CidAllocator`,
  `init_capabilities`, `keepalive_status`, `is_cancel_frame`, `ChannelLock`
  and `rsk_sdk::FIRMWARE_VERSION`; the two output streams must `cmp` clean.
  The dispatcher and worker-wait rows are pinned against Rust mirrors of the
  shipping decision tables (both layers are private in `rsk-usb`): each mirror
  imports the pub command/error consts and calls the pub predicates live,
  which is what caught a spec-memory transcription slip — this firmware's MSG
  is `0x83` (`TYPE_INIT|0x03`, ctaphid.rs:32), not the FIDO spec's `0x87`,
  and the spec byte is refused as unknown. Four pieces are spec-pinned or
  body-sourced rather than differential (each cited in-source): the INIT
  allocator's wrap rule (the oracle's counter cannot be seeded near the wrap
  boundary), the dispatcher's `len != 1` / `secs > 10` LOCK error rows (the
  shipping tests leave them unpinned), and the worker-wait's
  read-only-while-up_pending frame gating (the shipping
  `run_with_keepalive` loop, ctaphid.rs:737-813).
- **CCID message core — differentially tested.** `ccid.S` byte-identical to
  the shipping `rsk-usb` `ccid.rs` over the spec vectors and the `ccid` fuzz
  mode; unlike the dispatcher and worker-wait rows this is a full
  differential — `process_message`, `xfr_apdu`, `secure_apdu` and
  `put_header` are all `pub`, so the oracle links and calls the live
  functions, no mirror at all. The one owned datum, the private `T1_PARAMS`
  block, is pinned by the differential. Mutation-verified through the
  differential row: the power-on ATR clamp and the persistent
  `*status = ACTIVE` write, the range clamp, the sub-header message guard,
  and a T=1 params byte. The Rust `process_message` slices `out[10..17]`/
  `out[10..18]` unguarded on the params/rate replies — an out slice below
  those floors panics the oracle rather than diverging, so the generators
  keep sub-floor caps to the messages whose replies fit them (noted in
  both generators).
- **USB driver — verified against a MODEL.** The SIE model is derived from the
  datasheet, with write-to-clear behaviour and explicit host-driven EP1 OUT
  delivery. Green here means datasheet-model agreement only — real-silicon
  enumeration is **untested** and is the next gate.
- **Boot image — byte-identical `image_def`.** Matches the shipping block at
  `0x10000114` (picotool parses it as `image def / RP2350 / ARM Secure`). The
  `ref.disasm` audit trail is produced by `build.sh`.

## Not here yet

- **Hardware bring-up.** The USB driver is model-tested; nothing here has run
  against real silicon.