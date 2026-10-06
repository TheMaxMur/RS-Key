<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# rsk-emu — the software emulator

The RS-Key applet stack with no hardware under it. It runs the same
`crates/rsk-*` code a real key runs — FIDO2/U2F, PIV, OpenPGP, OATH, management,
rescue — and speaks CTAPHID and APDUs over TCP instead of USB.

**It is not a security key.** No secure boot, no OTP root, no fuses, no tamper
resistance; the seed lives in a file you can read. It exists to run the protocol
suites without a board and to develop host tools against.

```bash
cargo run --manifest-path tools/emu/Cargo.toml --target "$HOST" -- --store ./my.store
```

```text
  --host <addr>       bind address (default 127.0.0.1)
  --fido-port <n>     CTAPHID port, 0 disables (default 7799)
  --ccid-port <n>     APDU/card port, 0 disables (default 7800)
  --store <path>      the flash image to mount (default: a blank chip, memory only)
  --touch             ask for every user presence on the terminal
  --auto-touch-ms <n> report presence pending, then approve after n milliseconds
  --display           open the trusted display in a window (SDL2); presence
                      becomes an on-screen hold, as on a screen board
  --usbip [addr]      serve USB/IP (default 127.0.0.1:3240) so a Linux host can
                      attach the emulator as a real USB device
  --trace             log every command and its status
  --seed <hex>        seed the DRBG deterministically (predictable keys)
  --serial <16 hex>   device serial
  --yubico            present the Yubico identity — USB VID/PID and descriptor
                      strings, the ATR, the OpenPGP AID vendor — as the
                      VIDPID=Yubikey5 build does. `ykman` needs it.
  --power-cut <n>     cut the flash's power after n bytes of writes
  --image <elf>       serve that firmware ELF on an emulated RP2350 instead of
                      the applet stack (below)
  --rom <file>        the bootrom --image boots (default: picoem's pinned A4)
  --inspect-port <n>  image laboratory socket on loopback (disabled by default)
```

`--auto-touch-ms` is mutually exclusive with `--touch` and `--display`. During
the delay the CTAPHID endpoint reports `UPNEEDED`; a `CANCEL` on the active
channel ends the operation before it is approved. This mode is intended for
deterministic conformance runs that need to observe keepalive and cancellation.

A timer answers the prompt, so this remains an **auto-confirming** authenticator,
not a confirm-showing one: the CTAP 2.1 §6.6 reset window still applies, exactly
as under the default instant presence. `--touch`, where a person answers, is the
mode that is exempt from it.

Build the emulator with the conformance-specific FIDO feature and run it with
delayed presence like this:

```bash
HOST="$(rustc -vV | sed -n 's/^host: //p')"
cargo build --manifest-path tools/emu/Cargo.toml --target "$HOST" \
  --features fido-conformance
tools/emu/target/"$HOST"/debug/rsk-emu \
  --store ./conformance.store --fido-port 7799 --ccid-port 7800 \
  --auto-touch-ms 250 --trace
```

The `fido-conformance` feature forwards to `rsk-fido/fido-conformance`, which
uses the authenticator profile intended for the upstream FIDO corpus.

## Running the on-device suites against it

```bash
python tests/emu.py tests/11_fido_makecredential.py
python tests/emu.py tests/34_openpgp_rsa.py
```

`tests/emu.py` installs a fake `hid` module pointed at the CTAPHID socket and a
fake `smartcard` package pointed at the card socket, and redirects the
power-cycle helper at the emulator — so the suites run unmodified, and neither
hidapi nor pyscard need be installed. `RSK_EMU` / `RSK_EMU_CCID` override the
addresses.

**42 of the 53 suites pass; the other 10 are refused by name, with the reason,
before they start** (exit 77 — so a sweep counts skips apart from failures). None
of them is an unexplained failure:

| Skipped here | Why |
|---|---|
| `02`, `73`, `77` | raw USB — this shim serves reports. They run against `--usbip` below, as ordinary hardware suites |
| `51` | reboots to BOOTSEL; there is no bootloader to fall into |
| `53` | the PC/SC `FEATURE_VERIFY_PIN_DIRECT` reader layer |
| `61`, `65` | driven through python-fido2's own HID transport — faking it would leave the suite testing this shim instead of a third-party client. Under `--usbip` there is nothing to fake, and they run |
| `29`, `54`, `90` | real power-cut, SRAM residue and OTP-fuse migration — hardware by definition |

The list lives in `tests/emu.py` (`UNSUPPORTED`); removing an entry is a claim
that the emulator grew the capability.

`14` is the 43rd: it asserts with a credential a person enrolled
(`ssh-keygen -t ed25519-sk`), so without that key it skips 77 too.

`30` needs the Yubico card identity: start the emulator `--yubico` and it runs,
otherwise the shim asks the card for its ATR and skips. `28` and `76` take `--pin` and want a PIN already set (`21_pin_webauthn` sets
`1234`); given both, they pass. Without the flag the shim refuses them by name
(`NEEDS_ARGS`) rather than letting them die in argparse, so a hand-run sweep reads
them as not invoked instead of as a device failure. `50` and `52` measure that a
touch took time, so they only mean
something with `--touch` and a human at the keyboard.

## As a real USB device (`--usbip`)

The sockets above are not something a browser, `ykman` or `gpg` can reach — they
look for USB. `--usbip` fixes that without any USB hardware: the Linux kernel's
`vhci_hcd` attaches a TCP peer as a virtual host controller, and USB/IP is
network-transparent, so the emulator can stay on a Mac while a Linux VM imports
it.

```bash
cargo run --manifest-path tools/emu/Cargo.toml --target "$HOST" -- --usbip 0.0.0.0:3240
# then, on a Linux box that can reach it:
sudo modprobe vhci-hcd
sudo usbip list -r <host>              # lists rsk-emu and its three interfaces
sudo usbip attach -r <host> -b rsk-emu
```

What attaches is the device's own USB stack, not a description of it: the same
`embassy_usb::Builder`, the same three interfaces in the same order, the same
`rsk_usb::ctaphid` and `rsk_usb::ccid` transports the firmware runs, over
`usbip_driver` instead of the RP2350's USB peripheral. So the interface order —
`02_usb_interfaces`, issue #55 — is checked against the descriptors a host really
reads, and `fido2-token`, a browser, `ykman` and `gpg` all work.

```bash
fido2-token -L                 # /dev/hidraw1: vendor=0x1209, product=0xf1d2
fido2-token -I /dev/hidraw1    # CTAP2.3 getInfo
opensc-tool -a                 # 3b:fc:…:52:53:2d:4b:65:79  — the RS-Key ATR
```

Five of the nine suites this shim refuses run here instead, with nothing faked:
`02_usb_interfaces`, `61`/`65` (python-fido2's own HID transport, ML-DSA verified
by OpenSSL), `73_otp_keyboard` and `77_otp_touch_wait`. A USB/IP attach is this
build's power-up — RAM state goes, the card resets, the CTAP 2.1 §6.6 window
reopens — so `tests/replug.py`'s physical unplug becomes `usbip detach` +
`usbip attach`.

The keyboard interface carries the OTP frame protocol — the transport
`ykman otp` speaks — so `02_usb_interfaces`, `73_otp_keyboard` and
`77_otp_touch_wait` all run here. What it does *not* do is type: a ticket is
emitted by a button gesture and this build has no button, so the keyboard's IN
endpoint stays silent.

`ykman` finds a device by the Yubico VID, so those suites need `--yubico`, which
now presents the whole Yubico identity — VID/PID and descriptor strings as well as
the ATR and the OpenPGP AID vendor. `77` also needs `--touch` and a slot
programmed with one, or there is no wait for it to watch the device let go of:

```bash
rsk-emu --store ./emu.store --yubico --touch --usbip 0.0.0.0:3240
ykman otp chalresp --touch --force 1 <20-byte-hex>
python tests/77_otp_touch_wait.py --slot 1
```

PC/SC finds no reader on the default identity until the ccid driver's whitelist
carries it (`overlays.ccid-rs-key`, `docs/linux.md`) — the same thing that happens
with a real key, for the same reason.

Needs Linux and root for `vhci_hcd`; the emulator itself can stay on a Mac,
because USB/IP is network-transparent.

All of that in one command — including the two identities, since `73`, `77` and
p11test want the Yubico one and the rest must not have it — is
`scripts/usbip-suites.sh`, which is also what CI runs. It boots a guest that owns
a `vhci_hcd` (`nix build .#usbip-vm`) because a GitHub-hosted runner cannot be
one, and keeps the emulators outside it on the VM host. All seven run: `02`,
`61`, `65`, `73`, `77`, the pico-fido conformance suite and OpenSC's p11test.

`77` needs the emulator's stdin held **open** — the runner uses a fifo it never
writes to. On EOF the emulator correctly stops pretending anyone could answer and
times the touch out at once, which makes a `--touch` device behave like a
no-touch one and leaves the suite nothing to watch; a fifo gives it the real
thing, a wait nobody ever ends.

## The firmware image itself (`--image`)

`--image <elf>` serves the firmware's own ELF on the same two ports, in place of
the applet crates. It cold-boots through the real bootrom on
[picoem](https://github.com/TheMaxMur/picoem)'s RP2350 — two Cortex-M33 cores with
TrustZone, and the bus — and `src/image/` models what the bootrom and the image
lean on past it: the USB controller, OTP, the QMI with its SPI NOR flash, the
SHA-256 block, the TRNG, BOOTRAM, the PSM and the BOOTSEL pad. A host controller
on the emulated clock enumerates the image as Linux does and carries each
socket's reports and CCID messages over its endpoints, so `tests/emu.py` and the
suites run unchanged.

```bash
nix develop -c cargo build --release -p firmware --features no-touch
nix develop -c cargo run --release --manifest-path tools/emu/Cargo.toml --target "$HOST" -- \
  --image target/thumbv8m.main-none-eabihf/release/firmware --store ./image.store
python tests/emu.py tests/10_fido_getinfo.py
```

- **Time** is held to the wall clock and never runs ahead of it, so the image's
  own timeouts — the §6.6 reset window, keepalives, CCID time extensions — mean
  what they mean on a desk. One busy core runs at about the board's speed; two run
  slower (an on-card RSA-2048 keygen took 13.6 s, the board ~4.3 s). Empty PIO
  `PULL` stalls advance in batches while preserving divider phase and counters;
  active machines and other stalls keep the per-cycle path. On macOS arm64,
  three 10-second idle samples on the same no-touch ELF reduced median host
  CPU use from 68.7% to 22.4% of one core (2026-10-02). GetInfo after idle
  still completed in 15–17 ms. This measures idle CPU cost, not command speed.
- **The store** is the whole flash, image and KV store together, with the OTP
  rows beside it in `<store>.otp`. A new one starts blank but for the chip id,
  which is `--serial`. Placing the image rewrites only the sectors it covers, so
  the KV store stays when a rebuilt image goes in, as a reflashed board's does.
  The ELF's `__kvcnt_end` selects a 2, 4, 8 or 16 MiB part; the 16 MiB layout's
  reserved E10 sector is included in the chip. ELFs without that symbol retain
  the 4 MiB default. A file with another length is refused rather than resized.
- **Power**: a replug (`03`) is a power-on reset through the bootrom; a reboot the
  image asks for keeps the watchdog scratch, as a warm reset does — so the soft
  PIN lock and the reset window behave as on the board.
  Every cold or warm boot advances the model's entropy stream, so repeated
  resets cannot regenerate the deleted credential seed. `--seed` reproduces
  the whole boot sequence rather than repeating one stream at every reboot.
  Delayed ROM reboots count the normal 1 MHz watchdog ticks independently of
  the CPU step quantum. Custom TICKS divisors and active debugger pauses are
  outside this model.
- **Faults**: a HardFault or a PC inside either core's ELF panic handler marks
  the image dead until a power cycle. A sampled PC past the handler's entry
  still counts as a panic. The log names the instruction before its return
  address, which may otherwise point into the next function.
- **Presence and identity are the image's.** A `--features no-touch` build
  confirms presence; a touch build waits for BOOTSEL, which each line on the
  terminal holds down for half a second under `--touch`, and a keepalive asking
  for the touch says so there. The Yubico identity is a `VIDPID=Yubikey5` build. `--display`, the pad, `--auto-touch-ms`, `--security-trace`, `--yubico`
  and `--power-cut` are refused by name.
- **`--usbip`** offers the image's current descriptors. Attach and detach
  power-cycle a running image; in BOOTSEL they warm-boot back into the ROM
  loader. A socket replug always cold-boots. Successful control and data
  transfers complete after their final packet and ACK have crossed the bus.
- `--trace` prints what the chip models log and, every five seconds, where each
  core is. `--rom` boots another bootrom (the A2's, say); the default is the A4
  one picoem pins, read from its checkout.

Against the tests/emu.py sweep of `scripts/emu-suites.sh` — the default,
reset-window, PIN and Yubico-identity sessions — the image passes the same 54
suites the applet backend passes and refuses the same 11. It is still not
silicon: each model goes as deep as the bootrom and the image reach, and the
panel and the LED's light are not modelled. Power cuts use the explicit fault
model below; they do not model analog NOR-cell failure.

### Image laboratory

`--inspect-port <n>` opens a separate TCP listener on `127.0.0.1`. One line per
connection receives `ok ...` or `error ...`; this is emulator control, outside
the device's USB interface. It can inspect and modify emulated SRAM. Leave it
disabled for an ordinary protocol run.

| Request | Result |
|---|---|
| `status` | Current cycle, readiness, fault state, power-up count and last injected cut |
| `begin`, then `end` | Paint unused stacks, step by one cycle and record each core's lowest SP until `end` |
| `scan HEX` | Count and SRAM addresses of an exact 1–256-byte pattern; no secret bytes printed |
| `plant ADDRESS HEX` | Write a synthetic positive-control pattern at a hexadecimal SRAM address |
| `cut-cycles N` | Cut N cycles after the next socket HID report or CCID request is accepted |
| `cut-program N` | Cut after N accepted page-program bytes, counted across programs |
| `cut-program-cycles N` | Cut N cycles after the next page program starts |

Fault arms replace one another and clear on reboot. An injected cut immediately
disconnects in-flight transfers, saves flash and cold-boots. With `--store`, a
`<store>.cut` snapshot keeps the torn array *before* recovery can repair it.
During a busy program or erase, a cycle cut retains a prefix proportional to
elapsed operation time; a byte cut retains exactly that many program bytes.
Program order wraps within a 256-byte page. This deterministic fault model
exercises recovery from incomplete writes, not every physically possible cell
pattern. It changes no flash timing when unarmed.

Stack bounds come from the ELF, checked against the core's live `MSPLIM`.
`coreN_used` is the ELF stack symbol's top minus the lowest sampled SP; core1's
symbol includes `StaticCell` padding, so its value is a conservative bound.
`coreN_painted` means bytes covered by writes. It is **not stack usage**: the
firmware clears the entire dead stack after a command, which consumes all the
paint. Sampling SP also catches a reserved frame that never writes its bottom.
Single-cycle sampling slows the emulator and is enabled only between `begin`
and `end`, or while a fault is armed.

The standalone runner owns fresh processes, socket ports and flash files:

```sh
nix develop -c python tools/emu/image_assurance.py \
  --emulator tools/emu/target/"$HOST"/release/rsk-emu \
  --image current-notouch-pt.elf --release-image v0.4.11-notouch-pt.elf \
  --work /tmp/rsk-image-assurance
```

Build both ELF fixtures with `--features no-touch`, and run `scripts/pt.sh` on
each. The runner compares native/image OATH and OpenPGP responses, measures
ML-DSA-87 command stacks and verifies its signatures with dilithium-py,
checks known OATH key/HMAC-pad residues with a planted
leak through the same assertion, upgrades a release's OATH, FIDO signing key
and OpenPGP PIN on the same flash, and reboots from cycle/byte-cut snapshots in
new processes. `--only` selects a scenario. Logs, image hashes and measured
results stay in the new `--work` directory; no board is enumerated.

`--only operations` runs a second matrix against both backends. Every image
command records both cores' minimum SP and checks their ELF/MSPLIM bounds:

| Applet | Operations and independent oracle | SRAM patterns after the response |
|---|---|---|
| FIDO | Protocol-2 key agreement, set/get/change PIN, registration and assertion for ES256/384/512, ES256K, Ed25519 and ML-DSA-44/65/87; attestation and assertion signature verification; old-token refusal, reset and deleted-credential refusal | ECDH-derived HMAC/AES keys; old PIN token after changePIN |
| PIV | AES-192 management mutual authentication, EC/RSA-2048 import and signing, RSA-2048/3072/4096 generation and signing, P-256 ECDH, PIN verification/deauthentication and refused signing | Imported scalar and RSA factors; factors of the generated public modulus |
| OpenPGP | EC/Ed25519/RSA-2048 import, signing, internal authentication, ECDH/RSA decipher, RSA-2048/3072/4096 generation and signing, and refused authentication after deselection | Imported scalar, Ed25519 seed and RSA factors; factors of the generated public modulus |
| OTP | Slot programming, HMAC-SHA1 and AES challenge-response, deletion and empty-slot response | HMAC key/pads and AES key |

The live FIDO token must first be found in SRAM; changePIN must remove its
known bytes. A spent token retains its bytes by design, so a signature does
not require their absence. Every applet also plants a leak in SRAM9, runs
the same residue assertion, requires that exact address to fail and clears it.
Scalar/factor probes search 16-byte prefixes and suffixes in both byte orders.
These check selected known secrets and command paths, not arbitrary encodings
of every secret; cached device/session keys have their own lifetimes. Logs and
reports contain counts and addresses, not secret patterns.

RSA generation also requires core1's ELF counters to show a taken job and
candidate searches. Stack sampling continues through its background wind-down,
bounded by 30 seconds of emulated time and a separate host progress timeout.
Inspection `status` reports `emulated_ns` alongside the instruction-cycle count.
After it goes idle, the runner reads all 520 KiB of SRAM over the opt-in inspection
socket (`read ADDRESS LENGTH`) and checks every 128-, 192- or 256-byte window,
in both byte orders, for a nontrivial divisor of the returned 2048-, 3072- or
4096-bit modulus. A planted RSA factor at each size must fail that same assertion.
SRAM dumps and private factors are not saved. All three sizes run in PIV and
OpenPGP, with independent signature verification after each generation.

`nix develop -c ./scripts/image-suites.sh <new-output-directory>` builds the
current no-touch firmware and its partition table, builds the emulator with
assertions enabled, then runs `basic`, `stack`, `operations` and `cuts`.
Omitting the directory retains a fresh report directory under `target/`.
The `image` job in `.github/workflows/emulator.yml` runs this command on pull
requests and nightly. It retains reports and logs; emulated flash and OTP files
are not uploaded. Historical-release upgrade and scratch-ELF regression probes
remain explicit local runs with the fixtures above.

### PICOBOOT through USB/IP

`image_picoboot.py` runs real `picotool` against the image's A4 ROM loader.
Run it in an isolated x86_64 Linux VM as root, with `vhci_hcd` and a matching
`usbip` utility installed. The dev shell supplies `picotool` and Python; it
does not install the kernel utilities. Build a no-touch, partitioned fixture:

```sh
nix develop -c ./scripts/image-suites.sh target/picoboot-fixture
nix develop
sudo modprobe vhci-hcd
sudo env PATH="$PATH" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
  python tools/emu/image_picoboot.py \
    --emulator tools/emu/target/x86_64-unknown-linux-gnu/release/rsk-emu \
    --image target/picoboot-fixture/firmware-pt.elf \
    --work target/picoboot-run
```

Both output directories must be new. `--usbip` and `--picotool` accept explicit
utility paths. The runner owns a loopback emulator, a fresh flash/OTP pair and
one virtual USB/IP port. It checks the sysfs `vhci_hcd` parent before choosing
the bus/address for every `picotool` command. It requires all virtual ports to
be unused and unbinds `usb-storage` only from its own ROM interface, keeping
kernel SCSI probes out of the PICOBOOT session.

The run covers info, SRAM and spare-flash load/save/verify, a full ELF reload,
an unchanged-image update, reboot into the firmware and another cold boot.
An OATH credential must survive, and USB/IP must advertise the original
firmware descriptors again. A write into KV must fail with the ROM permission
error and leave its bytes unchanged. Raw and ECC OTP writes, refused bit
clearing and persistence across reboot are checked through `picotool` too.
Logs, image/emulator hashes and `report.json` remain in `--work`; the owned
virtual port is detached on exit. These are virtual OTP writes, not fuse writes
on a connected key. The emulator workflow's `usb` job runs this scenario and
MSC inside its throwaway NixOS guest, after detaching the native test devices.
The host builds the emulator and a partitioned no-touch ELF; the guest owns
the image processes, loopback USB/IP endpoints and virtual block devices.
The host stages picoem's pinned A4 ROM after checking its SHA256; both reports
record that ROM hash.
`nix develop -c ./scripts/usbip-suites.sh <new-output-directory>` runs the
same job locally on Linux. Omitting the directory retains evidence under
`target/`. CI uploads reports and logs, including failures, without flash,
OTP or executable fixtures. This remains separate from the default `image` job.

`image_msc.py` uses the same Linux setup and arguments with a new `--work`
directory. It leaves the owned ROM's `usb-storage` driver active, checks the
FAT16 MBR, directory, `INDEX.HTM` and `INFO_UF2.TXT`, and repeats `picotool info` 20 times
while MSC remains usable. A bad-magic UF2 sector must leave flash untouched.
The runner then writes the complete UF2 through the owned kernel block device,
checks every payload and unchanged bytes outside the image, and verifies reboot,
refreshed descriptors and OATH persistence through a cold boot. Block I/O is
guarded by the virtual sysfs parent and the block device's major/minor identity.
This exercises kernel SCSI reads/writes without mounting the FAT filesystem.
It uses fresh emulated flash/OTP and detaches its virtual port on exit.

The image host controller serializes transactions across all endpoint pipes,
including their packet/ACK time. A NAKing pipe yields to other ready pipes;
the transport regression covers concurrent MSC/PICOBOOT-style bulk endpoints.
Double-buffer completion status preserves both events and exposes the next
buffer after the CPU clears the first, as RP2350 datasheet §12.7.3.8 specifies.
The MSC runner invalidates its owned disk's cache before repeated file reads.
The picoem pin also makes Non-secure RCP reads return zero and ignores writes
to Secure RCP state (RP2350 datasheet §3.6.3.2), allowing BootROM's interrupted
Non-secure memory routines to coexist with Secure buffer validation.

For falsification, `--incompatible-image` takes a scratch current ELF with
`EF_OATH_CRED` moved from `0xBA00` to `0xB900`: upgrade must lose the credential
with `6984`, while boot and SELECT succeed. `--stack-regression` takes a distinct
scratch ELF with larger ML-DSA stack frames and must exceed the baseline by
more than 1 KiB of interrupt variation. Removing the `#[inline(never)]` attributes
from the six ML-DSA helpers in `rsk-fido/src/ec.rs` is the historical regression
probe; its result must be measured on the current compiler. These are separate
fixtures, never changes to the tested production checkout.

The historical probe was run on 2026-10-01 against `d7e19ad0`, Rust 1.96.0,
`no-touch`, using independently built ELF files. ML-DSA-87's maximum sampled
core0 use was 94,396 bytes with the helpers and 94,400 without their six
`#[inline(never)]` attributes: the old failure no longer reproduced. A separate
positive control kept a 65,536-byte local array live across `mldsa87_sign`, with
`core::hint::black_box(&mut stack_probe)` before the operation and after
`rnd.wipe()`. It raised the measured maximum to 159,640 bytes and exceeded the
same baseline envelope. This calibrates frame-growth detection; it does not
claim the historical wedge still exists.

## The wire

**CTAPHID** — the stream carries 64-byte HID reports, both directions, exactly
as the USB interface would. A client is a `send(64)` / `recv(64)` shim away.

**Card** — one CCID message at a time:

```text
request   op:u8 | len:u32 BE | payload
response         len:u32 BE | payload
```

`op` is `00` for a CCID message and `03` for a replug (a power cycle: RAM state
is dropped, the CTAP 2.1 §6.6 reset window reopens, and every plain Yubico-OTP
slot's use counter advances — CCID has no message for that, because a power cycle
is not a card reset, and a warm reboot is neither). The payload of a `00` is a
whole `PC_to_RDR` message, header and all, and the answer is a whole `RDR_to_PC`:
the same bytes a PC/SC driver puts on the bulk endpoints, so `rsk_usb::ccid` runs
here rather than being bypassed. One request may draw several responses, as a
bulk-IN stream does — a slow `XfrBlock` gets `bStatus = 0x80` time extensions
before its DataBlock, and a client is expected to step over them.

## What it does not emulate

The device identity is deliberately its own (serial `RSKEMU\x00\x01`), so
anything derived from it — the OpenPGP AID, the seal context, the management
serial — is recognisable as emulator-made.

- **Hardware**: secure boot, OTP fuses, the anti-rollback epoch, the partition
  table, glitch detectors, side channels, the TRNG.
- **Flash semantics**: these are real now. The store is the device's
  (`crates/rsk-store`) over `sequential-storage`'s mock NOR flash with the
  device's geometry — 4 KiB sectors, 1408 KiB main + 128 KiB counter — so writes
  clear bits and never set them, a page is erased before it is rewritten, and the
  ring migrates and reclaims where the board's does. `--power-cut <n>` arms the
  mock's own injector. What is still standing in for hardware is the medium
  itself: no wear, no partial-erase physics, and the write-once *tracking* resets
  across a restart (the bits do not — they are in the image).
- **The trusted display**: `--display` runs it for real. The window is the panel:
  the pixels come from the same `rsk_ui::render` the ST7789 gets, the flow is the
  same `crates/rsk-display`, and the mouse enters it through the same `TouchPad`
  a finger does — held, not clicked, because a panel reports contact continuously
  and the 800 ms hold-to-approve is built on that. The ambient loop runs too, so
  the window behaves like a device sitting on the desk: it comes up on its own
  screen, the tabs and menus answer taps, and a host ceremony paints over them —
  the panel's loop and the host's share one executor exactly as they do on the
  board. The backlight is applied by scaling the pixels on their way to the
  window, and the **space bar is the wake button**. An open menu hands the parked
  worker its executor back when a host command lands, as a board's does — after
  `UI_YIELD_FLOOR_MS`, which is what stops a browser looping `getInfo` from
  shutting the operator's screen.
- **The vendor AID's hardware arms**: the applet itself runs (`crates/rsk-vendor`
  — the counter, the U2F/SELECT routing, the warm reboot), but SET/GET LED, the
  second core's statistics, the measurement benches and the drop to BOOTSEL all
  answer `INS_NOT_SUPPORTED`, because there is nothing behind them here.
- **USB**: enumeration, interface order, the OTP keyboard interface, and the LED.
  The CCID *block* layer does run — the socket carries whole CCID messages — but
  its packetisation does not: a socket delivers a message whole, where the device
  accumulates it off 64-byte bulk-OUT transfers with a receive timeout.
- **The firmware's outer loop**: the applet wiring *is* shared now
  (`crates/rsk-device`), so a routing or gating bug shows up here. What is still
  written twice is the worker's sequencing — refresh the capability set when the
  dirty latch is up, run a queued reboot once the response is out or on an idle
  pass, never ahead of a request already waiting — and
  `firmware/src/{main,worker,presence,led}.rs`, which are the board's.

A green run against the emulator is a protocol result, not a device result.
