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
  --display           open the trusted display in a window (SDL2); presence
                      becomes an on-screen hold, as on a screen board
  --usbip [addr]      serve USB/IP (default 127.0.0.1:3240) so a Linux host can
                      attach the emulator as a real USB device
  --trace             log every command and its status
  --seed <hex>        seed the DRBG deterministically (predictable keys)
  --serial <16 hex>   device serial
  --yubico            present the Yubico card identity (ATR + OpenPGP AID
                      manufacturer), as a build carrying the Yubico VID does
  --power-cut <n>     cut the flash's power after n bytes of writes
```

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

**43 of the 52 suites pass; the other 9 are refused by name, with the reason,
before they start** (exit 77 — so a sweep counts skips apart from failures). None
of them is an unexplained failure:

| Skipped here | Why |
|---|---|
| `02`, `73`, `77` | raw USB: interface layout, the OTP keyboard, pyusb |
| `51` | reboots to BOOTSEL; there is no bootloader to fall into |
| `53` | the PC/SC `FEATURE_VERIFY_PIN_DIRECT` reader layer |
| `61`, `65` | driven through python-fido2's own HID transport — faking it would leave the suite testing this shim instead of a third-party client |
| `54`, `90` | SRAM residue and OTP-fuse migration — hardware by definition |

The list lives in `tests/emu.py` (`UNSUPPORTED`); removing an entry is a claim
that the emulator grew the capability.

`30` needs the Yubico card identity: start the emulator `--yubico` and it runs,
otherwise the shim asks the card for its ATR and skips. `28` and `76` take `--pin` and want a PIN already set (`21_pin_webauthn` sets
`1234`). `50` and `52` measure that a touch took time, so they only mean
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
fido2-token -L                 # /dev/hidraw1: vendor=0x1209, product=0x0001
fido2-token -I /dev/hidraw1    # CTAP2.3 getInfo
opensc-tool -a                 # 3b:fc:…:52:53:2d:4b:65:79  — the RS-Key ATR
```

Two things to know. The keyboard interface is declared but types nothing: this
build has no OTP transport, and the interface exists so the *order* is the
device's. And PC/SC finds no reader on the default identity until the ccid
driver's whitelist carries it (`overlays.ccid-rs-key`, `docs/linux.md`) — the
same thing that happens with a real key, for the same reason.

Needs Linux and root for `vhci_hcd`; the emulator itself can stay on a Mac,
because USB/IP is network-transparent.

## The wire

**CTAPHID** — the stream carries 64-byte HID reports, both directions, exactly
as the USB interface would. A client is a `send(64)` / `recv(64)` shim away.

**Card** — one CCID message at a time:

```text
request   op:u8 | len:u32 BE | payload
response         len:u32 BE | payload
```

`op` is `00` for a CCID message and `03` for a replug (a power cycle: RAM state
is dropped and the CTAP 2.1 §6.6 reset window reopens — CCID has no message for
that, because a power cycle is not a card reset). The payload of a `00` is a
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
  window, and the **space bar is the wake button**. One behaviour is deliberately
  *not* the board's: `host_request_pending` is always false here, so a host
  command never closes an open menu. On a device that is a host-starvation guard;
  on a desk it would shut the operator's menu because a browser sent `getInfo`.
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
  dirty latch is up, run a queued reboot only after the response is out — and
  `firmware/src/{main,worker,presence,led}.rs`, which are the board's.

A green run against the emulator is a protocol result, not a device result.
