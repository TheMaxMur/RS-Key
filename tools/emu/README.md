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
  --store <path>      persist the file system here (default: memory only)
  --touch             ask for every user presence on the terminal
  --trace             log every command and its status
  --seed <hex>        seed the DRBG deterministically (predictable keys)
  --serial <16 hex>   device serial
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

**38 of the 52 suites pass; the other 14 are refused by name, with the reason,
before they start** (exit 77 — so a sweep counts skips apart from failures). None
of them is an unexplained failure:

| Skipped here | Why |
|---|---|
| `01`, `14`, `15`, `30`, `51`, `76` | the vendor AID (counter, LED, bench, reboot) lives in `firmware/`, not a crate |
| `02`, `73`, `77` | raw USB: interface layout, the OTP keyboard, pyusb |
| `53` | the PC/SC `FEATURE_VERIFY_PIN_DIRECT` reader layer |
| `61`, `65` | driven through python-fido2's own HID transport — faking it would leave the suite testing this shim instead of a third-party client |
| `54`, `90` | SRAM residue and OTP-fuse migration — hardware by definition |

The list lives in `tests/emu.py` (`UNSUPPORTED`); removing an entry is a claim
that the emulator grew the capability.

`28` takes `--pin` and wants a PIN already set (`21_pin_webauthn` sets `1234`).
`50` and `52` measure that a touch took time, so they only mean something with
`--touch` and a human at the keyboard.

## The wire

**CTAPHID** — the stream carries 64-byte HID reports, both directions, exactly
as the USB interface would. A client is a `send(64)` / `recv(64)` shim away.

**Card** — one length-prefixed APDU at a time:

```text
request   op:u8 | len:u32 BE | payload
response         len:u32 BE | payload
```

`op` is `00` transmit, `01` power on (answers the ATR), `02` power off,
`03` replug (a power cycle: RAM state is dropped and the CTAP 2.1 §6.6 reset
window reopens). Requests carry APDUs, not CCID blocks — a PC/SC client hands
the reader an APDU, so the emulator starts where `SCardTransmit` does.

## What it does not emulate

The device identity is deliberately its own (serial `RSKEMU\x00\x01`), so
anything derived from it — the OpenPGP AID, the seal context, the management
serial — is recognisable as emulator-made.

- **Hardware**: secure boot, OTP fuses, the anti-rollback epoch, the partition
  table, glitch detectors, side channels, the TRNG.
- **Flash semantics**: the store overwrites in place. It is not
  `sequential-storage`, so there are no log-structured remnants and no torn
  writes — power-cut behaviour still has to be proved on hardware.
- **USB**: enumeration, interface order, the CCID block layer, the OTP keyboard
  interface, and the LED.
- **The firmware's own wiring**: `firmware/src/{main,worker,handler,ccid_handler,
  presence,led}.rs` are not shared with the emulator — `src/device.rs` is a
  second implementation of that glue. A bug that lives there will not show up
  here.

A green run against the emulator is a protocol result, not a device result.
