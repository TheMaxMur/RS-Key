# RS-Key

[![ci](https://github.com/TheMaxMur/RS-Key/actions/workflows/ci.yml/badge.svg)](https://github.com/TheMaxMur/RS-Key/actions/workflows/ci.yml)
[![deep-checks](https://github.com/TheMaxMur/RS-Key/actions/workflows/deep-checks.yml/badge.svg)](https://github.com/TheMaxMur/RS-Key/actions/workflows/deep-checks.yml)
[![docs](https://github.com/TheMaxMur/RS-Key/actions/workflows/pages.yml/badge.svg)](https://themaxmur.github.io/RS-Key/)

**An open-source hardware passkey.** Flash one file onto a Raspberry Pi
**RP2350** board and it becomes a USB security key: passkey logins in the
browser, `ssh` and `git` signing, GPG, PIV, and TOTP codes.

| | |
|---|---|
| **What this is** | Firmware. A `.uf2` file you drop onto a board. Nothing here is for sale. |
| **What you need** | Any RP2350 board (from about $5) and a USB cable. No soldering, no programmer, no toolchain. |
| **What you get** | A USB authenticator your browser, `ssh`, `gpg` and `ykman` already know how to talk to. |

![What RS-Key is: any RP2350 board, plus this firmware, gives you passkey and WebAuthn logins, ssh and git signing, an OpenPGP card for gpg, a PIV smart card, and TOTP codes](docs/images/what-it-is.svg)

> **This project is experimental.** It has had no external security audit, the
> RP2350 is not a secure element, and a stolen board is only as strong as the
> optional OTP / secure-boot hardening you have applied to it. Don't use it to
> guard credentials you can't afford to lose or have stolen. Read the
> [threat model](docs/threat-model.md) and [limitations](docs/limitations.md)
> before trusting it with anything real.

## Quick start

From a fresh board to a passkey login. Nothing to build.

1. Download the newest **`rs-key-<version>-default.uf2`** from the
   [releases page](https://github.com/TheMaxMur/RS-Key/releases/latest).
2. Hold the board's **BOOT** button while you plug it in. A drive named
   `RP2350` appears.
3. Copy the `.uf2` onto that drive. The board reboots as a security key.
4. Go to [webauthn.io](https://webauthn.io) and register a passkey. The browser
   walks you through setting a PIN the first time, then asks for a touch: press
   the **BOOT** button.

Which file to take:

| Your board | Image |
|---|---|
| Most RP2350 boards, 4 MB flash | `default` |
| 2 MB flash (Seeed XIAO RP2350, Waveshare RP2350-Zero-CM) | `2mb` |
| 16 MB flash (TenStar RP2350-USB) | `16mb` |
| Waveshare RP2350-Touch-LCD-2.8 | `display` |

The other ten images are behaviour variants (post-quantum algorithms, the FIPS
profile, `alwaysUv`, PIN hardening). Full table, plus how to verify the cosign
signature and reproduce the build yourself: [docs/releases.md](docs/releases.md).

The longer walkthrough, with the PIN, `ssh` and `gpg` steps, is
[docs/quickstart.md](docs/quickstart.md). On Linux the smart-card half needs a
little host setup first: [docs/linux.md](docs/linux.md).

<p align="center">
  <img src="assets/webauthn-demo.gif" width="240" alt="Registering a passkey on webauthn.io with the trusted-display build: the device screen shows a Device PIN pad, then an Approve / Save-passkey prompt, and the browser confirms you are logged in. The PIN and the approval both happen on the device's own screen"><br>
  <sub>Step 4 on the <code>display</code> image: the PIN and the Approve/Deny happen on the device's own screen</sub>
</p>

## What it supports

- **FIDO2 / WebAuthn / U2F** — passkeys, two-factor logins, `ssh ed25519-sk`
- **OpenPGP card 3.4** — `gpg` signing, decryption, authentication (EC + RSA)
- **PIV** — X.509 smart-card via PKCS#11 (or `ykman piv`, which needs the opt-in `VIDPID=Yubikey5` build)
- **OATH** — TOTP / HOTP codes (`ykman oath`, Yubico Authenticator — both need the opt-in `VIDPID=Yubikey5` build)
- **Yubico-style OTP** — four slots, plus a USB-keyboard interface that types the code
- **Seed backup** — export the FIDO master seed as BIP-39 / SLIP-39 words
- **At-rest soft-lock** — keep the FIDO seed in flash encrypted to a key only you hold
- **On-device audit journal** and **enterprise (org-provisioned) attestation**
- **Post-quantum FIDO2 (experimental)** — implements the ML-DSA-44 (COSE −48)
  and ML-DSA-65 (−49) schemes; ML-DSA-65 uses an in-tree, stack-optimized FIPS
  204 implementation so it fits the RP2350. Advertising them in getInfo is off
  by default because some shipped browsers reject an unknown algorithm id. This
  is not a FIPS-validated module.

Capacities are flash-bound and generous (e.g. up to 256 resident passkeys,
255 OATH accounts, 24 PIV slots, 4 OTP slots); details are in the
[feature guides](docs/guides/) and [build options](docs/build.md).

```mermaid
flowchart TD
    host["Host software<br/>browser · ssh · gpg · ykman · rsk / rsk-tui"]
    host -->|USB| usb["Composite USB device"]
    usb --> fido["FIDO HID"]
    usb --> ccid["CCID (smart-card)"]
    usb --> kbd["Keyboard (OTP typing)"]
    fido & ccid & kbd --> applets["Applets: FIDO2/U2F · OpenPGP · PIV · OATH · OTP · mgmt"]
    applets --> core["Master seed · TRNG · flash store"]
    core --> rp["RP2350 (no secure element)"]
```

## What it does not protect against

- **Physical / lab attacks** — decapping, microprobing, fault injection beyond
  the on-chip glitch detectors, power/EM side channels, and flash-emulation
  TOCTOU. The RP2350 is not a secure element; if your threat model includes a
  funded lab, buy a certified key.
- **A compromised host with the device unlocked** — like any security key, it
  will perform operations you have authorized while plugged in and unlocked.
- **Loss of secrets without the optional hardening** — at-rest protection only
  becomes meaningful after you fuse the OTP master key (see Production, below).

Full reasoning: [docs/threat-model.md](docs/threat-model.md).

## Hardware

Any RP2350 board with USB. Developed and tested on the **Waveshare RP2350-One**
(WS2812 status LED on GPIO16; boards without an LED run fine). A different flash
size, LED pin, or presence-button GPIO is a one-line build knob. Details:
[docs/hardware.md](docs/hardware.md).

<p align="center">
  <img src="assets/hero-boards.jpg" width="330" alt="Three RS-Key boards on a blueprint background: a bare RP2350 USB stick, the trusted-display variant showing its Home &quot;Ready&quot; screen (USB connected, Device PIN set, 2 passkeys), and a Waveshare RP2350-One"><br>
  <sub>Three boards, one firmware: stick · trusted display · RP2350-One</sub>
</p>

## Documentation

The docs live in [docs/](docs/) and are published as a site:
**<https://themaxmur.github.io/RS-Key/>**.

| | |
|---|---|
| [Quick start](docs/quickstart.md) | flash, enroll, first login |
| [Hardware](docs/hardware.md) | supported boards and build knobs |
| [Build options](docs/build.md) | every flag: VID/PID presets, version, touch, PQC, FIPS profile |
| [Production setup](docs/production.md) | OTP fuses + secure boot, step by step (**irreversible**) |
| [Feature guides](docs/guides/) | FIDO2, SSH, OpenPGP, PIV, OATH, OTP, backup, soft-lock, LED, audit, … |
| [Threat model](docs/threat-model.md) · [Limitations](docs/limitations.md) | what it protects against, and what it does not |
| [Architecture](docs/architecture.md) · [`unsafe` audit](docs/unsafe.md) | how it's built; every `unsafe` site |
| [Testing](docs/testing.md) · [Interop](docs/interop.md) | host tests, fuzzing; real-tool results |
| [Linux setup](docs/linux.md) · [Motivation](docs/motivation.md) | pcscd/udev/polkit; why this exists |

## Build it yourself

The release images are reproducible, so you can rebuild any of them bit for bit
([docs/releases.md](docs/releases.md)). To build your own:

```sh
git clone https://github.com/TheMaxMur/RS-Key && cd RS-Key
nix develop                       # toolchain, picotool, host tools, everything

cargo build --release -p firmware
picotool uf2 convert target/thumbv8m.main-none-eabihf/release/firmware -t elf firmware.uf2

# hold BOOTSEL, plug the board in, then flash, either way:
cp firmware.uf2 /Volumes/RP2350/                    # macOS drag-and-drop; Linux: the mounted RP2350 volume
picotool load -v firmware.uf2 && picotool reboot    # more robust; verifies the write (use if cp flakes)
```

Re-plug the board and it enumerates as a composite USB authenticator. The default
build requires a **physical touch** (the BOOTSEL button) for FIDO operations;
build with `--features no-touch` for a no-touch build (the automated test
suites need it). Every compile-time knob, including the flash size, LED pin and
USB identity, is in [docs/build.md](docs/build.md).

## Development setup

`nix develop` is the whole setup: Rust with the `thumbv8m.main-none-eabihf`
target, `picotool`, the Python host stack, and the security tooling. One command
is the merge gate, and CI runs exactly the same script:

```sh
nix develop -c ./scripts/check.sh   # fmt, clippy, host tests, firmware builds, audit, deny, gitleaks
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/testing.md](docs/testing.md).

## Production / secure boot (irreversible — read first)

By default the firmware flashes by drag-and-drop and roots its at-rest
encryption in a key derived on the device. An optional, opt-in path hardens
that: it fuses a random master key into RP2350 OTP and enables secure boot so
the board runs only images you sign.

```mermaid
flowchart LR
    subgraph dev["Default (development)"]
      d1["drag-and-drop UF2"] --> d2["flash-derived key"] --> d3["boots any image"]
    end
    subgraph prod["Production (opt-in)"]
      p1["sign UF2<br/>picotool seal"] --> p2{{"burn OTP fuses<br/>IRREVERSIBLE"}} --> p3["secure boot:<br/>only your signed images"]
    end
```

These steps **burn one-time-programmable fuses**: they cannot be undone, they
change your reflash workflow forever (signed images only), and a mistake can
brick the board. They are also what makes a stolen board's flash dump useless.
Read [docs/production.md](docs/production.md) end to end before running anything.

## Host tools

Inside the dev shell two commands are on `PATH`:

- **`rsk`** — the device CLI (Python): `rsk status`, `rsk backup`, `rsk lock`,
  `rsk secure-boot`, `rsk otp`, `rsk fido`, `rsk led`, `rsk reboot`, … (`rsk --help`)
- **`rsk-tui`** — a terminal dashboard for day-to-day reads and a few in-band
  actions ([guide](docs/guides/tui.md); `rsk-tui --demo` needs no hardware)

Without the dev shell, `rsk` also runs on a plain Python ≥ 3.9 toolchain via
[uv](https://docs.astral.sh/uv/) or pip — `uvx --from ./tools rsk status`,
`uv tool install ./tools`, or `pipx install ./tools`. Details and the native-lib
notes are in [tools/README.md](tools/README.md).

Separately, **`rsk-wipe`** is a RAM-only flash-erase *image* you flash
deliberately to wipe a board for clean-slate testing — it is built and flashed
like firmware, not run from `PATH` ([rsk-wipe/README.md](rsk-wipe/README.md)).

Third-party: **[PicoForge](https://github.com/librekeys/picoforge)** (from the
librekeys project) is a desktop GUI that configures an RS-Key over the same `phy`
record `rsk hw` writes — see the
[host protocol](docs/protocol.md#11-integration-notes-for-picoforge).

## Limitations (short list)

- **No secure element.** OTP + secure boot is real hardening, but physical
  attacks are out of scope.
- **Seed backup covers the deterministic identity only** — resident passkeys,
  OpenPGP and PIV keys do not survive a board swap.
- **No brainpoolP512r1 / X448 / Ed448** OpenPGP curves (no mature `no_std` Rust
  arithmetic yet); brainpoolP256r1 and P384r1 are supported.
- The default USB identity is **RS-Key's own** pid.codes id `0x1209:0x0001`;
  the YubiKey USB identity that `ykman` / Yubico Authenticator auto-recognize is
  the opt-in `VIDPID=Yubikey5` build, not for distribution.

Details and reasoning: [docs/limitations.md](docs/limitations.md).

## License

**AGPL-3.0-only** — see [LICENSE](LICENSE), [NOTICE](NOTICE), and
[COMPLIANCE.md](COMPLIANCE.md). RS-Key is a from-scratch Rust reimplementation of
the AGPL-3.0-**only** [pico-keys](https://github.com/polhenarejos) firmware
family (pico-fido / pico-openpgp / pico-keys-sdk) by Pol Henarejos; the upstream
grant is version-3-only, so RS-Key inherits it and so must forks. Not affiliated
with or endorsed by Yubico, Nitrokey, or Raspberry Pi. See [motivation](docs/motivation.md).

<sub>The name: **R**aspberry **S**ecurity **Key**, and a nod to Rust. Nothing to
do with RSA. The crates and the CLI shorten it to `rsk`.</sub>
