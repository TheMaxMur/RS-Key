<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Versions

What the firmware advertises itself as, per protocol: the place to look when a
host tool gates a feature on a version number. The build knobs that change any of
this are documented in [Build options](build.md); what has actually been checked
against real host software is in the [Interop matrix](interop.md).

## Firmware version

`5.7.4` (`rsk_sdk::FIRMWARE_VERSION`) is reported everywhere a tool reads a device
firmware version: FIDO getInfo and CTAPHID `INIT`, the YubiKey Management
`DeviceInfo` (`ykman info`), and the OATH / OTP / PIV version fields. It mimics a
current YubiKey 5 so Yubico tooling unlocks its feature gates. Override it with
the `FW_VERSION` build variable. It is **not** the OpenPGP card version and **not**
the USB `bcdDevice`.

| Surface | Advertised version | Spec implemented |
|---|---|---|
| FIDO / CTAPHID | getInfo `versions` = `U2F_V2`, `FIDO_2_0`, `FIDO_2_1`, `FIDO_2_3`; device version `5.7.4` | CTAP2 (FIDO2) + CTAP1 (U2F) |
| OpenPGP card | `3.4` | OpenPGP Smart Card Application 3.4 |
| PIV | `5.7.4` | NIST SP 800-73-4 (command subset) |
| OATH | SELECT version `5.7.4` | YKOATH (Yubico OATH over CCID), AID `A0 00 00 05 27 21 01` |
| Management | `DeviceInfo` version `5.7.4` | YubiKey Management over the FIDO / CCID transports |
| USB `bcdDevice` | a four-digit hex counter (current value: the top of [the changelog](https://github.com/TheMaxMur/RS-Key/blob/main/CHANGELOG.md)) | internal build counter — bumped on every behaviour change, **not** a protocol version |

`U2F_V2` drops out of `versions` on a build with `alwaysUv` enabled (CTAP 2.1
§7.2.4 disables U2F there). `FIDO_2_2` is deliberately absent: CTAP 2.3 §6.4 says
that string "MUST not be present", and the 2.2 surface is discovered through
option ids and getInfo members instead.

## Which build is on this device?

Not the firmware version — `5.7.4` is a **compatibility constant**, identical on
every build of every release, so it answers "what will Yubico tooling unlock",
never "what is flashed here". The build identity is the **`bcdDevice`** counter:

```sh
rsk-tui --once          # prints "bcdDevice 0x…" alongside the applet state
lsusb -v -d 1209:0001 | grep bcdDevice          # Linux
ioreg -p IOUSB -l | grep -i bcdDevice           # macOS
```

Map that value to a release through the [changelog](https://github.com/TheMaxMur/RS-Key/blob/main/CHANGELOG.md);
each entry names the counter it shipped at. A host tool that shows `bcdDevice`
and calls it "the version" is reading the right field — it is the only number
that changes between builds.

**The image file itself carries no version.** `nix build` output is unsigned and
unstamped, so nothing distinguishes two `.uf2`s but their bytes. If you need a
version readable from the file, `picotool seal --major/--minor` stamps one into
the RP2350 boot metadata that `picotool info` reads back without flashing
([production.md](production.md)); that is part of the signing path, not the plain
build.

## Algorithms, by build knob

The default algorithm menu and the two feature flags that change it (full
mechanics in [Build options](build.md)):

| | Default | `--features advertise-pqc` | `--features fips-profile` |
|---|---|---|---|
| FIDO signature algorithms (COSE) | ES256 (−7), ES384 (−35), ES512 (−36), ES256K (−47), EdDSA / Ed25519 (−8) | ML-DSA-65 (−49) and ML-DSA-44 (−48) prepended to the getInfo `algorithms` list | ES256K (−47) removed from the menu |
| Post-quantum | ML-DSA-44 and ML-DSA-65 negotiable from `pubKeyCredParams` (capability always on); not advertised | advertised in getInfo | same as default |
| Minimum PIN length | 4 | 4 | 6 |
| Vendor seed export | allowed | allowed | refused |
| PIV | 3DES management keys + RSA-1024 import allowed | same | new 3DES management keys + RSA-1024 refused |

- **PQC capability is on in every build.** `advertise-pqc` only controls whether
  ML-DSA-65 (−49) and ML-DSA-44 (−48) appear in the getInfo `algorithms` list. It
  is off by default because released Firefox aborts the entire getInfo parse on an
  unknown COSE id. makeCredential negotiates −49 / −48 from the request's
  `pubKeyCredParams` regardless — the RP lists the one it wants first, since the
  first supported entry is selected (CTAP 2.1 §6.1.2).
  −49 / −50 (ML-DSA-65 / 87) are recognised but have no enabled backend.
- `fips-profile` is a locked policy, **not** a FIPS validation. See the
  [FIPS-style profile](guides/fips.md) guide.

## Toolchain

The project tracks the latest stable Rust, pinned hermetically rather than to a
declared MSRV. `nix develop` / `nix build` take the toolchain from the flake
(fenix `stable`, frozen in `flake.lock`, currently rustc 1.96), on Rust edition
2024. `rust-toolchain.toml` (`channel = "stable"`) is only the fallback for the
non-Nix rustup path. "Which Rust built this image" is answered by the committed
`flake.lock`, so there is no separate minimum-version commitment to drift.
