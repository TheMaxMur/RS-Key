<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Interop

Use this page to choose a real client test. For protocol, emulator and
image tests, see [Testing](testing.md). The
[interop run records](https://github.com/TheMaxMur/RS-Key/blob/main/assurance/reports/interop.md)
keep the firmware, host, commands and outcomes for individual runs.

## How to run the CLI sweep

```sh
nix develop -c python tests/interop/run.py
nix develop -c python tests/interop/run.py --touch
nix develop -c python tests/interop/run.py --json
```

The default sweep probes HID and CCID without modifying the key. Touch
cases can enroll credentials or generate a key, so use a test device.
Some automated cases expect a no-touch build. Use a touch build for
WebAuthn, physical presence, and OTP keyboard checks.

`ykman` and Yubico Authenticator rely on the Yubico reader name. Use
`VIDPID=Yubikey5` for those checks. The default RS-Key identity is enough
for the libfido2, browser and GnuPG probes. See [Build options](build.md).

## FIDO2 / WebAuthn / U2F

| Client | Operation |
|---|---|
| libfido2 | Enumerate with `fido2-token -L`, read getInfo, enroll with `fido2-cred`, verify an assertion with `fido2-assert` |
| Chrome, Firefox and Safari | Register and sign in with a WebAuthn credential |
| OpenSSH | Enroll an `ed25519-sk` key and authenticate with it |
| CTAP1/U2F client | Register and authenticate with a U2F credential |

On a display board, check what the panel shows and what the browser does
after approve, deny and cancel. A browser may send another request after
a terminal reply, so correlate the prompt with the CTAP exchange.

## OpenPGP

Run `gpg --card-status` and `ykman openpgp info` to check card discovery
and data parsing. On a disposable key, generate a key through GnuPG and
use it for signing or decryption. A successful raw GENERATE APDU does
not exercise response chaining through scdaemon.

## PIV

Use `ykman piv info` or OpenSC to check discovery and read card data.
Use a test slot to exercise PIN verification, key and certificate
operations, and a signing operation through the client.

## OATH / OTP

Use `ykman` or Yubico Authenticator to add, calculate and remove OATH
credentials. Test the OTP HID interface separately. For keyboard output,
focus a text field, tap the configured slot and compare what the key
types with its configured value.

## Differential against a real YubiKey

The socket emulator compares getInfo, ATR and management DeviceInfo with
checked-in responses from a YubiKey. For a live comparison, attach both
keys and use the [interop tools](https://github.com/TheMaxMur/RS-Key/tree/main/tests/interop).
Compare each result with the documented divergence rule. A rule can allow
a different value because of configuration or a deliberate protocol choice.

## Known issues

See [Limitations](limitations.md) for current constraints. The
[interop run records](https://github.com/TheMaxMur/RS-Key/blob/main/assurance/reports/interop.md#known-issues)
retain past reproductions for GET DATA parsing and chaining, and management
interface masks.
