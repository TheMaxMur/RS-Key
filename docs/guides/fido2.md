# FIDO2 / WebAuthn / U2F

The FIDO half of the device: passkeys, two-factor security-key logins, and
legacy U2F. It speaks CTAP2 (`FIDO_2_0`) and CTAP1 (`U2F_V2`) over the HID
interface, so standard WebAuthn browsers and OS dialogs drive it without extra
software. It passes the FIDO Alliance Conformance Tools clean (CTAP2.3
235/0, U2F 55/0, a self-run pass, not a paid certification; see
[testing](../testing.md#fido-conformance)). What has been checked against
real client software is in the [interop matrix](../interop.md).

The default build enumerates as "RS-Key", its own USB identity
(`0x1209:0x0001`, the pid.codes FOSS VID), not a YubiKey one
([build.md](../build.md)). FIDO clients don't care: browsers, `python-fido2`,
and libfido2 bind the FIDO HID usage page, not the VID/PID, so everything on this
page works regardless of USB identity. The one exception is `ykman`, which gates
on a "Yubico YubiKey" reader name and so needs the opt-in
`VIDPID=Yubikey5` interop build ([build.md](../build.md)). The reported firmware
version is `5.7.4`, which is what FIDO tooling reads back. It is a build constant,
not the RS-Key release.

## Touch is always required

On the default (touch) build **every** FIDO operation needs a press of the
**BOOTSEL button**: both registration (makeCredential) and login
(getAssertion). The firmware's user-presence bit is implicitly true and it does
**not** honour a request to skip it. WebAuthn `userVerification`/`up` cannot turn
the touch off, and OpenSSH's `-O no-touch-required` is silently ignored on this
device. A "no-touch" SSH key still asks for the touch at login. The LED tells
you when the device is waiting. See [led.md](led.md) for the colours. A request
times out after no touch (the browser shows its own timeout UI). No button wired
on a custom board means presence confirms instantly.

## Set a PIN first

```sh
rsk fido set-pin            # set, or change once one exists
ykman fido access change-pin   # the same operation via ykman (needs the VIDPID=Yubikey5 build)
```

The clientPIN gates credential creation once it exists. It unlocks anything a
site requests user verification (UV) for. Rules from the firmware:

| | Value |
|---|---|
| Length | 4–63 characters (6–63 on the `fips-profile` build), counted in Unicode code points — `密码` is two, not six |
| Per-power-cycle | 3 wrong attempts → `PIN_AUTH_BLOCKED` (`0x34`), re-plug to retry |
| Retry budget | 8 wrong attempts (across power cycles) |
| On exhaustion | PIN locks **until a factory reset**, no separate unblock |

After 3 wrong attempts in a single power cycle the device returns
`PIN_AUTH_BLOCKED` (`0x34`) and refuses more PIN entry until you unplug and
re-insert it. The 8-attempt budget is the across-power-cycle hard limit.

"Power cycle" means a real one. Both the block and the count of wrong attempts
that arms it are held in a register a warm reset preserves and only a power-on
reset clears, so a host that reboots the device — which it can do without any
credential — cannot restart the batch and walk through the 8-attempt budget
unattended.

The retry counter resets on a correct PIN. There is no PUK or admin override:
once it is locked, the only way back is `ykman fido reset`, which wipes everything
and has to run within ten seconds of a replug (see [Factory
reset](#factory-reset)). `rsk fido set-pin` asks for the current PIN when changing,
the new one twice, and prints the resulting `clientPin` state.

Once a PIN is set, registering a **passkey** refuses to run without it (CTAP
`PUAT_REQUIRED`, `0x36`). The browser collects the PIN and retries. That is
expected, not a fault.

Registering a plain second-factor credential (non-discoverable, what a site asks
for with `userVerification: "discouraged"`) needs only a touch, PIN or no PIN —
the CTAP 2.1 `makeCredUvNotRqd` option, as on a YubiKey. Sites that want the PIN
on every registration ask for UV, and `ykman fido config toggle-always-uv` (or
the `always-uv` build) forces it device-wide.

## Passkeys (resident / discoverable credentials)

Register on any site offering a passkey or "security key" method. The browser
drives the device. You touch the button when the LED pulses. These are stored on
the device and surface at login without the site sending an allow-list.

Capacity: **256** resident passkeys (and 256 relying parties), flash-bound. When
the store is full, makeCredential returns `KEY_STORE_FULL` (`0x28`) and the
browser reports the key is out of space. Delete some first.

Inspect and clean up (PIN required, credentialManagement is PIN-gated):

```sh
rsk fido list-passkeys              # relying parties + user handles + free slots
ykman fido credentials list        # same, via ykman (needs the VIDPID=Yubikey5 build)
ykman fido credentials delete <id>  # remove one (same build; browsers expose this too)
```

`rsk fido list-passkeys` prints the existing count and remaining slots, then each
relying party with its user names and a credential-id prefix. There is no
`rsk`-native delete yet. Use `ykman` or the browser/OS passkey manager for that.

**credProtect.** A site can mark a passkey UV-required (credProtect level 3). The
firmware then hides it from discovery and from exclude-list checks until you
verify with the PIN, so it never leaks its existence to an unauthenticated
caller. RS-Key applies a credProtect level only when the relying party asks for
one. It does not silently force a default.

## Second-factor registrations (non-resident)

The classic security-key flow (GitHub, Google, GitLab, ...) stores **nothing** on
the device. The credential is derived deterministically from the master seed and
handed back as an opaque id the site presents at login. This path is effectively
unlimited (it costs no flash). The registrations survive a
[seed backup → restore](seed-backup.md) onto a new board: the same derivation
on the same seed reproduces the same keys.

Legacy **U2F** (CTAP1, `U2F_V2`) works the same way for older 2FA setups: the
register/authenticate pair is non-resident, with a monotonic signature counter,
attested by the device's end-entity certificate.

## Signature counters

Every assertion carries a signature counter, the tripwire a relying party watches
for a cloned key. RS-Key keeps one **per resident credential**: a passkey starts at
0 and only its own logins advance it, so colluding sites can't read a shared global
counter to gauge how much you use the key elsewhere (WebAuthn §6.1.1). A non-resident
second-factor credential stores nothing on the device, so it reports 0. Legacy U2F
keeps the single monotonic counter that protocol expects.

Upgrading an existing key is forward-safe for passkeys: each seeds its counter from
the old global value on first use, so the reported number never counts backwards.

## Advertised algorithms

getInfo advertises these COSE algorithms. A relying party picks one in its
`pubKeyCredParams`:

| COSE alg | Curve / scheme | Notes |
|---|---|---|
| `-7` ES256 | NIST P-256 | the universal default |
| `-8` EdDSA | Ed25519 | |
| `-35` ES384 | NIST P-384 | slow keygen/sign (pure-Rust arithmetic) |
| `-36` ES512 | NIST P-521 | slow keygen/sign |
| `-47` ES256K | secp256k1 | dropped from new credentials on `fips-profile` |

The curve-explicit COSE ids (`-9` ESP256, `-19` Ed25519, `-51` ESP384, `-52`
ESP512) are also accepted in `pubKeyCredParams`. RS-Key selects the **first**
supported algorithm a site offers, so put your preferred curve first in the list.

## Post-quantum credentials

The device implements **ML-DSA-44** (FIPS 204, COSE `-48`) and **ML-DSA-65**
(COSE `-49`) makeCredential / getAssertion. They obey the same first-supported
rule as everything else, so a site that wants one lists it **before** its classic
fallback. Nothing mainstream requests them yet. A client that does (e.g. a
`python-fido2` script offering `-49`) gets a PQC
credential today. Both are backed by the in-tree, stack-optimized `rsk-mldsa`
implementation, which streams the FIPS 204 matrix A on the fly so ML-DSA-65's
larger keys still fit the RP2350 stack.

The getInfo advertisement is build-gated behind `advertise-pqc`
([build.md](../build.md)) because shipped Firefoxes (authenticator-rs before
2026-06-02) hard-fail the whole getInfo parse on an unknown COSE id. The
*capability* is always on. Only the advertisement is opt-in. ML-DSA-87 (`-50`)
is recognised but unsupported: its makeCredential response overruns the CTAPHID
message ceiling.

## Extensions supported

getInfo advertises seven extensions:

| Extension | What it does | Limit |
|---|---|---|
| `hmac-secret` | per-credential secret keyed by a salt (the WebAuthn PRF maps onto it) | 32-byte output |
| `hmac-secret-mc` | the same evaluation at registration time | |
| `credProtect` | UV-gated credential visibility (levels 1–3) | |
| `credBlob` | small opaque blob stored with the credential | 128 bytes |
| `largeBlobKey` + large blobs | per-credential key into a device blob store | 4 KB store |
| `largeBlob` (CTAP 2.3) | the blob itself, per credential, inside the assertion | 4046 B/credential; **replaces** the row above, `largeblob-ext` build only |
| `minPinLength` | the device hands its PIN-length policy to the RP | |
| `thirdPartyPayment` | the secure-payment-confirmation marker | |

Enterprise attestation is supported but off until enabled. The `ep` option flips
to true once an org key is installed. See [attestation.md](attestation.md).

## Factory reset

```sh
ykman fido reset            # needs the VIDPID=Yubikey5 build; or any WebAuthn "reset security key" UI
```

Wipes **all** FIDO state: resident passkeys, the PIN, and the master seed (so all
derived non-resident credentials and U2F registrations die too). It regenerates
a fresh identity and signature counter. The OpenPGP / PIV / OATH
applets are untouched: each applet's reset wipes only its own files, and a FIDO
reset deliberately steps around them even where the file ids interleave.

**Replug the key first.** The wipe is gated by a physical touch *and* by the
CTAP 2.1 §6.6 power-up window: the firmware accepts `authenticatorReset` only
within **10 seconds** of the key attaching to USB. Later than that it answers
`CTAP2_ERR_NOT_ALLOWED` (`0x30`) straight away, before asking for the touch, and
the host tool reports the reset as failed. So the flow is: unplug, plug back in,
run the reset, touch within ten seconds.

Two details that catch people out:

- **A software reboot does not reopen the window** — it closes it. A host can ask
  the device to reboot without any credential (`rsk reboot`, a phy config write),
  so a window a host could restart at will would be no protection. Pull the key out.
- **Trusted-display builds are exempt.** There the prompt names the operation on
  screen, so the window is not what stands between you and an accidental wipe; the
  reset works whenever you confirm it on the panel.

The flash wipe is bounded: if storage keeps reporting a record after a successful
delete, reset returns `CTAP2_ERR_OTHER` instead of staying in the processing state
indefinitely.

`rsk offboard` handles this for you: it sends the reset, and only if the device
refuses does it prompt for the replug and retry.

## Troubleshooting

- **"device not eligible / already registered"**. Expected: the site sent an
  exclude-list matching a credential already on the device.
- **"PIN required" / repeated PIN prompts at registration**. A PIN is set and the
  site is registering a passkey, so makeCredential needs it (`PUAT_REQUIRED
  0x36`). Enter it. If you have forgotten it, only a [reset](#factory-reset)
  clears it — replug first.
- **The reset fails immediately with `CTAP2_ERR_NOT_ALLOWED` (`0x30`)**, without
  ever asking for a touch. The key was plugged in more than ten seconds ago.
  Unplug it, plug it back in, re-run. A `rsk reboot` does not count: only a real
  power cycle opens the window.
- **A site demands UV but you have no PIN**. Set one (`rsk fido set-pin`); UV on
  this device means the FIDO PIN.
- **"no space" / store-full at registration**. 256 resident passkeys is the cap
  (`KEY_STORE_FULL 0x28`). Delete some with `ykman fido credentials delete` (needs
  the `VIDPID=Yubikey5` build) or your browser/OS passkey manager.
- **`rsk fido …` says "missing dependency: python-fido2"**. Run `rsk` from
  inside `nix develop`. The management commands need the `python-fido2` library.
- **A "no-touch" SSH key still asks for a touch**. By design: the firmware
  always polls the button (see the top of this page). For the `ssh-keygen` PIN /
  touch / resident flags, see [ssh.md](ssh.md).
- **Linux permissions / the device is invisible to the browser**. Udev rules in
  [linux.md](../linux.md).
