# Windows host setup

The board enumerates as a composite **FIDO HID + CCID** device. By default it
uses the project's own RS-Key USB identity `0x1209:0x0001` (pid.codes), with the
PC/SC reader name containing `RS-Key`. The opt-in `VIDPID=Yubikey5` interop build
instead presents the YubiKey identity `0x1050:0x0407` (other presets:
[build.md](build.md)). The two transports have different host requirements on
Windows:

| Transport | Used by | Out of the box? |
|---|---|---|
| **FIDO HID** (`0xF1D0`) | WebAuthn, `ssh ed25519-sk` (see [ssh.md](guides/ssh.md)), browser passkeys | yes — Windows drives it through the built-in `webauthn.dll`, no driver install |
| **CCID** (PC/SC) | OpenPGP (`gpg` / Kleopatra), PIV, OATH, Yubico-OTP | yes — the Windows **Smart Card** service binds the standard CCID class; the friction is arbitration, not drivers |

FIDO needs nothing: WebAuthn talks to the HID interface directly. CCID needs no
driver either — the device is a standard CCID smart card — but the whole card is
**a single reader carrying several applets** (OpenPGP, PIV, OATH, OTP), and only
one host program can hold that one reader at a time. That is the crux of the
Windows friction below.

> **Not yet hardware-verified on Windows.** The Linux remedy in
> [linux.md](linux.md) is confirmed on real hardware; the steps here mirror it
> and the cross-platform GnuPG behaviour, but have **not** been checked on a
> Windows host. Treat them as a starting point and please report corrections via
> an issue. (The Linux page carries the tested reference config.)

## The single-reader contention (issue #44)

RS-Key presents OpenPGP and PIV on **one** CCID card, exactly as a YubiKey does.
On Windows two different stacks then compete for that one card:

- **GnuPG's `scdaemon`** claims it to drive the **OpenPGP** applet (Kleopatra,
  `gpg --card-status`).
- The **Windows PIV minidriver** (and any PKCS#11 layer such as OpenSC/`ykcs11`)
  claims the same card to drive the **PIV** applet.

Because a smart-card SELECT switches the *whole* card between applets, two
stacks talking at once stomp on each other's selection. The visible symptoms in
issue #44 — Kleopatra showing the device as **two cards**, a PIV error that then
makes the OpenPGP keys look gone, and **PicoForge unable to reconnect until you
unplug and re-plug** — are this host-side arbitration, not a fault on the card.
The keys are never lost: OpenPGP clears only its PIN-verified state on an applet
switch (spec-required, same as a YubiKey), and re-selecting the card shows them
again.

## Reducing the contention

There is no driver to install. The fixes are arbitration hygiene:

1. **One PC/SC app at a time.** Close **PicoForge** (and any other tool that
   opened the card) before using Kleopatra/`gpg`, and vice-versa. If a tool
   wedges and will not reconnect, unplug and re-plug the board — this clears the
   held reader handle.

2. **Let `scdaemon` share the reader.** By default `scdaemon` can grab the
   reader exclusively and lock out other tools. Route it through the Windows
   Smart Card service and let it share. Edit (create if absent)
   `%APPDATA%\gnupg\scdaemon.conf`:

   ```
   pcsc-shared
   disable-ccid
   ```

   Then reload it from a terminal:

   ```
   gpgconf --kill scdaemon
   ```

   `pcsc-shared` is the key line (share the reader instead of taking it
   exclusively); `disable-ccid` forces `scdaemon` onto the Windows PC/SC stack
   rather than its own internal CCID driver. Re-plug the board afterwards.

3. **Prefer one PIV path.** For PIV, either the native Windows minidriver **or**
   OpenSC/`ykcs11` (PKCS#11) — not both against the card at the same moment. If
   OpenSC and GnuPG clash, drive PIV through `ykcs11` and keep OpenPGP in
   Kleopatra, one operation at a time.

## FIDO / SSH (`ed25519-sk`)

FIDO uses the HID transport and the built-in `webauthn.dll`; no PC/SC, no
`scdaemon`, so none of the contention above applies. OpenSSH for Windows enrols
and authenticates directly:

```
ssh-keygen -t ed25519-sk -f %USERPROFILE%\.ssh\id_ed25519_sk
ssh -i %USERPROFILE%\.ssh\id_ed25519_sk user@host
```

See [ssh.md](guides/ssh.md) for the WebAuthn/OpenSSH details.

## Troubleshooting

- **Kleopatra shows two cards / a serial unrelated to the PIV one:** expected —
  one physical card surfaced through two host stacks (OpenPGP via `scdaemon`, PIV
  via the minidriver). Recent firmware aligns the OpenPGP card serial with the
  device serial the other applets report; older firmware showed a divergent
  OpenPGP serial.
- **PIV certificates unusable / signing "pending" under CAPI (CryptoAPI):** the
  Windows PIV minidriver enumerates the card's containers from its CHUID. Recent
  firmware serves a default CHUID automatically, so a freshly flashed card is
  usable; on older firmware, provision one with `ykman piv objects generate chuid`.
  (The RSA/EC signing itself is unaffected — it matches a real YubiKey byte-for-byte.)
- **PicoForge / a PC/SC tool cannot connect until re-plug:** another program is
  holding the single reader. Close it (PicoForge, Kleopatra, a stray `gpg`), or
  unplug and re-plug. `gpgconf --kill scdaemon` releases a `gpg`-held handle.
- **`gpg --card-status` and another PC/SC tool cannot coexist:** apply the
  `pcsc-shared` + `disable-ccid` config above, then `gpgconf --kill scdaemon`.
- **`ykman` does not see the device:** `ykman` matches on the PC/SC reader name
  containing `Yubico YubiKey`, which the default RS-Key build does not present.
  Build the opt-in `VIDPID=Yubikey5` flavor (reader name `Yubico YubiKey RSK
  OTP+FIDO+CCID`) to use `ykman` (see [build.md](build.md)).
