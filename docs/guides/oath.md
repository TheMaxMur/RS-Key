# OATH — TOTP / HOTP codes

The device stores authenticator-app secrets and computes the 6/8-digit codes
on-card, over Yubico's YKOATH protocol (CCID). The HMAC secret is written once
and never leaves the chip again: every code is derived inside the firmware and
only the digits come back. Up to **255 accounts**.

Clients are the stock Yubico tooling: `ykman oath` on the command line and the
**Yubico Authenticator** desktop/mobile app over USB. There is no `rsk oath`
subcommand; OATH is driven entirely through those. Both `ykman oath` and the
Yubico Authenticator gate on a `Yubico YubiKey` reader name, so they only see
the device on the opt-in `VIDPID=Yubikey5` build; the default RS-Key build
enumerates as `RS-Key Security Key` (VID:PID `0x1209:0x0001`) and stays invisible
to them. Build that flavor when you want to drive OATH from the Yubico tools
([build.md](../build.md)).

On Linux this needs `pcscd` running plus the polkit rule from
[linux.md](../linux.md); if you also use `gpg`, the `disable-ccid` line there
keeps `scdaemon` from grabbing the reader and locking `ykman` out.

```sh
ykman oath info        # applet version + whether an access password is set
```

## Add accounts

```sh
# Interactive: paste the base32 secret when prompted.
ykman oath accounts add github --issuer GitHub

# Straight from an otpauth:// URI (everything — secret, issuer, digits,
# algorithm, period — is parsed out of the URI):
ykman oath accounts uri 'otpauth://totp/GitHub:me@example.com?secret=BASE32SECRET&issuer=GitHub'
```

The account name shown in lists is `issuer:account` (here `GitHub:me@example.com`).
Most sites hand you the secret two ways at enrollment: a QR code and a
"can't scan it?" base32 string. Either works:

- **base32 string** → `accounts add` (or `accounts uri` if they give the full
  `otpauth://` link).
- **QR code on screen** → `ykman oath accounts uri --` reads it from the
  primary display, or the **Yubico Authenticator** GUI has a *Scan QR code*
  button that grabs whatever QR is visible.

Options that matter:

| Option | Effect | Default |
|---|---|---|
| `--touch` | computing this account's code needs a button press | off |
| `--oath-type {TOTP,HOTP}` | counter-based vs time-based | `TOTP` |
| `--algorithm {SHA1,SHA256,SHA512}` | HMAC hash | `SHA1` |
| `--digits {6,7,8}` | code length | `6` |
| `--period N` | TOTP step in seconds | `30` |
| `--counter N` | HOTP starting counter | `0` |
| `--force` | overwrite an existing account of the same name without asking | — |

All three hashes are implemented on-card (SHA-1/256/512); RFC 6238/4226 test
vectors for each pass in `crates/rsk-oath`. Adding a name that already exists
**overwrites** the old secret in place (`--force` skips the prompt). There is
one credential per name.

## Get codes

```sh
ykman oath accounts code            # every TOTP account at once
ykman oath accounts code github     # one account by name substring
```

`code` with no name runs the bulk path (CALCULATE ALL). Two kinds of account
are *not* computed there and show a placeholder instead:

- **Touch-required accounts** are listed but not calculated. Name them
  explicitly (`ykman oath accounts code github`) and the firmware waits for the
  press, then prints the code. This is deliberate: a bulk read can never make a
  touch account leak a code without the button.
- **HOTP accounts** are never computed in bulk either (it would silently burn
  the counter). Name them to step the counter once.

The **Yubico Authenticator** GUI shows all TOTP codes live and re-derives them
each period. Touch and HOTP entries get a tap-to-reveal button instead.

## Touch-required accounts

```sh
ykman oath accounts add aws --issuer AWS --touch
# existing account → re-add with --touch --force, or toggle it in the GUI
```

With `--touch`, the firmware refuses to compute that account's code until the
BOOTSEL button is pressed; a timeout or a declined press returns "security
status not satisfied" and **nothing is computed**. For HOTP this gate sits
*before* the counter advances, so a denied touch burns no counter. A refused
press leaves the account exactly where it was. The button is the same physical
press used by FIDO and OpenPGP UIF; only one prompt is outstanding at a time.

## The OATH access password

By default the credential list and codes are readable by anything that can
reach the CCID interface. An optional access password gates the applet:

```sh
ykman oath access change            # set or change the password
ykman oath access remember          # cache it for this host (keyring)
ykman oath access forget            # drop the cached password
```

How it works on-card: the password becomes an HMAC key (PBKDF2 over the
password, salted with the device serial, done host-side by `ykman`). On every
fresh connection the card issues a random challenge; the host must answer with
`HMAC(key, challenge)` before any account command is allowed. The card
answers the host's challenge with the same key (mutual proof). Selecting the
applet again re-locks it. The compare is constant-time and full-length, so a
truncated or guessed response can't brute-force its way in one byte at a time.

Footguns:

- The password gates **listing and computing** codes over CCID. At rest the
  secrets are protected separately: every credential record — name, secret,
  HOTP counter — and the access password's own validation key are individually
  AES-256-GCM-sealed before they reach flash, under the device key `kbase`
  (accounts enrolled before that landed are re-sealed on the next boot). The
  password is not part of the sealing key, deliberately: codes have to compute
  without a separate at-rest unlock, exactly like PIV slot keys. So the seal is
  **device-bound, not password-bound**. Once the OTP master key is burned a
  flash dump on its own no longer yields your secrets
  ([threat-model.md](../threat-model.md)); what it never buys is protection from
  something that can drive *this* chip's firmware — that is what the access
  password and `--touch` are for.
- There is **no recovery** for a forgotten access password short of
  `ykman oath reset`, which wipes every account with it.
- `--touch` per account and the access password are independent hardenings.
  Use either, both, or neither.

### The OTP PIN and the password safe

Alongside the OATH accounts the applet can store a login, a password and a note
per credential — the password-safe extension `nitropy` speaks. Those fields are
secrets in a way a TOTP code is not: a code expires, a stored password does not.

They are read by `GET CREDENTIAL`, and **the rule is that an OTP PIN, once set,
is always required for it** — on a fresh connection, whether or not an access
password is also configured, and again after every re-select. `VERIFY CODE` is
gated the same way. Set the PIN with `nitropy nk3 secrets set-pin`; the card
demands a touch when it mints one, so a PIN cannot be planted on a key someone
briefly picked up.

With **neither** a PIN nor an access password the store is open to anything on
the CCID interface, exactly as the credential list is — that is the code-less
default this applet shares with a YubiKey, not an oversight. If you keep
passwords on the key, set one of the two.

## Manage

```sh
ykman oath accounts list                       # account names (extended list also flags which need touch)
ykman oath accounts list -P                    # include the period column
ykman oath accounts rename github GitHub:work  # current name → new name
ykman oath accounts delete github              # remove one account
ykman oath reset                               # wipe the OATH applet only
```

`rename` rewrites the name in place and keeps the same secret and counter;
renaming to a name that already exists is rejected. `delete` of an unknown name
is a no-op error. `reset` clears all accounts, the access password, and the OTP
password-PIN. Nothing outside OATH is affected (FIDO/PIV/OpenPGP survive). To
wipe the whole key instead, see `rsk offboard`.

## Notes

- Secrets live in device flash, each record sealed to this chip (see the
  footgun above). Codes are computed on-card, so the secret never returns to
  the host after `add`.
- OATH accounts are **not** covered by the [seed backup](seed-backup.md) and
  do not come back on a [backup key](backup-key.md): they are sealed to *this*
  chip, not derived from the FIDO seed. Keep your `otpauth://` URIs/QRs
  somewhere safe, or re-enroll on loss. The device cannot export a secret once
  it is stored.
- HOTP counters are persisted across reboots and continue from where they were.
  Touch-required HOTP accounts only advance the counter *after* the touch, so
  there are no drive-by increments.
- OATH interop (add → list → calculate → delete, plus TOTP crypto-verified
  against RFC vectors, via both `ykman oath` and Yubico Authenticator) is
  tracked in [interop.md](../interop.md#oath--otp).

## Troubleshooting

- **`ykman` finds no reader / "Failed to connect":** on Linux this is almost
  always `scdaemon` holding the CCID interface after a `gpg` call. Apply the
  `disable-ccid` line from [linux.md](../linux.md) and run
  `gpgconf --kill scdaemon`, then retry.
- **Codes are rejected by the site:** TOTP depends on the host clock. The card
  has no battery-backed time and trusts the timestamp `ykman`/the GUI sends.
  Fix the host's clock (NTP) and re-read. For HOTP, a code is rejected once the
  server counter has moved past yours; resync on the server side.
- **"Touch" account prints nothing under `accounts code`:** that's expected.
  Bulk read skips touch accounts. Name the account so the firmware prompts for
  the press.
- **Forgot the access password:** there is no unlock; `ykman oath reset` is the
  only way out, and it deletes every account.
