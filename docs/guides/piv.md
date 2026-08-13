# PIV

A PIV smart-card (NIST SP 800-73-4) over CCID: X.509 client certificates,
S/MIME, PIV-aware OS login, SSH and `age` through PKCS#11. Driven with
`ykman piv` or `yubico-piv-tool`; the applet also speaks the Yubico extensions
(metadata, serial, attestation, move/delete, set-retries) those tools use.
`ykman piv` and `yubico-piv-tool` gate on the "Yubico YubiKey" reader name,
which the default RS-Key build (VID:PID `0x1209:0x0001`) does not present. They
need the opt-in `VIDPID=Yubikey5` interop build ([build.md](../build.md)). The
PKCS#11 / OpenSC and OS-native (macOS CryptoTokenKit, Windows) routes below
identify the card by its applet, not the reader name, so they work on the default
build.

> **Windows note:** the card serves a default CHUID automatically — the Windows
> PIV minidriver needs it to enumerate the certificate containers, so no manual
> `ykman piv objects generate chuid` step is required.

Prereqs: on Linux, `pcscd` plus the polkit rule from [linux.md](../linux.md);
if you also use GnuPG, the `disable-ccid` line so `scdaemon` and `pcscd` stop
fighting over the reader. Check the card is visible (the `ykman` commands here
assume the opt-in `VIDPID=Yubikey5` build):

```sh
ykman piv info            # PIV version 5.7.4, slot + PIN/PUK/mgmt-key state
```

## Defaults

| | Default | Notes |
|---|---|---|
| PIN | `123456` | 6–8 chars; padded to 8 with `0xFF` on the wire |
| PUK | `12345678` | 6–8 chars; unblocks a blocked PIN |
| Management key | `010203040506070801020304050607080102030405060708` | AES-192, the well-known YubiKey 5.7-era default |
| PIN / PUK retries | 3 / 3 | resets to full on each correct entry |

Change all three before real use:

```sh
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect
```

`--protect` stores the new management key on the card, encrypted under the PIN,
so `ykman` can recover it from the PIN alone (no separate hex string to carry).
The applet accepts AES-128/192/256 management keys; under the FIPS-style build
it refuses to *set* a new 3DES key, though an existing 3DES key still
authenticates so a reflashed device can migrate itself to AES.

> **PIN protection is per key and does not survive a rotation.** Setting a new
> management key clears the protected flag, so the new key is not PIN-readable
> unless you opt in again — `ykman piv access change-management-key --protect`
> re-writes the flag as part of the same operation, so nothing changes for the
> command above. It matters if you rotate with anything else (a raw `SET
> MANAGEMENT KEY` APDU, `yubico-piv-tool`): the card then holds a key only the
> hex string opens, and `ykman piv info` reports it as not protected. Rotating
> away from a protected key is also how you revoke that PIN-only access. The flag
> is cleared only once the new key is stored, so a rotation that fails part-way
> leaves the escrow describing the key that is still on the card — you are never
> left holding a `PRINTED`-only key the card no longer admits to escrowing.

**On the panel (trusted-display builds).** The PIV PIN and PUK can be changed
(and a blocked PIN unblocked with the PUK) on the device, no host needed:
Settings → Security → **PIV PIN** → *Change PIN* / *Change PUK* / *Unblock PIN*.
Each verifies the current PIN/PUK against the applet's own retry counter (shown
on the pad) and stores the new value in the 8-byte `0xFF`-padded wire form, so a
later `ykman` / `yubico-piv-tool` VERIFY accepts it.

A 24-byte **management key** can't be typed on a numeric pad, so the panel sets a
**random, PIN-protected** one instead: Settings → Security → **PIV PIN** →
*Protect mgmt key*. The device generates a random AES-256 management key, seals
it, and marks it PIN-protected (the ykman `--protect` scheme), so a host then
uses it with just the PIV PIN. `ykman piv info` shows it as protected and
`ykman piv` operations no longer need the hex key. **Security:** once protected,
the PIV PIN **alone** grants management access (it unlocks the random key), so
treat the PIN accordingly; the panel states this and gates the action behind the
device PIN and a hold. (`ykman piv access change-management-key --generate
--protect` installs a random PIN-protected key from the host too.) If you had
raised the management key's touch policy (`--touch`, below), **the panel action
keeps it** — it replaces the key, not the gate, so admin actions still ask for a
press. The host command does not: `ykman` sends the policy in the command itself
and defaults it to off, so re-run it with `--touch` if you want the gate back.

The panel manages PINs/PUKs that follow the standard PIV convention (**6–8
digits, padded to 8 bytes with `0xFF`**), which is what `ykman`, `yubico-piv-tool`
and OpenSC all use. Since firmware `0x088A` the card refuses to *store* a value
shorter than six bytes at all, so a sub-6-digit reference can no longer be
provisioned by any route. A reference stored **unpadded** by an older build is
still possible, and it can't be verified on the panel; re-set it with `ykman`
first. The factory defaults follow the convention, so the panel works out of the
box.

> **If an older build shortened *both* the PIN and the PUK, the only way back
> destroys the keys.** Since `0x08D1` a `CHANGE REFERENCE DATA` / `RESET RETRY
> COUNTER` body is sixteen bytes or nothing, so no build can enter this state any
> more — but a card already in it has no non-destructive exit. A shortened PIN
> alone is repaired by `ykman piv access unblock-pin` (the PUK still works), and a
> shortened PUK alone by `ykman piv access set-retries` (the PIN still works),
> both with every key intact. With both shortened, neither repair is presentable:
> block both counters with wrong guesses and run `ykman piv reset`, which wipes
> every PIV key and certificate. The state needed an older build *and* a host that
> sent a fourteen-byte reference pair, which no shipped tool emits, so it is
> unlikely you are here — but if you are, restore the slots from backup after the
> reset rather than looking for a gentler command.

> The defaults are public. Until you change the PIN, PUK and management key,
> anyone with physical access can generate, import or delete keys. Treat a
> default-credential card as unprovisioned.

## Slots

| Slot | Role | Typical use | Default PIN policy |
|---|---|---|---|
| `9a` | PIV Authentication | system / domain login, SSH, client TLS | once per session |
| `9c` | Digital Signature | document & email signing | **every operation** |
| `9d` | Key Management | decryption, key agreement (ECDH) | once per session |
| `9e` | Card Authentication | physical-access / contactless | **no PIN** |
| `82`–`95` | Retired Key Management | 20 slots for old decryption keys | once per session |
| `9b` | Management Key | admin auth (not an asymmetric key) | — |
| `f9` | Attestation | signs slot attestation certs (on-card) | — |

The signature slot (`9c`) demands the PIN before **every** private-key
operation; the other slots cache the PIN for the rest of the session after one
VERIFY. A session ends when the card loses power or another application is
selected on it — an OpenPGP or OATH tool reaching for the same key mid-session
does exactly that. Selecting **PIV** again does not end it (SP 800-73-4 Part 2
§3.1.1), so a tool that re-selects before each command keeps the PIN it already
gave. `9e` is the exception at the other end: SP 800-73-4 makes the Card
Authentication Key the one usable **without** a PIN, so a default-policy `9e` key
signs with no VERIFY at all — which is what makes it usable for physical-access
and contactless readers. Give it `--pin-policy ONCE` (or `ALWAYS`) at generate
time if you want it gated like the rest.

**Algorithms.** On-card generation and import accept **RSA-2048 / 3072 / 4096**,
**RSA-1024** (disabled under the FIPS-style build, SP 800-131A), **ECC P-256 /
P-384**, and the Curve25519 pair **Ed25519** (signing) and **X25519** (key
agreement), the Yubico 5.7 PIV algorithm ids `0xE0` / `0xE1`, so `ykman` drives
them as `--algorithm ED25519` / `X25519`. An Ed25519 key generates with a
self-signed certificate like the other curves; an X25519 key is key-agreement-only
and can't self-sign, so generation writes **no** auto-certificate (provision one
from a CA via `ykman piv certificates import`). RSA-3072/4096 keygen is slow on
this hardware (tens of seconds to a minute-plus).

## Generate a key on-card

```sh
ykman piv keys generate --algorithm ECCP256 9a pub.pem   # on-card key, public part out
ykman piv certificates generate --subject "CN=me" 9a pub.pem   # self-signed cert into 9a
ykman piv info
```

Generating in a slot already writes a self-signed certificate into that slot's
certificate object, so a GET DATA serves one immediately even before you run
`certificates generate`. Management-key auth is required to generate.

For a real CA, emit a CSR instead of a self-signed cert:

```sh
ykman piv certificates request --subject "CN=me" 9a pub.pem me.csr
# … sign me.csr at your CA, then import the issued cert:
ykman piv certificates import 9a issued.pem
```

On-card generation means the private key never existed off-device and cannot be
exported or backed up. Losing the card loses the key (that is the point). RSA
generation is slow on this hardware (RSA-2048 takes 4–6 s on the reference board
and about twice that on others, and the prime search is random so run-to-run
times vary; the device streams CCID keepalives so the connection stays alive; it
is not a hang). See [limitations.md](../limitations.md) for the measured
dual-core figures and which board they are from. EC generation is instant.

## Or import an existing key

```sh
ykman piv keys import 9d existing.pem        # PEM with the private key
ykman piv certificates import 9d existing-cert.pem
```

Import is management-key gated and also accepts RSA-2048/1024, P-256/P-384 and
Ed25519/X25519.
An imported key keeps whatever copy you imported it from. Your call which way
the trade-off goes. Imported keys **cannot be attested** (see below): attestation
proves on-card *generation*, which import didn't do.

## PIN and touch policy per key

Both policies are fixed at generate/import time and stored in the slot metadata:

```sh
ykman piv keys generate --pin-policy ALWAYS --touch-policy ALWAYS 9a pub.pem
```

| `--pin-policy` | Effect |
|---|---|
| `NEVER` | no PIN to use the key (default for `9e`) |
| `ONCE` | PIN once per session (default for `9a`/`9d`/retired) |
| `ALWAYS` | PIN before every operation (default for `9c`) |

`ALWAYS` means the VERIFY has to be the last thing before the operation: a
private-key operation at **any** PIN-gated slot uses it up — including one that
fails after reaching the key — so
`VERIFY` → sign at `9a` → sign at `9c` refuses the second signature with `6982`.
Verify again between them. Nothing else is affected — the PIN itself stays
verified, so a `9c` signature does not close the `ONCE` slots, the PIN-protected
management key or a plain `VERIFY` status query, and a `NEVER`-policy key never
uses anything up.

| `--touch-policy` | Effect |
|---|---|
| `NEVER` | no button press — **the default**, for slot keys and the `9b` management key alike |
| `ALWAYS` | a physical touch before every private-key operation |
| `CACHED` | treated as `ALWAYS` on this device (see below) |

Ask for the press and you get it on every sign / decrypt / ECDH, and a declined
touch fails the operation with `6982`. Don't ask, and the key never prompts —
which is what makes `pkcs11`, `age-plugin` and SSH usable unattended. Raise the
management key's own policy with `ykman piv access change-management-key
--touch` if you want admin actions gated too.

> `CACHED` is treated as `ALWAYS`. The device has no wall clock, so it cannot
> honour the 15-second touch cache a real YubiKey offers; it errs strict and
> asks every time. If you set `CACHED`, expect `ALWAYS` behaviour.

## Data objects that need the PIN to read

Most `PUT DATA` objects are readable by anything that can open the reader — that
is what SP 800-73-4 pt1 Table 3 says, and a certificate is public anyway. Four
are not:

| Object | Name |
|---|---|
| `5FC103` | Cardholder Fingerprints |
| `5FC108` | Cardholder Facial Image |
| `5FC109` | Printed Information |
| `5FC121` | Cardholder Iris Images |

`ykman piv objects export 5fc103 -` on one of those needs a `VERIFY` first, or
the card answers `6982`. The refusal comes before the lookup, so an empty object
and a populated one are indistinguishable without the PIN. The management key
does **not** substitute for it: writing these is management-gated, reading them
is PIN-gated, and the two are separate conditions.

`5FC109` has a second job: it is where a PIN-protected management key is read
back from. **While protection is on, PRINTED is that escrow and nothing else** —
the read answers with the key, synthesized from slot `9b`, and a write of any
other content is refused with `6985` rather than accepted and hidden underneath
it. Revoke the protection first (`ykman piv access change-management-key`
without `--protect`, or set a new key any other way) and it is ordinary storage
again. Note that `ykman`'s own revoke clears PRINTED as its first step, so
anything stored there before you turned protection on does not survive the round
trip.

The one write the card never keeps is a *PivmanProtectedData* body — exactly
`88 L { 89 L <key> }`, what `--protect` sends — which is acknowledged and
dropped, because the key it carries is already sealed in `9b` and a second copy
would sit in flash in plaintext. The match is on that exact shape, so printed
information that merely happens to contain those tags is stored like anything
else. One consequence worth knowing: `--protect` fails on a card that already
has other content in PRINTED, because `ykman` tries to parse it as an escrow
record. Clear the object first.

## Attestation

```sh
ykman piv keys attest 9a attestation.pem
```

Proves a slot key was generated on-device, not imported. The attestation
certificate is signed on-card by the `f9` key (a P-384 CA key, self-signed at
first boot) and carries the standard Yubico OIDs: firmware version, device
serial, and the slot's pin/touch policy. Subject/issuer names are
`C=ES, O=RS-Key, CN=RS-Key PIV …`. Read the `f9` CA cert with:

```sh
ykman piv certificates export f9 attestation-ca.pem
```

Attestation only works for **generated** keys; an imported key returns
`6A80` / `WRONG DATA` (there is nothing to attest). For the FIDO side of
attestation (org-provisioned enterprise attestation) see
[attestation.md](attestation.md).

An **interrupted** `keys import` or `keys move` fails closed: the target slot's
metadata is dropped before the new key is written, so a power cut between the two
leaves a slot that reads as empty (`GET METADATA` → `6A88`) rather than one whose
key and its recorded provenance disagree. Re-run the import; the slot works again
once it completes. That ordering is what keeps attestation honest — it can never
certify an imported key as generated on-device.

## Move and delete keys

`ykman piv` 5.7 can move a key (with its certificate and metadata) between
slots, or delete it:

```sh
ykman piv keys move 9a 82          # 9a → retired slot 82, cert + metadata follow
ykman piv keys delete 9c           # wipe the signature slot's key
```

Moves go both ways — a key parked in a retired slot can come back to an active
one. Moving a key onto its own slot is refused, because the source-delete would
erase what the move just wrote. Both operations require management-key auth.

## Use it

The card shows up as a standard PIV token; nothing here is RS-Key-specific.

- **PKCS#11** (browsers, VPNs, SSH, `age`): point the app at OpenSC's
  `opensc-pkcs11.so`, found at `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` on
  Debian, `/usr/lib/opensc-pkcs11.so` on many distros, or the Nix store path
  under NixOS ([linux.md](../linux.md)).
- **SSH** via PKCS#11:

  ```sh
  ssh-keygen -D /usr/lib/opensc-pkcs11.so          # print the slot 9a public key
  ssh -I /usr/lib/opensc-pkcs11.so you@host        # log in with it (touch + PIN per policy)
  ```

  For an `ed25519-sk` hardware SSH key the FIDO path is simpler (see
  [ssh.md](ssh.md)). PIV-over-PKCS#11 is the route when you need an RSA or
  NIST-curve key, a smart-card-login certificate, or a server that wants a real
  X.509 chain.

- **`age` encryption**: `age-plugin-yubikey` drives PIV slots directly for
  identity files but, like `ykman`, keys off the "Yubico YubiKey" reader name, so
  it wants the opt-in `VIDPID=Yubikey5` build; on the default RS-Key build use any
  PKCS#11-aware `age` build against `opensc-pkcs11.so`.

- **ECDH / key agreement** (`9d` and retired slots, P-256/P-384 and X25519):
  `ykman piv ... ` exposes it (`ykman piv keys calculate-secret` for X25519); at
  the wire level it is GENERAL AUTHENTICATE with tag `0x85`, the operation
  `yubico-piv-tool` and OpenSC use for decryption.

- **Windows / macOS native** smart-card stacks pick the PIV applet up as-is;
  macOS CryptoTokenKit binds its `pivtoken.appex` to the reader
  ([interop.md](../interop.md#piv)).

## At rest

PIV private keys are stored **AES-256-GCM-sealed** under the device root (the
sealed blob is `nonce ‖ ciphertext ‖ tag`, authenticated against the device
serial). Once the OTP master key is [fused](../otp-fuses.md), a flash dump does
not yield key material; **before** that burn, the seal's root derives from
on-chip state an attacker with the flash and chip could reconstruct, so at-rest
protection is only meaningful after provisioning (see
[threat-model.md](../threat-model.md)). The seal is bound to the device, not the
slot, so a `keys move` re-homes the blob verbatim (no re-encryption).

## Factory reset (PIV only)

```sh
ykman piv reset
```

Wipes PIV keys, certificates and PINs only; the other applets are untouched.
The reset is **only accepted once both the PIN and the PUK are blocked**;
`ykman` blocks them for you first. To wipe *every* applet at once (PIV included),
use `rsk offboard`, which blocks PIN+PUK then resets PIV as part of a full-device
wipe with a signed receipt (see [fleet.md](fleet.md#offboarding)).

`9000` from the reset means **every** PIV file is gone — private keys, public-key
caches, certificates, the data objects a host wrote through `PUT DATA`, and the
PIN/PUK files, which are then re-seeded to the factory defaults. The sweep runs
until the enumeration comes back empty rather than for a fixed number of passes,
and its safety budget counts files actually deleted, so neither a card stuffed
with `PUT DATA` objects nor one whose flash holds many superseded copies of them
can outrun it.

If the flash refuses a delete — or reports an enumeration it could not finish, so
"nothing left" cannot be proven — the command answers `6581` (`MEMORY_FAILURE`)
instead of claiming a wipe it did not complete. Treat that as "the card is still
provisioned" and retry: a failed reset still re-creates the PIN, PUK and
retry-counter files it deleted first, so the next attempt behaves like the first
one instead of answering `6A88` for the rest of the power cycle.

There is no `rsk piv` command group: PIV is provisioned entirely through
`ykman piv` / `yubico-piv-tool` / PKCS#11, with `rsk` only involved for a
whole-device offboard.

## Troubleshooting

- `ykman` can't connect → [linux.md](../linux.md) (pcscd + polkit + the
  `disable-ccid` scdaemon note).
- `ykman` stops seeing the card after `gpg` used it → `scdaemon` grabbed the raw
  CCID interface; apply `disable-ccid` and `gpgconf --kill scdaemon`
  ([openpgp.md](openpgp.md#troubleshooting)).
- **PIN blocked** → `ykman piv access unblock-pin` (needs the PUK). PUK blocked
  too → only `ykman piv reset` recovers, and it wipes the slots.
- `ykman piv keys attest` fails with `INCORRECT PARAMS` → the key in that slot
  was **imported**, not generated; attestation is generated-keys-only.
- `change-management-key` rejects 3DES on the FIPS-style build → expected; set an
  AES-128/192/256 key instead.
- RSA-2048 generate takes a few seconds (≈ 4–6 s on the reference board, ≈ 10 s
  on other boards, occasionally longer since the prime search is random) →
  that's the prime search on this hardware, not a hang; the device keeps the
  CCID connection alive with keepalives.
