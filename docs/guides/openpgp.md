# OpenPGP card

A full OpenPGP card 3.4 over CCID: three key slots (signature, decryption,
authentication), works with stock GnuPG. The same slots cover commit signing,
SSH login (via gpg-agent), and end-to-end mail/file encryption.

Prereqs: on Linux, `pcscd` + the `scdaemon.conf` lines from
[linux.md](../linux.md). Check the card is visible:

```sh
gpg --card-status            # reader: RS-Key Security Key …, OpenPGP v3.4
```

gpg works regardless of the reader name. scdaemon identifies the card by its
ATR and applet SELECT, not the USB identity. The default build reports the
reader as "RS-Key"; the opt-in `VIDPID=Yubikey5` flavor reports it as "Yubico
YubiKey" ([build.md](../build.md)).

## PINs

| | Default | Length | Unlocks |
|---|---|---|---|
| User PIN (PW1) | `123456` | 6–127 | signing, decryption, authentication |
| Admin PIN (PW3) | `12345678` | 8–127 | key import/generation, card settings |
| Reset Code (RC) | unset | 8–127 | unblocking PW1 without PW3 |

Those columns are exclusive: the admin PIN authorises no key operation. It
cannot sign, decrypt or authenticate, however recently it was entered — that is
the card spec's rule and what a YubiKey does. (Earlier RS-Key builds let PW3
stand in for PW1 here. If you have a script that unlocks signing with the admin
PIN, it needs the user PIN now.)

The card enforces those lengths itself: a `CHANGE REFERENCE DATA` or `RESET
RETRY COUNTER` carrying a new value outside the range is refused with `6700`,
whatever the host's own policy is. gpg applies the same `≥ 6` / `≥ 8` minima
before it ever reaches the card. A shorter reference stored by an older firmware
keeps verifying; only new ones are checked.

A fresh card has **no** Reset Code. It stays deactivated until an admin sets one
(`passwd` option 4, below), so `RESET RETRY COUNTER` in its RC form cannot run
against a known default.

Each PIN has its **own retry counter**, default **3**. A correct entry resets
that PIN's counter. A wrong one decrements it. `gpg --card-status` prints them
as `PIN retry counter : 3 3 3` (PW1, RC, PW3: all three default to 3).

Change them first:

```sh
gpg --card-edit
gpg/card> admin
gpg/card> passwd            # menu: 1 change PW1 · 3 change PW3 · 4 set Reset Code
```

The same menu sets the **Reset Code** (option 4, under `admin`), which lets a
holder who has forgotten PW1 reset it *without* the admin PIN. Useful when the
admin PIN lives somewhere offline.

**Two ways admin operations lock:**

- **Three wrong PW3** blocks the admin PIN. Unlike PW1, the admin PIN has no
  higher authority to unblock it. Recovery is a **factory reset** of the
  applet (below). Plan to keep PW3 written down somewhere offline.
- **Three wrong PW1** blocks the user PIN. This one *is* recoverable: unblock it
  with the admin PIN or the Reset Code (see [Unblocking PW1](#unblocking-pw1)).

## Generate keys on-card

```sh
gpg --card-edit
gpg/card> admin
gpg/card> key-attr           # per slot, pick the algorithm (table below)
gpg/card> generate           # makes all three keys + a gpg keyring entry
```

`key-attr` is asked once **per slot** (signature, then encryption, then
authentication), so you can mix: e.g. Ed25519 for signing and authentication,
Cv25519 for encryption (gpg's default modern pair), or RSA across the board.

Supported per-slot attributes (advertised via DO `0xFA`, the list `ykman` and
gpg read back):

| Family | Choices | Notes |
|---|---|---|
| ECC (sign/auth) | **Ed25519**, NIST **P-256 / P-384 / P-521**, **secp256k1**, **brainpoolP256r1 / P384r1** | EdDSA on Ed25519; ECDSA on the Weierstrass curves |
| ECC (encrypt) | **Cv25519** (X25519), NIST **P-256 / P-384 / P-521**, **secp256k1**, **brainpoolP256r1 / P384r1** | ECDH; the DEC slot only |
| RSA | **2048 / 3072 / 4096**, plus **1024** | exponent fixed at 65537 (what gpg imports) |

**RSA-1024 is advertised and it works** — a YubiKey does not offer it at all.
It is below every current guidance (NIST SP 800-131A retired it in 2013) and it
is here only so a key generated under an older build keeps working. Do not pick
it for a new key.

Not supported. gpg will offer them, and the card even accepts the `key-attr`
write, but **GENERATE / keytocard** then refuses with `0x6A81` "Function not
supported": **X448**, **Ed448**, and **brainpoolP512r1**. (X448 and Ed448 still
appear in the `0xFA` advertisement but are non-functional; brainpoolP512r1 is not
advertised.) No mature `no_std` Rust arithmetic exists for those yet, so shipping
them would mean unaudited curve math.

On-card generation means the private keys never existed anywhere else, and
**cannot be backed up**. gpg's "make an off-card backup" prompt covers the
**encryption key only**, and only if you say yes. (A lost signing or
authentication key is regenerated, not recovered.) RSA generation is slow on
this hardware. The firmware races both RP2350 cores for the two primes and
streams CCID keepalives while gpg waits:

| Size | Typical on-card keygen |
|---|---|
| RSA-2048 | ≈ 4–6 s |
| RSA-3072 | ≈ 22 s |
| RSA-4096 | ≈ 50 s |
| any EC curve | instant |

The spread is wide because the prime search is random. RSA-4096 has been seen
anywhere from ~17 s to ~120 s on the same board. See
[../limitations.md](../limitations.md) for the measured dual-core numbers. EC
is the pragmatic default unless a peer needs RSA.

## Or import existing keys

If you already have a GnuPG key (and want a recoverable off-card copy), import
the subkeys instead of generating:

```sh
gpg --expert --edit-key YOURKEY
gpg> toggle                  # show secret subkeys (ssb)
gpg> key 1                   # select the subkey to move (repeat per subkey)
gpg> keytocard               # pick the matching slot: 1 sig · 2 enc · 3 auth
gpg> save
```

`keytocard` *moves* the selected subkey onto the card, replacing the on-disk
copy with a stub that points at the device. Set `key-attr` to match the
incoming key's algorithm **before** `keytocard`, or the card refuses the import.
The **size** counts as much as the family: a 2048-bit key offered to a slot
announcing RSA-4096 is refused, because the attribute is what `gpg
--card-status` and every other host reads back as the truth about that slot.
A mismatched algorithm/curve/size returns "Wrong data" / "Function not supported"
and a missing admin (PW3) session returns "Security status not satisfied". gpg
surfaces one of these as a card refusal.

Importing keeps an off-card copy in your keyring until you delete it. Your call
which way the trade-off goes. The usual recoverable setup: generate the master
key **offline**, move only the three subkeys to the card, and store the master
key material on encrypted offline media.

The card records which way each slot was filled and reports it in DO `0xDE`,
because that is the difference between a key that can only exist here and one
that has a copy somewhere. A slot filled by a build older than this one, or one
whose GENERATE lost power partway, reads as **imported**: the card will not
claim on-card generation it cannot prove. Generate into the slot again if you
want the stronger claim back.

## Daily use

### Signing and decryption

```sh
echo hi | gpg --clearsign                 # PW1, then a touch if UIF is on
gpg --encrypt -r alice@example.com file    # public-key op, no card needed
gpg --decrypt file.gpg                     # PW1 (PW2), card does the ECDH/RSA
```

gpg drives the slots automatically: the SIG slot signs, the DEC slot decrypts.
Encryption *to* a recipient is a public-key operation and never touches the
card. Only **decryption** does.

By default PW1 stays valid for the session after the first signature. That
session ends when the key is unplugged or another application is selected on the
card — a PIV or OATH tool reaching for the same key mid-session does exactly
that. Selecting **OpenPGP** again does not end it (§4.2 spends its rule on "a
SELECT to a *different* DF"), so a tool that re-selects before each command keeps
the PIN it already gave. To force a PIN on **every** signature, flip the PW1
status byte:

```sh
gpg/card> admin
gpg/card> forcesig          # toggles "PW1 valid for one signature only"
```

### SSH authentication via gpg-agent

The AUT slot doubles as an SSH key through gpg-agent:

```sh
# one-time agent setup
echo enable-ssh-support >> ~/.gnupg/gpg-agent.conf
gpgconf --kill gpg-agent

# add the authentication subkey's keygrip to sshcontrol
gpg --list-keys --with-keygrip YOURKEY     # find the [A] subkey's keygrip
echo <KEYGRIP> >> ~/.gnupg/sshcontrol

# export the public key in OpenSSH format and install it
gpg --export-ssh-key YOURKEY > ~/.ssh/id_rsk.pub
ssh-copy-id -f -i ~/.ssh/id_rsk.pub you@server
```

Then `export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)` (in your
shell rc) and `ssh you@server` prompts for PW1 and logs in. This is the
standard gpg-agent recipe, nothing device-specific.

> For FIDO-backed SSH (`ed25519-sk`, no gpg) see [ssh.md](ssh.md); for signing
> git commits and tags with the SIG slot see [git.md](git.md).

### Touch policies (UIF)

Each slot has an independent **user-interaction flag**. When on, every use of
that key additionally requires a button press. The firmware polls the BOOTSEL
button and fails the operation (`0x6600`) if it is not pressed in time. PIN
alone is no longer enough. A remote attacker holding your unlocked session
still cannot sign or decrypt without physical access.

```sh
gpg/card> admin
gpg/card> uif 1 on          # 1 sig · 2 enc · 3 auth   (off to disable)
gpg/card> uif 1 permanent   # irreversible: only a factory reset clears it
```

UIF is per-slot, so you can require a touch for signing but not decryption, or
any mix. On a board with no button configured the check is a no-op.

`on` is revocable with the admin PIN, so it protects against a stolen *user* PIN,
not a stolen admin PIN. `permanent` (the card's UIF value `02`) cannot be lowered
by any command — `PUT DATA` answers `6985` — so a host that learns PW3 still
cannot turn your signatures touchless. Clearing it takes `TERMINATE DF` +
`ACTIVATE FILE`, which wipes the applet. Set it only when you mean it.

## AES encryption (PSO)

The DEC slot carries an on-card **AES-256** key, minted automatically whenever
the encryption keypair is generated. Tools that expose the card's symmetric
PSO (e.g. `gpg-card`) can `ENCIPHER` / `DECIPHER` arbitrary block-aligned data
with it (raw AES-CBC, zero IV; output is `0x02 || cryptogram`). It needs PW1
(PW2). Most users never touch this. Public-key encryption is the normal path.

## Recovery and reset

### Unblocking PW1

Three wrong user-PIN tries block PW1 but not the keys. Two ways back:

```sh
# with the admin PIN
gpg --card-edit
gpg/card> admin
gpg/card> unblock           # verify PW3, set a new PW1

# or with the Reset Code, if one was set (no admin PIN needed)
gpg/card> passwd            # menu option 2: "unblock PIN" via Reset Code
```

Both reset PW1's retry counter and re-seal its key material under the new PIN.

### A PIN change interrupted by unplugging the key

Changing a PIN rewrites two things: the PIN's verifier, and the copy of the key
that PIN unwraps. Pull the key out of the port between the two — during
`gpg --change-pin` — and the card reports a memory error.

Since firmware `0x0889` the card finishes the interrupted change itself on the
next `VERIFY`, so there is nothing to do. **On an older build the card comes back
in a state that looks fatal and is not:** the affected PIN verifies, and every
operation that needs a key answers *"Card error"*. Do **not** factory-reset it.

The card keeps one copy of the key per PIN and only the copy belonging to the PIN
you changed was damaged, so the repair is to reach the key through a *different*
PIN. Which one depends on which PIN you were changing, and the two recipes are
not interchangeable:

**The admin PIN (PW3) was being changed** — verify the user PIN first, in the
same session, then change PW3 again:

```sh
gpg --card-edit
gpg/card> verify            # PW1 — its copy of the key is untouched
gpg/card> admin
gpg/card> passwd            # change PW3 again; the card is repaired
```

**The user PIN (PW1) was being changed** — use the admin unblock, and do **not**
verify PW1 anywhere in that session:

```sh
gpg --card-edit
gpg/card> admin
gpg/card> passwd            # menu option 1, "unblock PIN" — sets PW1 via PW3
```

The order matters for a reason worth knowing: the card reaches for PW1's copy of
the key whenever PW1 is verified, ahead of the admin's. So for a torn PW1 change,
verifying PW1 — even with the PIN that now works — puts the damaged copy back in
front and the repair fails. `unblock` never verifies PW1, which is why it is the
one that works there.

### Factory reset (OpenPGP only)

```sh
rsk openpgp reset      # or: gpg --card-edit → admin → factory-reset
```

`rsk openpgp reset` blocks both PINs, then drives the spec-compliant
`TERMINATE` (0xE6) + `ACTIVATE` (0x44) and reseeds factory defaults
(PW1 `123456`, PW3 `12345678`). It wipes the OpenPGP applet (keys, PINs, DOs,
reset code) and **nothing else**. FIDO / PIV / OATH / OTP survive (the
TERMINATE is scoped to the OpenPGP FIDs). This is also the only way out of a
PW3 that you have blocked: a blocked admin PIN cannot be unblocked, only reset
away, along with the keys it protected. It also works when the admin verifier
itself is unusable — a card provisioned by an older firmware with an empty PW3
could otherwise neither verify nor terminate, leaving a device-wide factory reset
as the only escape.

It is destructive but idempotent, so it is the clean way to clear non-default
PINs a prior gpg session left behind (which otherwise block the test suite at
VERIFY).

## Troubleshooting

- `gpg: selecting card failed: No such device` → scdaemon vs pcscd fight;
  apply [linux.md](../linux.md)'s `disable-ccid`, then
  `gpgconf --kill scdaemon`.
- `ykman` stops seeing the device after gpg used it → same fix; gpg's scdaemon
  holds the reader. `gpgconf --kill scdaemon` releases it.
- A card refusal on `keytocard` / `generate` (gpg may report "Function not
  supported", "Wrong data", or "Security status not satisfied") → the slot's
  `key-attr` doesn't match the key, or you skipped `admin` (no PW3 session).
- `gpg --card-status` shows `PIN retry counter : 0 …` → that PIN is blocked;
  see [Recovery and reset](#recovery-and-reset).
- RSA `generate` seems to hang → it isn't; on-card RSA keygen takes the times
  above and gpg shows no progress bar. Wait it out, or use an EC curve.
- `ykman openpgp info` (needs the opt-in `VIDPID=Yubikey5` build: `ykman` only
  sees the device when the reader name contains "Yubico YubiKey") →
  `ERROR: Incorrect TLV length` on firmware **before
  `0x0759`**: the GET DATA `6E` reply was missing its constructed-DO wrapper,
  which ykman's strict parser requires (`gpg` tolerated it). Fixed in `0x0759`;
  flash it and re-run. See [interop.md](../interop.md#known-issues).
