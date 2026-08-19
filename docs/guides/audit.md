# Audit journal

A tamper-evident, on-device log of security events: boots, FIDO registrations
and logins, factory resets, PIN set/change/lockouts, policy changes, seed
backup and soft-lock activity.

```sh
rsk audit log              # export + print (add --pin if a PIN is set)
rsk audit verify           # log + DEVK-signed checkpoint (touch)
rsk audit verify --expect-key <hex>   # also pin the enrolled attestation key
```

`log` is a plain read. It pretty-prints the live window and the recomputed
chain head, no signature. It takes `--pin` on a device with a PIN, and a touch
on one with none (the read is never fully open). `verify` does the same read
*and* asks the device to sign the head. It is the command that actually proves
the log is real. Use `log` for a quick glance, `verify` when the answer matters.

## What it records

| event | detail |
|---|---|
| `BOOT` | first journal touch of each power cycle |
| `MAKE_CREDENTIAL` / `GET_ASSERTION` / `U2F_REGISTER` / `U2F_AUTH` | first 8 bytes of the rpIdHash (only *weakly* pseudonymous, see [Gating](#gating)). A run of the two *silent* variants folds — see below |
| `RESET` | factory reset (survives it — see below) |
| `PIN_SET` / `PIN_CHANGE` / `PIN_LOCKOUT` | lockout aux: 0 = retries exhausted, 1 = per-boot block |
| `CFG_MIN_PIN` | aux = new minimum; detail[0] = forceChangePin |
| `CFG_ENTERPRISE_ATT` | no aux/detail (flag-only) |
| `CFG_EA_RPIDS` | the vendor-facilitated [enterprise](attestation.md) RP list was rewritten; aux = how many RPs it now holds, `0` = cleared |
| `LOCK_ENGAGE` / `LOCK_RELEASE` | [soft-lock](soft-lock.md) engage/release |
| `BACKUP_EXPORT` / `BACKUP_LOAD` / `BACKUP_FINALIZE` | [seed-backup](seed-backup.md) lifecycle |
| `ATT_IMPORT` / `ATT_CLEAR` | [org attestation](attestation.md) provisioning |
| `CFG_ALWAYS_UV` | alwaysUv toggled; no aux/detail (flag-only) |
| `CONFIG_WRITE` | a device-config write over the FIDO vendor channel. aux = the target that opened the entry (`0` dev-conf, `1` phy, `2` led); detail = `repeats(2 LE) ‖ targets(1)` (see below) |
| `AUDIT_CFG` | journalling itself: aux `1` = turned on, `0` = turned off (that entry is the last one written, so the trail shows when it stopped) |
| `CHECKPOINT` | every signed checkpoint is itself logged |

Each entry is a fixed 20 bytes:
`seq(4) ‖ uptime_ms(4) ‖ event(1) ‖ aux(1) ‖ detail(8) ‖ repeats(2 LE)`. There is
**no wall clock** on the device. `uptime_ms` counts from the moment the key
*attached to USB*, not from power-on — boot spends seconds before that on TRNG
seeding and flash migrations, and none of it is time a host could have used.
Every power cycle opens with a `BOOT` entry, and the sequence number gives total
order. Wall-clock attribution is the host's job (e.g. record when you ran
`rsk audit verify`).

For the FIDO operations — `MAKE_CREDENTIAL`, `GET_ASSERTION`, `U2F_REGISTER`,
`U2F_AUTH` — the `detail` field carries the **first 8 bytes of the rpIdHash** and
nothing else: no RP names, user handles, or credential IDs. That is deliberate:
the log answers "how was this key used and how often" without revealing *which
sites*. See [gating](#gating) below. Other events use `detail` for their own small
payload (`CFG_MIN_PIN`'s forceChangePin flag, `CONFIG_WRITE`'s run counters); none
of them records a site.

### Events a silent host can drive cost one slot per run

The journal is append-only with one bounded exception. Three events can be
driven on demand with no touch and no PIN, so 128 of any one of them would
otherwise evict every other entry from the 128-slot window:

- `CONFIG_WRITE`, [ungated on the default build](../protocol.md);
- `GET_ASSERTION` from a `getAssertion` carrying `up:false` — the spec-mandated
  silent pre-flight, which needs a credential but no gesture;
- `U2F_AUTH` from an `AUTHENTICATE` with `P1=0x08` (don't-enforce-user-presence),
  for the same reason.

Each folds a *run* into a single entry that keeps the `seq` and the timestamp of
the **first** occurrence. The two shapes differ in where the count lives.
`CONFIG_WRITE` carries its own inside `detail` — `repeats(2 LE) ‖ targets(1)`,
where `targets` is a `1 << target` mask of every record the run touched — and
folds only into the newest entry. The two silent FIDO events instead keep the
`detail` of the first occurrence (so the rpIdHash shown is the first site of the
run) and count the rest in the entry's trailing `repeats(2 LE)`, scanning the
whole window rather than only the newest entry, so interleaving two of them does
not defeat the fold. A gestured assertion always earns its own slot.
`rsk audit log` renders both:

```text
   seq      uptime  event              aux  detail
   201       8.2s  CONFIG_WRITE         1  300× write (phy+led)
   202       9.1s  GET_ASSERTION        0  a3f1c2...  ×128
```

Two consequences worth knowing:

- **A run never folds across a power cycle**, so the `BOOT` entry between two runs
  is never swallowed.
- **A fold moves the chain head without advancing `seq_next`.** Seeing the same
  `seq_next` with a different head is legitimate, not a tamper signal; `verify`
  re-folds the exported window and still matches.

This bounds the flood, it does not remove it: a phy write latches a reboot, so a
host willing to make the key re-enumerate can still spend two slots per cycle
(a fresh `BOOT` plus a fresh run). Each cycle is a visible re-enumeration, and
building `--features strict-config` — which puts the write behind a touch and a
PIN token — is the complete answer.

A `log` run prints a header, the chain state, then the window:

```text
window [72, 200)  —  128 entries, 72 folded into the epoch
epoch : 4f1c…           (the accumulator for evicted history)
head  : a93b…  (chain over the window — OK)

   seq      uptime  event              aux  detail
    72       3.4s  GET_ASSERTION        0  1a2b3c4d5e6f7081
    73     120.9s  MAKE_CREDENTIAL      0  9f8e7d6c5b4a3928
   …
```

## How the tamper evidence works

The journal is a 128-entry flash ring. Each entry extends a SHA-256 hash
chain; when the ring is full, the oldest entry is folded into an **epoch**
accumulator (`epoch' = SHA-256(epoch ‖ entry)`) before its slot is reused, so
evicted history stays attested in aggregate even though its per-event details
are gone. The chain head is `fold(epoch, window)`: the epoch run forward
through every entry still in the ring.

The chain is anchored, on an empty journal, at
`SHA-256("RSK-AUDIT-GENESIS-v1" ‖ serial_hash)`, bound to the device so two
boards' empty journals never share a head.

```mermaid
flowchart TD
    e["new event"] --> chain["SHA-256 hash chain (window)"]
    chain -->|ring full| fold["fold oldest into epoch accumulator"]
    fold --> reuse["slot reused"]
    chain --> head["chain head = fold(epoch, window)"]
```

`rsk audit verify` sends a fresh 16-byte random challenge. The device signs
`"RSK-AUDIT-CKPT-v1" ‖ head ‖ seq_next ‖ challenge` with an ECDSA P-256 key
derived (HKDF) from the **OTP DEVK** ([production.md](../production.md) stage 1)
and returns the signature plus its 65-byte SEC1 public key. The host refolds
the exported window, verifies the signature over the message *it* reconstructs,
and checks that the signed head matches the refold. The challenge is what makes
the verdict fresh. A replayed old checkpoint signs a stale challenge and fails.

A successful `verify` prints the window, the head, and the attestation key with
a short fingerprint. The verdict depends on whether you pinned the key:

```text
chain   : OK — head a93b…
sig     : OK — checkpoint over seq_next=201, fresh challenge
att key : 04a1b2…   (65-byte SEC1)
          fingerprint 9c4e7f12ab… — record this; pin later runs with --expect-key
verdict : chain + signature OK — the key is NOT pinned, so this does not prove
          which device signed it
```

With `--expect-key` the last line becomes
`journal authentic ✓ (signed by the pinned key)`.

Meta updates are ordered so that a power cut at any point loses at most the
newest event and never produces a false tamper verdict: when the ring is full
the fold-and-advance meta is committed *before* the slot is reused.

## Pinning the attestation key — `--expect-key`

The checkpoint key is deterministic and reset-stable (HKDF of the DEVK), so a
given device always signs with the same public key. Record it once at
provisioning, then pass it back on every later run:

```sh
rsk audit verify                         # first run: copy the printed "att key" hex
rsk audit verify --expect-key 04a1b2…    # afterwards: fail loudly on any mismatch
rsk audit verify --expect-key 9c4e7f12ab…   # the short fingerprint works too
```

A mismatch means the public key changed, which can only happen if the DEVK
changed. That means you are talking to a **different device**, or a clone that
was flashed without burning the same OTP. `--expect-key` takes either the full
65-byte SEC1 point (`04 ‖ x ‖ y`) or the 16-hex fingerprint, lower-case, and the
comparison is exact. The full key is the stronger pin. Stash it in your
provisioning record alongside the device serial.

**Without a pin, `verify` proves nothing about identity.** The public key it
checks against arrives in the same response it is checking, so an unpinned run
establishes only that the journal is internally consistent and self-signed — a
counterfeit signing with a key of its own passes it. The device refuses to sign
without an OTP DEVK, but a host cannot tell a DEVK-derived key from any other
P-256 point. Pinning is what turns "some key" into "*your* device".

## Reset semantics (privacy by design)

`authenticatorReset` does **not** erase the journal. It *folds* the whole
window into the epoch and deletes the per-event details, then logs the
`RESET`. A handed-over device therefore proves "N events happened, then a
reset" without revealing where it had been used. The chain (and the
checkpoint key, which is DEVK-derived) continue uninterrupted across resets, so
`verify` keeps working and the head still validates against the same
`--expect-key`.

## Gating

| command | open device | PIN set |
|---|---|---|
| `audit log` / `AUDIT_READ` | touch | pinUvAuthToken with the `acfg` permission |
| `audit verify` / `AUDIT_CHECKPOINT` | touch | touch **+** `acfg` pinUvAuthToken |

- **`AUDIT_READ` (export).** With a PIN set it needs a pinUvAuthToken carrying
  the `acfg` (authenticator-config) permission. With no PIN it needs a physical
  touch. The entries are only *weakly* pseudonymous. A `detail` is a 64-bit
  rpIdHash prefix, never an RP name or user handle, but short enough to be
  dictionary-matched back to a domain. So the touch is what stops a silent host
  from harvesting a no-PIN device's RP-usage history.
- **`AUDIT_CHECKPOINT`.** The same PIN gate **plus a physical touch**, and it
  refuses entirely without a provisioned OTP DEVK. An attestation that anyone
  could re-derive would be theatre. The signing step is what the touch protects.
  The read that precedes it is `AUDIT_READ`-gated as above.

If a PIN is set, both subcommands take `--pin`. The PIN is exchanged over the
standard CTAP pinUvAuth protocol (it is not sent in clear), and a wrong PIN
counts against the FIDO retry counter. Do not guess.

## Troubleshooting

| symptom | meaning / fix |
|---|---|
| `device requires a PIN — pass --pin` (status `0x36`) | a FIDO PIN is set; add `--pin <pin>` |
| `checkpoint refused — no OTP DEVK provisioned` (status `0x30`) | dev board with no DEVK burned; `verify` cannot sign. `log` still works. See [production.md](../production.md) |
| `denied — no touch within 30 s` (status `0x27`) | press the button when the LED blinks; rerun |
| `attestation key MISMATCH — this is not the enrolled device` | `--expect-key` did not match: wrong device, or a clone flashed without your OTP |
| `signed head differs from the exported window` | the journal changed between the read and the checkpoint. Rerun; if it persists, treat it as **TAMPER** |
| `checkpoint SIGNATURE INVALID — do not trust this journal` | the signature did not verify under the returned key. Do not trust the log |
| `export length does not match the window` | the exported entry bytes don't match `seq_next − start`; a corrupt or truncated read |

The two "rerun first" verdicts are different. A head mismatch can happen
benignly if an event landed between the read and the checkpoint (a login on
another host, say). One rerun usually clears it. A signature failure or a key
mismatch never has a benign cause. Do not retry your way past those.

## What it does and does not prove

The log is written by the firmware, so its honesty is rooted in the boot
chain: with **secure boot + the OTP master key** ([production.md](../production.md),
[otp-fuses.md](../otp-fuses.md)) only your signed firmware can append to the
journal or wield the checkpoint key, and a flash dump cannot forge it. On an
unprovisioned dev board the journal still works as a debugging aid, but `verify`
is refused. There is no device-bound key to sign with, and a checkpoint without
one would prove nothing.

Two honest limits worth stating:

- **The window is 128 entries.** Older events are folded into the epoch and
  their *details* are gone. You can prove they happened (the head still
  covers them) but not read them back. `verify` regularly if you want a
  per-event record. The host transcript is your archive, the device is not.
- **There is no wall clock.** The device cannot tell you *when* in calendar
  time something happened, only the order and the milliseconds since that power
  cycle's USB attach. Pair the `seq` and `BOOT` markers with your own host-side
  timestamps.
