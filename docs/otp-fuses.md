<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# OTP fuses (RP2350)

The "production" hardening in RS-Key comes down to writing the RP2350's **OTP**:
the OTP master key, secure boot, and anti-rollback. This page explains what OTP
is, why it is irreversible, how RS-Key writes it, and exactly which rows it
touches. Read it before [production.md](production.md). It is the substrate
everything else stands on.

> "OTP" here means **One-Time-Programmable fuses on the chip**, not the Yubico
> one-time-password feature ([guides/otp.md](guides/otp.md)). Different thing,
> same three letters.

## What OTP is

OTP is a block of on-chip memory made of **antifuses**: writing a bit physically
and permanently changes the silicon. A bit goes **0 → 1 and never back.** There
is no erase, no reset, no "factory default". For OTP, *factory* is wherever you
left it. Every chip has its own OTP. Nothing about it is shared between boards.

This is the whole point. The value of OTP for a security key is exactly that it
**cannot be undone**: a key fused here can't be un-fused, a secure-boot bit
can't be cleared, a rollback floor can't be lowered. Hardening that you could
reverse would be hardening an attacker could reverse too.

> ⚠️ **Every write on this page is permanent.** A mistake can lock you out of
> reading a value forever, or brick the board for new firmware. The tools refuse
> to act without typed confirmations and support `--dry-run`. Use it.

## Layout: pages, rows, and reliability copies

OTP is addressed in **rows** (24 bits each), grouped into **pages of 64 rows**
(so page *N* starts at row `N × 0x40`; page 58 begins at row `0xE80`). Page
granularity matters because **read/write locks are applied per page**, not per
row.

A single antifuse can be marginal, so the values that the bootrom and firmware
depend on are stored redundantly:

- **RBIT-3**: the value is written into **three consecutive rows**, and the
  reader takes the **bitwise 2-of-3 majority**. An interrupted burn that set
  only one copy doesn't count. Two copies do. The secure-boot flags, the
  boot-key fingerprints, and the rollback rows are all RBIT-3.
- **ECC**: other pages store an error-correcting code alongside the data.

## Who can write OTP, and when

Two paths write OTP, and the difference is central to how RS-Key stays safe:

- **BOOTSEL / `picotool`**: with the board in BOOTSEL you can read and write OTP
  directly from the host. This is how the bulk of provisioning happens (the
  master key, the secure-boot key, the enable bits).
- **Secure firmware (the rescue applet)**: a handful of rows must be written by
  the running, secure-boot-validated firmware, not from BOOTSEL. Two cases:
  - rows that are made **bootloader-read-only** by a page lock (so BOOTSEL can no
    longer write them) but stay **secure-writable**. The page-58 lock and the
    `ROLLBACK_REQUIRED` flag are applied this way, by `rsk otp lock-page58` /
    `rsk otp rollback-require`, each guarded by an exact magic payload so a
    stray APDU can never trigger them.

Each OTP page lock is a byte encoding three independent levels: `LOCK_BL`
(bootloader), `LOCK_NS` (non-secure), `LOCK_S` (secure), each of `read-write` /
`read-only` / `inaccessible`. That three-way split is what lets a page be
**unreadable to BOOTSEL but still readable/writable by secure firmware** (see
page 58 below).

## What RS-Key burns

These are the rows RS-Key provisions, grouped by the stage that writes them. The
authoritative source is the code (`tools/rsk/otp.py`, `tools/rsk/secureboot.py`,
`crates/rsk-rescue/src/rollback.rs`). The table is the map.

| Region | Rows | What it holds | Written by |
|---|---|---|---|
| **Page 58** | `0xE80…` | `DEVK` (device attestation key), `MKEK` (master sealing key), anti-imaging chaff | `rsk otp burn` (BOOTSEL) |
| Page-58 lock | `0xFF5` | makes page 58 **BOOTSEL-unreadable, secure read/write** | `rsk otp lock-page58` (firmware) |
| **Boot key** | `0x80…` | `SHA-256` fingerprint of your secure-boot public key (slot 0 of 4) | `rsk secure-boot load-key <otp.json>` |
| `BOOT_FLAGS1` | `0x4B` | `KEY_VALID` / `KEY_INVALID` (which key slots are live / revoked) | `load-key`, `lock` |
| `CRIT1` | `0x40` | `SECURE_BOOT_ENABLE`, `DEBUG_DISABLE`, `GLITCH_DETECTOR_ENABLE/SENS` | `harden`, `enable` |
| `BOOT_FLAGS0` | `0x48` | `ROLLBACK_REQUIRED` (bit 11) | `rsk otp rollback-require` (firmware) |
| `DEFAULT_BOOT_VERSION` | `0x4E`, `0x51` | the **48-bit rollback thermometer** (two 24-bit rows) | the bootrom, on boot |
| Page 1/2 locks | `0xF83`, `0xF85` | make the flag + key pages **bootloader-read-only** | `rsk secure-boot lock` |

A few notes that matter:

- **Page 58 is read-write to secure firmware even after the lock.** The lock
  value (`0x3C3C3C`) sets BL and NS to *inaccessible* but leaves S
  *read-write*. So only secure-mode firmware can ever read the MKEK/DEVK again,
  and a BOOTSEL flash dump cannot.
- **The MKEK/DEVK are generated randomly and forgotten.** `rsk otp burn` does not
  keep a copy. The fuses *are* the key. There is nothing to back up and nothing
  to lose.
- **The rollback thermometer is advanced by the bootrom**, not by a host write,
  when a higher-version image boots. See [anti-rollback.md](anti-rollback.md).
- **Pages 1 and 2 stay bootloader-*read-only* after `lock`** (`0x141414`), not
  inaccessible. The bootrom must read the keys and flags on every boot. They
  remain secure-writable, which is how the firmware applies `ROLLBACK_REQUIRED`
  after the pages are otherwise locked down.

![OTP fuse map. The rows RS-Key provisions grouped by page: page 1 boot-policy flags (CRIT1, BOOT_FLAGS0/1, the 48-bit rollback thermometer), page 2 boot-key fingerprint, page 58 DEVK and MKEK with high-half complement chaff, and the lock rows. Each row coloured by whether picotool over BOOTSEL, the secure firmware, or the bootrom writes it](images/otp-fuse-map.svg)

### Anti-imaging chaff

Page 58 stores the keys in its **low half** and the bitwise **complement** of
every key row in its **high half**: `DEVK` at `0xE80…0xE8F` with its complement at
`0xEA0`, `MKEK` at `0xE90…0xE9F` with its complement at `0xEB0` (offset `0x20` =
half a page). The firmware never reads the high half. It plays no part in key
reconstruction (`firmware/src/otp_keys.rs` reads only the key rows). It exists for
one reason.

The cheapest invasive OTP read demonstrated against this antifuse family
(IOActive, RP2350 Challenge 1, see [threat-model.md](threat-model.md)) recovers
the bitwise **OR of two physically paired bitcell rows**, not the rows
individually. Raspberry Pi's mitigation is to put the key in one half of a page
and its complement in the opposite half, so each physical pair reads
`OR(b, ¬b) = 1`, a uniform all-ones pattern that carries no key bits. The
low-half / high-half placement here is exactly that scheme, and it neutralises the
demonstrated readout.

> This defeats the *demonstrated* OR-read. IOActive note that a
> more advanced attack might separate the paired (even/odd) rows with additional
> effort, which would read the key half directly, and a plain complement does not
> stop that. Raspberry Pi have said a forthcoming application note will describe a
> storage scheme mitigating both the current attack and that hypothetical one. If
> it prescribes more than complement-in-opposite-half, revisit this.

## Reading OTP

OTP is readable until a lock says otherwise:

```sh
rsk secure-boot status        # decodes the secure-boot + rollback rows for you
picotool otp get -r -n 0x48   # raw row read (BOOTSEL), if you want the bytes
```

`rsk inventory list` / `rsk status` surface the human-readable state. Once page
58 is locked, `picotool otp get` on it fails with a permission error forever.
That failure is the lock working, not a fault.

## Honest limits

- **OTP is not a secure element.** It hardens against software- and BOOTSEL-level
  attacks, and the anti-imaging chaff above neutralises the demonstrated
  passive-voltage-contrast OTP readout. But the antifuses are still on a
  general-purpose die: a funded lab with a focused ion beam can image them, and
  that (like laser fault injection and power/EM analysis) is out of scope
  ([threat-model.md](threat-model.md)). The antifuse readout is not fixed by any
  silicon stepping. Use A4 for the fault and boot-ROM fixes (our own boards are
  A2, the stepping broken in the public challenge).
- **It is finite.** The rollback thermometer is 48 bits for the board's life.
  There are 4 key slots. Neither resets. See [anti-rollback.md](anti-rollback.md).
- **It is per-chip.** None of this carries to another board. A new board is a
  fresh, blank OTP.
