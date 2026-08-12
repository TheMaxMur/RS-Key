<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Changelog

All notable changes to RS-Key are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and **releases** are
versioned with [SemVer](https://semver.org/).

Two other version numbers live in the firmware and are deliberately **not** this
tag: the USB `bcdDevice` build counter (bumped on every behavior change), and
`FW_VERSION` — the YubiKey-compatibility version reported to host tools (5.7.4).

> ## ⚠️ Upgrading a 16 MB key provisioned before 0.4.8 wipes it
>
> **Export your seed first** ([seed backup](docs/guides/seed-backup.md)).
>
> 0.4.7 gave every image a partition table that fenced the KV store off BOOTSEL.
> On a 16 MB part that table claimed the chip's last sector — which holds
> `0x10FFFF00`, the absolute block the bootrom's RP2350-E10 workaround owns — and
> `picotool` refuses to hand it over, so the 16 MB images never built and 0.4.7
> was never published. **0.4.8 stops the layout one sector short of the top, and
> that moves the store 4 KB down.** A key provisioned with an older 16 MB build
> comes up factory-empty: no passkeys, no OpenPGP or PIV keys, no OATH
> credentials.
>
> This affects the 16 MB flavors only — `display` and `16mb`, and the
> `abrobot-16m` and `waveshare-touch-lcd` board presets. **4 MB and 2 MB keys
> upgrade in place**: their stores end far below the E10 block and their layouts
> are byte-identical to 0.4.7.
>
> Kept here as well as in the release's own notes below: this banner is for
> whoever opens the file, and the copy inside the release section is what the
> release page shows — `release-build.yml` builds the notes from that section
> alone, so a warning only at the top would never reach it. **Carry the copy
> forward into each new version's section while pre-0.4.8 16 MB keys are still
> out there.**

## [Unreleased]

### Security

- **⚠️ The OpenPGP admin PIN no longer authorises any key operation. This
  removes something that works today.** §7.2.10 gives `PSO:CDS` the access
  condition PW1 no. 81, §7.2.11 gives `PSO:DECIPHER` PW1 no. 82 and §7.2.13
  gives `INTERNAL AUTHENTICATE` the same; none of them names PW3. The applet
  accepted PW3 in place of all three, with a comment saying it was "for parity
  with the cards in the field" — and the only card in the field we can measure
  contradicts it. A YubiKey 5.7.4 answers `6982` to PW3 alone on all three
  operations, three runs of the full 8 × 3 latch matrix, cell for cell. Three
  rows of that matrix change here: PW3 alone, PW1.81 + PW3, and PW1.82 + PW3 —
  a session holding the admin PIN plus the wrong PW1 mode used to get
  everything. The AES `PSO` was swept with them (§7.2.11 names PW1 no. 82; that
  card has no AES DO to measure, so the spec decides and its siblings' rule
  applies). **If you have a script or habit that unlocks signing with the admin
  PIN, it needs the user PIN now**; `docs/guides/openpgp.md` says so, and its
  PIN table already described the narrower rule. `gpg` and `gpg-agent` are
  unaffected — they verify PW1 for these operations, which is why nothing
  caught this. Six host tests and five `tests/*.py` suites verified only PW3
  before a crypto operation and are corrected in the same change; the
  `forcesig` special case in `pso.rs` existed only to stop PW3 standing in when
  PW1 was one-shot, and goes with it (`inc_sig_count` still clears PW1 exactly
  as before). **bcdDevice → 0x089B.**

- **The OpenPGP `VERIFY` status query reports the latch, not the counter.**
  §7.2.2's empty-`Lc` form reports the *verification state*, and the applet
  answered `6983` whenever the reference's retry counter was 0 — before looking
  at whether that reference was verified. Both ends of that were wrong. With
  PW1 blocked at 0/3, a PW1.82 latch raised before the block is still live and
  still authorises `PSO:DECIPHER` and `INTERNAL AUTHENTICATE`; a YubiKey 5.7.4
  answers `9000`, so a host asking "am I still authenticated?" was told the
  session was dead while the very next command worked. And with the latch down
  and the counter at 0 that card answers `63C0`, the count — it never answers
  `6983` to this form at all. Both now match, measured across the whole
  transition. The data-bearing `VERIFY` is untouched: a blocked reference still
  refuses with `6983`, correct password or not. The PIV applet has the same
  shape in its own `VERIFY` status form; it is governed by a different spec and
  was not measured here, so it is left alone. **bcdDevice → 0x089A.**

- **GET CHALLENGE serves exactly what DO `C0` announces, and takes `P1 = P2 =
  00`.** `C0` bytes 3-4 said **128** while the command handed over anything up
  to the applet's 1024-byte scratch, so the one number a host can read off the
  card about its randomness described nothing the card did. The two are one
  constant now (`MAX_CHALLENGE_BYTES`, tied by compile-time assertions to the
  scratch it is drawn into and to the CCID frame it must fit), announced as the
  1024 that was always being served — raising the
  announcement to meet the behaviour rather than cutting the behaviour, so no
  host that works today stops working. Past it the command refuses (`6700`)
  rather than truncating under `9000`. §7.2.15 fixes `P1` and `P2` at `00` and
  neither was read; both are enforced now, which is stricter than a YubiKey
  5.7.4 — measured, that card refuses only when *both* are non-zero, so this
  refuses everything it refuses and nothing a conformant host sends. A command
  carrying data and **no `Le` at all** now answers `6A80` — the code measured on
  that card — instead of `9000` with zero random bytes. The ISO case-1 form of that (`00 84 00 00`)
  still returns 256: `Apdu::parse` defaults a missing `Ne` to 256 for every
  applet, so the OpenPGP handler cannot tell it from `Le = 0`. **bcdDevice →
  0x0899.**

- **DO `C4`'s announced password maxima can no longer be rewritten.** §4.4.2
  says of the PW status bytes' length information that it "should not be
  changed", and `put_pw_status` copied the flag *plus all three*. So
  `PUT C4 = 01 06 06 06` answered `9000`, the card then told every host its
  passwords may be at most 6 bytes, and `VERIFY` went on comparing a 40-byte
  one — an announcement about itself that it did not enforce, writable by
  anyone holding the admin PIN and persistent across a power cycle. A YubiKey
  5.7.4 takes a **one-byte** write of `00` or `01` — the "PW1 valid for several
  signatures" flag, which is the DO's whole writable surface — and answers
  `6A80` to every other length and value with the DO untouched. Measured across
  nine payloads, matched cell for cell. `gpg`'s `forcesig` sends exactly the
  accepted form and is unaffected. A card whose maxima an older build already
  moved has them restored at boot — with nothing else in the applet writing
  those bytes, `01 06 06 06` would otherwise announce max 6 for good and `gpg`
  would refuse to let its owner set a longer PIN. **bcdDevice → 0x0898.**

- **PUT DATA no longer stores a fingerprint or a timestamp of an impossible
  length.** OpenPGP 3.4 §4.4.1 fixes each key fingerprint at 20 bytes and each
  generation timestamp at 4, and `C5`/`C6`/`CD` republish them as fixed-width
  slices. `put_data` length-checked only the UIF and algorithm DOs, so a
  28-byte `C7` was accepted with `9000` and then read back as *two different
  values* — 28 bytes standalone, 20 inside `C5` — with no error either way.
  gpg writes `C7` immediately after generating a key, so a host that got the
  length wrong had no way to find out. All nine writable DOs of the class are
  now gated (`C7`–`C9` and the CA fingerprints `CA`–`CC` at 20, `CE`–`D0` at 4),
  the empty write included, and a refusal leaves the DO byte-for-byte as it was
  — measured on a YubiKey 5.7.4 at eight lengths per DO, which is exactly what
  it does. The reader's stride and the writer's gate now come from one pair of
  constants, so they cannot drift. `C5`/`C6`/`CD` stay unwritable; we answer
  `6A88` where that card answers `6B00`, which is a divergence in the status
  byte only. **bcdDevice → 0x0897.**

- **DO `0xDE` tells an imported key from a generated one.** OpenPGP 3.4
  §4.4.3.8 gives each slot's status byte three values — `00` absent, `01`
  generated on card, `02` **imported** — and its first sentence says why: the
  DO exists so a host can tell whether the private key could have been backed
  up. Ours collapsed it to a boolean, so an imported key reported `01` and
  claimed a guarantee the card had never made. Measured on a YubiKey 5.7.4,
  which ships a factory `02` on its imported attestation key and moves the byte
  on every transition; ours now matches that table cell for cell, including
  across a power cycle: absent → GENERATE `01` → IMPORT `02` → GENERATE `01`,
  each of the three slots independent, and TERMINATE DF back to `00`. The
  origin is a new internal record (`EF_KEY_ORIGIN`), and **a key that predates
  it reads as imported** — `02` is the honest default, since absent proof of
  on-card generation the card must not claim it. That default is also the
  power-cut design: GENERATE records its origin *after* the key is committed
  and IMPORT *before*, so a tear in either direction leaves `02` and never a
  false `01`. An IMPORT whose origin record cannot be written is refused
  (`6581`, key untouched) rather than storing a key the slot still describes as
  generated. Generate into the slot again to restore the stronger claim.
  **bcdDevice → 0x0896.**

- **GET NEXT DATA now does the one thing the spec defines it for.** OpenPGP 3.4
  §7.2.7 gives INS `0xCC` a single use — walk the three occurrences of the
  cardholder certificate (7F21) — and §5's access table makes that read
  *Always*. Ours could not do it at all: `00 CC 7F 21` answered `6A83` whether
  or not the admin PIN was verified, so the second and third certificates were
  reachable only by a SELECT DATA before each read. Three independent causes,
  all fixed. The GET DATA handler's 7F21 arm returned before recording the DO,
  so the walk had no anchor; the command was gated on PW3, which is the ACL of
  a write, not of this read; and SELECT DATA — the way to walk from an arbitrary
  occurrence without a read to throw away — did not arm the walk either, though
  measurement shows the reference card walks straight on from it. What it
  implemented instead — a `current_ef + 1`
  walk over the private DOs `0101`–`0104` — is in no version of the card spec
  and is removed; a YubiKey 5.7.4 answers `6A80` to GET NEXT DATA for every tag
  but 7F21, and so do we now. The rest of the model is measured against that
  card cell for cell: GET DATA anchors the walk and does not move the
  occurrence pointer, GET NEXT advances then reads, the step past the last
  occurrence is `6A80` and leaves the pointer where it was, an intervening GET
  DATA of another DO drops the anchor, and a refused GET NEXT of another tag
  does not. Swept with it, the class the walk sits in: **command data on a GET
  DATA is ignored rather than refused**, as that card ignores it — `00 CA 00 5E
  01 AA` serves the DO instead of answering `6700`, and GET NEXT DATA with a
  body answers `6A80`. **bcdDevice → 0x0895.**

- **MANAGE SECURITY ENVIRONMENT had its two control-reference templates the
  wrong way round, so the only form a conformant host sends did nothing.**
  OpenPGP 3.4 §7.2.18 names the templates by their ISO 7816-8 meanings — `A4`
  is the Authentication Template and configures INTERNAL AUTHENTICATE, `B8` the
  Confidentiality Template and configures PSO:DECIPHER — and its worked example
  is `00 22 41 A4 03 83 01 02`. The applet read `A4` as DECIPHER and `B8` as
  INTERNAL AUTHENTICATE. Both halves were wrong in the way that hides: the
  spec's own example answered `9000` and repointed DECIPHER at the DEC key it
  already used, a silent no-op, while `41 B8 83 01 02` — which no conformant
  host sends — is what actually cross-wired a slot. Measured end to end with an
  ECDSA P-256 authentication key and an ECDSA P-384 decryption key, so the
  response length names the slot: `41 A4 83 01 02` then INTERNAL AUTHENTICATE
  used to return 64 bytes (unchanged) and now returns 96. A real YubiKey 5.7.4
  does not implement INS `0x22` at all — `6D00` to all eleven forms probed, and
  its own DO C0 byte 10 says so — so there is no oracle here and the spec
  decides; our C0 keeps announcing MSE as supported, because we do implement
  it. **Three existing tests encoded the inversion** and are corrected in the
  same change; a new end-to-end test drives the `A4` arm through the applet's
  dispatcher, which no test did before — that arm was the no-op, so nothing
  failed when it broke. **bcdDevice → 0x0894.**
- **An OATH rename onto a name that is already taken is refused instead of
  minting a second credential with that name.** One credential per name is the
  store's rule, and only one of its two writers held it: PUT looks the name up
  and overwrites, RENAME looked up the source and never the target. Measured on
  the emulator, `RENAME alpha -> beta` with a `beta` already stored answered
  `9000` and left two rows called `beta`. Every name-addressed command then
  resolves to the lower slot, so `CALCULATE beta` returned alpha's code,
  `GET CREDENTIAL beta` returned alpha's stored login and password, and the real
  `beta` became unaddressable while still holding its slot — so deleting the row
  a host displays silently changes which code the remaining one produces. It
  compounds: three more renames onto the same name gave four rows called `beta`,
  and they survive a power cycle. A YubiKey 5.7.4 answers `6984` to a taken
  target and changes nothing, measured across the surface — including a target
  differing only in case (free, so `9000`), a target of the other OATH type, and
  renaming a credential onto itself, which the applet used to report as a syntax
  error (`6700`). The target is now looked up with the byte-exact lookup the
  source already uses, and both refusals report the same "no such object", so a
  rename whose source does not exist reads the same whatever the target names —
  which is also the one cell of the card's own order that cannot be measured
  from outside. Nothing else moves: a rename onto a free name still carries the
  secret, type, algorithm, digits, HOTP counter, touch property and LIST
  position across, still needs no free slot on a full store, and the
  access-code gate still answers before the parser. `ykman` hid this — it
  pre-checks the collision on the host and never sends the APDU, so only a
  client that does not pre-check ever saw the duplicate, and that is why
  `docs/guides/oath.md` already described the behaviour the card only has now.
  A duplicate an older build already wrote is left alone: both rows are real
  credentials, and removing one is data loss.
  **bcdDevice → 0x0893.**

- **The Yubico-OTP use counter now stops one short of the ceiling instead of one
  past it.** Its two writers disagreed by one. `ticket::build` guarded the counter
  it already held and *then* incremented, so the press whose session counter wraps
  at `0x7FFF` stored `0x8000` — the reserved high bit — while `power_up_bump`
  guards the value it is about to store and so can never write above `0x7FFF`.
  Once `0x8000` is on flash the boot bump computes `0x8001`, fails its own guard
  and never writes again: the use counter is frozen while the RAM session counter
  restarts at 0 on every power-up, so the `(use, session)` pair a Yubico
  validation server orders OTPs by repeats every 256 presses. That is the replay
  defence, not a display field. Nothing reached it — the fuzz target presses each
  slot once from session 0, so the wrapping branch never runs, and the unit test
  exercised the path at counter 5. Both writers now take their step from one
  place, pinned by host tests at the ceiling and by two Kani proofs over every
  session byte against every counter at or below `0x7FFF`: the counter only
  climbs and never leaves `stored..=0x7FFF`, and the two writers take the same
  step from the same value. A counter *above* the ceiling — the very state this
  bug wrote — is assumed away rather than proved, which makes those two the
  induction step; the base case is that the only other writers of those bytes
  zero the record or copy it forward verbatim. What a key should do once it
  legitimately reaches the ceiling is unchanged and still open; what it must not
  do is lower the counter, because lowering it *is* the replay.
  **bcdDevice → 0x0892.**

- **A PIV signature at a PIN-always slot no longer locks the whole card.**
  Slot `9C`'s pin policy is *always* — "the PIN must be verified every time
  immediately before a signature" (SP 800-73-4 pt1 Table 5). The applet had no
  state for that condition, so it enforced it by clearing the card's only PIN
  latch, and that latch gates everything: after one signature at `9C`, a
  signature at `9A`, an ECDH at `9D`, the PIN-protected `PRINTED` object and even
  the `VERIFY` status query all refused with `6982` until the host verified
  again. The ordinary sign-then-decrypt session — S/MIME, or PIV-auth followed by
  key management — asked for a second PIN it should not need. Measured on a
  YubiKey 5.7.4: every one of those answers `9000`. The same line was wrong in
  the other direction too, and that half is the security-relevant one: because
  the clear was keyed on *always*, an operation at a pin-policy **once** slot
  spent nothing, so `VERIFY` → sign at `9A` → sign at `9C` produced a `9C`
  signature with no PIN immediately before it — on a YubiKey that second
  signature is refused. There are now two flags. The PIN's own status is set by
  `VERIFY` and cleared only by a failed `VERIFY`, `VERIFY P1=FF`, SET RETRIES,
  another applet's SELECT or a reset; a separate freshness bit is spent by any
  private-key operation that reaches a slot key needing a PIN — retired slots
  `82`–`95` included, and a failed one counts, since a garbage ECDH point or an
  RSA cryptogram of the wrong length still used the key — and read only by
  *always* slots. A pin-policy **never** operation spends nothing, a
  management-key (`9B`) handshake spends nothing (it is not a key slot, so the
  escrow flow `age-plugin-yubikey` uses kept working), and neither does a request
  that never gets to the key: a wrong algorithm, an unprovisioned slot, a denied
  touch, or a body whose tags the dispatcher declines. **bcdDevice → 0x0891.**

- **A failed authentication now revokes the standing one on OpenPGP and on the
  PIV management key.** `0x088B` fixed this for PIV's `VERIFY`; the same rule was
  unenforced on two neighbouring commands. On OpenPGP, a wrong PW1/PW2/PW3 in
  `VERIFY` *or* `CHANGE REFERENCE DATA` left the access status standing:
  measured on the emulator, three wrong PW1 entries blocked the card at 0/3 and
  `PSO:CDS` kept producing real signatures, and three wrong PW3 entries left the
  admin surface open — an attacker holding a live session could still install a
  resetting code and reset the user's PW1. Entering wrong PINs at a card you
  believe is compromised, the human reflex, did nothing. Now exactly the
  addressed reference is cleared, and nothing more: PW1 no. 81 and no. 82 stay
  independent latches (they share an error counter but not a status, so gpg's
  two-mode verify is unaffected), a wrong *resetting code* still clears nothing,
  and an operation another reference also authorises — `PSO:CDS` with PW3
  verified, say — goes on working until that one is cleared too. A reference
  already at 0 retries is turned away before the comparison, so it clears
  nothing either. On PIV, a standing management-key (`9B`) status survived a
  wrong-key handshake; starting a fresh handshake now revokes it and only a
  completed one raises it again. Nothing else at `9B` touches it — not a step 2
  with no handshake in progress, not a refused tag, not a bad algorithm — because
  that is where the YubiKey draws the line too. A single-auth challenge asked for
  at a *key* slot no longer enters the session at all: it used to authenticate
  `9B` when answered there, which staged a failed management-key attempt that
  cost no standing status, and its arrival wrecked a `9B` handshake already in
  progress that a YubiKey completes. Both rules were measured on a YubiKey 5.7.4
  first, runs from a factory reset — and the same measurement is why PIV's
  `CHANGE REFERENCE DATA` and `RESET RETRY COUNTER` were deliberately **left
  alone**: the YubiKey keeps the PIN's security status through both, against
  SP 800-73-4 §3.2.2/§3.2.3, and we match it. **bcdDevice → 0x0890.**

- **OpenPGP's own in-application SELECT matches an AID the way the dispatcher
  does.** The AID rule changed for every applet at `0x088C`, but the OpenPGP
  applet carries a second SELECT of its own and it kept the old test, so
  `AID ‖ anything` still selected there. It is reachable: the dispatcher only
  intercepts `P2` `00`/`04`, so a `P2 = 05` SELECT lands in the applet and used
  to answer `9000` with a full FCI for exactly the input the dispatcher had just
  started refusing — one card, two rules. Found by reviewing the `0x088C` change
  rather than by a test, which is the point of the other half of this entry:
  that change altered a rule shared by seven applets and two transports and
  shipped with no test at all, since every existing suite selects by an exact
  constant. `rsk-sdk` now pins it — every prefix selects, `AID ‖ byte` and a
  divergence inside the AID do not, an empty candidate is refused, and a prefix
  two applets share resolves to the first registered one.
  **bcdDevice → 0x088F.**

- **The rescue applet no longer reports a write it did not perform.** `WRITE`
  (`0x1C`) answered `9000` to any selector it does not implement — measured, P1
  `0x03` / `0x07` / `0x42` / `0xFF` each returned success and wrote nothing while
  the real `P1=0x01` grew the phy record in the same run. The comment called it a
  no-op OK, framed as forward compatibility, and for a write that is backwards:
  this is the **provisioning** path, where `P1=0x01` writes VID/PID, the USB
  interfaces and the LED — the device's identity. A newer `rsk` or PicoForge
  against older firmware sends a selector that firmware does not know, is told the
  write landed, and the operator moves on believing the device is provisioned.
  Silent success is precisely what stops a host detecting the version mismatch,
  which is what `0x6A86` exists for. The inconsistency was inside one function:
  the inner P2 dispatch and `keydev_sign` directly above already refuse an unknown
  selector that way. No YubiKey comparison is possible and that is a measured
  fact, not a skipped step — the rescue applet is RS-Key's own and has no
  counterpart on any other card. **bcdDevice → 0x088E.**

- **OpenPGP's security-status reset refuses a password reference that does not
  exist.** `VERIFY` with `P1=FF` is the standard's way for a host to drop its own
  privileges, and §7.2.2 defines `P2` = `81` / `82` / `83`. Ours matched those
  three and fell through to `9000` for anything else, so `00 20 FF 00`,
  `… FF 80`, `… FF 84`, `… FF FF` all reported a successful reset of nothing —
  while the *same* undefined `P2` on the `P1=00` path already answered `6B00`, so
  one command disagreed with itself. That self-contradiction is what made it a
  defect rather than a taste question. A YubiKey 5.7.4 answers `6B00` to every
  undefined `P2` here, measured across all eight values. The three defined ones
  are untouched and still reset only their own latch. **bcdDevice → 0x088D.**

- **SELECT matches an AID the way ISO 7816-4 and a YubiKey do.** The dispatcher
  asked whether the requested AID *started with* a registered one, so any applet
  answered to `its AID ‖ anything`. On PIV that meant selecting with
  `A0 00 00 03 08 00 00 00 00` — the AID SP 800-85A-4 C.1.1.2 names as invalid and
  expects `6A82` for — and with `A0 00 00 03 08` followed by five junk bytes. The
  test is now the other way round, which is what truncated SELECT means: the
  requested AID must be a **prefix of** a registered one, first match wins.
  Measured on a YubiKey 5.7.4 across three applets, including a one-byte
  candidate, so this is its rule and not an inference. PIV consequently registers
  its full AID (`A0 00 00 03 08 00 00 10 00 01 00`) rather than the bare NIST
  RID — with the old rule a shortened registration was what let the junk through,
  and with the new one it would have made the real AID unselectable. The 9-byte
  version-agnostic prefix and the bare RID both still select, matching the
  YubiKey. An **empty** candidate is refused rather than treated as "select the
  default": it is a prefix of everything, and nothing here should be reachable
  without being named. **bcdDevice → 0x088C.**

- **A failed PIV VERIFY now drops the standing one.** SP 800-73-4 Part 2
  §3.2.1.1 is explicit that on a mismatch "the card command shall fail, the PIV
  Card Application shall return the status word `63 CX`, **the security status of
  the key reference shall be set to FALSE**", and a YubiKey 5.7.4 does exactly
  that — measured: sign, one wrong VERIFY, and the next signature is `6982`. Ours
  kept signing: a wrong PIN reported `63 CX` and left the session's standing
  verification alone, and three wrong PINs blocked the reference (`6983`) while
  PIN-gated signing continued on the same session. Bounded to a live session, but
  it meant that entering wrong PINs at a card you believe is compromised — the
  human reflex, and the standard advice — did nothing to an attacker who already
  had a session in which the real PIN had been entered. `6983` then described the
  card's willingness to take another PIN rather than its capability.
  **bcdDevice → 0x088B.**

- **PIV no longer accepts a 3-digit PIN as its own credential.** The applet
  checked nothing about a *new* PIN or PUK, so `CHANGE REFERENCE DATA` and
  `RESET RETRY COUNTER` would set the card's authentication floor to three
  digits — 1000 candidates against a three-try counter, when the 6-byte minimum
  exists precisely to make that search larger than the counter. Confirmed end to
  end: set it to `"777"`, and `"777"` then verifies. `ykman` validates
  client-side, but SP 800-73-4 §2.4.3 puts the rule on the *card* because a
  client cannot be trusted to, and SP 800-85A-4 assertion C.2.2.1 tests it.
  Both writers now require the reference to be 6-8 bytes before its `0xFF`
  padding, answering `6A80` without spending a try — which is what a YubiKey
  5.7.4 does, measured on one factory-reset applet per case. The digits-only half
  of §2.4.3 is deliberately **not** enforced: the same YubiKey stores a non-digit
  reference on both the PIN and the PUK, so a host may send one and the card has
  to take it. The old reference is still judged first, so a wrong current PIN
  spends a try whether or not the new value is well formed — also matching.
  **bcdDevice → 0x088A.**

- **A PIN change interrupted by losing power no longer looks like a dead card.**
  Updating an OpenPGP PIN writes two flash records — the verifier, and the copy
  of the data-encryption key sealed under that PIN — and a cut between them left
  the new verifier standing over a copy sealed under the PIN nobody holds any
  more. The new PIN verified and every operation needing the key answered `6400`.
  Measured on `tools/emu --power-cut`, reproducible at every byte offset in the
  window. Ordering cannot fix it: whichever record lands first, the tear leaves
  the other one describing the other PIN, which is why the two paths that already
  wrote the key copy first were no safer. The update now stages the new copy in
  its own slot, writes the verifier, then commits, and the next `VERIFY` finishes
  an interrupted one — the detection-based recovery `migrate_pin_kbase` has always
  used for the kbase migration, applied to all four sites that update a verifier
  and its key copy together. Every torn state is covered by a host test that
  builds it directly rather than by whichever offset a power-cut sweep happens to
  land on.

  **It was never key loss, contrary to how this was first recorded.** The key
  copies are per-PIN and only the one being changed was damaged, so a card in
  that state is repaired by reaching the key through a different PIN — but the
  two directions need different commands and are not interchangeable. A torn
  **PW3** change is repaired by verifying PW1 and re-running the change, because
  `load_dek` prefers PW1's copy when PW1 is verified. That same preference is
  what breaks the mirror image: for a torn **PW1** change, verifying PW1 puts the
  damaged copy back in front, so the repair is the admin `unblock` (RESET RETRY
  COUNTER), which never verifies PW1. Both are now in
  `docs/guides/openpgp.md` for anyone on an older build.
  **bcdDevice → 0x0889.**

- **An OATH/OTP PIN now actually gates the password safe.** The applet can store
  a login, a password and a note per credential — the password-safe extension
  `nitropy` speaks — and `GET CREDENTIAL` (`0xB5`) served them to any fresh,
  unauthenticated connection whenever no OATH access password was configured,
  **which is the shipping default**. The only gate was the session's `validated`
  flag, and `SELECT` sets that unconditionally on a code-less applet, so a PIN
  the owner had deliberately set guarded nothing at all: the card handed back the
  stored password to a host that presented no credential of any kind. `VERIFY
  CODE` (`0xB1`) had the same gate and the same hole. Both now require the OTP
  PIN to have been presented in the current session once `EF_OTP_PIN` exists,
  tracked separately from `validated` because `VERIFY PIN` also sets that one (it
  doubles as `VALIDATE` for the nitropy flow) and the two facts are not the same.
  A wrong PIN revokes a standing unlock and a re-`SELECT` does not inherit it.
  The applet already reasoned about exactly this hole in `SET PIN`, which defends
  itself with an operator touch; the two commands that return secrets never got
  the treatment. A store with **neither** a PIN nor an access password stays open,
  as YKOATH intends for a code-less applet — this only makes the credential the
  owner did create mean something. **bcdDevice → 0x0888.**

- **OpenPGP no longer returns a truncated data object as if it were complete.**
  DO `C0` announced room for a 2048-byte cardholder certificate and 2048-byte
  special DOs, `PUT DATA` stored whatever it was given, and `GET DATA` then
  clamped the read to the applet's 1024-byte scratch and answered `9000`. A
  1500-byte certificate — an ordinary X.509 size, and exactly what OpenPGP Card
  3.4 §9.7 defines the object for — wrote OK, read back 1024 bytes and reported
  success: 476 bytes gone with nothing on the wire to say so, which is silent
  corruption rather than a status-code nit. The same cliff hit Login data (`5E`),
  URL (`5F50`) and the private-use DOs. Both numbers are now one constant, and it
  is the transport's real ceiling — 2036, the CCID frame's 2038-byte body less
  the status word — so values up to it round trip byte for byte and a longer one
  is refused at the write with `6A80`, the answer a YubiKey 5.7.4 gives past its
  own limit. **The announcement went down, not up:** 2048 was never deliverable,
  because `ResBuf::extend` writes *nothing* when a body does not fit, so an
  over-long DO would have come back empty with `9000` — the same lie twelve bytes
  further out. `rsk-device`, the one crate that sees both, now carries a
  compile-time assertion tying them. The length is checked once, before `PUT
  DATA` routes, because the cardholder certificate is the one DO whose target
  file is chosen by session state (`SELECT DATA`'s occurrence) rather than by its
  tag, so it writes flash on its own path and a check in the generic writer would
  have missed exactly the object `C0`'s bytes 5-6 are about. An earlier build's
  chaining buffer capped a write at 2037, one byte past the new limit, so the two
  read paths no longer clamp either: a stored value they cannot return whole
  answers `6581` instead of a short body under `9000`. That keeps the run-3 #1
  guarantee — never slice past the buffer, never panic-reset — and drops only the
  part of it that reported the truncation as success.
  **bcdDevice → 0x0887.**

- **A stack overflow now faults instead of corrupting RAM.** The firmware links
  through `flip-link`, which puts the stack below `.data`/`.bss` so running off
  the end hits unmapped memory under `0x20000000` rather than overwriting the
  statics next to it. The stack is the same size; the failure is loud. This is
  the mode that wedged ML-DSA-65 `makeCredential` at `0x082A` — the overflowing
  write landed in `.bss` and the device halted with no diagnostic.

- **Core0's stack floor no longer depends on the linker.** `flip-link` puts that
  stack at the bottom of RAM, so an overflow already faults on unmapped memory:
  this closes no gap. Below that stack is not a narrow guard band a large frame
  could step over, but the whole unmapped half of the address space. What arming
  `MSPLIM` on entry to `main` adds is that the bound is stated in code, so
  dropping `flip-link` becomes a visible edit rather than a silent return to a
  stack growing into `.bss`.

- **Core1's stack has a hardware limit.** Its 16 KiB stack is an array in
  `.bss`, which `flip-link` cannot help with — that guards core0's stack by
  moving it to the edge of RAM. Core1 now programs ARMv8-M's `MSPLIM` on entry,
  so an overflow faults on the stack-pointer decrement rather than writing into
  the statics below. Measured: with the limit, an 80 KiB overflow on core1
  leaves the device answering normally; without it, the device passes `getInfo`
  and two suites and *then* hangs on the first `makeCredential`. The fault is
  not graceful — `pause_core1` spins waiting for a core that no longer answers,
  so the next flash write wedges until a replug — but that is the intended
  trade against a silent write issued while a key is being generated.

- **The fused device key is no longer resident.** The OTP DEVK — the attestation
  root, and the one secret on the key that can never be rotated — was read at
  boot and parked for the whole power cycle in *two* places, `FidoState` and the
  rescue applet. Three rarely-run commands want it: the two rescue keydev
  commands and the audit checkpoint, which belongs to a journal that is off by
  default. So on a shipped device it sat in RAM for commands nobody calls. Both
  copies are now a `fn` that reads OTP when a command needs it, and the fetched
  copy is zeroized before that command returns. This narrows what a
  memory-disclosure bug reaches. It changes nothing against an attacker already
  executing code on the device, who has the store root in RAM either way.

- **Neither is the fused master key.** The DEVK change left the bigger secret
  behind: the MKEK — the root every sealed record hangs off — was read once at
  boot and then copied *by value* into eight owners (the CTAP handler, all five
  CCID applets, the display's key block, and `main`'s own local), each resident at
  a fixed address for the whole power cycle. The derived material never was: every
  `derive_kbase` recomputes and zeroizes. So the raw fuse value was the only thing
  actually parked in RAM, and it was parked eight times. All eight now hold a
  reader; the key exists only inside the operation that asked for it, which puts
  it out of reach of a parser bug — parsing happens before any store access. Same
  scope as the DEVK change: nothing against code execution. Measured cost of the
  read: **48 µs**, against 8.9 ms for the cheapest crypto step it precedes.

### Changed

- **An unimplemented subcommand answers what a YubiKey answers.** CTAP 2.2 §8.1
  makes `CTAP2_ERR_INVALID_SUBCOMMAND` a MUST here, and its own NOTE concedes
  that implementations of earlier versions do not follow it. A YubiKey 5.7.4 is
  one of them, so hosts are written against *its* codes and these now match it,
  measured cell for cell: `authenticatorConfig` judges the subcommand **before**
  the pinUvAuthParam — `0x00` is the absent-parameter sentinel
  (`CTAP2_ERR_MISSING_PARAMETER`), an id the card does not implement is
  `CTAP1_ERR_INVALID_PARAMETER` with or without a token, and only a known one
  reaches `CTAP2_ERR_PUAT_REQUIRED`; `credentialManagement` keeps answering
  `CTAP2_ERR_PUAT_REQUIRED` to every subcommand without a token and
  `CTAP1_ERR_INVALID_PARAMETER` once one verifies. Previously
  `authenticatorConfig` said `CTAP2_ERR_UNSUPPORTED_OPTION` and gated first.
  `clientPIN` is the exception and is left on the spec's `0x3E`: the YubiKey has
  no stable answer to copy there — the same key returns `0x01`, `0x33`, `0x02` or
  `0x14` for the same undefined subcommand depending on `pinUvAuthProtocol` and
  on what ran before it. That also covers `0x06`/`0x07` on a build with no PIN
  pad, which used to report an unsupported *option*. **bcdDevice → 0x0886.**

- **An abandoned `largeBlobs` write is dropped after 30 s.** CTAP 2.3 §6 names
  four stateful sequences and bounds all of them the same way: "exclusively
  preceded" by their own continuation, with "no more than 30 seconds" between
  those commands. The command half was already enforced for all four; this
  finishes the time half for the one sequence still missing it, and it is the one
  that needed it most — a part-written array is the only sequence whose
  continuation legs carry no authorization on a PIN-less key, so nothing but some
  *other* command arriving could retire it. Send nothing and it sat in RAM for the
  rest of the power cycle. The window is per fragment, not per array, so a slow
  link transferring a full 4078-byte blob is unaffected; an expired transfer
  answers `CTAP2_ERR_INVALID_SEQ` and leaves the stored array untouched, exactly
  as an interrupted one already did. Inert on a `--features largeblob-ext` build,
  which never arms this accumulator. **bcdDevice → 0x0885.**

- **A credential-management enumerate walk now retires on a timer of its own.**
  The cursor is dropped once 30 s pass with no leg served. That is the bound CTAP
  2.3 §6 names for every stateful command — an authenticator may assume "no more
  than 30 seconds will elapse between such commands" — and *between* is why the
  timer is per leg rather than per walk: a platform drawing an account picker
  cannot run out of it halfway down its own list. §6.3 step 7 says the same for
  `getNextAssertion`, which already did it.

  The same clause requires the state to die with the pinUvAuthToken that
  authorized the opening call, and that part was already in place. It is not
  enough on its own: the **persistent** `pcmr` token has no usage timer (§6.8.2),
  so a walk opened with one had no bound at all and stayed continuable for the
  whole power cycle as long as nothing else was sent. The *Next* legs carry no
  authorization of their own (§6.8), which makes the cursor the authorization; it
  is now bounded in time as well as to its channel. This is also the one row of
  the YubiKey 5.7.4 comparison below that did not match. **bcdDevice → 0x0884.**

- **A flash record now holds 4078 bytes instead of 2046.** Two things ride that
  ceiling and doubled with it: the serialized large-blob array
  (`maxSerializedLargeBlobArray` in `getInfo`, so a platform sees the new room
  without being told) and an imported enterprise attestation chain
  (`ATT_IMPORT`). No other applet sizes itself against it — PIV, OpenPGP and
  OATH carry their own, lower caps and are unchanged. The number is not round
  because a `sequential-storage` item must fit inside one 4096-byte flash page:
  16 bytes of page and item headers come off the top, then the 2-byte FID that
  shares the scratch with the value. **A provisioned key upgrades in place** —
  only the size of the buffer the backend serializes through changed, not the
  on-flash item format, so every existing record still reads. **bcdDevice →
  0x0880.**

- **The CTAP 2.3 `largeBlob` extension answered the wrong status for a mistyped
  input** (`--features largeblob-ext` only). §12.4 says a CDDL violation is
  `CTAP2_ERR_INVALID_CBOR` for both commands, but the parsers went through the
  shared decode helper, which reports a wrong *type* as
  `CTAP2_ERR_CBOR_UNEXPECTED_TYPE`. The extension's own inputs now map every
  decode failure to `INVALID_CBOR`. The unit tests missed it because their
  CDDL-violation cases were all well-typed — an external CTAP 2.3 conformance
  runner driven against a `largeblob-ext` emulator caught it (large-blob F-4 and
  F-5), and the regression test now covers the type axis too. That group is
  12/12 green after the fix. **bcdDevice → 0x0883.**

- **getInfo claimed a config subcommand that, by the spec's own definition, it
  did not implement.** `authenticatorConfigCommands` (`0x1F`) listed
  `vendorPrototype` (`0xFF`) while `vendorPrototypeConfigCommands` (`0x15`) was
  absent — and CTAP 2.3 §6.11.3 makes the second the precondition for the first:
  the subcommand "is only implemented if the `vendorPrototypeConfigCommands`
  member in the authenticatorGetInfo response is present". So the two members
  together said a supported subcommand was not implemented.

  This finishes the `0x0875` fix rather than reversing it. Listing `0xFF` was
  itself required (§6.11.7 makes it a MUST once the arm exists); what that change
  left out was the companion member, on the reasoning that `0x15` is optional
  "and a YubiKey hides it" — true, but a YubiKey hides `0xFF` along with it. Now
  published: the six vendorCommandIds `authenticatorConfig` actually dispatches,
  the soft-lock enable/disable pair and the four PicoForge phy writes. Nothing is
  given away — [docs/protocol.md](docs/protocol.md) §9 already documents them,
  and §6.11.7 says vendors "MUST NOT count on obscurity of the vendorCommandId
  value as any sort of security".

  Found by an external CTAP 2.3 conformance runner driven against a live board.
  The rule is a cross-field constraint over getInfo, so nothing in the gate was
  in a position to see it. **bcdDevice → 0x0882.**

- **A multi-call sequence no longer survives an unrelated command in the middle
  of it.** CTAP 2.2 §6 lets an authenticator assume each stateful command is
  "exclusively preceded" by its own kind or by the command that initialized it —
  "no other authenticator operation occurs in between" — and fail it with
  `CTAP2_ERR_NOT_ALLOWED` otherwise. The device now takes that up for all four
  sequences the spec names: the `getNextAssertion` walk, credentialManagement's
  two enumerate cursors, and a part-written large-blob array. The clause is a
  MAY, so the previous behaviour was conformant; what this buys is a smaller
  state surface, and the large-blob buffer in particular had nothing else
  bounding it — no timer, and on a PIN-less key no token — so an abandoned
  transfer sat in RAM until some later `offset == 0`. A platform that interleaves
  (a `getInfo` between `getAssertion` and `getNextAssertion`, say) now gets
  `CTAP2_ERR_NOT_ALLOWED` where it used to be served; the spec asks platforms not
  to.

  The enumerate cursor goes further, because a shipped authenticator does:
  measured on a YubiKey 5.7.4, its walk dies on an unrelated command, on a
  `credentialManagement` subcommand that is not one of the two *Next* walkers, on
  a `largeBlobs` command, and on a 35-second gap with the token still live. All
  four are matched here, the timer as of `0x0884` above. Its large-blob write, by
  contrast, survives all four — so on that one sequence this device is the
  stricter of the two, kept that way because the failure modes are not
  symmetric: a YubiKey drops the stored array on the *opening* fragment, so an
  abandoned transfer destroys it, while this one accumulates in RAM and leaves
  the previous array intact.
  **bcdDevice → 0x087F.**

### Security

- **A second process could walk another channel's `getNextAssertion`, and its
  credential-management enumeration.** Both are multi-call sequences whose
  continuation legs carry no authorization of their own: `getNextAssertion` has
  no parameters at all, and CTAP 2.1 §6.8 exempts credMgmt's *Next* subcommands
  from a `pinUvAuthParam` — each inherits what the opening call established.
  Neither was bound to the CTAPHID channel that opened it, so a second process on
  its own channel could ask for the next leg and be served: an assertion signed
  over the **first** channel's clientDataHash under the first request's presence
  and UV decision, or the relying-party ids the first channel's token bought.
  Both now record the opening channel and refuse any other with
  `CTAP2_ERR_NOT_ALLOWED` — the scoping the seed-backup MSE key already used, and
  the unscoped form of it is what audit run-31 filed as HIGH. The two other
  multi-call sequences were checked and are not affected: the large-blob write
  re-verifies a token on every fragment, and the MSE handshake was already
  channel-bound. Found by porting Google OpenSK's `test_channel_interleaving`,
  which pins the same rule. **bcdDevice → 0x087E.**

### Fixed

- **`CTAPHID_LOCK` was advertised nowhere, and let a foreign `CTAPHID_INIT`
  through.** Two halves of one command. The INIT reply's capability byte left
  `CAPABILITY_LOCK` (0x02) clear although the lock is implemented, and a host
  decides from that byte whether to attempt the command at all — so a working
  feature was unreachable. Meanwhile the dispatch exempted *every* `CTAPHID_INIT`
  from a held lock, though its own comment justified only the broadcast one
  (asking for a channel id). An INIT aimed at another allocated channel is
  §11.2.9.1.3's other function — it "discards the current transaction, buffers and
  state" — which is precisely what the lock exists to withhold from a second
  application. The bit is set now, and only a broadcast INIT survives someone
  else's lock. **bcdDevice → 0x087D.**

- **`tools/emu` could not see a `CTAPHID_CANCEL` while it waited for a touch.**
  Its socket transport parks in the job wait for the whole of a command and reads
  nothing meanwhile, so the cancel frame sat in the receive buffer until the
  ceremony it was sent to abort had already ended: `authenticatorSelection` and a
  presence-gated `makeCredential` both answered as though no cancel had come,
  instead of `CTAP2_ERR_KEEPALIVE_CANCEL`. It now polls the connection during the
  touch wait — the window `CtapHid` watches on the device, and only that window,
  since off it the platform pipelines and a frame read there would be a swallowed
  next command. Emulator only: the firmware and the emulator's `--usbip` path
  (which runs the real transport) were never affected.

- **`docs/protocol.md` §4 invited a SELECT that fails for three of its ten
  AIDs.** The section opens "SELECT an applet with `00 A4 04 00 Lc <AID> 00`" and
  then tables FIDO2, the FIDO2 backup id and U2F beside the seven real card
  applets — but those three are not CCID applets and answer `6A82`
  (FILE_NOT_FOUND); CTAP1/U2F and CTAP2 ride CTAPHID and have no SELECT at all.
  §4 is the third-party / PicoForge wire spec, so a reader building from it wrote
  a probe that could not work and had nothing to tell that apart from a broken
  key. The table gains a **Transport** column with all ten measured on both
  transports, which also records the narrower half nobody had written down:
  `CTAPHID_MSG` offers exactly one applet, the vendor one. Documentation only —
  no wire change.

- **`tools/emu`'s power cycle skipped the Yubico-OTP use-counter bump, so the
  bench could not test the replay defence.** `firmware/src/main.rs` runs
  `power_up_bump` at every cold boot precisely because the RAM session counter
  restarts at 0 on each power-up: if the persistent use counter stood still, the
  `(use, session)` pair a Yubico validation server orders OTPs by would repeat.
  The emulator had no reference to it at all — neither at process start nor on
  the replug (`OP_REPLUG`, and the USB/IP attach that shares it), so it reset the
  session half and left the persistent half exactly where it was: the one
  arrangement the defence exists to prevent, on the bench built to test it. Both
  power-ups bump now, and the ungated warm reboot still does not — a bump there
  would hand any host a way to walk the counter to its ceiling. Emulator only.

- **`tools/emu` had no CTAPHID inter-frame timeout, so an abandoned message
  wedged the session for good.** The device transport races its frame read
  against `RX_TIMEOUT_MS` and answers `CTAPHID_ERROR(MSG_TIMEOUT)`; the socket
  loop blocked in `read_exact` with no deadline instead. Measured: after frame 1
  of a 200-byte `CTAPHID_PING` and nothing more, a complete PING on a second
  channel was refused `CHANNEL_BUSY` at t+0.6 s, t+2 s and t+5 s alike, and only
  a `CTAPHID_INIT` on the abandoned channel ever cleared it. One TCP connection
  is one HID interface, so a client had nowhere else to go — the emulator
  modelled the wedge faithfully and never modelled the escape. It now shares the
  transport's own constant and times the message out at 500 ms, carrying a
  half-arrived report across the deadline (TCP may split one; USB never does).
  Emulator only.

- `metadata/README.md` called the attestation `basic_surrogate`; the statements
  themselves declare `basic_full`, which is what the device sends — packed with a
  self-signed per-device `x5c` leaf.

- **A record the routing table no longer points at could not be deleted, and
  `authenticatorReset` swept for it forever.** The store keeps two partitions and
  routes each fid to one of them; `for_each_key` walks BOTH, but `remove` targeted
  only the routed one. A fid whose routing changed between firmware versions
  therefore sat in the other partition — invisible to every read, yielded on every
  walk, deletable by nothing — and the reset sweep, which finishes only when its
  range comes back empty, could never finish. `EF_CRED_CTR` is exactly such a fid:
  0x081D wrote it to the main partition on every assertion and 0x0821 moved it to
  the counter one, so a key flashed from source inside that window carries one (no
  release does — 0.3.6 predates the record and 0.3.7 already routes it). `remove`
  now clears both partitions. **bcdDevice → 0x087C.**

- **`authenticatorReset` deleted the same record up to 64 times.** `for_each_key`
  walks stored items, so an overwritten file yields its fid once per superseded
  version until reclaim; the API says a batching caller must de-dup, and the reset
  sweep did not. Its 64-slot batch filled with copies of one fid — the counters and
  a re-registered credential are exactly what a busy key rewrites most — so a pass
  spent its whole budget re-deleting a record already gone and left the rest of the
  wipe to later passes. It de-dupes now, and carries the same progress backstop as
  the PIV, OATH and OpenPGP wipes: a backend that keeps yielding a record it has
  confirmed removed returns `CTAP2_ERR_OTHER` rather than holding the worker in
  processing. **bcdDevice → 0x087B.**

- **A signed release image did not boot on a secure-boot device.** `picotool
  seal --sign` retires the image's own `IMAGE_DEF` — the linker's, carrying no
  signature and no rollback version — only when it is handed the **ELF**. Given
  a UF2 it appends its signed block and leaves that first one live, so a board
  with `SECURE_BOOT_ENABLE` and `ROLLBACK_REQUIRED` meets it first and refuses
  the image, while the host still prints `signature: verified`. The documented
  ritual said UF2, so every signed image built that way since the partition
  table landed (`0x0871`) would fail to boot — found by upgrading a provisioned
  key, which then would not start until it was reflashed. All five sealing
  snippets in the docs now seal the ELF and convert afterwards.

### Added

- **The CTAP 2.3 `largeBlob` extension, as an opt-in build
  (`--features largeblob-ext`).** It carries the whole blob inside the
  `getAssertion` that reads or writes it and keeps it with the credential,
  instead of the CTAP 2.1 arrangement where the platform manages one array and
  the device only hands out a per-credential key. Read it with
  `largeBlob: {read: true}`, write it with `{write: <bytes>, originalSize: n}`
  and a **non-empty allowList** — §12.4 makes naming the credential the
  precondition for a write — and the answers come back in
  `unsignedExtensionOutputs`.

  It is not additive, and that is the spec's doing: §12.4 says
  *"Authenticators MUST NOT support both extensions"*, so the build **withdraws**
  the `largeBlobKey` extension, the `authenticatorLargeBlobs` command (`0x0C` now
  answers `CTAP1_ERR_INVALID_COMMAND`), the `largeBlobs` option and
  `maxSerializedLargeBlobArray`. Since every shipping browser drives the 2.1 pair
  today and no client speaks the 2.3 extension yet, **the default build is
  unchanged** — turning this on trades working WebAuthn `largeBlob` support for
  a design nothing currently asks for. Up to 4046 bytes per credential
  (discoverable only: a non-discoverable credential has no record to hang a blob
  on, so `support: "required"` there is `CTAP2_ERR_LARGE_BLOB_STORAGE_FULL`).

  One thing the spec does not ask for: each blob is sealed at rest under the
  device seed with the credential id as AAD. The 2.1 array arrives already
  encrypted by the platform, but a 2.3 blob arrives as compressed plaintext, so
  without the seal it would sit readable in a flash dump — and the AAD is also
  what stops a record left behind in a reused slot being served to the
  credential that takes it next. **bcdDevice → 0x0881.**

- The gate asserts a **stack floor** (`FIRMWARE_STACK_FLOOR_KIB`, alongside the
  flash budget). Static RAM had grown 28.5 KiB since `0x082B`, taking the same
  amount off the stack ceiling with nothing measuring it.
- The gate seals a throwaway-keyed image and asserts its first metadata block is
  `ignored`, so the sealing order above cannot silently regress. The real signing
  key stays out of it.
- **Deterministic delayed presence for `rsk-emu`.** `--auto-touch-ms` exposes a
  real pending-presence interval to CTAPHID clients, honours channel-scoped
  cancellation, and then confirms automatically — the window a conformance
  client needs in order to see a `KEEPALIVE` and send a `CTAPHID_CANCEL` at all.
  It stays an *auto-confirming* authenticator, so the CTAP 2.1 §6.6 reset window
  still applies to it. The emulator workspace also forwards the
  `rsk-fido/fido-conformance` feature for unattended conformance runs against
  the socket applet stack.

## [0.4.9] - 2026-08-09

The emulator release: `tools/emu` runs the applet stack on the host, and with it
the suites that had been hand-run against a flashed board — including, over
USB/IP, the ones that need a kernel to have enumerated the device. Both vendored
upstream conformance suites are refreshed, classified against the specs and now
gate; one of their new tests found a real getInfo bug. CI runs what a change can
affect instead of everything.

> ### ⚠️ Upgrading a 16 MB key provisioned before 0.4.8 wipes it
>
> **Export your seed first** ([seed backup](docs/guides/seed-backup.md)).
>
> 0.4.8 moved the KV store on a 16 MB part 4 KB down — 0.4.7's partition table
> claimed the chip's last sector, which holds the `0x10FFFF00` block the bootrom's
> RP2350-E10 workaround owns, so the 16 MB images could not be built at all. A key
> provisioned with an older 16 MB build comes up factory-empty: no passkeys, no
> OpenPGP or PIV keys, no OATH credentials.
>
> The 16 MB flavors only — `display` and `16mb`, and the `abrobot-16m` and
> `waveshare-touch-lcd` board presets. **4 MB and 2 MB keys upgrade in place.**

### Added

- **A software emulator, `tools/emu`.** The applet crates run on the host and
  serve CTAPHID and APDUs over TCP, so the `tests/*.py` suites — until now
  hand-run against a flashed board, and therefore never run in CI — work with no
  hardware attached (`python tests/emu.py tests/11_fido_makecredential.py`). It
  is a development tool, not a key: no secure boot, no OTP, no fuses, no USB
  stack. Its device identity is deliberately its own, so emulator-made material
  is recognisable as such. See [docs/testing.md](docs/testing.md) and
  `tools/emu/README.md`.
- **`tools/emu --display` runs the trusted display in a window.** The Approve/Deny
  ceremony — the screen whose whole promise is that a signature cannot be had
  without a tap on a panel naming the true relying party — could until now only be
  seen on a board with a screen soldered to it. It renders on the host, from the
  same `rsk_ui::render` and the same `crates/rsk-display` flow, and a mouse held on
  the button enters that flow through the same `TouchPad` a finger does. The
  ambient loop runs alongside the host's, on one executor, as on the board — so
  the window is a device you can pick up and use, not just a ceremony viewer.
- **`tools/emu --usbip` makes the emulator a real USB device.** The Linux kernel's
  `vhci_hcd` attaches a TCP peer as a virtual host controller, so a host sees
  `/dev/hidraw*` and a PC/SC reader with no USB hardware anywhere — and what it
  enumerates is the device's own stack, not a description of it: the same
  `embassy_usb::Builder`, the same three interfaces in the same order, the same
  `rsk-usb` transports, over an `embassy_usb::driver::Driver` written against the
  USB/IP protocol. `fido2-token`, a browser, `ykman` and `gpg` reach the emulator
  through it, and the interface order issue #55 was about is now checked against
  the descriptors a host actually reads. USB/IP is network-transparent, so the
  emulator can stay on a Mac while a Linux VM imports it. See
  `tools/emu/README.md`.

- **The trusted-display guide shows the display, not photographs of it.** The six
  screens in [docs/guides/display.md](docs/guides/display.md) were camera shots of
  a 2.8" panel, complete with the room's white balance — the background reads blue
  in them and is near-black on the device. They are now what `rsk_ui::render`
  draws, at the panel's own 240×320, written by `rsk-emu --screenshots` and
  regenerable the day a screen changes. The guide also says the display can be
  tried in a window (`--display`) before buying the board. Ten screens it only
  described in prose are now shown too — including the Approve / Deny ceremony the
  page is *about*, and the same prompt against a padded look-alike relying party,
  where the clip keeps `…m.attacker.com` in view instead of the head an attacker
  padded it with.

- **The emulator is described where people look for it.** README, the docs' front
  page, the quick start and CONTRIBUTING all now say it exists and how to use it
  for testing — it had been reachable only from `docs/testing.md` and
  `docs/architecture.md`, which is not where someone with no board goes looking.
  CONTRIBUTING's on-device bullet also said those suites are run by hand against a
  board; that stopped being true when CI started running them.

- **CI runs the on-device suites.** `scripts/emu-suites.sh` drives every suite
  that needs no board — `tests/*.py` over the emulator's socket transports, plus
  the vendored OpenPGP card conformance suite — each on a fresh flash image, and
  `.github/workflows/emulator.yml` runs it on pull requests and nightly. These
  suites were hand-run against a flashed key, which is why seven of them had
  rotted unnoticed; this is what stops the eighth. The half that wants real USB
  (`02`, `61`, `65`, `73`, `77` and the pico-fido suite) still needs a runner with
  `vhci_hcd` and is not in CI yet.

- **`tests/third_party.py` runs the vendored upstream suites against RS-Key.**
  `third_party/` has carried pico-fido's and pico-openpgp/Gnuk's own conformance
  suites for a while with no way to run them that did not need a board and a
  person. The runner supplies what they cannot ask for — the power cycle RS-Key's
  CTAP 2.1 §6.6 reset window needs, which against `tools/emu` is one message on the
  card socket — and names every deliberate divergence as a strict `xfail`, so one
  that gets fixed fails the run rather than staying listed for ever. Nothing in
  `third_party/` is edited: the run is steered from outside by a pytest plugin.
  Both suites were refreshed from upstream at the same time (commits recorded in
  `third_party/README.md`, which nothing did before). pico-fido: **214 passed / 19
  expected divergences / 0 failed**. The OpenPGP card suite: **269 passed / 19
  divergences / 181 deselected / 0 failed** — it reaches the card through pyscard
  alone, so it runs over the emulator's card socket with no PC/SC, no USB and no
  root, on any machine rather than one with a reader and a key in it. Both gate.
  Every listed divergence is a spec citation, not a shrug: where the suite and the
  spec disagree the spec decides, and one of the refreshed suite's new tests found
  a real bug (`authenticatorConfigCommands`, below). The OpenPGP entries include a
  place where the spec contradicts itself (§4.4.1 says a constructed DO is returned
  *including* its tag and length; §7.2.6's worked example omits it). The
  deselections are a separate list, and a narrower claim: whole modules exercising
  a vendor extension RS-Key does not implement — Gnuk's admin-less mode, where PW1
  gains admin rights, which OpenPGP Card 3.4.1 never mentions. They are removed at
  collection rather than xfailed because an xfailed test still runs, and these ones
  block the card's admin PIN on the way past: deselecting the feature took the card
  suite from 192 failures to 13, and the difference was all cascade.

- **The emulator speaks the OTP frame protocol.** The keyboard interface's feature
  reports — the transport `ykman otp` uses, and the one `ykpers`/KeePassXC drive —
  now answer on `--usbip`, running the device's own state machine
  (`rsk_otp::hid::OtpHid`, moved out of `firmware/` so both builds share it). With
  it, `tests/02_usb_interfaces.py`, `73_otp_keyboard.py` and `77_otp_touch_wait.py`
  run with no hardware: interface order, an HMAC-SHA1 challenge-response through
  ykman's own `OtpConnection`, and a touch wait the host can abandon — as do
  `61`/`65`, driven by python-fido2's own HID transport with OpenSSL verifying the
  ML-DSA signatures. Five of the nine suites the socket shim refuses now run. Typed
  tickets are not emulated — a ticket comes from a button gesture, and this build
  has no button.
- **A USB/IP attach is a power-up.** RAM state goes, the card resets and the CTAP
  2.1 §6.6 reset window reopens, so `tests/replug.py`'s physical unplug becomes a
  `usbip detach` + `attach`. Measuring that window from process start instead left
  it already shut the first time any host looked, and `authenticatorReset` answered
  `NOT_ALLOWED` for ever.

- **`--yubico` now presents the whole Yubico identity**, USB VID/PID and descriptor
  strings included, not only the ATR and the OpenPGP AID vendor. `ykman` and Yubico
  Authenticator find a device by the Yubico VID; a half-applied masquerade is a
  card they cannot see at all, which is why the firmware ties all of it to one
  effective VID.

- The CTAPHID and CCID message vocabularies in `rsk-usb` are public, so the
  emulator's transports name the same values instead of redeclaring them.
- `scripts/docs_constants.py` now checks the constants copied into `tests/*.py`
  and `metadata/*.json`, not only those quoted in `docs/`, and resolves one
  `const A = B;` indirection — which is where the large-blob value below hid.
  66 copies checked, up from 5; the gate prints the live count on every run.

- **The applet wiring moved into `crates/rsk-device`.** `firmware/src/handler.rs`
  and `ccid_handler.rs` were the last of the device that no test could reach and
  the emulator had to reimplement — and what they hold is exactly the load-bearing
  part: whether a U2F command can land on the vendor applet, whether a disabled
  application is really invisible, and which records a device-wide wipe may take
  first. Both builds now run the same code, and the board's own parts (the LED
  atomics, the watchdog register carrying the clientPIN soft lock across a warm
  reset, the dual-core prime search, the display's PIN latch) sit behind a `Hooks`
  trait whose defaults are exact no-ops. Behaviour and wire surface unchanged; no
  `bcdDevice` bump.
- **The vendor applet moved into `crates/rsk-vendor`.** It was the last applet
  living in `firmware/`, so it was the only one with no host tests and the only
  one the emulator could not serve. Its hardware — the LED atomics, the second
  core's counters, the measurement benches, the reset — now sits behind a
  `Platform` trait the firmware fills in, and the applet itself is host-tested.
  Behaviour and wire surface unchanged: the same AID, the same instructions, the
  same status words (a build without an LED answers `INS_NOT_SUPPORTED` exactly
  as the unmatched instruction did before). No `bcdDevice` bump — nothing the
  device does over the wire changed.
- **The flash backend moved into `crates/rsk-store`.** The two
  `sequential-storage` partitions, the counter-FID routing and the scrub lap
  lived only in `firmware/src/flash_storage.rs`, so nothing that is not a board
  could run them: the `power_cut` fuzz target tortured a hand-written mirror, and
  the emulator had no log-structured store at all. Both now drive the shipped
  backend — the emulator over `sequential-storage`'s mock NOR flash with the
  device's geometry, with `--power-cut <n>` arming the injector. The firmware
  keeps what is the board's: the shared flash peripheral and its cache sizes.
  Behaviour unchanged; no `bcdDevice` bump.
- **The trusted display's flow moved into `crates/rsk-display`.** `rsk-ui` already
  held *what to draw*, host-tested and Kani-proved; the layer that decides *which
  screen when* — the PIN pad's state machine, the browse modals, the Approve/Deny
  wait that is the anti-phishing guarantee — lived in `firmware/`, so the only
  thing that could run it was a flashed board with a panel soldered on. The panel
  and the touch controller are now type parameters (a `DrawTarget<Color = Rgb565>`
  and a `TouchPad`), and the verbs that are genuinely the board's — backlight, wake
  button, the LED a ceremony borrows, the firmware globals it coordinates through —
  sit behind a `Hooks` trait whose defaults are exact no-ops. Behaviour and wire
  surface unchanged; no `bcdDevice` bump.

- **The suites that need a real USB stack now run in CI too, inside a VM.**
  `02_usb_interfaces`, `61`/`65`, `73`/`77` and the pico-fido conformance suite
  read USB descriptors or go through python-fido2's and pyscard's own transports,
  so they want a device the kernel enumerated — `vhci_hcd`, which a GitHub-hosted
  runner cannot supply: it cannot load a module
  ([runner-images#7541](https://github.com/actions/runner-images/issues/7541))
  and has no reliable `/dev/kvm`
  ([community#8305](https://github.com/orgs/community/discussions/8305)).
  `scripts/usbip-suites.sh` boots a QEMU guest that does (`nix build .#usbip-vm`)
  and attaches the emulator to it over the network. The emulator stays *outside*
  the guest — it is a TCP peer, not a device — which keeps the guest a fixed
  appliance (kernel, `usbip`, `pcscd`, Python) that no firmware change can
  invalidate, and keeps its build the same `cargo` one as everywhere else. Two
  emulators run at once on separate ports, because `73` drives ykman's own
  `OtpConnection` (which binds Yubico USB ids and nothing else) while the rest
  must stay on the default identity — the one whose CCID interface a stock driver
  skips, and the reason `nix/ccid.nix` exists. Everything inside runs on software
  emulation, so it costs minutes rather than seconds; it runs on every PR and
  nightly alongside the socket half.

### Changed

- **CI stopped building 24 firmware images for a documentation edit.** Every pull
  request ran the whole package — the gate, every feature flavour, every build
  knob — while `scripts/docs.sh check` ran in no workflow at all, so a docs-only
  change got 26 heavy jobs and zero link checking. `scripts/ci-scope.sh` now
  classifies a change and the jobs gate on it: the flavour matrix and the knob
  smokes want firmware, `crates/`, a toolchain pin or `nix/firmware.nix`; the
  emulator suites want the code they run; a documentation-only change runs the
  new `docs` job and nothing else. The rules are a script with a `--self-test`
  that `check.sh` runs, not a `paths:` filter, because their failure direction is
  a job that silently does not run. Two things stay unconditional: the mdBook
  build with its link check, and gitleaks — a secret scan that can be skipped is
  not a secret scan.

- **The firmware matrix stopped rebuilding from cold every time.** All 24 flavour
  rows shared one cargo cache key with each other *and* with the gate, so they
  raced to write the same entry while each restored a `target/` some other feature
  set had built — a matrix whose entire point is that the rows differ, thrashing a
  cache on that difference. Each row now has its own key. The build-knob smokes,
  which ran thirteen VIDPID presets and five env builds in sequence as the
  workflow's slowest job, moved into `scripts/ci-knobs.sh` and run as five
  parallel rows; grouped rather than one row per preset, because a public repo
  gets 20 concurrent runners and the flavour matrix already wants 24. The script
  and the matrix name the same groups in two places, so `check.sh` checks they
  still agree — a group only the script knows about is a smoke nobody runs.

### Fixed

- **On-panel settings were lost if the key was unplugged with the menu still
  open.** Brightness, display-sleep and the touch timeout were written to flash
  only when Settings *closed* — one write per editing session instead of one per
  −/+ tap, which is what keeps that churn out of the credential partition. But a
  USB key is unplugged, not shut down, and the settings screen is exactly where
  someone decides they are done: the change they had already watched take effect
  silently did not survive. An edit now also flushes once the menu has gone quiet
  for 1.5 s, so a run of taps is still a single write and the loss window shrinks
  from "the whole time the menu is open" to a moment. `bcdDevice` `0x0873` →
  `0x0874`.
- **The emulator pinned two CPU cores while doing nothing.** `embassy_futures::block_on`
  re-polls in a tight loop and its waker does nothing — correct on a microcontroller
  with nothing else to do, and 200% of a laptop for a tool meant to be left running
  while you use the browser talking to it. Everything the emulator awaits registers a
  real waker, so it now sleeps between them: 201% → 1.3% idle, and the same while a
  USB/IP host is attached.
- **`tests/02_usb_interfaces.py` demanded behaviour the device deliberately does
  not have.** It required the OTP frame protocol on *both* HID interfaces, which
  was true until audit run-30 removed it from the FIDO one — on macOS, serving it
  there put the whole FIDO interface behind the Input Monitoring prompt. The suite
  has failed on real hardware ever since and nobody ran it. It now checks the
  decision instead: the keyboard interface serves the frame protocol, the FIDO
  interface must refuse it.

- **`tests/14_up_only_after_reboot.py` passed on one laptop and crashed
  everywhere else.** It asserts with the credential from an enrolled
  `ed25519-sk` key and defaults to `~/.ssh/id_ed25519_sk`; on a machine that has
  never run `ssh-keygen -t ed25519-sk` that is a `FileNotFoundError` traceback,
  which reads as a device fault. It now skips (77) with the reason. Found by
  running the emulator sweep on a second machine — which is what the CI job is
  for.

- **The emulator was building against a different embassy than the firmware.**
  `tools/emu` is a detached workspace, so its `branch = "main"` resolved on its own
  clock — two months ahead of the lock the device ships. Harmless while the
  emulator only spoke sockets; not harmless now that it runs the real USB stack,
  where the drifted crate is the one that emits the descriptors a host enumerates.
  It follows the firmware's rev, and `scripts/check.sh` fails if any workspace
  parts from it. Same shape as the vendored `sequential-storage` fork the same
  workspace had silently replaced with upstream.
- **The `power_cut` fuzz target was tearing a mirror of the store, not the
  store.** The re-implementation it drove had drifted three ways, each load-bearing
  for what the target claims to prove: no `last_error`, so it could not see
  "absent" being confused with "the read failed" (the audit run-36 class); no
  `compact`, so the scrub lap that destroys superseded secrets was never fuzzed;
  and `EF_CRED_CTR` (0xC001) routed to the main partition where the device routes
  it to the counter one, tearing the store's busiest key in the wrong place. It
  now drives `rsk_store::SeqStorage` directly.

- **The published metadata statements said `maxSerializedLargeBlobArray` was
  2048.** The value moved to 2046 on 2026-08-04, when `MAX_LARGE_BLOB_SIZE`
  became `rsk_fs::MAX_VALUE_BYTES` — the store's real per-record ceiling — and
  both `metadata/rs-key.metadata.json` and its conformance variant kept
  advertising the old number to whoever reads them. `tests/62_metadata_statement.py`
  is the check for exactly this drift, and it had not been run since.

- **getInfo hid the `vendorPrototype` config subcommand it implements.**
  `authenticatorConfigCommands` (`0x1F`) listed `0x01`, `0x02` and `0x03` but not
  `0xFF`, and CTAP 2.3.1 §6.11.7 is explicit: "authenticatorConfigCommands MUST
  contain an array member with the value 0xFF if this subcommand is supported".
  RS-Key does support it — it is the phy/soft-lock configuration arm
  [docs/protocol.md](docs/protocol.md) §11 publishes for PicoForge — so a client
  reading the member to decide whether to use it was told the arm was absent while
  the wire spec documented it. Not obscurity in either direction: the same section
  says vendors must not count on it, and the arm still needs an `acfg`
  pinUvAuthToken. `0x15` (`vendorPrototypeConfigCommands`, *which* vendor ids
  exist) stays unadvertised. Found by the refreshed pico-fido suite.
  `bcdDevice` `0x0874` → `0x0875`.

## [0.4.8] - 2026-08-08

Everything in 0.4.7 below, plus the fix for the reason it never shipped: the
`v0.4.7` tag exists, but its release build failed on the 16 MB images and no
release was ever published for it.

### Fixed

- **A 16 MB image can carry the storage fence at all.** The partition table that
  arrived in 0.4.7 covered the whole chip, and on a 16 MB part the store's last
  sector holds `0x10FFFF00` — the absolute block the bootrom's RP2350-E10
  workaround owns. `picotool partition create` refuses to claim it (and separately
  requires unpartitioned space to accept the `absolute` family), so `nix build
  .#firmware-display` failed in the release with no diagnostic: the error goes to
  stdout, which `pt.sh` sends to `/dev/null`. The 16 MB layout now stops one
  sector short of the top, leaving that block outside every partition, and `pt.sh`
  no longer swallows picotool's message. This was never a 4 MB or 2 MB problem —
  their stores end far below the E10 block, and their layouts are byte-identical
  to 0.4.7.
  **Upgrading a provisioned 16 MB key (the `display` and `16mb` flavors, the
  `abrobot-16m` and `waveshare-touch-lcd` presets) moves its store 4 KB down, so
  the device comes up factory-empty: export your seed first**
  ([seed backup](docs/guides/seed-backup.md)). A 4 MB key upgrades in place, as
  usual.
- **The gate builds a 16 MB image and fences it.** The partition-table assertion
  ran on the 4 MB default only, and the display smoke build did not set
  `FLASH_SIZE=16M` either — so the one geometry with a special case in it was
  checked by nothing until the release ran.

## [0.4.7] - 2026-08-08

### Security

Audit run-37 found no MEDIUM or above. What follows is the LOW tail, grouped by the class
each defect belongs to rather than by the site that surfaced it — several were one of
several sites of a rule the codebase had already decided once and swept incompletely.

- **OATH's boot re-seal lap no longer destroys a record it cannot authenticate.** Six
  at-rest migrations run before the USB pull-up, and five leave a record that opens under
  neither key arm alone — PIV's comment says re-sealing garbage "would only destroy
  evidence", OTP's says such a slot must be "skipped rather than truncated and
  mis-resealed". OATH re-sealed unconditionally, through a buffer sized for plaintext
  (`CRED_MAX`) rather than for a sealed blob (`seal::MAX_BLOB`), so past that ceiling the
  GCM tag was discarded before the re-wrap and every credential and the access code were
  lost for good — permanently, because a later boot with the right key authenticates the
  outer wrapper and stops touching it. The scratch is now sized correctly and the lap
  requires positive structural evidence of legacy plaintext (a credential opens with
  `TAG_NAME` and carries `TAG_KEY`, which every pre-seal `cmd_put` guaranteed) before it
  will re-seal. Not attacker-reachable — no host can plant an unsealable record — but a
  wrong MKEK, a chip-serial change or a page-58 misconfiguration all reach it. A residual
  is named in the code: `EF_OATH_CODE`'s plaintext has no structure to check.
- **A PIN change on the device's own pad now revokes the persistent `pcmr` grant.**
  `EF_PAUTHTOKEN` is a flash record whose *presence* is a credential-directory read grant.
  Three of four PIN paths cleared it; the trusted display's own change signalled revocation
  through a RAM flag consumed only by the next CBOR dispatch — so a host that sent the
  ungated warm reboot as a plain APDU, or simply waited for an unplug, kept a grant minted
  under the old PIN for ever. The revocation moved down into `write_pin_verifier`, the one
  function in the crate that writes an `EF_PIN` verifier, so a future PIN path inherits it
  by construction instead of by review.
- **Three journalled events an ungated host can drive now coalesce, not one.** The
  defence existed and covered `CONFIG_WRITE` alone; a `getAssertion` carrying `up:false`
  and a U2F `AUTHENTICATE` with `P1=0x08` both take the spec-mandated silent path and
  appended unbudgeted, so 128 of either evicted the whole evidence window. The fold scans
  the window rather than only the newest entry — folding into the newest is defeated by
  interleaving two classes — and counts repeats in the entry's previously reserved
  trailing two bytes. Four comments asserting `CONFIG_WRITE` was the only such event are
  corrected.
- **A stranded chain segment can no longer swallow the next SELECT.** `chain_hdr` was
  consulted only at the terminator, and the SELECT escape hatch fired only on a header
  *mismatch* — so a segment sent as `10 A4 04 00`, whose masked header equals every
  SELECT-by-AID's, absorbed a co-resident process's SELECT and left the previous applet
  selected with its verified-PIN latch intact. A SELECT is now judged before the header
  comparison, and the accumulation branch is bound to its opener too.
- **`CTAPHID_WINK` can no longer forge the awaiting-touch indicator.** Re-arming reset the
  deadline unconditionally, so one 64-byte report every 70 ms held the reserved touch
  colour solid for ever — on the default single-LED board, pixel-identical to a real
  consent prompt, from any unprivileged process, with FIDO2 and U2F disabled and nothing
  written to the journal. A burst now always ends `WINK_MS` after the *first* arm, and a
  wink arriving during a touch wait shows the real prompt instead. The re-arm rule lives in
  `rsk-led` with a Kani proof rather than in the firmware.
- **`CTAPHID_WINK` on a build with no indicator now answers `ERR_INVALID_CMD`.** It left
  `CAPABILITY_WINK` clear and then reported a successful wink anyway — the device saying
  both "I have no indicator" and "yes, I winked". `docs/guides/led.md` already described
  the correct behaviour; the code did not.
- **`ykman config set-lock-code` no longer discards the enabled-applications policy.**
  `trim_to_cap`, added last cycle to stop stored bytes vetoing a write, evicted entries
  from the front by position and never looked at the tag — so on an over-cap legacy record
  the first thing dropped was `USB_ENABLED`, whose absence resolves to *everything
  enabled*. The eviction is tag-aware now, and the companion defect is fixed in the same
  pass: the merge buffer is sized for the overflow case, so `overlay_dev_conf` can no
  longer answer `TooLong` before the trim gets a chance.
- **The host-writable LED pin can no longer steal a pad another driver owns.** The
  effective data pin is resolved from the phy record at boot and was filtered only against
  the GPIO range and the presence pin, so on a board with an LED-power or USR-LED pin a
  host could point it at either — falsifying a containment precondition `docs/unsafe.md`
  states for eleven `AnyPin::steal` sites.
- **`rsk secure-boot load-key` verifies the burn it made.** The post-burn check tested
  that the first two ECC rows were non-zero, which passes on any garbage — including
  picotool's replication of a two-byte `bootkey0` across all sixteen rows, the one
  malformed shape the tool's own type gates let through. It now reads the slot back and
  compares it to the fingerprint it wrote, and refuses a `bootkey0` that is not 32 bytes.
  Without this, enforcement could be enabled on a board whose only trusted fingerprint
  matched no signing key.
- **`gate_union.py` now catches the defect it was written for.** Run the shipped script
  against the tree containing last cycle's OATH bug and it exited 0: its regex required
  `pub`, and that predicate was private. It now matches private and crate-private
  predicates, scans `firmware/src/` too, and asserts a roster of applet crates so a missing
  arm is loud instead of invisible.
- **The most destructive host command's two-key refusal has a driven test.** `offboard`'s
  replug guard could be deleted with all 280 tests green, because the refuse-to-guess
  inventory classifies by callee name and the guard's AST is identical with and without it.
  Raw `hid.device()` opens are now inventoried with written rationale, and the guard itself
  is exercised with two devices attached.
- **Hardening, swept as classes:** every `EF_PW_PRIV` retry-counter write clamps its slice
  (five sites, one idiom — unreachable today, but a panic there bricks the device before
  USB comes up); `Sw::retries` clamps its argument so a large retry total cannot collide
  with `63C0` "blocked"; the vendor CTAPHID path scrubs its scratch like its sibling; both
  host tools verify the CTAPHID INIT nonce echo and bound-check the response; `rsk identify`
  reports a refusing device instead of aborting the walk; and `docs_constants.py` stops
  scanning test files, where a stale literal masked a moved constant.

### Changed

- **Consent titles are shorter and can no longer run off the panel.** The ceremony title
  was the one label on that screen painted unclipped, so 23 of 36 were cut mid-word —
  including both irreversible OTP fuse burns, where the title is the *only* text on the
  card. Six were reworded and the rest now fit outright; a test measures every consent
  title against the band, so a future long one fails the gate instead of being cut on
  glass. A `pcmr` token request also gets its own title now: it grants a permanent
  directory-read capability behind what was the same card as a ten-minute session token.
- **The audit screen distinguishes "nothing happened" from "I was not watching."** With
  journalling off — the default — it said "No activity yet", which is a claim about the
  world the device never made.
- **The on-panel PIV generate no longer promises more than it delivers.** It said "Does
  not erase anything" while overwriting the retired slot's certificate; the picker and the
  sink now both skip a slot holding one, and the caption says what the fence covers.
- **`rsk-tui --selftest` refuses a flag where the PIN should be.** `--selftest --demo` sent
  the literal string `--demo` to the device as a clientPIN, spending a real retry, and
  `--demo --selftest` silently ignored `--demo` and ran a real seed export. Both are
  refused, and `--help` now shows the `[PIN]` positional the guide already documented.
- **`rsk audit log` and the offboard receipt render a coalesced run's count.**

- **The KV store is fenced off from the USB bootloader.** An attacker with brief physical
  access could `picotool save` the whole flash, guess PINs until the retry counter locked,
  then `picotool load` the snapshot back to reset it — unlimited offline guessing, against
  every applet's counter at once ([#37](https://github.com/TheMaxMur/RS-Key/issues/37),
  reported by Token2). The shipped image now embeds an RP2350 partition table that denies
  the bootloader read *and* write over `__kvmain_start..__kvcnt_end`, so both halves answer
  `permission failure` from the bootrom while the running firmware keeps `secure: rw`.
  `scripts/pt.sh` derives the fence from the ELF's own linker symbols rather than restating
  the layout, so it cannot drift from the store on any `FLASH_SIZE`/`KVMAIN`/`BOARD`, and
  `check.sh` asserts the emitted table back against those symbols. Upstream leaves the
  bootloader `r` here; RS-Key denies the dump too, because before the OTP burn the at-rest
  seal root derives from on-chip state alone.
- **Read that as "the attack now needs a reflash first", not "rollback fixed".** The
  firmware partition has to stay bootloader-writable or updates could not exist, so on a
  board without secure boot an attacker flashes an image carrying a permissive table and is
  back where they started. Sealing is what makes the fence hold — the signature covers the
  table, and a byte flipped anywhere in it fails both hash and signature. It is worth doing
  because this is the one snapshot/restore gap secure boot did *not* close by itself:
  secure boot verifies executable images, and writing the data region is not execution, so
  a fully provisioned board was still snapshot/restore-able until now. One consequence
  worth planning for: any image you signed earlier carries no table and re-opens the fence,
  which is an ordinary downgrade and wants a rollback floor above your pre-table builds
  ([threat-model.md](docs/threat-model.md), [production.md](docs/production.md)).

### Added

- **`rsk identify` and a TUI "Identify this key" action.** Nothing in the first-party
  tooling could drive the wink that now works, so it was useful only to whoever wrote
  their own script. The CLI is the one command that does *not* refuse to guess between
  attached authenticators — telling them apart is the whole job — so it walks every one
  in turn and names it; a device whose INIT leaves `CAPABILITY_WINK` clear is reported
  rather than winked. The TUI action takes the first match like its other reads, so it
  points at the device the dashboard is actually showing.
- **`CTAPHID_WINK` actually winks.** Every `INIT` reply set `CAPABILITY_WINK`, which
  §11.2.9.2.1 defines as "implements CTAPHID_WINK", and the handler then answered the
  command with an empty frame and no visible action — so `fido2-token -W` and every
  "which key is this?" flow reported success while nothing happened, in exactly the
  situation the command exists for (two identical keys on one host). The indicator now
  answers with four fast blinks over ~0.6 s in the touch colour, overriding the
  configured effect and `--steady` — a wink that a display setting can render invisible
  is the same bug again. It also outranks nothing else: the ambient status resumes
  where it was. A build with no indicator (`LED_KIND=none`, which the display build
  forces) now leaves the capability bit **clear** instead of claiming it.

- **`perCredMgmtRO` and a real persistent pinUvAuthToken (CTAP 2.2 §6.5.2.2).** The
  `pcmr` permission was half-wired: clientPIN accepted it and handed out a token, but
  `credentialManagement` never verified against that token, so it authorized nothing —
  and getInfo did not advertise `options.perCredMgmtRO`, which §6.5.5.7.2/.3 make the
  precondition for requesting `pcmr` at all. Both halves are now real. getCredsMetadata,
  enumerateRPsBegin and enumerateCredentialsBegin verify the persistent token first and
  fall back to the session token (§6.8.2/.3/.4); deleteCredential and
  updateUserInformation still refuse it, because the permission is read-only. The token
  itself lives in `EF_PAUTHTOKEN`, sealed under the device key like the seed, so it
  outlives the power cycle — the point of "persistent": a platform can refresh a
  credential list across replugs without re-prompting for the PIN. Its record's
  presence *is* the grant, so `resetPersistentPinUvAuthToken` is a deletion, which
  `changePIN`, a `setMinPINLength` that forces a PIN change, and `authenticatorReset`
  all perform. It was previously RAM-only and, on a device whose PIN had been *set* but
  never *changed*, was never seeded at all — 32 zero bytes, which would have become a
  known token the moment anything verified against it.

- **A ccid driver that knows the default identity: `overlays.ccid-rs-key` and
  `packages.<system>.ccid-rs-key`.** `pcscd` does not drive readers — the **ccid**
  driver does, and it binds only the USB ids in its own `supported_readers.txt`, so
  on the default identity (`0x1209:0x0001`) the CCID interface was skipped
  *silently*: FIDO kept working while OpenPGP, PIV, OATH and Yubico-OTP looked
  absent rather than broken, and no udev or polkit rule helps with a reader the
  driver never claimed. Documenting it (0.4.6) told people what to patch by hand;
  this does the patching. The overlay replaces `pkgs.ccid` — exactly what the NixOS
  `pcscd` module puts in its plugin list — with the same driver plus one reader
  entry, verified additive at build time: 629 entries become 630, none removed, no
  other bundle key touched. It stays *ours* rather than an upstream submission
  because `0x1209:0x0001` is pid.codes' shared **prototype** id, and listing it in
  the ccid project would bind every unrelated prototype using it; the build fails
  loudly if a future ccid restructures the list out from under the edit. The
  `VIDPID=Yubikey5` build still needs none of this — `0x1050:0x0407` is listed
  already. Reported in [#67](https://github.com/TheMaxMur/RS-Key/issues/67) and
  [discussion #58](https://github.com/TheMaxMur/RS-Key/discussions/58);
  [linux.md](docs/linux.md) has the wiring for both routes.

- **The docs name the two third-party host tools, and the quick start shows one.**
  Nothing in the setup path mentioned that a flashed key can be configured from a GUI
  at all: [PicoForge](https://github.com/librekeys/picoforge) appeared only in the
  host-tools section, below the build instructions, where someone who just flashed a
  board never reaches. It is now in both quick starts and in the `rsk` guide beside
  the CLI and the TUI, with a screenshot of the Device Overview page. The screenshot
  is deliberately a *freshly flashed default* board — `1209:0001`, no PIN yet, boot
  mode `Development` — so it matches what the reader is looking at rather than a
  provisioned key or the `VIDPID=Yubikey5` flavor.
- **[Telesma](https://github.com/go-ctap/app) is tracked in the interop matrix as
  `⏳ untested`** — the first row to use a mark [interop.md](docs/interop.md) has had
  in its legend from the start. It is a desktop CTAP workbench over
  [`go-ctap/ctap`](https://github.com/go-ctap/ctap), an independent CTAP 2.0–2.3
  client stack, and that is the reason it is worth a row: every FIDO cell in that
  matrix reads the device through libfido2 or python-fido2, so a divergence both of
  them tolerate is invisible at that layer — the same shape as the `ykman openpgp
  info` GET DATA `6E` bug, which every protocol test passed.
  [testing.md](docs/testing.md) says as much where it explains the layer.
- **`rsk status --json` reports the chip serial** (`rsk` 0.3.32), the field
  `rsk-tui --once` already showed, so a script that tells two attached keys apart
  no longer needs the TUI. It comes from the rescue SELECT response, so it is
  `null` wherever the CCID interface is unavailable — on Linux that is the ccid
  reader list above, not a device fault. Thanks to @mannp
  ([#69](https://github.com/TheMaxMur/RS-Key/pull/69)).

### Fixed

- **The packaged `rsk-tui` found no device on Linux.** `nix run .#rsk-tui` built
  against `pkgs.systemd`, which no longer carries `libudev.so.1` in `lib/`, so
  hidapi's hidraw backend lost the library at *runtime* — the build succeeded and
  the dashboard then saw nothing plugged in. It links `pkgs.udev`
  (systemd-minimal-libs) instead, where the library actually lives. Thanks to
  @mannp ([#68](https://github.com/TheMaxMur/RS-Key/pull/68)).

- **Three seal recipes produced an image that would not boot on a provisioned board.**
  production.md states the rule — every `picotool seal` carries `--rollback <your floor>`,
  and a versionless sealed image is refused fail-closed — while signing-keys.md (twice) and
  build.md showed `--major 1 --minor 0` and stopped. Exactly the pages a reader reaches
  *after* enabling anti-rollback. All three now carry it.
- **The gate compares documented constants against the code.** A number copied into prose
  rots silently — the constant moves, everything still compiles, every test still passes, and
  the docs go on asserting the old value. `architecture.md` spent the whole capacity-work era
  claiming `MAX_DYNAMIC_FILES` was 256 against a real 1280. `scripts/docs_constants.py` now
  fails the gate on any value the docs state next to a constant's name that the code no longer
  assigns to it. Narrow by construction — 5 pairs, because the docs rarely state a value that
  way — and it fails if that count drops, so it cannot start passing vacuously.
- **`otp_secureboot.json` now has a reason, not just a description.** Four pages named the
  file; none said why it exists. It is the courier for one number: the bootrom compares
  `SHA-256(public key in the image)` against a fused fingerprint, signing happens on the host
  with a key that must never reach the device, and fusing happens against the board — so
  something has to carry the fingerprint between two operations that may be months and
  machines apart. 2b now says that, with a table of who writes it, who reads it, and what is
  inside, plus the fact nobody had established: it is a pure function of the signing key
  (`--major`/`--minor`/`--rollback` do not change a byte), so losing it costs one command and
  it never needs backing up. The `.pem` is the thing to protect.
- **`production.md` opens with every command it will run, in order.** The CLI groups by fuse
  family and the page groups by goal, so `rsk otp` appears in stage 1 and again in stage 3 —
  which reads as disorder until someone says the two axes cross. The table names each
  command, its stage, what it writes and whether it can be undone (seven of the eight: never).
- **`production.md` stage 2b asked you to sign an image you had not built yet.** The build
  recipe lived below stage 2c, so a first pass through the page hit `picotool seal
  firmware.uf2` with no such file and no `otp_secureboot.json` — and nothing said where
  either comes from. 2b is now self-contained: build, embed the partition table, convert,
  seal, with the `otp.json` named as something `seal` creates at a path you choose.
- **`architecture.md` understated the file budget by 5×** — `MAX_DYNAMIC_FILES` has been
  1280 since the capacity work, not 256, in the section that reasons about how full a key
  can get.
- **Two documented `rsk secure-boot` commands could not run, and the file they revolve
  around was never explained.** `otp.json` is a required positional, so production.md's burn
  ritual (`rsk secure-boot load-key` with nothing after it) and signing-keys.md's key-loss
  row both exited 2 — the latter six lines below the same file spelling the command
  correctly. The file itself was named four times and defined nowhere: it is an **output**
  of `picotool seal`, carrying the SHA-256 fingerprint of your signing key plus the two burn
  flags, not a secret and not something you write by hand. production.md now says that where
  you first meet it. A new gate test (`tools/rsk/test_docs_commands.py`) parses every `rsk …`
  line inside a docs shell block against the real CLI parser, so a command nobody can run
  cannot ship again; prose mentions stay out of scope, fenced blocks do not.
- **Linux: the CCID driver's reader list, and why the applets go missing without an error.**
  `pcscd` cannot bind a reader the **ccid** driver never claimed, and that driver claims only
  USB ids present in its own list — which the default `0x1209:0x0001` identity is not. FIDO
  keeps working while OpenPGP, PIV, OATH and Yubico-OTP simply look absent, and no udev or
  polkit change touches it, because those govern access to a reader that was skipped
  ([#67](https://github.com/TheMaxMur/RS-Key/issues/67) — the third report of this same root
  cause). [linux.md](docs/linux.md) now says so before the setup steps, gives both workarounds,
  and explains why the fix is not simply upstream: `0x1209:0x0001` is pid.codes' shared
  *prototype* id, so listing it in the ccid driver would bind every unrelated prototype using
  it. A dedicated VID/PID is pending and the submission waits on it.
- **`versioning.md` advertised the wrong `versions` and a stale `bcdDevice`.** It listed
  getInfo `versions` as only `U2F_V2` + `FIDO_2_0` (missing `FIDO_2_1` and `FIDO_2_3`) and
  pinned a `bcdDevice` literal hundreds of builds old. It also never answered the question
  people arrive with ([#66](https://github.com/TheMaxMur/RS-Key/issues/66)) — *which build is
  on this device* — which `5.7.4` cannot, being a compatibility constant identical across
  every build of every release. The page now names `bcdDevice` as the build identity, shows
  how to read it, and notes that a plain `nix build` image carries no version in the file at
  all.
- **A `nix build` with `fwVersion` set no longer calls itself `5.7.4`.** The derivation's
  `version` was a literal that ignored the knob, which reads as a version pinned in the flake
  ([#66](https://github.com/TheMaxMur/RS-Key/issues/66)).
- **An over-long `allowList` or `excludeList` is refused, not truncated.** Both
  parsers dropped every credential descriptor past `maxCredentialCountInList` (16)
  and carried on as if the list had ended there, instead of returning
  `CTAP2_ERR_LIMIT_EXCEEDED` so the platform splits it. On getAssertion that answers
  `NO_CREDENTIALS` for a credential the device holds — invisible whenever the match
  happens to sit in the retained head. On makeCredential it silently forfeits
  re-registration protection: padding the `excludeList` past 16 hid the registered
  credential and minted a duplicate, where a YubiKey returns
  `CTAP2_ERR_CREDENTIAL_EXCLUDED`.
- **A credential descriptor whose `type` is not `public-key` is ignored.** Both
  parsers read the field only to check it was present and then matched on the `id`
  regardless, so a descriptor naming a credential kind this device cannot assert was
  treated as one of ours. Foreign descriptors are now skipped — while still counting
  towards the ceiling, so they cannot buy room past it — and an `allowList` left with
  no usable descriptor keeps scoping the request: it fails with `NO_CREDENTIALS`
  rather than falling through to resident discovery and answering with some other
  credential.
- **getInfo no longer advertises `FIDO_2_2`.** CTAP 2.2 never defined that version
  string and CTAP 2.3 §6.4 says it outright: "MUST not be present in versions member".
  The 2.2 surface is discovered through option IDs and getInfo members instead.
  `versions` is now `U2F_V2, FIDO_2_0, FIDO_2_1, FIDO_2_3`, and both metadata
  statements match.
- **A PIN established over a torn `authenticatorReset` cannot inherit an old
  read grant.** The wipe's last phase can drop `EF_PIN` and lose power before
  `EF_PAUTHTOKEN`; `setPIN` now clears the persistent token first, so the holder of a
  pre-reset `pcmr` grant cannot enumerate the credentials created after it.
- **Two reserved-but-unwired definitions are gone.** `EF_AUTHTOKEN` (0x1090,
  "pinUvAuthToken seed") was never written or read by any build — the session token is
  RAM-only by design, since §6.5.6 regenerates it at power-on — yet it sat in both
  `authenticatorReset` sweep predicates claiming there was something there to wipe. And
  the OpenPGP extended-header tag was compared as a bare `0x4D` literal beside an
  `EF_EXT_HEADER` constant nothing used.

## [0.4.6] - 2026-08-06

### Security

- **An rpId carrying whitespace is refused.** `font::width` measures glyph ink, so
  trailing spaces paint nothing: `bank.com ` rendered pixel-identically to `bank.com`
  on the trusted display's sign-in, passkey-list and delete screens while hashing to a
  different relying party, and an all-whitespace id passed every length-based
  emptiness check and painted a ceremony naming no relying party at all. No browser
  can send either — WebAuthn requires a valid domain string.
- **The CCID pinpad no longer paints on a bare host request.** Any local PC/SC client
  could raise the trusted display's PIN pad titled "OpenPGP Admin PIN" for 30 s, with
  nothing selected and even with the applet disabled, and a typed PW3 was spendable
  from the attacker's own session because OpenPGP's touch default is off. It now
  refuses *without painting* unless the addressed applet is selected and enabled, and
  asks for the same deliberate hold the clientPIN built-in-UV path does.
- **A refused PIV `GENERATE` no longer destroys the slot.** The certificate, key and
  public-point cache were written before the requested PIN/touch policy was validated,
  so a request carrying a policy byte this firmware does not implement — Yubico's Bio
  policies, say — answered `6A80` with the previous key already gone and the new one
  governed by the old key's metadata.
- **A failed flash read is no longer cached as "file absent".** `Storage::read`/`size`
  collapse "absent" and "the read failed" into `None`, and the present-cache recorded
  that as a decided fact for the rest of the boot — which would have opened every gate
  that reads `has_data`, `clientpin::set_pin` among them.
- **`WRITE CONFIG` values are width-bounded and the cap can no longer wedge the
  owner.** Only `USB_ENABLED` was bounded, so one unauthenticated 40-byte entry made
  every later partial write — the only shape ykman sends — exceed the post-merge cap,
  and the owner could never enable or disable an application again. The merge now
  evicts its oldest un-restated entries instead of refusing, so already-shipped
  oversized records cannot veto a write either, and the idempotent-replay
  short-circuit compares the merge rather than the request.
- **Both irreversible OTP burns refuse on a fake-key image.** `PK_FAKE_MKEK` populates
  the in-RAM key without reading OTP, forging the one guard that says "the real fuses
  are already written" — so the page-58 lock could be burned on a blank board, after
  which it can never be provisioned. `docs/build.md` already promised a fake-key image
  writes no fuses.
- **The CCID receive path abandons an interrupted message.** It had no timeout and
  never reset its accumulator, so a bus reset inside a multi-packet import left a
  prefix that was spliced onto the next host's message and misparsed — the CTAPHID
  sibling in the same crate has carried exactly this guard since it was written. The
  bad-framing reply also echoes the sequence it is answering instead of `0`.
- **`rsk secure-boot` treats an unreadable OTP row as fatal**, not as a blank one: with
  a second RP-series board in BOOTSEL every read failed and a hardened, secure-boot
  *locked* unit printed as virgin, while `load-key` reached its typed confirmation on
  state the tool had never read. It also refuses more than one device, and no longer
  burns into a revoked slot.
- **Every applet's gate records are now deferred to the second phase of a wipe** —
  five were missing. `for_each_key` yields in flash-ring order, so a factory reset
  interrupted in its first phase could delete a gate ahead of the secrets it
  protects: the next SELECT derived OATH's `validated` from the absent access code
  and served every surviving TOTP credential with no authentication; `scan_files`
  re-seeded the published default PIV management key over slot keys that were still
  live; a deleted `EF_BACKUP_SEALED` re-opened the one-time master-seed export window
  over a seed that survived; and OpenPGP's UIF flags and retry counters were re-seeded
  to touch-OFF and a full budget over a key its surviving DEK could still open.
  `is_oath_lock_fid` was private, so the firmware could not name it at all — every
  applet now exports its own gate predicate, the union is a plain fold over them, and
  `scripts/gate_union.py` fails the gate when an applet is missing from it. OpenPGP's
  own TERMINATE DF sweep became two-phase for the same reason, and `scan_files`
  repairs a surviving management key's metadata — reading its algorithm from the
  sealed key and failing safe on touch policy, since `EF_META` is shared with every
  other applet and goes in the first phase.
- **PIV factory RESET is two-phase.** The single sweep deleted the PIN/PUK/retry
  files and the slot keys in flash-ring order, so a RESET interrupted between them
  let the next SELECT re-provision the factory PIN over key material that was still
  live and, unlike OpenPGP's, not PIN-bound at rest. Keys go first now; the same
  ordering was swept into `authenticatorReset` and the device-wide `factory_wipe`,
  which both bypassed the per-applet rule. A failed RESET also no longer hands back
  a fresh 3/3 retry budget.
- **A failed registration no longer leaves an unreachable passkey.** `credential_store`
  committed the credential before its RP record, so a store that filled — or a power
  cut between the two writes — left a working discoverable credential that neither
  `credentialManagement` nor the trusted display could list or delete. The RP record
  is written first, and a 256-credential RP is refused rather than silently
  saturating its count.
- **The at-rest scrub is re-armed by every lazy pre-OTP re-key**, not just OpenPGP's.
  The FIDO clientPIN, the trusted-display device PIN, PIV and OATH all superseded a
  verifier keyed under the public chip serial without clearing `EF_HARDENED`, leaving
  it in the flash ring after the OTP burn — the one step whose purpose is to make
  at-rest protection real.
- **A dangling command chain no longer prefixes another process's APDU.** Only the
  header that opened a chain may close it (ISO 7816-4 §5.1.1.1, `6883`); previously
  a single `CLA 0x10` segment made any later command the terminator, so a victim's
  PIV `GENERAL AUTHENTICATE` signed injected data under their own touch. SELECT keeps
  its escape hatch so a stranded chain cannot wedge the next process.
- **A host can no longer close the trusted display's menus.** The 2.5 s yield floor
  written for exactly this attack was applied at 2 of 26 modal exit polls, so a
  process looping the ungated `authenticatorGetInfo` shut every screen as the owner
  opened it. All 24 now use the floored form.
- **`WRITE CONFIG` merges instead of replacing.** ykman sends only the fields it
  changes, so `ykman config set-lock-code` — which sends the lock TLV alone — stored
  an empty record and silently re-enabled every application the owner had disabled.
- **NDEF writes are gated on the access code**, like SET SCAN MAP: the fix that
  closed that gap did not reach its sibling, leaving an ungated device-global write.
- The CTAPHID MSG channel-scoping check is no longer skipped: it sat in the right
  operand of a `||` whose left side every `CTAPHID_INIT` sets, so an attacker could
  leave the vendor AID selected under a victim's channel and deny them U2F.
- An on-panel factory reset now exits its menu, so nothing re-creates the display
  record after the wipe — `pin_declined` was surviving the reset and the next owner
  was never offered device-PIN onboarding.
- `rsk-tui` clips device strings by display column rather than character count, so a
  wide-character value can no longer push its truncation marker off-screen, and the
  restore path wipes the master seed on every error path rather than only on success.
- Recorded in the threat model: a WebAuthn large-blob key is obtainable with no user
  interaction. CTAP 2.1 §12.3 imposes no UP/UV precondition (unlike §12.5 for
  `hmac-secret`), so this is conformant behaviour, and §6.10 ties that data's
  confidentiality to the credential's `credProtect` policy.

Two audit runs' findings land here. Full write-ups are in the commits; the
one-line rule for each is below.

- **The seed-backup MSE channel is one-shot.** Binding it to the CTAPHID channel
  id (added below) was not a boundary — an interloper forges the victim's cid, and
  `mse_ready()` compared the attacker's bytes with themselves, so the device still
  encrypted the 32-byte master seed to a co-resident process under the owner's
  genuine PIN and touch. A second `MSE` while one is live now refuses *and* drops
  the channel, and every gated consumer spends it: a squatter can deny a handshake,
  never redirect one. No wire change; the channel's **lifetime** changes, so
  handshake immediately before each subcommand and retry once on `0x30`.
- **A torn OATH `RESET` could strip the access code while the credentials
  survived.** The batched sweep deleted in flash-ring order, so on a device whose
  code predates its credentials the lock went first; cut power there and an
  unauthenticated `LIST` / `CALCULATE ALL` returned labels, live TOTP codes and the
  password-safe fields. Two phases now: credentials to provable emptiness, then the
  lock records. (Seeds never leave — `CALCULATE ALL` withholds HOTP and touch
  credentials, `GET CREDENTIAL` never returns `TAG_KEY`.)
- **`WRITE CONFIG` accepted records the device and a host read differently.** No
  tag-uniqueness and no `USB_ENABLED` length check, against a ykman parser that is
  last-wins and any-length. A 1-byte value made the owner's own `config usb
  --enable PIV` disable five applets; a 4-byte one escaped the clamp and was
  self-perpetuating, so every later `ykman config usb` reported success and changed
  nothing, permanently. Each tag once, `USB_ENABLED` exactly two bytes.
- **A stored device-config record is validated on read, not only on write.** One a
  laxer build accepted survived the upgrade and kept being echoed verbatim — which
  hid the device from ykman for good — while enforcement skipped the same value.
  READ CONFIG now synthesises its echo from the mask actually enforced, so the two
  can no longer disagree. `dev_conf_unchanged` moved to the read bound with them.
- **OpenPGP algorithm attributes were validated on write only**, and the floor
  under the read sites is an assembly alignment constraint (any 32-byte multiple).
  Every released build through v0.4.5 accepts `PUT DATA C1 = rsa512` from PW3 —
  a factory card's PW3 is the spec default — and the attribute survives the
  upgrade, so the *owner's* next `GENERATE` mints a factorable key. Checked where
  the key is made now.
- **`GET DATA C1` answered a corrupted attribute for `rsa1024`** (`00 00 20 00`):
  a stored attribute was emitted bare on a standalone read while `get_data` decides
  whether to strip a header by *sniffing* one. `gpg --card-status` read a non-
  attribute while `GENERATE` made a 1024-bit key. Found by differential against a
  real YubiKey; 36/36 attributes round-trip on hardware.
- **OpenPGP `VERIFY` derived its verifier file from an unvalidated P2.** The bit
  test let 64 values through, and `0x1000 | p2` reaches internal FIDs of other
  applets, FIDO's `EF_PIN` included — held back only by a one-byte length
  coincidence in another crate. The three defined modes are enumerated now.
- **A failed OpenPGP EC `IMPORT` destroyed the key it failed to replace**: the
  sealed key was committed before the scalar was validated. Point derived first.
- **PIV metadata now matches what PIV enforces.** `DEFAULT` and undefined policy
  bytes reached flash, and both gates tested for the values that *require* a
  prompt — so anything unrecognised meant "no gate" while the screen said
  "Default". Only `NEVER` skips a gate now, and undefined values are refused at the
  write. The management key's declared algorithm is also read at use: 3DES and
  AES-192 are both 24 bytes, so an AES-192 key completed a full 3DES mutual
  authentication.
- **`keyCertSign` is asserted only on a CA.** Every certificate the device emits
  carried it with `basicConstraints cA=FALSE` — an RFC 5280 §4.2.1.3 MUST
  violation on the object an auditor reads to decide what a key is for.
- **`SET SCAN MAP` is gated on the access code it can silence.** The map is global
  and decides the scancodes a slot emits, so an all-zero one suppressed a protected
  slot's OTP and an all-`0x28` one made it type Enters — without ever presenting
  that slot's code. It also counts as a function slot, so `ykman config usb
  --disable OTP` takes it inert with the rest.
- **A SELECT terminates a command chain instead of finishing it.** `chaining` is
  sticky, untimed and survives across PC/SC connections, so one `CLA 0x10` APDU
  made the next process's opening SELECT the terminator: its selection silently did
  not happen, and PIV's per-operation touch prompt then authorised the injector's
  data. Matched by shape — `0xA4` is also YKOATH CALCULATE ALL.
- **The CTAPHID_MSG applet selection is scoped to its channel.** It was one global
  for all of them, and U2F has no SELECT of its own, so another process's SELECT of
  the vendor AID collided the victim's `REGISTER`/`AUTHENTICATE` with vendor
  instructions.
- **An on-panel FIDO PIN change revokes live `pinUvAuthToken`s.** `FidoState` lives
  in the worker and outlives every dispatch, and the token is random RAM state, not
  a PIN derivative — so a process holding a `PERM_CM` token kept deleting resident
  credentials (no touch) for up to ten more minutes, right after the owner did the
  one thing they believe revokes host access.
- **The on-panel factory reset goes through the worker's reboot**, not
  `SCB::sys_reset` — which skipped the scrub of the DRBG, the OTP keyboard buffers
  and core1's mailbox on a reset asked for precisely to leave nothing behind.
- **The panel writes to the audit journal.** Nothing under `display/` ever did,
  while the panel renders that journal as its evidence surface: an on-screen seed
  reveal, seal or PIN change left no entry although every USB equivalent is logged.
- **A host can no longer postpone the on-device auto-lock.** Its deadline was only
  evaluated inside the ambient-quiet window, which every ceremony exit pushes 400 ms
  forward, so an unauthenticated `authenticatorSelection` loop starved it and
  display sleep both.
- **The panel's touch latch survives a host's repaints.** It disarmed on *every*
  repaint and `Screen::Home` carries the LED status, which the host drives around
  each dispatch — so a plain CTAP loop discarded every tap. Only a change of surface
  disarms. The sleep→wake path, which assigned `shown` directly and never disarmed
  at all, is covered too: a finger held to wake a dark panel came back as a
  deliberate tap on the screen painted under it.
- **A hostile device can no longer author or hide rows in the TUI status panel.**
  `Wrap { trim: true }` put a wrapped continuation at column 0, indistinguishable
  from a row, and the extra lines pushed security verdicts off a pane with no
  scrollbar and no keys bound to it. One row is one line, clipped with a marker;
  overflow is counted.
- **The pinUvAuthToken gets a fresh IV** (CTAP 2.1 §6.5.7). Mostly masked by a
  per-issuance random token — except on the `PERM_PCMR` branch, whose token is
  filled once per power cycle, so repeated issuances were byte-identical.
- **`largeBlobs` bounds its read offset in the wire's own width.** Narrowing the
  `u64` first meant `2^32 + 5` read from 5 on the device.
- **`ATT_CLEAR` uses `force_delete`**, like its siblings: `Fs::delete` no-ops on a
  present-cache false-absent and still returns `Ok`, reporting a clean erase over a
  surviving key.
- **The OTP keyboard's response buffer is scrubbed before BOOTSEL.** `FrameTx::buf`
  held the last response — for slots `0x30`/`0x38` a 20-byte HMAC-SHA1
  challenge-response, which with a fixed challenge *is* the credential.
- **`core1::scrub` waits for core1 to reach its own sieve scrub** before the drop
  to BOOTSEL, instead of leaving the last candidate window resident.
- **A clipped cardholder value shows that it was clipped.** The reader cut at
  exactly the panel's label width, so the truncation marker could never fire.
- **`AUT_DISABLE` names the irreversible operation** it asks a touch for, instead
  of prompting "Unlock device?".
- **Host tooling: `rsk fido set-pin` no longer writes through a third, uncounted
  device selector** (and reads its confirmation back from the device it wrote);
  `rsk offboard` binds exclusively *before* any applet is wiped and at the replug;
  `rsk led --get` no longer writes; `rsk offboard --verify` treats a deleted
  `host_observations.steps` as a malformed receipt rather than "no cross-check
  available" — that one `del` laundered a signed receipt of a **failed** reset into
  a clean verdict with no forgery.
- **`rsk-wipe` requires a board.** The 4 MiB fallback let a build naming neither
  knob link and produce an under-sized wiper, which erases the code, leaves every
  sealed secret and still blinks green. Its LED pin and colour order come from
  `BOARD` too — GPIO16 is unwired on two boards and the panel backlight on a third,
  so a *successful* wipe could read as a failed one.
- **The gate's three named checks can now fail.** Running the host suites was
  necessary and not sufficient: the typed confirmations, the refuse-to-guess device
  binding and the brick guards were asserted at their helpers and at no caller, so
  43 of 61 mutations were silent — including removing `exclusive=True` from all 19
  call sites at once. They are asserted at the callers now, each verified to fail
  against the mutation it exists to catch.
- **`scripts/impact.py` sees multi-line definitions and says when it cannot parse.**
  It needed the definition's own line on both diff sides, so a value-only edit to
  any of the tree's 340 multi-line definitions reported nothing and exited 0
  (reproduced on the PIV default management key: 21 unread sites). It was also
  silenced entirely by `diff.noprefix` / `diff.mnemonicPrefix`, exit 0 either way.

The following landed in the same wave, before the fixes above:

- **Core 1's keygen scrub wiped a copy, not the mailbox.** `Option::take()` moves
  the payload out and writes back only the discriminant, so `zeroize()` cleared a
  local while a full 256-byte RSA prime — and the 48-byte DRBG seed that replays
  core1's entire candidate stream — stayed in the shared static, and `core1` was
  not on `worker::reboot`'s scrub list at all. Zeroizing goes *through* the slot
  now, and each core scrubs its own sieve when its search ends.
- **`rsk-wipe` builds for the board again.** `BOARD` never reached its build
  script, so the documented 16 MB build produced a 4 MB wiper — and the KV store
  sits at the *top* of flash, so that erased the code and left every sealed secret.
- **OpenPGP `PUT DATA` refuses the signature counter and unadvertised algorithm
  attributes**, a corrupt key record is rejected rather than silently re-sealed,
  and a torn soft-lock enable no longer reports a lock that is not there.
- **OATH `RESET` and FIDO `ATT_CLEAR` prove their deletes** instead of reporting
  success over a truncated enumeration.
- **The trusted display judges only a touch that began on the screen now showing**,
  and passkey/OATH list rows keep their truncation marker and their label.
- **`rsk offboard` receipts are bound to the run that produced them**, and the
  `exclusive` device-binding sweep covers every irreversible host command.
- **`rsk fido list-passkeys` sanitizes the credential counts** it prints, and the
  `picotool` failure path sanitizes the target's own strings — the last two unswept
  sites of the counterfeit-device terminal-injection class.

### Fixed

- **The OpenPGP card no longer advertises a resetting code it does not have.**
  OpenPGP Card 3.4 §4.3.4 reads DO `C4`'s RC error counter as 0 while no resetting
  code is set, and firmware 0x07F7..=0x0852 stopped seeding an RC verifier but kept
  writing a live counter into the PW-status record — which `init` only writes when
  it is absent, so a card provisioned in that window reported "Reset code tries
  remaining: 3" to `gpg` and `ykman` for the rest of its life. Never exploitable:
  `RESET RETRY P1=0` gates on the verifier's presence and answered `6A88`
  regardless. Found by diffing a real YubiKey, which reports 0.

### Added

- **Two more board presets: `BOARD=abrobot-4m` and `BOARD=abrobot-16m`.** The
  ABrobot RP2350 development boards carry four WS2812 LEDs on GPIO16 and a
  dedicated USER button on GPIO23, so presence comes from that button (active
  low) instead of BOOTSEL. Both are smoke-built in CI like the other shipped
  board files. Thanks to @Curious-r
  ([#64](https://github.com/TheMaxMur/RS-Key/pull/64)).

### Changed

- **`makeCredential` now ships packed *basic* attestation, fixing `-sk`
  enrollment on OpenSSH below 10.0.** The statement is an ES256 signature by the
  device key with the device certificate as its `x5c` leaf, whatever algorithm
  the credential itself uses. The previous `fmt:"none"` default (v0.3.5, for
  issue #26) turned out to break every OpenSSH from 8.2 through 9.9: they hand
  any credential without a certificate to libfido2's `fido_cred_verify_self()`,
  which rejects an empty statement with `FIDO_ERR_INVALID_ARGUMENT`, so
  enrollment aborted with "Key enrollment failed: invalid format" — the same
  message issue #26 reported, now on Debian 12, Ubuntu 24.04 and RHEL 9 instead
  of one Windows box. Confirmed on hardware, same board and command back to
  back: OpenSSH 9.9p2 failed, 10.4p1 enrolled. Basic attestation also keeps the
  credential's algorithm out of the verify path, which is what made the Ed25519
  self-attestation fragile in the first place. The cost is that the leaf is a
  per-device identifier ([limitations.md](docs/limitations.md)). Firmware
  `bcdDevice` `0x085F` → `0x0860`.
- **The attestation certificate now meets WebAuthn §8.2.1.** A packed `x5c` leaf
  must carry Subject-C/O/OU/CN with OU exactly `Authenticator Attestation`, plus
  `basicConstraints` with CA false; RP libraries such as SimpleWebAuthn and
  webauthn4j reject the registration outright when one is missing, and the
  U2F-era certificate had only a CN and no extensions. The template is now
  `C=XX, O=RS-Key, OU=Authenticator Attestation, CN=RS-Key FIDO2` with
  `basicConstraints` and `id-fido-gen-ce-aaguid` (1.3.6.1.4.1.45724.1.1.4)
  carrying the AAGUID. A device provisioned before this rebuilds `EF_EE_DEV` on
  the next boot; the U2F registration certificate changes with it.
- **The issue-#26 explanation is corrected.** OpenSSH did not gain
  `fido_cred_verify_self` in 10.0, as the 0.3.5 entry claimed. It has called it
  since 8.2; what 10.0 added (`d3a7ff7ce`) is the `fmt != "none"` bypass around
  it. What breaks the Ed25519 self-attestation on Windows is still not directly
  observed, but every other link was ruled out: the signature passes
  `verify_strict`, the emitted COSE key matches libfido2's own dump byte for
  byte, and LibreSSL 4.2.0 (the version Win32-OpenSSH 10.0p2 vendors) verifies
  Ed25519 correctly through libfido2's exact call sequence.
- **The README and the docs landing page say what RS-Key is before they say how
  it works.** Both now open with one line ("an open-source hardware passkey"),
  a three-row what-this-is / what-you-need / what-you-get table, and a figure
  ([`docs/images/what-it-is.svg`](docs/images/what-it-is.svg)): board, plus this
  firmware, equals passkey logins, `ssh` and `git` signing, an OpenPGP card, PIV
  and TOTP. A first-time reader could previously not tell whether the project
  was a device for sale, a mod for an existing key, or firmware. The board photo
  that made it read as a shop moves down to Hardware, and the CI badges move to
  Development setup.
- **The quick start starts from a released `.uf2`, not from a toolchain.**
  Downloading `rs-key-<version>-default.uf2` and dropping it on the board is the
  documented path in both `README.md` and [quickstart.md](docs/quickstart.md);
  building it yourself is the alternative behind a fold. The README gained a
  four-row "which image for my board" table pointing at
  [releases.md](docs/releases.md).

- **The small-prime sieve runs from SRAM, recovering 1.36× on RSA keygen.** The
  asm modexp was moved out of XIP flash long ago; the sieve loop that feeds it
  was not, and it runs for *every* candidate while walking a 1.8 KB prime table
  (5 KB at RSA-4096). From flash, loop and table evicted each other from the
  small XIP cache, and which of them won came down to where the linker put
  things — so 1708 bytes of unrelated image growth between v0.4.5 and `0x0864`
  cost 1.36× on RSA-2048 (medians 9.7 s → 12.7 s, three and four batches of 12,
  no overlap). Holding both in `.data` restores 9.7 s and takes the linker out
  of the loop. Moving only the table made it *worse* (13.8 s): the binding
  constraint was the instruction side. Costs 5.3 KB of SRAM, no flash. Measured
  on a Waveshare RP2350-Zero; firmware `bcdDevice` `0x0864` → `0x0865`.
- **The RSA keygen timings are labelled with the board they came from.** The PIV
  guide promised 4–6 s for RSA-2048 flat; that figure is the reference board's.
  Measured on a Waveshare RP2350-Zero the median is ~10 s (n=12) — the modexp
  runs from SRAM but the small-prime sieve, which rejects most candidates, runs
  from XIP flash, so the module's flash part lands in the total. Someone on
  another board was being told their key was twice too slow.
- **`rsk audit enable|disable` and a writing `rsk led` no longer guess which key
  they configure** (`rsk` 0.3.26). The refuse-to-guess sweep drew its line at
  *irreversible*, which left these two writes taking the first match: `audit
  disable` is the switch on the tamper-evident log, so landing it on the wrong
  attached key leaves the operator believing they silenced the other one. `rsk
  audit verify` joins them: it reads, but what it prints is a device-signed
  checkpoint, so answered by the wrong key it is one key's assurance under
  another's name. `rsk led --get`, `audit log` and the other status readers still
  take the first match — reading is what `rsk status` and `rsk inventory` are
  for, and they are multi-device aware.
- **`rsk fido attest import` checks the chain against the size the device
  actually stores** (`rsk` 0.3.26). Its pre-flight bound was a flat 2048; the
  device's `ATT_CHAIN_MAX` had since moved to what one flash record holds
  (`MAX_VALUE_BYTES - 1 - 2 * ATT_CHAIN_MAX_CERTS` = 2037), so a chain in the
  11-byte gap passed the host's own check and came back as a bare CTAP error
  instead of the message written for it. Found by running the new
  `scripts/impact.py` over everything since v0.4.5 — the constant moved, and the
  host copy of it did not.
- **The pre-commit hook reports what a redefinition leaves unread.** Changing a
  constant's *value* fails nothing on its own — it still type-checks, and a test
  written against the old meaning still passes — so a green gate says nothing
  about the sites nobody opened. `scripts/impact.py` lists, for every
  `const`/`static` value and every Python constant or `def` signature the change
  rewrote, the use sites outside that change; the hook prints it and never fails
  the commit, because it cannot decide whether a site is still correct. Written
  after a narrowed `EF_DEV_CONF_MAX` sized two readers as well as the writer it
  was narrowed for.
- **The gate runs the host test suites.** `tools/rsk`'s pytest suite and
  `tools/tui`'s tests ran in no gate and no CI workflow, so the checks guarding
  the irreversible host commands could be deleted with every test still green.
  Both now run in `scripts/check.sh`, alongside a 16 MB `rsk-wipe` build.

- **`getAssertion` no longer serves the `hmac-secret` extension on an `up:false`
  probe.** CTAP 2.1 §12.5 requires `CTAP2_ERR_UNSUPPORTED_OPTION` for that
  combination; RS-Key computed the extension 59 lines before the presence gate
  that `up:false` skips, so any local process that could open CTAPHID read the
  credential's PRF output — the key-derivation input behind
  `systemd-cryptenroll --fido2-device`, `age-plugin-fido2-hmac` and the WebAuthn
  PRF extension — with no touch and no PIN. The `always-uv` build was bypassed
  identically, since its refusal was gated on `req.up`. The credential's own
  signing key was never exposed: assertions still require touch for `up:true`,
  and the ssh-sk silent pre-flight (which carries no `hmac-secret`) is unchanged.
- **A factory wipe that cannot prove it emptied the store now fails instead of
  reporting success.** `Fs::factory_wipe` and the FIDO `authenticatorReset`
  sweep discarded `for_each_key`'s completeness flag, and both `factory_wipe`
  callers discarded its `Result` — so an interrupted page erase, which makes the
  enumeration yield zero keys, deleted nothing and still answered
  `CTAP1_ERR_SUCCESS` while the trusted display painted "RS-Key erased". PIV and
  OpenPGP already enforced this rule; the FIDO sweep is now the third. The
  display shows a new "Erase failed" notice and does not reboot, and the CCID
  Management reset reboots only on a completed wipe.
- **`rsk secure-boot lock` derives its `KEY_INVALID` mask from the board's live
  state.** It burned a hard-coded `0xE`, which is only correct when the live key
  sits in slot 0. On a board that had rotated to slot 1 but not yet revoked
  slot 0, that permanently revoked the key the board was booting on and restored
  the abandoned one as the only trusted key — then printed "secure boot LOCKED".
  It now revokes every slot the bootrom does not already trust, refuses when two
  slots are trusted (run `revoke` first) or none is, and `cmd_enable` refuses to
  fuse enforcement onto a board with no valid, non-revoked key.
- **The attestation certificate is rebuilt whenever it stops certifying the live
  key.** `matches_template` checked only the TBS length and the trailing AAGUID,
  so a torn `BACKUP_LOAD` or `authenticatorReset` left a certificate over the
  superseded seed and every packed attestation and U2F registration shipped an
  `x5c` leaf that did not certify the signing key. The check now binds the
  SubjectPublicKeyInfo point, `BACKUP_LOAD` drops the old certificate before the
  new seed commits, and a soft-locked device migrates its pre-§8.2.1 certificate
  on the next vendor `UNLOCK` instead of never.
- **The attestation serial is drawn minimally encoded.** Clearing only the sign
  bit left `serial[0] == 0x00` reachable, and the template's INTEGER is
  fixed-width, so roughly 1 device in 256 shipped an `x5c` leaf that X.690 §8.3.2
  makes unparseable — rejected outright by Go `crypto/x509`, OpenSSL and
  rust-asn1, permanently. The leading octet is now `0x01..=0x7F`, and the
  freshness check rejects a non-minimal serial so affected devices self-heal.
- **Vendor `ATT_CLEAR` asks for a named touch on a PIN-less device**, like
  `ATT_IMPORT` and `BACKUP_LOAD` already did. Erasing an org attestation identity
  that survives a factory reset sat behind one unlabelled press.
- **`ATT_IMPORT` writes the chain before the key and can no longer exceed the
  store's ceiling.** The 2048-byte cap was picked independently of the flash
  backend's real 2046-byte per-value limit, so an in-spec chain failed at the
  write after the key had already committed, leaving U2F REGISTER answering
  `0x6400` forever. The ceiling is now a `Storage::MAX_VALUE` constant enforced
  in `Fs::put`, and both `ATT_CHAIN_MAX` and `maxSerializedLargeBlobArray` derive
  from it.
- **`rsk otp burn` no longer leaves the MKEK and DEVK on disk.** The two OTP
  roots and their per-row complements were written to `$TMPDIR` unlinked but
  never overwritten, contradicting the documented "generates, verifies, and
  forgets the keys". They are now created `0600`/`O_EXCL` in a RAM-backed
  directory where one exists, and overwritten before unlink.
- **The irreversible OTP fuse commands refuse to guess which card they burn.**
  `ccid.find_reader` gained an `exclusive` mode — the run-30 hardening had closed
  only the no-match case, so a second attached key or a planted CCID gadget still
  won the first-match race. `rsk otp lock-page58`, `rsk otp rollback-require`,
  `rsk openpgp reset` and `rsk offboard` now use it, and the two fuse commands
  confirm against the device's chip serial instead of a static token.

### Internal

- **The two-device interop harness can no longer mislabel a snapshot.** `gpg
  --card-status` and `pkcs11-tool -L -O` take no device selector, so with both keys
  plugged they recorded whichever card scdaemon and OpenSC picked — for *both*
  labels — which is how a differing `openpgp.gpg.*` row could read as a match. The
  gpg cell now selects the card by its AID through `gpg-card` and the OpenSC cell
  pins `--slot-description` to the labelled reader, and both refuse the cell rather
  than record another device's answer.

## [0.4.5] - 2026-08-03

### Security

Audit run-31 fixes (bcdDevice `0x085F`, `rsk` 0.3.23, `rsk-tui` 0.3.3):

- **A cancel can no longer end another transport's touch ceremony.**
  `CANCEL_REQUESTED` was one global flag, so an unprivileged process holding only
  the FIDO HID nub could `CTAPHID_CANCEL` an OpenPGP, PIV, OATH or Yubico-OTP
  ceremony — `WORKER_LOCK` does not serialize the two, because a parked FIDO
  request acquires it *inside* the future the keepalive loop is already driving.
  On a screenless build the next ceremony then started with `spent == false`, so
  the user's descending finger could confirm the attacker's `makeCredential` /
  `getAssertion` instead. The single flag becomes a typed `WAIT_SCOPE` set around
  every dispatch; `request_cancel` honours it exactly as `cancel_otp_wait` already
  did, and the keepalive advertises `UPNEEDED` only for the channel that owns the
  wait (which also closes a cross-transport "a touch is imminent" oracle).
- **The trusted display's device PIN is a first-class credential on the host path.**
  The FIDO vendor gate keyed solely on the clientPIN, so a display build whose owner
  completed the panel's own onboarding — device PIN set, no clientPIN — exported its
  master seed on one touch, and a panel lock did not stand in the way (a host
  ceremony paints over it). `pin_gate` now falls back to a device-PIN entry on the
  device's own pad, covering `BACKUP_EXPORT`, `BACKUP_LOAD`, `ATT_IMPORT`,
  `ATT_CLEAR` and the audit subcommands.
- **The on-device auto-lock has its own deadline.** It rode on the display-sleep
  timer, which every host ceremony refreshed — including the ungated
  `authenticatorSelection` — so a loop of them held the panel unlocked for the whole
  plugged-in session. The lock now counts from the last *local* interaction, and it
  re-arms without blanking, so "Display sleep: Off" no longer switches a security
  control off with it.
- **Seal backup and Firmware → reboot-to-BOOTSEL take the device PIN**, like every
  other irreversible panel action. Sealing cannot be undone except by a factory
  reset that destroys the seed it protects, and BOOTSEL is the entry point for the
  issue-#37 flash-rollback.
- **The passkey rename is device-PIN gated, and the delete card names the real
  relying party.** A nickname replaces the rpId on the browse screens, so an
  unauthenticated relabel could aim the owner's own PIN-gated delete at the wrong
  credential.
- **A host can no longer hold the on-device UI shut.** Modals abandoned themselves
  the instant a host command queued, with no floor — and because `REQ` latches until
  the worker drains it, one repeated ungated command kept the unlock pad closing on
  its first poll. Entry and hold modals now keep a short guaranteed slice and never
  yield mid-entry or mid-hold.
- **Touch, the wake button and the auto-lock no longer depend on USB being
  configured.** They sat behind the LED status, which stays at `Boot` until a host
  completes `SET_CONFIGURATION`, so on charger or battery power the panel animated
  but ignored every touch.
- **The at-rest scrub is re-armed by the lazy OpenPGP migration.** The one-shot
  compaction lap latched at boot, but the OpenPGP DEK chain and its verifiers migrate
  off the pre-OTP key base on the *first PIN verify* — appends, leaving the superseded
  chip-serial-rooted copies readable in a flash dump forever. That contradicted the
  threat model's "a flash dump cannot brute-force the PIN offline": the pre-OTP root
  derives from the public chip serial. `EF_HARDENED` moves to `rsk-fs` and the
  migration clears it, so the next boot scrubs.
- **A host-requested warm reboot no longer advances the Yubico-OTP use counter.**
  `power_up_bump` ran on every `main`, so ~32768 ungated warm reboots saturated the
  15-bit counter while the RAM session counter restarted at 0 — leaving the key
  re-emitting `(useCtr, sessionCtr)` pairs a validation server rejects as replays.
- **The OTP keyboard transport zeroizes its buffers** (frame reassembly, the taken
  request, the type queue) and joins the pre-BOOTSEL scrub. They could hold a slot's
  AES key, private UID, access code or static password.
- **`forcesig` holds on OpenPGP PSO:CDS.** PW3 is still accepted for parity, but not
  when the card is configured "PW1 valid for one signature" — only PW1 can be cleared
  per signature, so an admin-PIN entry would otherwise have authorised unlimited
  signatures silently.
- **`TERMINATE DF` fails instead of reporting a wipe it could not prove.**
  `wipe_openpgp` used `delete` (which skips a false-absent file `for_each_key` keeps
  yielding, so the sweep could spin) and discarded the enumeration's completeness
  flag. It now matches the FIDO and PIV sweeps: `force_delete`, a delete budget, and
  `MEMORY_FAILURE` on a truncated walk.
- **`rsk offboard`, `rsk inventory verify` and `rsk backup restore/finalize` refuse
  to guess between two attached keys.** The PC/SC half picks its device by reader
  name and the HID half took the first match, so offboard could confirm one device's
  serial and factory-reset another's FIDO identity, and `inventory verify` could bind
  a serial to a different device's attestation key — the enrollment anchor
  `docs/guides/fleet.md` tells operators to record. `ctaphid.find_all` is new;
  `connect_fido(exclusive=True)` gates the destructive callers.
- **`rsk backup export` no longer prints the PIN beside the mnemonic.** The export is
  gated on touch *plus* the PIN; echoing it into the block the user was just told to
  record collapsed both factors into one artifact.
- **`rsk-tui`: no first-reader fallback, a real reboot status word, and the audit
  window cross-check.** With CCID absent the cockpit connected to whatever card was
  in a reader — SELECTing five applets on it every 5 s and rendering its PIN counters
  as the RS-Key's. `reboot` reported a declined on-screen gate as success. `audit_read`
  kept only the modulo check under a comment claiming parity with `audit.py`, so a
  device could present 1 of N events as a complete window. The header also refuses to
  vouch for an identity when more than one FIDO device is attached.

### Fixed

- **Board files: flash size and LED pins.** `waveshare-touch-lcd` and `tenstar-usb`
  declared `size_mb = 4` where every other reference (nix, CI, the docs, the flash-map
  diagram) builds them at 16M — a 12 MiB shift of the key store, which reads as an
  empty device and boots a display build unlocked. `tenstar-usb` and `seeed-xiao`
  pointed the WS2812 at GP16 (the Waveshare One's pin) instead of the hardware-verified
  GP22, leaving the consent indicator dark. Each shipped board file is now smoke-built
  in CI, and `BOARD=` is documented in `docs/build.md`.
- **`build.rs` rejects instead of truncating.** `u8()` wrapped an out-of-range pin into
  a plausible one *before* the resolvers' range asserts could see it, and the four
  display control pins had no range check at all — a value ≥ 128 aliases onto a real
  GPIO through embassy's bit-7-banked `AnyPin`. Board-file booleans now accept the same
  spellings the env resolvers do (`yes`/`on`) and panic on anything else, rather than
  silently reading as `false`; `presence.source` is matched case-insensitively.
- **`rsk backup finalize` works on a device with a PIN set** (`rsk` 0.3.22). It
  sent the vendor command with no pinUvAuthToken, so `pin_gate` answered
  `CTAP2_ERR_PUAT_REQUIRED` (0x36) and the one-time export window could not be
  sealed once `clientPin` was enabled; it now takes the same `_gated()` path
  `rsk backup export` already used
  ([#59](https://github.com/TheMaxMur/RS-Key/issues/59), thanks
  [@lockedmutex](https://github.com/lockedmutex)).
- **A touch-gated challenge no longer looks like a timeout the moment the button
  is pressed.** While a command ran, the keyboard transport picked its status
  byte from the live presence flag — `0x20` while a touch was awaited, `0x10`
  otherwise. But that flag drops as soon as the press is collected, and the
  response only appears once the HMAC has been computed, so every touch-gated
  challenge served a short `0x10` window in between: measured at 9 ms against
  Windows and 11 ms against macOS. ykpers' blocking read
  (`yk_wait_for_key_status`, which KeePassXC vendors) arms itself on `0x20` and
  then reads *any* byte carrying neither the pending nor the waiting bit as "the
  key timed out waiting for the user" — so a host polling inside that window
  abandoned a challenge the key had already answered. A YubiKey never shows it:
  it reports the wait, plus a seconds countdown, right up to the response. The
  wait now latches for the rest of the command, so only the response — or the
  idle status frame after a real timeout — replaces it, which leaves an expired
  wait ending exactly as promptly as before. **bcdDevice → `0x085C`.**
- **The PIN-entry band no longer leaves a stale "+" overflow marker and the right
  half of the 10th dot behind when the user deletes from a long PIN back to ≤10
  digits** (`render_pin_dots`). The repaint cleared one small rectangle per dot,
  centred on each circle, but `masked_entry` draws dots top-left-aligned — so the
  clear was off by `ENTRY_DIA/2` and missed the "+" at x 184 plus dot 10's right
  tail (x 176..180). Deleting 11 → 10 left the "+" on screen for the rest of the
  session, lying that the PIN was still long, and 10 → 9 left a one-pixel stub.
  The repaint now clears one strip over the whole entry band (every dot position
  plus the overflow slot to its right) before redrawing. Covered by a host test
  in `rsk-ui`.

Audit run-30 fixes (bcdDevice `0x085D`, `rsk` 0.3.21, `rsk-tui` 0.3.2):

- **The OTP frame protocol is served on the keyboard interface only again.** It
  had also been answered on the FIDO HID interface to match a YubiKey; on macOS
  that removed a privilege boundary — IOKit gates a keyboard-usage HID nub behind
  Input Monitoring while the `0xF1D0` FIDO nub opens to any console-user process,
  so slot programming and challenge-response became reachable unprompted. The
  keyboard interface is already index 0 (what index-addressing hosts need), so the
  FIDO door gained nothing and is removed.
- **`rsk openpgp reset` no longer risks destroying an unrelated OpenPGP card.** It
  now checks the SELECT status (refusing a card with no OpenPGP application) and
  takes the typed confirmation the docs already promised, and `find_reader` fails
  with a clear error instead of silently grabbing the first PC/SC reader when no
  RS-Key is present.
- **A slot UPDATE no longer resets the Yubico-OTP use counter / OATH-HOTP moving
  factor.** It built a 52-byte record, dropping the 8-byte counter tail, so a
  routine `ykman otp settings` silently rolled the anti-replay counter back. The
  tail is now carried forward; only a full re-CONFIGURE resets it.
- **A YubiKey config-lock code is no longer stored or disclosed.** RS-Key does not
  implement the lock, but WRITE CONFIG kept the 16-byte code and READ CONFIG
  echoed it in cleartext to any unauthenticated host. The lock tags are now
  stripped on write, and READ CONFIG always reports the lock unset (as hardware
  does).
- **`rsk offboard` always writes a receipt now.** A missed touch (or a malformed
  device) on the post-wipe journal read used to abort before the receipt was
  written, leaving an irreversible wipe with no artifact; the failure now degrades
  to a note in a written receipt.
- **`rsk backup status` sanitizes device output.** The `sealed`/`has_seed` values
  from the device are coerced to booleans, so a hostile device can no longer inject
  terminal escapes during the seed-backup ceremony.
- **`rsk-tui` no longer prints "identity verified ✓" for an unpinned device.** The
  verifying key comes from the same response being checked, so a self-signed
  counterfeit passed; the verdict now states only that the signature is
  self-consistent and points at `rsk inventory verify --expect-key`, matching the
  CLI.
- **The host tools bound CTAPHID response reassembly by wall clock.** A device
  trickling one small continuation frame per timeout could hang `rsk` or freeze
  the TUI for hours; both now enforce the same 120 s deadline the keepalive loop
  uses.
- **The release workflow refuses a tag that is not an ancestor of `main`** as
  defence in depth. The primary control against a leaked write token laundering
  unreviewed code into a signed release is a repository tag ruleset restricting
  who may create `refs/tags/v*` — configure that in the repo settings.
- `docs/unsafe.md` records the four new `AnyPin::steal` sites (display
  `CS`/`DC`/`RST`/`TP_RST`) and the `firmware/build.rs` `env::set_var` site,
  restoring the runtime-site count from 15 to 19 and matching the new
  collision-assert containment in the prose.

### Added

- **Per-board build configuration: `BOARD=<name>` picks `firmware/boards/<name>.toml`**
  instead of setting the LED / presence / flash / display env vars one by one.
  Ships with `waveshare-one`, `waveshare-touch-lcd`, `tenstar-usb`, and
  `seeed-xiao`. The individual env vars still work and still win over the board
  file, so existing build recipes are unaffected. The display's SPI1
  (`PIN_10/11/12`) and I2C1 (`PIN_6/7`) lines stay hard-wired; only the control
  GPIOs (`cs`/`dc`/`rst`/`tp_rst`/backlight), bus frequencies, colour inversion,
  and colour order are per-board.
- **Trusted-display UI redesign** (`--features display`): anti-aliased circles for
  the boot, reset, and PIN-entry dots; a shared component system (`card`,
  `rect_card`, `list::group_card`, `list::row`) behind the Passkeys, Audit,
  Applets, and Settings screens; and a unified 10 px gap between the title bar and
  the content on every screen. The passkey rename screen replaces the up/down
  character wheel with a **T9 phone-style keypad** — a repeated press cycles the
  key's letter group, a different key or an 800 ms pause commits, and the field
  and keypad repaint in place instead of clearing the frame.

### Changed

- **`bcdDevice` bumped to `0x085E`** for the UI redesign and the per-board
  configuration system.
- **OpenPGP RSA heap restored to 128 KiB.** It was halved to 64 KiB inside the
  per-board-config commit without a callout; on `embedded_alloc` a failed
  allocation aborts (`handle_alloc_error` → panic → watchdog reset), so a long
  RSA-4096 keygen/CRT mid-operation could reset the device. Back to the v0.4.4
  value until a separate justification for the smaller size is on record.
- **Display control GPIOs are now checked for collisions at compile time.** The
  four new `AnyPin::steal` sites for `CS`/`DC`/`RST`/`TP_RST` were added by number
  with no compile-time guard beyond `WAKE_PIN` vs the `10..=18` range, so a board
  config could aim `cs` at the same pad as `WAKE_PIN`, `LED_PIN`, the hard-wired
  SPI1 (`PIN_10/11/12`) / I2C1 (`PIN_6/7`) lines, or another control line, and
  silently drive one pad from two owners. A `const _: () = assert!(...)` now
  rejects all of those at build time. The backlight PWM `(pin, slice, channel)`
  combo likewise had no compile-time guard and panicked at boot on an unsupported
  board (a runtime panic on fully constant operands); it too is now a `const`
  assert, and the runtime match arm is `unreachable!`.
- **`firmware/build.rs` re-rustc's when any of the 11 `PK_DISPLAY_*` env vars
  change.** They were the only env knobs missing a `cargo:rerun-if-env-changed`,
  so overriding `PK_DISPLAY_CS` etc. without touching `BOARD` reused the cached
  build and shipped a firmware with stale pins.

### Removed

- Dead code from the UI redesign: `aa::filled_rounded_rect` (~64 lines, never
  called), and the `CARET_BLINK_MS` const left behind with `#[allow(dead_code)]`
  after the rename pad switched from a caret blink to a T9 pending-char.

### Internal

- **The on-device tests no longer guess which key they are talking to.** Every
  `tests/*.py` script picked the first FIDO HID device the OS listed, so with a real
  YubiKey attached next to a board built `VIDPID=Yubikey5` (both `1050:0407`), tests
  `10` and `15` ran against the *YubiKey* and reported its aaguid, its `alwaysUv` and
  its `6700` as RS-Key failures. Selection now lives in one place, `tests/_device.py`:
  the `RSK` marker breaks a tie, `RSK_TEST_SERIAL` / `RSK_TEST_PATH` name a target
  explicitly, and an unresolved choice stops the run instead of picking one. The
  seven copied `find()` helpers and `ctaphid.find` route through it, as do the
  python-fido2 suites (`61`, `65`) and `replug.reset_fido2` — that last one sent
  `authenticatorReset` to whatever it found first. Same bug class as the audit run-31
  fix in `tools/rsk` (`ctaphid.find_all`, `connect_fido(exclusive=True)`).
- **The CCID half of that, over PC/SC.** The reader pick was copy-pasted into 24
  scripts. Eighteen matched the `RSK` marker in the reader name but fell back to
  `rs[0]`, so a build with `USB_PRODUCT` overridden drove whatever reader the OS listed
  first — next to a real YubiKey, the YubiKey, which enumerates ahead of the board on
  the maintainer's machine. `53` took `rs[0]` with no match at all, `90` took the first
  of the marker-matched, and `80_piv.py` matched `"Yubico"` and `"PIV"` too, aiming a
  suite that blocks both PIN references and factory-RESETs the applet at a real
  YubiKey's PIV. All 24 now call `_device.find_reader()`, with `RSK_TEST_READER` as the
  pin. Five pass `require_marker=True`, so an unmarked reader reads as "not attached"
  rather than as the board: the destructive `80` and `90`, and the reboot pollers `14`,
  `51` and `76`, where "is the board back yet?" was answerable by a stranger — `51`
  probes `A0 00 00 05 27 47 11 17`, Yubico's own management AID, and a real YubiKey
  answers it `9000`.
- **Test fixed.** `31_openpgp_select.py` asserted the OpenPGP `VERSION` (INS `0xF1`)
  reply was `04 06 00` and so failed against any default build, which answers with
  the device firmware version (`05 07 04`). The expectation now derives from
  `FW_VERSION` like the firmware does, as does `10_fido_getinfo.py`'s
  `firmwareVersion` check, which had the default packed in by hand.
- Cross-executor `Ordering` consistency: the `CANCEL_REQUESTED.store(false, …)`
  false-clears in `display/pin.rs` and `display/presence.rs` are `Relaxed` (no
  publication occurs from a `false` store — the publication is the subsequent
  `true`/`Release` store), matching the same false-clears already in
  `firmware/src/presence.rs`.
- **Test changed.** `t9_groups_are_printable_and_have_distinct_chars` checked
  for duplicate characters *within* each group (where the old
  `rename_charset_is_printable_and_cycles` checked the whole charset). The test
  now also rejects a character appearing in *two* groups — a T9 char must belong
  to exactly one, else `active_group`/`cycle_at` on the rename screen is
  ambiguous. (`const _: () = assert!(T9_GROUPS.len() == 10)` pins the
  relationship `hit_rename` (`Char(0..=9)`) expects, so dropping a group fails
  the build instead of panicking on device at `groups[gi]`.)
- The AA fringe in `aa::filled_circle` now blends to a caller-passed `bg`
  colour instead of the hardcoded `theme::BG` — truthful blending against
  the surface the circle is drawn over, so a future AA circle on a card or
  other non-`BG` region won't get a global-background halo. Existing call
  sites (boot splash, reset warning, PIN-pad dots, success circle) pass
  `theme::BG`, so the rendered output is byte-equivalent.
- `firmware/build.rs` strips a trailing `# ...` comment from a TOML value
  before parsing it (handling the `"`-quoted case, since a quoted value may
  legitimately contain `#`). Previously `pin = 13 # GPIO for chip-select`
  read as `13 # …` and panicked `parse_toml`'s `u32` helper; today's four
  board configs are clean of inline comments, so this is a trap removed
  for future edits, not a current-data fix.
- `firmware/build.rs` renames the board-config display slice from `b2` to
  `disp_cfg` and documents that `display_cs` is the semantic gate pin
  (a `[display]` section without `cs` is dropped, and the knobs fall back
  to the Waveshare defaults). It was previously a one-line clever `and_then`
  with no note explaining why.
- `masked_entry`'s `total` reverts to the v0.4.4 one-liner
  `(expected as usize).max(entered).min(ENTRY_MAX_SHOWN)` — the UI redesign
  rewrote it as an `if/else` with the same result and a cosier comment
  ("no leftover outlines on delete") describing a change that didn't happen;
  the original is shorter and says exactly what it does.

## [0.4.4] - 2026-07-27

### Fixed

- **Challenge-response reaches KeePassXC, `ykchalresp` and `pam_yubico` on Linux
  again.** Those tools share the `ykpers`/`ykcore` libusb backend, which claims USB
  interface 0 and pushes the OTP frame reports at it without reading a descriptor
  first. RS-Key enumerated the FIDO HID interface there, and that interface serves
  no HID feature reports, so every transfer stalled: the host reported a USB "Pipe
  error" and listed no hardware key
  ([#55](https://github.com/TheMaxMur/RS-Key/issues/55)). The interfaces now
  enumerate in the stock YubiKey order — keyboard/OTP, FIDO HID, CCID — so the
  reports land on the OTP interface as they do on a real key. Windows and macOS
  were never affected: their `ykcore` backends find the interface through the OS
  HID stack. Nothing changed on the wire, and hosts re-enumerate the device once
  after the upgrade. KeePassXC also filters on Yubico's vendor id, so it still
  needs a `VIDPID=Yubikey5` build and Yubico's udev rules — see
  [guides/otp.md](guides/otp.md#challenge-response-from-software).
  Verified end-to-end on Linux against `ykchalresp`, `ykinfo` and
  `keepassxc-cli` 2.7.11, with a real YubiKey as the control.
  **bcdDevice → `0x0859`.**
- **The OTP frame protocol now answers on the FIDO interface as well.** Measuring
  the fix above showed a 5.7.4 YubiKey serving the OTP status frame on its FIDO
  interface too, while keeping the CTAP-exact report descriptor that declares no
  feature report — so a host that pokes interface 0 blind finds OTP whatever the
  order happens to be. RS-Key stalled there. It now answers on both HID
  interfaces, marshalling one frame state machine, and the FIDO report descriptor
  is unchanged. Disabling the keyboard interface in the phy record still removes
  the protocol from both, so `ykman config usb --disable OTP` keeps its meaning.
  **bcdDevice → `0x085A`.**
- **A touch-gated challenge-response slot no longer wedges the OTP transport.**
  Field report: challenge-response worked without `--touch` and failed with it,
  while a YubiKey was fine. A host that meets a slot waiting for its button press
  ends that wait one of two ways, and RS-Key honoured neither: it sends the dummy
  write `0x8f` (ykpers `yk_force_key_update`, also its way of resetting the read
  mode after collecting a response), which the frame decoder dropped as an
  out-of-range sequence; or it simply sends the next command, which a YubiKey lets
  supersede the challenge. So the key stayed in the touch wait and answered
  "would block" to *everything* for the next 30 seconds — measured against a real
  YubiKey, which recovers instantly. Since KeePassXC probes every slot before
  unlocking, one touch slot was enough to make the whole key look broken. Both
  paths now end the wait, scoped to the OTP transport so an abort there cannot
  abandon a FIDO ceremony on the same button. The press itself was never the
  problem — traced on hardware, a press has always produced its HMAC.
  **bcdDevice → `0x085B`.**

## [0.4.3] - 2026-07-26

### Fixed

A second pass over the CTAP 2.1 text, this time across `authenticatorLargeBlobs`,
`authenticatorClientPIN`, `authenticatorCredentialManagement`, `authenticatorReset`,
CTAPHID and the CTAP1/U2F interface. bcdDevice → `0x0857`.

Two of these change who may do what, and are called out first:

- **A key with no PIN can now write the large-blob array.** §6.10.2 gates the write
  on the authenticator being "protected by some form of user verification or the
  alwaysUv option ID is present and true", and its note spells out the converse — an
  unconfigured key writes without one. RS-Key demanded a `pinUvAuthParam`
  unconditionally, so `authenticatorLargeBlobs` was simply unusable before a PIN was
  set. Array entries stay AEAD-sealed under their per-credential `largeBlobKey`, so an
  unverified write can destroy but never read. Set a PIN (or turn on `alwaysUv`) and
  the token requirement returns.

- **A `display` build now asks on screen before issuing a `pinUvAuthToken`.** All
  three token subcommands (`getPinToken`, and both `…WithPermissions`) carry the same
  step: "If the authenticator has a display, request user consent for the requested
  permissions." RS-Key minted the token straight off the PIN check, so malware holding
  the PIN could take an `acfg` token with nothing shown. The prompt lands *before* the
  PIN is verified, so declining costs no retry. Screenless builds are unaffected —
  they have no display to ask on, and their button is not polled.

The rest are status codes and bounds:

- **`authenticatorLargeBlobs` reads are validated.** A `get` larger than
  `maxFragmentLength` is `CTAP1_ERR_INVALID_LENGTH` instead of a silent clamp, and a
  `get` carrying `length`, `pinUvAuthParam` or `pinUvAuthProtocol` is
  `CTAP1_ERR_INVALID_PARAMETER`. A 17-byte array no longer skips the trailing-hash
  check — §6.10.2 grants the minimum length no exemption.
- **`setPIN` on a device that already has one answers `CTAP2_ERR_PIN_AUTH_INVALID`**
  (§6.5.5.5), not `CTAP2_ERR_NOT_ALLOWED`.
- **The minimum PIN length is counted in Unicode code points**, as getInfo `0x0D`
  defines it, not UTF-8 bytes. Measuring bytes let a two-character CJK PIN clear a
  floor of four. The stored `PINCodePointLength` follows the same unit, which is what
  `setMinPINLength` compares its new floor against.
- **A forced PIN change can no longer be satisfied by the same PIN** (§6.5.5.6): the
  flag survives and the operation is a policy violation.
- **Built-in UV speaks its own status dialect** (§6.5.5.7.3): an unconfigured method
  is `CTAP2_ERR_NOT_ALLOWED` and an exhausted budget `CTAP2_ERR_UV_BLOCKED`, where the
  host-PIN path reports PIN_NOT_SET / PIN_BLOCKED for the same states. The `acfg`
  permission is refused over that subcommand, since it is gated by a `uvAcfg` option
  this device does not advertise — `authnrCfg`, which gates it on the host-PIN path,
  is a different option.
- **An rpId-scoped `cm` token may manage its own relying party's credentials.**
  §6.8.5/6.8.6 match the token's permissions RP ID against *the credential's* rp;
  RS-Key rejected every scoped token outright, so `deleteCredential` and
  `updateUserInformation` were unreachable with one. Another rp's credential — and an
  id that matches nothing — both answer `PIN_AUTH_INVALID`, so the code never reveals
  who owns an id.
- **`authenticatorGetNextAssertion` resets its timer on every leg** (§6.3), so the
  30-second budget covers the gap between calls rather than the whole walk. A platform
  drawing an account picker over many passkeys no longer runs out partway through.
- **`authenticatorReset` distinguishes a refusal from a timeout** (§6.6):
  `CTAP2_ERR_OPERATION_DENIED` when the user declines ("the platform SHOULD NOT
  repeat"), `CTAP2_ERR_USER_ACTION_TIMEOUT` when nothing happens.
- **A credBlob of exactly `maxCredBlobLength` is stored.** The bound was exclusive
  while getInfo advertised 128, so the advertised maximum was refused and reported
  back as `credBlob: false`.
- **CTAPHID hands out a unique channel id per `CTAPHID_INIT`** (§11.2.9.1.3) instead
  of one fixed value shared by every application, and an INIT on an already-allocated
  channel echoes that channel rather than renaming it. Two concurrent clients — a
  browser and an `ssh-agent`, say — no longer resynchronise each other's transactions.
- **`CTAPHID_LOCK` actually locks.** It was acknowledged and ignored, so a host that
  took the lock believed it had exclusivity it never got. The claim now holds for the
  requested 1–10 seconds, other channels get `ERR_CHANNEL_BUSY`, and only the owner
  can release it early.
- **U2F under `alwaysUv` returns `SW_COMMAND_NOT_ALLOWED`** as §7.2.4 requires. The
  old `SW_CONDITIONS_NOT_SATISFIED` is the "touch me again" code, which left clients
  retrying an interface that was switched off.
- **…and on a `display` build with a PIN, U2F is no longer switched off at all.**
  The same clause disables CTAP1/U2F "unless the CTAP1/U2F authenticator is protected
  by a built-in user verification method", which a configured PIN pad is. RS-Key took
  the blanket branch. Now, on such a build, `U2F_V2` stays in the advertised versions
  and every REGISTER / AUTHENTICATE runs the pad — the PIN authorizes the operation
  instead of a bare touch, so U2F is no longer a presence-only way around alwaysUv.
  A wrong PIN refuses with `SW_CONDITIONS_NOT_SATISFIED`, and the
  don't-enforce-user-presence control byte can skip the touch but not the
  verification. Capability alone does not qualify: with no PIN set there is nothing
  to verify against, so the interface goes away exactly as on a screenless key.

The earlier pass over §6.1.2 / §6.2.2 / §6.11, from the same reading:

- **`options: {uv: true}` alongside a `pinUvAuthParam` is no longer rejected.**
  §6.1.2 step 5 (and §6.2.2 step 4) are explicit: "If the pinUvAuthParam is
  present, let the 'uv' option be treated as being present with the value false" —
  the two are mutually exclusive with the parameter taking precedence. RS-Key
  instead answered `CTAP2_ERR_INVALID_OPTION` (`0x2C`) to the combination, which
  python-fido2 and other platforms do send when user verification is required.
  The option is now normalised away, and it is an error only when the request
  carries no token *and* the build has no configured built-in user verification
  method — on a screenless key, still always.

- **A `display` build now honors the `uv` option it advertises.** getInfo
  advertises `options.uv` on a trusted-display key, but `makeCredential` /
  `getAssertion` refused `uv: true` outright — advertising a capability and then
  rejecting every request that used it. `uv: true` now runs `performBuiltInUv` on
  the panel's PIN pad (§6.1.2 step 11.2, §6.2.2 step 6.2), and that entry counts
  as the ceremony's evidence of user interaction (§6.1.2 step 13, §6.2.2 step 8), so
  the *response* sets `up` without a second gesture being required. The panel still
  paints the Approve / Deny card, because it is the only screen that names the relying
  party — see the Security section. With `alwaysUv` on, a token-less
  request is likewise upgraded to built-in UV instead of being refused with
  `PUAT_REQUIRED` (§6.1.2 step 6.3, §6.2.2 step 5.4). Screenless builds are
  unaffected — they have no built-in UV method, so every branch is unreachable.

  One deliberate divergence inside that path: **an explicit Deny on the PIN pad
  answers `CTAP2_ERR_OPERATION_DENIED`**, where the spec's error ladder would fold
  it into `PUAT_REQUIRED` (the ladder checks `clientPin` before it reaches its own
  `OPERATION_DENIED` branch). `PUAT_REQUIRED` tells the platform to collect the
  same PIN over USB, which would turn the trusted display's refusal into the very
  prompt the user just declined — the panel's veto has to be final. Every other
  outcome of the ceremony follows the ladder exactly: a wrong PIN or an exhausted
  budget is `PUAT_REQUIRED`, a timeout is `USER_ACTION_TIMEOUT`.

- **`pubKeyCredParams` again picks the platform's first supported algorithm.**
  The build preferred ML-DSA whenever an RP offered it, even listed after a
  classic algorithm — a deliberate deviation so a PQC rollout would not need the
  RP to reorder its list. §6.1.2 step 4 is unambiguous ("…and no algorithm has yet
  been chosen by this loop"), so the list order is the RP's preference order again
  and the override is gone. An RP that wants ML-DSA lists `-49` / `-48` first;
  both remain fully supported and negotiable.

- **`setMinPINLength` with more RP IDs than fit answers `CTAP2_ERR_KEY_STORE_FULL`.**
  A `minPinLengthRPIDs` list longer than `maxRPIDsForSetMinPINLength` (8) was
  silently truncated, so an administrator authorising ten RPs got eight and no
  indication. §6.11 specifies the code for exactly this, and nothing is written
  now when the list does not fit. The check runs after the `pinUvAuthParam`
  verification, so it is not an unauthenticated probe.

### Added

- **`makeCredUvNotRqd`: a PIN no longer blocks `userVerification: "discouraged"`
  registrations (issue #51).** With a PIN configured, RS-Key demanded a
  `pinUvAuthParam` for *every* `authenticatorMakeCredential` and answered
  `CTAP2_ERR_PUAT_REQUIRED` (`0x36`) without one. A relying party that asks for
  `userVerification: "discouraged"` (a plain second-factor key — addy.io, and the
  same shape on WebAuthn.io) never sends that parameter, so Safari looped: prompt
  for the PIN, mint a token, resend without it, get `0x36` again, and the final
  touch did nothing. RS-Key now advertises the CTAP 2.1 `makeCredUvNotRqd` option
  in `authenticatorGetInfo` and creates a **non-discoverable** credential on user
  presence alone, with the `uv` flag clear — the behaviour of a real YubiKey.
  Discoverable credentials (passkeys, `rk: true`) still require a verified
  `pinUvAuthParam` (§6.1.2 step 7), and `alwaysUv` still forces user verification
  for everything (§6.1.2 step 6), so `ykman fido config toggle-always-uv` — or the
  `always-uv` build — restores PIN-on-every-registration. bcdDevice → `0x0855`.

- **`CONFIG_READ` now reports the effective LED pin / driver and touch timeout.**
  The FIDO `0x41` `CONFIG_READ` PHY response gains an optional `2:` map of the
  boot-resolved values (build defaults or overrides) keyed by phy tag — LED GPIO
  (`4`), LED driver (`12`), presence timeout (`8`) — so a host config UI can show
  the real values instead of a bare "firmware default" for a record with no
  override. Display-only; the `1:` blob stays the raw override record for
  read-modify-write, and older/headless behaviour is unchanged. bcdDevice → `0x0852`.

### Security

Findings from the 28th internal security audit, which read only the CTAP
spec-alignment pass above. Three of twelve candidates survived adversarial
validation. bcdDevice → `0x0858`.

- **A `display` build stopped naming the relying party once built-in UV ran
  (MEDIUM).** §6.1.2 step 13 / §6.2.2 step 8 let a PIN typed on the pad stand in for
  the presence gesture, and the pass used that to skip the whole ceremony. But
  `UserPresence::collect_pin` carries no `Confirm`, and `PinPad.title` is a trusted
  firmware-supplied `&'static str` by construction, so the pad can never name a
  relying party. A host could therefore send `options: {uv: true}` with no
  `pinUvAuthParam`, get a bare PIN prompt painted, and turn one context-free entry
  into a `UP=1 | UV=1` assertion — or a resident credential — for an rp the user was
  never shown. The spec excuses the second *gesture*, not the disclosure: the
  Approve / Deny card is painted again whenever the backend paints ceremonies at
  all. Screenless builds never reached this path and are unchanged. The same applies
  to U2F under §7.2.4's built-in-UV exception, where "Register key?" and "Sign in?"
  had collapsed into one unlabelled prompt — there the card comes first, so the
  operation is named before the PIN is typed. The PIN pad now also waits for the
  finger to lift before its first poll, like every other modal: the touch controller
  reports a level, and the Allow button overlaps the pad's bottom key row, so a
  still-held finger would have typed a stray digit and burned a PIN retry.
- **`makeCredUvNotRqd` was advertised while `alwaysUv` was on.** §6.4: "If the
  alwaysUv option ID is present and true the authenticator MUST set the value of
  makeCredUvNotRqd to false", and §6.11.2 makes clearing it a step of
  `toggleAlwaysUv` — which this device advertises. `authenticatorMakeCredential`
  already refused such requests, so the device failed closed; only the
  advertisement lied, which re-created the issue-#51 client retry loop for
  `always-uv` users. The conformance run is alwaysUv-off, so it did not catch this.
- **A completed large-blob transfer left its accumulator armed.** `write_fragment`
  did not clear `expected_length` / `expected_next_offset` after committing, so a
  seven-byte follow-up (`{2: h'', 3: <total>}`) re-entered the commit branch and
  re-ran the full flash write — unauthenticated on a key with no PIN, where §6.10.2
  correctly requires no token. Repeated, that churns the credential partition. A
  completed transfer is now terminal: the next write starts a fresh array at offset
  0, as the reference implementation does.

Findings from the 26th internal security audit. bcdDevice → `0x0853`.

- **A phy USB string longer than the descriptor limit bricked the device
  (HIGH).** `CONFIG_WRITE`/`CONFIG_TARGET_PHY` is ungated by default and stored a
  product/manufacturer string with no length bound. embassy-usb encodes string
  descriptors into the 64-byte control buffer under an `assert!`, so from the 31st
  UTF-16 code unit the USB stack panicked *during enumeration* — before any command
  could be served, with `panic_halt` spinning in the USB interrupt. No host path
  (factory reset, rescue wipe) could reach the device and a firmware reflash did not
  clear the record, so recovery meant a full flash erase, destroying the seed and
  every credential. It also fired from ordinary input: the ykman-compatibility
  suffix (` OTP+FIDO+CCID`, 14 bytes) pushed any 17-byte YubiKey-style name over the
  edge, well inside the `≤32` that `rsk hw` advertised. Every string is now clamped
  to 30 code units on a char boundary; the suffix is preserved by truncating the
  *name* instead of dropping the token, build-time overrides are checked at compile
  time, and `rsk hw` rejects what would be truncated. **A device already bricked
  this way now boots again after a firmware update** — the record is clamped on
  read.
- **The "permanent" OpenPGP touch policy could be switched off.** UIF value `02`
  is defined as not changeable by `PUT DATA` (OpenPGP 3.4 §4.4.3.6), but the DOs
  went through the generic writer, so a caller with PW3 — which already satisfies
  the PSO:CDS access condition — could lower it to `00` and sign with no press,
  silently. `PUT DATA` on a permanent UIF now answers `6985`, and undefined flag
  values are rejected instead of stored and echoed back. Only `TERMINATE DF` clears
  it, as the spec intends.
- **An OATH OTP-PIN planted before an access code existed survived it.** `SELECT`
  sets `validated = !code_set`, so on a factory-state applet `validated` is
  vacuously true and `SET PIN` was effectively unauthenticated; `VERIFY PIN` sets
  the same flag as `VALIDATE`, so the planted PIN remained a second, invisible
  unlock path *through* the access code the owner set afterwards, removable only by
  a reset that destroys every credential. Minting the PIN on a code-less applet now
  requires the operator, and installing an access code drops any PIN minted without
  it (re-mint it from a validated session).
- **A CCID card reset no longer leaves a verified PIN behind.** `IccPowerOff`/
  `IccPowerOn` only flipped a status byte and never reached the applet layer, so
  after `SCardDisconnect(SCARD_RESET_CARD)` — the host's primitive for forcing
  re-authentication — the previously selected applet stayed current with PIV
  `has_pin` / OpenPGP `has_pw1-3` / OATH `validated` intact, and a second local
  process could sign, decrypt or read OATH codes without ever authenticating.
  Contrary to OpenPGP 3.4 (VERIFY) and NIST SP 800-73pt2-5 §2.3. A power transition
  now deselects the current applet and clears its security status plus any buffered
  chain / pending response, and OpenPGP and OATH gained the `deselect` their own
  docs already promised.
- **The touch indicator can no longer be silenced or disguised.** On a build
  without the trusted display the LED is the only sign the key is awaiting consent,
  and the CCID `SET LED` had no gate at all — not even under `strict-config`, which
  gates its FIDO twin. The touch state is now clamped to a minimum brightness and a
  visible colour on every write path, and `SET LED` is presence-gated under
  `strict-config` so the vendor AID cannot bypass it.
- **Resident credential IDs are genuinely fingerprint-free now.** The v4 id set
  its last 10 bytes to `HMAC(id[0..32], "resident-id")` — keyed by the half already
  published to the relying party — so any RP holding an id could recompute the
  relation offline and identify the authenticator model, which is exactly the
  correlation handle the format was rewritten to remove. All 42 bytes are now keyed
  by the device secret. Forward-only: existing credentials keep working unchanged.
- **The clientPIN soft lock survives a warm reboot.** CTAP 2.1 §6.5.5.6 requires a
  power cycle after three failed PIN attempts, so a host cannot burn the retry
  budget unattended — but the flag was RAM-only and a host can request a warm reset
  ungated, clearing it. Two reboots then exhausted all eight attempts in seconds and
  permanently blocked the applet. The lock is now recorded in a watchdog scratch
  register, which survives `sys_reset` but not a real power cycle.
- **An OATH-HOTP slot no longer answers challenge-response.** `CFG_CHAL_HMAC` is a
  two-bit mask but was tested for any bit, and `TKT_OATH_HOTP` shares a bit with
  `TKT_CHAL_RESP` — so a slot from `ykman otp hotp --digits 8` entered the HMAC arm
  and, carrying no `CFG_CHAL_BTN_TRIG`, answered with **no button press**, turning a
  press-gated HOTP seed into a free chosen-message MAC oracle. Both arms now match
  the full mask, and such a slot is reported to `ykman` as a touch slot as it should
  have been.
- **One press no longer authorizes two operations over OTP-HID.** The OTP-HID
  dispatch did not clear the click-gesture state the way every other dispatch does,
  so the release edge of a press already consumed for a touch-gated
  challenge-response was counted as a click and typed a ticket as well — a static
  password in slot 1 in full.
- **`authenticatorLargeBlobs` no longer halts the device.** The length ceiling was
  checked on a 32-bit-truncated value while the floor was checked on the raw `u64`,
  so a length ≥ 2³² with small low bits passed both, stored a value below the
  minimum, and underflowed a slice bound at commit — panicking with `panic_halt`,
  which took every applet down until a physical replug. The length is now narrowed
  once and bounded on both ends.
- **Seed-moving vendor commands state what they do.** `BACKUP_LOAD` re-keys the
  device, making every existing credential undecryptable, but the PIN half of its
  gate is waived when no PIN is set — leaving it on one touch under a generic
  prompt. It now takes an explicit "Replace device seed?" confirmation in that
  state. `BACKUP_FINALIZE`, which irreversibly closes seed export and the on-device
  recovery-phrase reveal, took no request parameter at all and so could not be
  PIN-gated even in principle; it now carries the PIN gate and says
  "Seal backup permanently?" instead of "Finish backup?".
- **The trusted display waits for your finger to lift.** `confirm_wait` and
  `run_add_passkey` were the only modals that did not debounce, and the touch
  controller reports a level rather than an edge — so one continuous press could
  approve two consecutive ceremonies (two OpenPGP signatures, two OATH codes), and
  the single-tap passkey card could be approved in the same frame it was painted,
  too fast to read.

Findings from the 27th internal security audit. Most of the run re-examined the
run-26 fixes, and three of them turned out to guard one path out of several.
bcdDevice → `0x0854`; host tooling → `tools/rsk` 0.3.20.

- **A PIV factory reset now finishes the job (HIGH).** The sweep ran eight batches
  of 32 — a hard 256-file budget with no completion check — and then reported
  `9000` regardless. `PUT DATA` exposes 240 host-writable data objects, so anyone
  holding the management key (the public default on an unprovisioned card) could
  push a provisioned card past that budget: the reset then deleted the PIN files
  and stopped, `scan_files` re-seeded the default PIN `123456`, and the previous
  owner's private keys kept both their sealed scalar and their policy record, so
  `GENERAL AUTHENTICATE` still signed. `rsk offboard` signed a receipt certifying
  the wipe. The sweep now runs to convergence like the FIDO and OpenPGP wipes: it
  budgets *distinct deletes*, not passes, because the log-structured flash yields
  one entry per superseded version and a batch of 32 entries can be three files; it
  refuses to call a range clear when the enumeration was cut short by a read fault;
  and it re-creates the PIN/PUK/retry files even when it fails, since a card left
  without them answered `6A88` to every later `RESET` instead of the honest error.
  A sweep that cannot converge answers `6581` instead of claiming success.
- **The clientPIN retry budget can no longer be burned by a rebooting host
  (HIGH).** run-26 persisted the soft-lock *flag* across a warm reset but not the
  mismatch counter that arms it. A host that stopped at two wrong PINs never armed
  the lock, took the ungated warm reboot, and started a fresh batch — while the
  flash retry counter, decremented before the comparison, kept falling. Four rounds
  spent all eight attempts in seconds, with no user interaction, and permanently
  blocked the applet; the only recovery destroys every passkey and the seed. The
  counter now travels with the flag in the watchdog scratch register, so the
  power-cycle CTAP 2.1 §6.5.5.6 demands is a real one.
- **One button hold no longer authorises two operations (HIGH).** The wait broke on
  the button *level*, and its release debounce was bounded by the same presence
  timeout as the wait itself, so it could return "confirmed" with the finger still
  down. Requests are serialised, so a second one queued behind entered the wait
  milliseconds later and consumed the same unbroken press — a full `getAssertion`,
  an OpenPGP UIF signature or a PIV touch-policy signature the user never approved.
  A press is now spent once a ceremony returns and stays spent until the finger
  actually lifts. The phy record's presence timeout (tag `0x08`) was also
  host-settable to 1 s through the ungated `CONFIG_WRITE`, which made the window
  trivial to open; it is now clamped to **≥ 10 s**, the floor the device's own
  settings menu already offered.
- **`authenticatorReset` now takes a fresh power-up.** CTAP 2.1 §6.6 lets an
  authenticator with no display refuse a reset that does not follow one, and the
  keys people compare this one against do. RS-Key did not: destroying the seed,
  every passkey and the PIN was one ungated CTAP command plus a touch, at any point
  in a session — and on a screenless build the touch prompt says nothing about what
  it approves, so the press could be collected under cover of an ordinary sign-in.
  A reset more than **10 seconds** after the device attached now answers
  `0x30 CTAP2_ERR_NOT_ALLOWED` before the prompt. The window is measured from the USB
  attach rather than from power-on: boot spends seconds on the TRNG seed, the seal
  migrations and the one-shot at-rest hardening lap, which would have closed the
  window before the first command could arrive on exactly the devices whose owners
  most need the reset. A warm reset *closes* the window instead of reopening it,
  since a host can request one ungated. Trusted-display builds stay exempt — their
  prompt names the operation. Practical effect: `ykman fido reset` and the browser
  "reset security key" flows now need the key replugged first, and `rsk offboard`
  detects the refusal and walks the operator through the replug.
- **A reserved U2F control byte no longer signs.** U2F Raw Message Formats §7.2
  assigns AUTHENTICATE exactly three P1 values — check-only `07`, enforce
  user presence `03`, don't-enforce `08` — and anything else fell through to the
  don't-enforce path. The device signed the challenge with no touch *and* with the
  user-presence bit clear, so nothing in the assertion recorded that no human was
  there: a silent signing oracle over every registered app id for any process that
  could open the HID interface. Reserved values now answer `6A86`, and the
  `strict-up` build — which promises a touch on every assertion — rejects `08` as
  well.
- **Installing an org attestation key says what it replaces.** `ATT_IMPORT` hands
  the device the identity every later U2F registration signs with, and its gate
  waives the PIN half when no PIN is set — the same waiver run-26 fixed for
  `BACKUP_LOAD` — leaving the handover on one generic "Import attestation key?"
  touch. On a device with no PIN it now takes a distinct "Replace attestation
  identity?" confirmation first.
- **Rotating the PIV management key now revokes its PIN escrow.** `PRINTED`
  discloses the live `9B` key when ADMIN DATA carries the "PIN-protected" flag —
  but that object is written verbatim by any management-authenticated host through
  `PUT DATA` on `5FFF00`, and nothing cleared the flag on rotation. So the flag
  could be planted on a key that was never escrowed, and the owner's obvious
  remediation (rotate to a strong key) handed that new key to whoever held the PIN.
  `SET MANAGEMENT KEY` now clears the flag once the new key and its metadata are
  stored, so a rotation that fails part-way leaves the flag describing the key that
  is still there rather than stranding an owner whose only access was `PRINTED`. A
  host that wants escrow re-writes ADMIN DATA afterwards, which is what `ykman piv
  access change-management-key --protect` already does.
- **A torn PIV key import no longer attests as generated on-device.** `IMPORT`
  committed the sealed private key first and the origin record last, so a write
  failure at the wrong moment left an attacker-supplied key in a slot still marked
  `ORIGIN_GENERATED` — and `ATTESTATION` takes no PIN and no management gate, so
  the device's own F9 key would certify a software-held key as hardware-backed and
  non-exportable. The slot's metadata is now dropped *before* the key is written
  (`MOVE KEY` too), so a torn import fails closed: the slot reads as absent until
  it is re-provisioned.
- **An empty new admin PIN no longer wedges the OpenPGP applet.** `CHANGE
  REFERENCE DATA` carved the old PIN out with an off-by-one bound, so an APDU whose
  `Lc` equalled the stored PW3 length authenticated and then stored an *empty* new
  PW3. From then on every `VERIFY` answered `6A88` before the retry counter moved,
  and `TERMINATE DF` — allowed only with PW3 verified or blocked — was refused
  forever, leaving a device-wide factory reset as the only escape. The card now
  enforces its own reference lengths: PW1 ≥ 6, PW3 and the Reset Code ≥ 8, all
  ≤ 127, answering `6700`. A PIN accepted by an older firmware keeps verifying.
- **The touch indicator's guarantee now holds on every write path.** run-26 clamped
  the awaiting-touch LED, but the clamp sat in the CCID `SET LED` handler only. The
  FIDO `CONFIG_WRITE` LED target (ungated by default, and what `rsk led --transport
  fido` uses), the effect/speed setters, the phy boot-brightness default and the
  boot reload all reached the same pixels unclamped — so the commit's own
  documented behaviour was false for its own CLI flag. The floor moved into the
  `EF_LED_CONF` codec, so every decode enforces it, and it now covers the two
  bypasses the brightness check missed: a `speed` of 1 rendered an all-black
  breathing frame while brightness read compliant, and setting *idle* to the touch
  look made the two states pixel-identical. The touch **colour** is now reserved —
  any other status configured in it is reset to its own factory look, whatever its
  effect, brightness or speed. Keying that on the whole quad would not have held:
  one unit of brightness or speed is byte-unequal and eye-identical, steady mode
  ignores the effect byte outright, and on a one-LED board every effect renders the
  same solid frame.
- **The `rsk offboard` receipt can be re-checked offline.** The two checks that
  gave the receipt meaning — the signed head folding from the recorded window, and
  that window containing the `RESET` event — ran in memory and against data the
  saved JSON then dropped, so no later reader could redo them. A departing device
  holder could capture a genuine signature block from an *unwiped* key and
  hand-write a receipt for a wipe that never happened. The receipt is now split
  along the trust boundary — `attested` (what the device signed, plus the epoch and
  raw window needed to re-derive it) and `host_observations` (serial, timestamp,
  per-step results, decoded window, none of it attested) — and `rsk offboard
  --verify <receipt.json> [--expect-key …]` redoes the fold, the `RESET` scan and
  the signature with no device present. **Breaking for anything parsing the old
  flat shape**; `--verify` refuses a v1 receipt rather than pretend to check it.
- **The display's add-passkey card no longer approves a still-held finger.** The
  run-26 release-debounce gives up with the finger down once the presence timeout
  expires, and this card evaluated its single-tap *Allow* before the timeout check —
  so two back-to-back registrations could register the second silently. The
  timeout is now tested first, and the release wait carries a floor of its own so a
  host-shortened presence timeout cannot reduce it to nothing. (`confirm_wait` was
  already immune: its 800 ms hold outlasts the check.)
- **A blocked OpenPGP PIN no longer derives or writes flash before refusing.**
  `check_pin` derived the verifier, compared, retried against the legacy key-base
  arm and could run a two-write migration, and only then consulted the retry-block
  floor. The status word was `6983` either way, but the work was not: on a device in
  the narrow pre-migration state, a correct guess took measurably longer than a
  wrong one against an already-blocked reference. The floor is now checked first,
  as every sibling applet already does.
- **An abandoned credential-management enumeration no longer outlives its token.**
  The `getNextRP` / `getNextCredential` walkers carry no `pinUvAuthParam` of their
  own (CTAP 2.1 §6.8) — they inherit the *Begin* call's authorisation — but nothing
  invalidated the cursor when that token stopped being usable. A credential manager
  that opened an enumeration and closed its dialog left the remainder drainable by
  any unauthenticated caller for the rest of the power cycle: each RP, and per
  credential the user id, name, credential id, public key and `largeBlobKey` (which
  then decrypts that credential's large blob through the unauthenticated read). The
  cursor now dies with the token.
- **`rsk offboard` checks the journal before it wipes, and always writes the
  receipt.** Audit journalling is opt-in and off by default, so on a stock device
  the post-wipe window was empty, the `RESET` scan failed, and the tool exited
  before saving anything — every applet destroyed, no record, and re-running could
  not help. It now probes the journal state *before* the confirmation prompt and
  refuses with a pointer to `rsk audit enable` or the new `--no-receipt` opt-out.
  Post-wipe problems are recorded as `notes` entries and the file is written
  unconditionally; the exit code still reports the failure. `--no-receipt` means
  what it says — no preflight, no checkpoint touch, no file — and the re-check hint
  printed at the end now points at the fingerprint recorded when the key was
  enrolled, not at the receipt's own, which would check the receipt against itself.
- **An unauthenticated host can no longer flush the audit journal.**
  `CONFIG_WRITE` is ungated on the default build and is the only journalled event a
  silent host can drive on demand, so 128 of them evicted every other entry — boots,
  resets, PIN lockouts, seed moves — from the 128-slot ring. Skipping the entry for
  a byte-identical replay was no defence: alternating a single brightness byte
  really changes the record every time. A *run* of config writes now costs one slot.
  The newest entry keeps its sequence number, timestamp and opening target and
  counts the rest in its detail (`repeats(2 LE) ‖ targets(1)`, a `1 << target` mask
  of every record the run touched), so `seq_next` never advances and nothing is
  evicted; a run never folds across a power cycle, which would have swallowed the
  `BOOT` entry between them. `rsk audit log` prints the entry as `300× write
  (phy+led)` instead of raw hex. One thing for anything re-checking a chain: a
  coalesce moves the head *without* advancing `seq_next`, so the same `seq_next`
  with a different head is now legitimate rather than a tamper signal. Separately,
  a phy `CONFIG_WRITE` on a device whose `EF_PHY` is absent or unreadable was
  answered `Ok` with nothing stored — the no-op check could not tell "no record"
  from "a record equal to the defaults" — so a host writing the defaults to repair
  it got silence. It now takes the write.
- **`rsk audit verify` no longer calls an unpinned run "journal authentic".** The
  verifying key comes from the same device response being checked, so without
  `--expect-key` the check proves self-consistency and nothing about *which* device
  signed. The verdict now says so, and `--expect-key` accepts the 16-hex fingerprint
  as well as the full SEC1 point, matching the fingerprint the tool tells you to
  record.
- **The release workflow no longer interpolates the tag into a shell command.**
  `release-build.yml` substituted the raw tag input into a `run:` block inside the
  SLSA signing job, and `git check-ref-format` accepts `$(…)`, backticks, `;` and
  `|`. A credential with `Contents: write` but without the `workflow` scope can
  create a tag while being rejected on any workflow-file edit, so tag creation was a
  way into the job holding the release signing identity. The tag is passed through
  `env:` and validated for shape and character set before use. CI-only; no runtime
  effect.

Two of the run's findings were assessed and **not** fixed in code, so they are
written down rather than closed. The at-rest seals authenticate nothing against
someone who can *write* flash over BOOTSEL: the pre-OTP key base derives from the
public chip serial and stays readable after the burn (that is what keeps an
already-provisioned device working across the upgrade), so a planted record opens
under it and the boot migration re-seals it under the fused root. Closing that
needs a fuse-rooted latch on the migration window, which makes `lock-page58`
load-bearing for boot correctness — the threat model and the limitations page now
say so. And the config-write coalescing above bounds the ring flood to one slot per
power cycle, not to none: a phy write latches a reboot, so a host willing to
re-enumerate the device can still spend two slots per cycle. Each cycle is a full
USB re-enumeration and plainly visible, and gating the write (`--features
strict-config`) remains the complete answer.

## [0.4.2] - 2026-07-25

### Changed

- **FIDO2 credential IDs are now fingerprint-free — they look random, like a
  YubiKey's.** Both credential-ID formats used to carry a fixed cleartext prefix a
  relying party (or a flash dump) could recognise: non-resident boxes led with
  `f1d00202`, and resident (passkey) ids led with a 10-byte header
  (`HMAC(serial)[..4] ‖ f1d00203 ‖ version ‖ 00`) whose first four bytes were
  **device-specific and identical across every passkey on the device** — a
  cross-RP device-correlation handle. New credentials carry neither marker: a
  non-resident box is `iv ‖ ciphertext ‖ tag ‖ silent-tag` (its key comes from a
  fixed internal label, not an on-wire byte) and a resident id is 42
  pseudo-random per-credential bytes. **Backward-compatible:** already-registered
  credentials keep working — the authenticator still opens the legacy
  `f1d00202` / `f1d00203` formats (the AEAD tag and a length-based allowList
  lookup tell the framings apart), so no re-registration is required. The change
  is forward-only: ids issued before the upgrade stay as they were until a site
  is re-registered. **bcdDevice → 0x0851.**

## [0.4.1] - 2026-07-24

### Changed

- **The default build's CCID ATR no longer impersonates a YubiKey.** The card's
  answer-to-reset was the YubiKey 5's ATR on every build; it is now gated on the
  effective USB VID, exactly like the iManufacturer and OpenPGP AID. A Yubico
  identity build (`VIDPID=Yubikey5`, or a PicoForge-repointed VID) keeps the
  YubiKey ATR for `ykman` / `ykmd` compatibility; the default RS-Key build
  presents an ATR with the same T=1 card capabilities but a `RS-Key`
  historical-byte label. On Windows a default build is therefore no longer bound
  to Yubico's `ykmd` minidriver by the "YubiKey Smart Card" ATR entry — PIV falls
  to the inbox `msclmd` (which recognises the card by its PIV AID). **bcdDevice →
  0x084F.**

- **`ykman config usb --disable`/`--enable` now actually disables applications.**
  The enabled-applications mask (`USB_ENABLED` in the Management DeviceConfig) used
  to be reporting-only — a "disabled" app kept working. It is now **enforced**: a
  disabled application's applet stops answering — PIV/OpenPGP/OATH/OTP return `6A82`
  on CCID SELECT, FIDO2 (CBOR) and U2F (MSG) are refused over CTAPHID, and the OTP
  keyboard goes inert (no typed tickets, no challenge-response). It takes effect
  live (next command, no replug) and is **reversible**: the Management applet, the
  FIDO vendor `CONFIG_WRITE`, and the OTP-HID identify/config slots are never gated,
  so any one transport can re-enable. On the default build the admin write stays
  ungated for ykman parity, so a hostile host can toggle applications — a reversible
  DoS, documented in docs/threat-model.md; `--features strict-config` gates the
  write on operator presence. **bcdDevice → 0x084A.**

### Fixed

- **OATH `CALCULATE ALL` no longer breaks the Yubico Authenticator (regression of the
  unreleased issue-#44 SELECT fix).** YKOATH `CALCULATE ALL` reuses instruction byte
  `0xA4` — the same as `SELECT` — as `00 A4 00 01 …`. The first cut of the
  master-file-`SELECT`→`6D00` rule matched on `INS 0xA4` + `P1=0x00` and so shadowed
  `CALCULATE ALL`, returning `6D00`; the Yubico Authenticator (which refreshes codes
  with `CALCULATE ALL`) then failed and spun, re-connecting in a loop (the LED blinked
  hard). The rule now keys on `P2=0x0C` (`SELECT`, no response data), which
  `CALCULATE ALL` (`P2=0x01`) does not use. **bcdDevice → 0x0850.**

- **Smart card: the master-file `SELECT` (`00 A4 00 0C …`) now answers `6D00`, the way
  a YubiKey does.** GnuPG's `scdaemon` probes a card with `SELECT 3F00` and only when
  that fails with a card error does it recognise a YubiKey and read the real serial
  from the management applet. RS-Key answered `6A88`, so `scdaemon` skipped that step:
  Kleopatra / `gpg --card-status` showed a raw serial (`0006 47537774`) instead of the
  device serial and did not surface the PIV application alongside OpenPGP. The applet
  dispatcher now returns `6D00` for the master-file `SELECT` (`A4 P1=0x00 P2=0x0C`) —
  RS-Key is applet-only and has no master file — so the whole YubiKey code path in
  `scdaemon` runs. Found via a live differential against a real YubiKey (issue #44).
  **bcdDevice → 0x084E.**

- **FIDO: `makeCredential` no longer answers `excludeList` without a touch.** An
  `excludeList` hit returned `CTAP2_ERR_CREDENTIAL_EXCLUDED` instantly, before any
  user-presence gesture, so a host holding a candidate credential id could silently
  probe whether it is registered on the inserted key (an rpId-bound existence
  oracle). CTAP 2.1 §6.1.2 requires the presence gesture before disclosing the
  match; RS-Key already did this on the `getAssertion` no-match path and now does it
  here too, spending the pinUvAuthToken on that touch. **bcdDevice → 0x084D.**

- **FIDO: a pinUvAuthToken no longer keeps its permissions across a touch.**
  After a user-presence-gated `makeCredential` or `getAssertion`, CTAP 2.1 §6.5.5.7
  requires clearing the token's user-present / user-verified flags and every
  permission except `largeBlobWrite`. RS-Key only refreshed the token's inactivity
  timer, so a token minted with `mc|ga|acfg` could register or authenticate with one
  touch and then run `authenticatorConfig` (`toggleAlwaysUv`,
  `enableEnterpriseAttestation`) with **no second touch**. RS-Key now runs the full
  §6.5.5.7 triad at every place a `makeCredential` / `getAssertion` tests presence —
  including the `getAssertion` no-match (`NO_CREDENTIALS`) branch, which takes a real
  anti-oracle touch. (`makeCredential`'s `up` is implicit; `getAssertion` keys on the
  raw `up`, so a silent `up:false` pre-flight still does not consume the token.)
  Authenticated (needs a valid PIN/UV token); reported by @cresseelia
  (GHSA-wqjm-653g-hgw3). **bcdDevice → 0x084C.**

- **`ykman otp swap` now works.** The OTP applet's SWAP (slot `0x06`) accepted only
  an empty body or RS-Key's `[a,b]` 4-slot-offset extension, but ykman/yubikit send
  the standard swap as a bare 6-byte access code (no offset bytes). RS-Key rejected
  that frame as `WRONG_LENGTH`, so the host saw `Failed to write` / `No data`; it now
  swaps slots 1↔2 and honours the code. Found by a full OTP-HID differential against
  a real YubiKey — every other OTP-HID command already matched. **bcdDevice → 0x084B.**
- **`ykman config usb` no longer fails with `CommandRejectedError: No data` over the
  OTP keyboard transport.** ykman/yubikit confirm an OTP-HID config write by the
  status frame's program-sequence byte advancing; `SET_DEVICE_INFO` (and the other
  OTP-HID admin writes) persisted the config but never bumped that counter — so on a
  host without PC/SC, where ykman falls back from CCID to the OTP-HID transport, the
  write was reported rejected even though it took. They now advance the sequence like
  a slot configure. **bcdDevice → 0x084A.**

## [0.4.0] - 2026-07-22

### Security

- **`rsk hw` no longer lets a counterfeit device inject terminal escapes.** The phy
  dump printed the device-controlled USB manufacturer/product strings raw, so a
  hostile device could embed ANSI/OSC/bidi sequences to forge terminal output (e.g.
  a fake "verified") or write the operator's clipboard. They now pass through the
  same `sanitize()` filter every other device-string printer already uses. Host-only
  (`tools/rsk` → 0.3.18); no `bcdDevice` change.
- **OpenPGP key import rejects an RSA public exponent other than 65537.** The signer
  and DECIPHER hardcode e = 65537, so importing a key with a different exponent used
  to store a silently-unusable key while the public-key DO advertised the imported e;
  import now fails with `6A80` (incorrect parameters), matching the PIV path.
  **bcdDevice → 0x0848.**
- **`VENDOR_AUDIT_CONFIG` rejects an unknown op instead of enabling.** Any target
  other than 0 (disable) / 1 (enable) / 2 (status) used to alias to enable; an
  unknown op is now rejected with `CTAP2_ERR_INVALID_PARAMETER`. **bcdDevice → 0x0849.**

### Added

- **The audit journal is now opt-in and OFF by default.** It used to record every
  boot and FIDO/config/backup event to a flash ring unconditionally; that write
  churn is now gated behind a per-device flag that ships **off**, so a default key
  writes no journal entries. Turn it on/off from the host with `rsk audit enable` /
  `rsk audit disable` (`rsk audit status` reads the state without a touch), or the
  new `VENDOR_AUDIT_CONFIG` (0x0E) CTAP vendor subcommand. A change needs a PIN
  (when set) plus a touch — a silent host cannot flip a user's tamper-evident trail
  — and the transition is itself journalled. An existing device upgrades to off; its
  prior journal and hash chain are preserved (still readable and checkpointable),
  logging just stops until re-enabled. **bcdDevice → 0x0847.**
- **`strict-config` cargo feature** — restores the strict admin-write
  authorization that used to be the shipped default (device-config writes
  presence/PIN-gated, ungated transport writes refused). OFF by default now; see
  the "default posture flipped" Changed entry. Build/ship the strict image with
  `--features strict-config` (release flavor `firmware-strict-config`). Distinct
  from the runtime flash flag `EF_HARDENED`.
- **Build-time AAGUID override.** `AAGUID=<uuid-or-32-hex> cargo build` bakes a
  custom FIDO2 AAGUID (the authenticator-model id in getInfo / attestation): the
  value is validated in `crates/rsk-fido/build.rs` and const-parsed in `consts.rs`
  (baked as `PK_AAGUID`), defaulting to RS-Key's reproducible UUIDv5. It is meant
  for a fork that ships its own metadata — a non-default AAGUID makes the
  checked-in metadata statement no longer match, and advertising a real vendor's
  AAGUID would be an attestation forgery that fails to chain anyway. The default
  build's AAGUID is unchanged and its image is **byte-for-byte identical**
  (compile-time const parse, no runtime code) — **no bcdDevice bump.**
- **The USB manufacturer/product strings are runtime-configurable via the phy
  record, and a Yubico VID now auto-fills the whole identity.** A new phy tag
  `0x0F` (USB_MANUFACTURER) sets the iManufacturer string; `rsk hw` gains
  `--manufacturer` / `--product`. Precedence per string: an explicit phy tag wins,
  else the effective VID picks a default (a Yubico VID `0x1050` fills in both
  `Yubico` and `YubiKey RSK OTP+FIDO+CCID`, so a VID-only repoint via PicoForge /
  `rsk hw` now "just works" for `ykman` / Yubico Authenticator — previously the
  manufacturer followed the VID but the product did not), else the build const.
  The default build still presents its own RS-Key identity; nothing masquerades
  unless you set it. ⚠️ an explicit manufacturer/product lets any VID carry any
  vendor name — the identity stays cosmetic, never an authenticity signal
  (docs/threat-model.md). Forward-compatible: an old phy record without `0x0F`
  falls back to the VID/build default. **bcdDevice → 0x083D.**
- **PIV serves a default CHUID, so a freshly flashed card works under Windows
  CAPI.** The Windows PIV minidriver enumerates a card's containers from the Card
  Holder Unique Identifier (CHUID, object `5FC102`); a card that had none answered
  `6A82`, and CryptoAPI sign / auth then stayed "pending" on slots `9A`/`9C`. The
  applet now synthesizes a default CHUID when none is provisioned — the well-known
  non-federal FASC-N plus a device-stable GUID (`sha256(serial)[..16]`), the same
  shape `ykman piv objects generate chuid` writes. A host-written CHUID still
  overrides it (flash is read first). RSA/EC signing itself was always correct
  (verified byte-for-byte against a real YubiKey 5.7.4); this is the enumeration
  half of the issue #44 PIV-under-CAPI reports. **bcdDevice → 0x0839.**
- **OpenPGP brainpoolP256r1 and brainpoolP384r1** (ECDSA on the sign / auth slots,
  ECDH on the decrypt slot). gpg can now `key-attr` / `generate` / `keytocard` a
  brainpool key, matching the curves a real YubiKey 5.7.4 advertises in the
  algorithm-information DO (`0xFA`). brainpoolP512r1 stays absent — no Rust
  arithmetic for the 512-bit brainpool curve exists yet. The applet keys off the
  `bp256` / `bp384` crates (fiat-crypto backend), checked byte-for-byte against
  OpenSSL test vectors. **bcdDevice → 0x0836.**
- **`rsk bench` — an on-device crypto-latency harness that survives XIP-cache
  noise.** Steady-state EC latency on the RP2350 shifts ±~30 ms with code layout
  (the hot working set overflows the 16 KB XIP cache), so a host-timed mean fakes
  regressions. The new `bench` firmware feature (vendor command, never shipped —
  like `keygen-bench`) times a primitive with the device's own timer and returns a
  robust median / MAD plus a separate cold-cache sample; `rsk bench --compare`
  gives an A/B verdict between two saved runs. The summary is computed on-device by
  the new host-tested, Kani-proved `rsk-bench` crate. Feature is off by default, so
  the shipped image is byte-for-byte unchanged — **no bcdDevice bump.**
- **Default firmware images for 2 MB and 16 MB boards.** The signed release now
  ships `firmware-2mb` (`FLASH_SIZE=2M KVMAIN=896K`) and `firmware-16mb`
  (`FLASH_SIZE=16M`) alongside the 4 MB default — the flash-geometry siblings of
  the default image, same feature set and RS-Key identity, for boards whose chip
  is not the 4 MB default (Seeed XIAO RP2350 / Waveshare RP2350-Zero-CM at 2 MB;
  TenStar RP2350-USB at 16 MB). PR CI smoke-builds both so a 2 MB link/fit
  regression is caught early. Build/release wiring only; the 4 MB default image is
  byte-for-byte unchanged — **no bcdDevice bump.**

### Changed

- **Faster PIV/OpenPGP EC signing and key derivation.** The generic RustCrypto
  signer PIV GENERAL AUTHENTICATE and OpenPGP PSO:CDS used derived the public key
  `d·G` on every signature (never used when only signing) and ran `k·G` through
  the crate's slow generic `mul_by_generator`. Both `k·G` (ECDSA nonce commitment)
  and `d·G` (public-key derivation, used by keygen and GET DATA) now go through the
  shared fixed-base comb in the new **`rsk-ec`** crate — several× faster on the
  in-order Cortex-M33 and **byte-identical** to the crate (KAT-checked). The comb is
  **constant-time** (branch-free window add with a `subtle` table select), so it does
  not leak the nonce/scalar via timing — matching the crate's `mul_by_generator`; this
  also hardens the comb FIDO already carried, which `rsk-ec` now de-duplicates, so all
  three applets share one KAT-verified constant-time implementation. ECDSA over
  P-256/P-384/secp256k1 and the P-521 pubkey are covered; ECDH is variable-base and
  unchanged. On-device (Waveshare Zero):
  P-384 ECDSA sign ~537 ms → ~0.2 s, P-256 sign ~100 → ~50 ms, EC keygen much faster.
- **Faster PIV RSA signing** (~3.1× on RSA-2048, ~2.9× on RSA-4096; on-device
  medians — 0.13 s / 0.86 s — now beat a real YubiKey 5.7's 0.18 s / 1.39 s).
  Slot private-key operations now run the
  CRT modexp through the vendored UMAAL assembly (`rsk_rsa_asm::sign_crt`) instead
  of the pure-Rust `num-bigint-dig` 4-bit-window path, and the two full-width
  public-exponent modexps around it — the blinding factor `rᵉ` and the fault
  check `sigᵉ` — now use the asm too (`rsk_rsa_asm::modexp_pub`). The sealed key
  caches the CRT parameters (`P‖Q‖dP‖dQ‖qInv`) so a signature no longer rebuilds
  `d`/`dP`/`dQ`/`qInv` (two modular inversions) every time. Base blinding and the
  Bellcore fault check (`sigᵉ ≡ c mod n`) are kept — the fault check also means a
  faulted CRT half or an asm/marshaling bug can never emit a valid signature.
  Forward-compatible: keys sealed by an older firmware (`P‖Q` only) still load and
  sign — they get the fast modexp but recompute the CRT parameters once per
  signature until re-provisioned. OpenPGP RSA gets the same treatment — see below.
- **Faster OpenPGP RSA signing** (PSO:CDS and INTERNAL AUTHENTICATE), the same
  ~3× win the PIV applet already banked. gpg RSA signatures now run the CRT
  private operation on the vendored UMAAL assembly (`rsk_rsa_asm::sign_crt` /
  `modexp_pub`, via the shared `rsk_openpgp::rsa_crt` extracted from the PIV
  path) instead of the pure-Rust `num-bigint-dig` path that rebuilt `dP`/`dQ`/
  `qInv` (two modular inversions) on every signature. The sealed key now caches
  the CRT parameters (`P‖Q‖dP‖dQ‖qInv`). Base blinding and the Bellcore fault
  check (`sigᵉ ≡ c mod n`) are kept, so a faulted CRT half or an asm/marshaling
  bug can never emit a valid signature. PSO:DECIPHER is unchanged (still the `rsa`
  crate's constant-time PKCS#1 v1.5 unpadding). Forward-compatible: keys sealed by
  an older firmware (`P‖Q`, including the legacy CFB seal) still load and sign —
  they recompute the CRT parameters once and re-seal forward to the new
  authenticated 5-field layout.
- **⚠️ Default security posture flipped: device-config writes are now UNGATED by
  default (full YubiKey/ykman parity).** On the default build the CCID Management
  WRITE CONFIG (`0x1C`) and the FIDO vendor CONFIG_WRITE (`0x0C`) no longer require
  operator presence / a PIN `pinUvAuthToken` — any USB host can rewrite the
  reported DeviceInfo. The previous presence/PIN-gated behaviour is now opt-in via
  `--features strict-config`. This deliberately weakens the DEFAULT threat model
  (docs/threat-model.md); build/ship `firmware-strict-config` for the strict
  posture. Part of a broader default→permissive flip: the default build also now
  serves ykman's CTAPHID vendor WRITE CONFIG (`0x43`) and the OTP-HID
  SET_DEVICE_INFO (`0x15`) DeviceInfo writes — both ungated, persisting the same
  `EF_DEV_CONF` every READ CONFIG echoes — and the remaining OTP-HID admin slots:
  SCAN_MAP (`0x12`, functional — a stored custom scancode map remaps typed OTP
  output for non-US hosts) plus DEVICE_CONFIG (`0x11`) and NDEF (`0x08`/`0x09`) as
  accept+store (inert on this USB-only board, no NFC radio). Management RESET
  (INS `0x1E` / ykman's `0x1F`) is a device-wide factory reset in the default build
  — presence-gated even here, since an ungated one-APDU wipe would be a footgun —
  wiping all flash but the org attestation and rebooting to re-provision; it stays
  `6D00` under strict-config. **bcdDevice → 0x0841.**
- **The USB manufacturer string and OpenPGP AID vendor now follow the effective
  (phy-overridden) VID at runtime.** Previously only the *build-time* VID chose them
  (`VIDPID=Yubikey5`), so a runtime Yubico-VID repoint via PicoForge kept the
  manufacturer `RS-Key` and the OpenPGP AID vendor unmanaged; both now switch with
  the effective VID for a consistent identity (fixes the "manufacturer stays RS-Key"
  report, picoforge#102). ⚠️ this lets a phy-repointed default key present a full
  Yubico identity at runtime — a deliberate masquerade capability, previously
  build-time-only (see docs/threat-model.md). **bcdDevice → 0x083B.**
- **A FIDO PHY config-write now warm-reboots the device by default**, so a
  VID/PID/product/interface change applies without a manual replug (RS-Key#33). The
  phy `DISABLE_POWER_RESET` option bit (clear by default) turns it off; a `CONFIG_READ`
  never reboots.
- **The `flow` and `sparkle` LED effects honour the configured status colour**
  instead of a fixed yellow→red gradient / random RGB, so a per-status colour set
  via PicoForge or `rsk led` is actually shown.
- **Faster PIN: the clientPIN key-agreement key is generated at power-up and its
  public key is cached.** The first PIN entry after plugging the key in used to be
  noticeably slower than the rest (a one-time elliptic-curve key generation on the
  first `clientPIN` command); it now happens at boot, off the critical path. And
  because every `getKeyAgreement` was needlessly re-deriving the same public key,
  caching it speeds up *every* PIN operation, not just the first. Measured on the
  RP2350: first PIN ~162 → ~64 ms and each subsequent PIN ~106 → ~62 ms (a real
  YubiKey, for reference, is ~166 first / ~98 steady). The wire behaviour is
  unchanged (same key, same protocol). **bcdDevice → 0x0838.**
- **The elliptic-curve stack moved from RustCrypto 0.13 to 0.14** (`p256` / `p384`
  / `p521` / `k256`, with `elliptic-curve` 0.14 and `ecdsa` 0.17), so brainpool and
  the NIST curves share one arithmetic generation instead of two — cutting ~138 KB
  of flash. EC signatures are byte-for-byte unchanged (host KATs prove it), so
  keys provisioned before the upgrade keep working. **bcdDevice → 0x0836.**
- **P-384 and secp256k1 FIDO signatures now sign through the fixed-base comb**
  (as P-256 and P-521 already did), skipping 0.14's slower generic scalar
  multiplication: on the RP2350, P-384 `getAssertion` drops ~570 → ~230 ms and
  secp256k1 ~86 → ~50 ms. The signatures stay byte-identical to the crate signer,
  secp256k1's low-S normalization included. **bcdDevice → 0x0837.**

### Fixed

- **PIV `GET METADATA` on an RSA slot is ~30× faster.** It rebuilt the entire
  private key — `from_p_q`'s `dP/dQ/qInv` modular inverses, ~50 ms on RSA-4096 —
  only to emit the public modulus; it now computes `N = p·q` directly (the fixed
  65537 exponent needs no rebuild). Output is byte-for-byte identical.
  **bcdDevice → 0x0845.**
- **The first PIV Certificates-page open after a cold plug-in is no longer slow.**
  A cold `read`/`has_data` of an absent FID scanned the whole flash partition to
  prove absence, so the Yubico Authenticator Certificates tab — which probes the
  cert object of all ~24 PIV slots, most empty — paid a full-partition scan per
  empty slot on the first open of each power cycle (up to ~2 s on a well-used
  device). The boot `scan()` now reports whether it enumerated the whole store,
  and on a *complete* enumeration decides the entire FID space absent-by-omission,
  so every applet's cold absent lookup is O(1) instead of a per-slot flash walk.
  Robust by construction: a read-fault-truncated scan keeps confirm-on-miss, and a
  torn power cut cannot hide a committed key (the forward ring walk is a
  page-superset of `fetch_item`'s, and reclaim erases a source only after
  forwarding its items). **bcdDevice → 0x0846.**
- **A partial PicoForge config write no longer resets the fields it didn't touch.**
  The FIDO `CONFIG_WRITE` (`0x0C`, target PHY) and CCID rescue `WRITE 0x1C` used to
  *replace* the whole `EF_PHY` record with a parse of the incoming blob, so any tag a
  host omitted (product name, LED order/count, VID/PID) reverted to the build
  default. Both paths now do a read-modify-write merge (`phy::merge_save`): only the
  TLV tags in the blob are updated, the rest are preserved. Closes the firmware half
  of picoforge#102 / RS-Key#33. **bcdDevice → 0x083A.**
- **A YubiKey-masquerade product string can no longer crash Yubico Authenticator on
  Windows.** `ykman` derives a YubiKey PID from the PC/SC reader name; a name with
  `Yubico YubiKey` but no `OTP`/`FIDO`/`CCID` token makes it build the non-existent
  PID `YK4_` and raise `KeyError`, aborting the whole card scan. The firmware now
  appends ` OTP+FIDO+CCID` to a runtime product that looks like a YubiKey but omits
  the `CCID` token (`normalize_usb_product`).
- **"Steady / keep-LED-on" now works on the addressable (WS2812) backend.** The
  animated effects (vapor/flow/bounce/sparkle) ignored `LED_STEADY` — only the legacy
  on/off renderer read it — so on the default build the LED kept animating; the render
  loop now shows the status colour solidly when steady is set.
- **Plain single-colour LEDs now dim, and the `LED_DIMMABLE` bit is honoured.** The
  `gpio` backend was on/off only, so brightness (and PicoForge's "LED Dimmable") did
  nothing on a plain LED; it now uses software PWM (~500 Hz). The phy `LED_DIMMABLE`
  option bit gates the global boot-brightness override. **bcdDevice → 0x083C.**
- **Four small YubiKey-conformance nits surfaced by a full differential against a
  real YubiKey 5.7.4.** None broke tooling, but each now matches the YubiKey
  byte-for-byte: (1) standalone GET DATA of the OpenPGP General Feature Management
  DO (`7F74`) returned the bare flag `20` instead of the `81 01 20` sub-DO a real
  card returns — the primitive-DO unwrap no longer strips this constructed DO;
  (2) the OpenPGP algorithm-information DO (`FA`) advertised the DEC slot's NIST /
  secp256k1 curves as ECDSA (`0x13`) instead of ECDH (`0x12`) — the applet already
  accepted ECDH decryption keys, only the advertisement was wrong; (3) the CCID OTP
  status was 7 bytes (a stray trailing `0x00`) instead of the canonical 6; (4) the
  OATH device id / PBKDF2 salt (SELECT tag `71`) was the raw chip-id hex text,
  making it predictable from the semi-public serial — it is now an opaque one-way
  hash of the device seed, stable across boots like a YubiKey's. **A device with an
  OATH access code set must re-set it once after this change** (the salt moved).
  **bcdDevice → 0x0835.**

- **The OpenPGP card serial now matches the rest of the device identity.** The
  OpenPGP application AID (GET DATA `0x4F`) spliced in the *raw* chip-id bytes, so
  hosts rendered a serial unrelated to the one PIV (`INS 0xF8`), Management READ
  CONFIG and OTP GET SERIAL report — visible on Windows / Kleopatra as an OpenPGP
  serial with no bearing on the PIV one (issue #44). OpenPGP now carries the
  8-digit device serial as packed BCD, matching a real YubiKey (whose OpenPGP AID
  holds e.g. `37 36 50 93` for device serial 37365093), so `gpg` renders the same
  decimal across all applets. Persistent keys and PINs are unaffected: the PIN/DEK
  derivation roots on `sha256` of the full 8-byte chip id, not the serial. On an
  already-provisioned device GnuPG's scdaemon sees the card under its corrected
  serial once and re-adopts it (a one-time reconnect, no re-provisioning).
- **OpenPGP now reports the device firmware version and an identity-consistent
  manufacturer.** The vendor VERSION command (INS `0xF1`, read by `ykman openpgp
  info` as "Application version") returned a hardcoded `4.6.0` inherited from the
  upstream project; it now returns the shared `FIRMWARE_VERSION` (default `5.7.4`,
  `FW_VERSION`-overridable at build time) that FIDO / OATH / OTP / Management
  already report, matching a real YubiKey where the OpenPGP applet version equals
  the firmware version. The OpenPGP AID manufacturer id (bytes 8-9) now follows the
  USB identity: `0x0006` (Yubico) on the `VIDPID=Yubikey5` interop build so hosts
  show the same vendor as a real YubiKey, `0xFFFE` (unmanaged range) on the default
  RS-Key identity, which is not Yubico.
- **The OpenPGP Key Information DO (`0xDE`) is now spec-conformant.** It was emitted
  as a bare child of the application-related-data (`0x6E`) with 0-indexed key
  references (`00/01/02`); the OpenPGP Card 3.4 spec nests it inside the `0x73`
  discretionary DOs with references `01/02/03` for SIG/DEC/AUT. `ykman >= 5.2` reads
  the DO from the discretionary set and keys on those references, so with the
  firmware version now reporting 5.7.4, `ykman openpgp info` used to crash
  (`KeyError`); it now reads the card. **bcdDevice → 0x0834.**

## [0.3.10] - 2026-07-20

### Fixed

- **`authenticatorReset` could hang the device on a heavily-provisioned key.** The
  FIDO factory reset wiped its files with `Fs::delete`, which skips the backend
  removal when its in-RAM present-cache reads the key as absent. A torn-migration
  false-absent key (live in flash, present bit clear) was therefore never removed,
  yet the reset's `for_each_key` pass — which reads the backend directly — kept
  re-finding it, so the wipe looped forever and the authenticator wedged until a
  power cycle (the on-device LED froze). Reset now removes each FIDO file
  unconditionally (`Fs::force_delete`, as the trusted-display factory wipe already
  did) and aborts on a backend error rather than retrying it, so the wipe always
  terminates. Surfaced on a well-worn test key; a fresh key was unaffected.
  **bcdDevice → 0x0830.**

### Security

- **A `getAssertion` that matches no credential now asks for a touch before
  reporting "no credentials".** Previously the authenticator returned
  `CTAP2_ERR_NO_CREDENTIALS` immediately — the CTAP 2.1 §6.2.2 reference order,
  which lists the disclosure before the user-presence step — so anyone holding the
  plugged-in (PIN-locked) device could probe whether a credential exists for a
  given RP, or for a specific credential id, without any user gesture: a fast
  `0x2e` meant "absent", a touch prompt meant "present". An interactive request
  (`up` true) now polls the button before disclosing the miss, for both
  discoverable and allowList lookups, matching a genuine YubiKey (which does the
  same and passes FIDO conformance). The platform's silent `up:false` pre-flight
  (WebAuthn / ssh-sk credential discovery) stays touch-free and still fast-fails,
  so login latency and ssh-sk are unaffected. **bcdDevice → 0x082F.**
- **The FIDO `pinUvAuthToken` now expires instead of living for the whole power
  cycle.** A minted PIN/UV auth token carried no usage timer (CTAP 2.1 §6.5.5.7
  was unimplemented), so once issued it stayed valid until the next reboot. It
  now runs the spec's usage timer, checked before every CBOR command: a **30 s
  rolling inactivity window** — each token-authorized command (`makeCredential`,
  `getAssertion`, `credentialManagement`, `largeBlobs` write, `authenticatorConfig`,
  the vendor MSE channel) pushes the deadline out — bounded by a **10-minute
  absolute cap** from issuance that fires even under constant use. Impact was low
  — the token is RAM-only (a reboot always cleared it), it cannot be minted
  without the PIN, and `makeCredential`/`getAssertion` still require a fresh
  physical touch regardless; the practical exposure was a host that had already
  captured the token driving touch-free `credentialManagement` enumeration or
  deletion — but a bounded lifetime closes the gap. Found comparing the FIDO
  clientPIN state machine against the upstream lineage's own token-expiry fix.
  **bcdDevice → 0x082E.**
- **`rsk lock enable --key-out` no longer leaves the lock key briefly
  world-readable.** The key file was `chmod 0600`-ed only *after* the write
  finished and the descriptor closed, so the 32-byte host lock key (it wraps the
  FIDO seed) sat at the umask default in between, and the `chmod` followed a
  symlink swapped in during the window. The file is now created `0600` atomically
  with `O_EXCL`. Host-only (`rsk` → 0.3.13); `--key-out` is a test-only flag and
  the normal flow only prints the key to stdout, so exposure was minor.

## [0.3.9] - 2026-07-19

### Fixed

- **KV store no longer rolls a key back to an older value on a power-cut mid-delete.**
  The vendored `sequential-storage`'s `remove_item` erased a key's page copies starting
  from `find_first_page(PartialOpen).unwrap_or_default()`, which falls back to page 0
  whenever there is no partial-open page (the normal steady state: a closed frontier page
  plus an open buffer page). That inverted the intended oldest-first erase order, so a
  power loss during a delete could erase the newest copy first and leave an older copy
  live — which the next read then returned (a rollback past the committed value). The
  remove path now computes the newest page the same way the read path does, so the two
  agree. On RS-Key this was fail-closed (every stored value is AEAD-sealed and read past a
  length/tag gate, so a resurfaced stale/short blob is rejected, not used), but it is a
  real durability defect in the store that holds all sealed secrets. Found by the
  `kv_durability` fuzz target; an upstream `sequential-storage` bug (fix confined to the
  vendored fork, `third_party/sequential-storage.patch` item 3). **bcdDevice → 0x082D.**

## [0.3.8] - 2026-07-19

### Added

- **`strong-pin` build feature — stronger PIN policy for the FIDO clientPIN.** A new
  opt-in cargo feature that raises the clientPIN minimum to **6** code points (from
  CTAP's default 4) and refuses trivially guessable PINs — a single repeated digit, or
  a ±1 run like `123456` / `654321` — on both the host `setPIN`/`changePIN` path and the
  trusted-display PIN pad. Off by default; the default build is unchanged. `fips-profile`
  now bundles this same PIN policy. Motivated by the RP2350 BOOTSEL flash snapshot/restore
  that rolls back the wrong-PIN counter ([#37](https://github.com/TheMaxMur/RS-Key/issues/37)):
  with the retry ceiling removed, PIN entropy is the practical brute-force bound. See
  [docs/build.md](docs/build.md) and [docs/threat-model.md](docs/threat-model.md).
- **`LED_POWER_PIN` build knob — support boards whose LED is power-gated.** A new
  compile-time env knob names an optional GPIO the firmware drives **high at boot**
  to power a gated LED rail, then holds for the device's lifetime. This is what the
  **Seeed Studio XIAO RP2350** needs: its onboard WS2812 data is on GP22 but its
  power sits behind GP23, so the LED stayed dark ([#36](https://github.com/TheMaxMur/RS-Key/issues/36)).
  Build it `LED_PIN=22 LED_ORDER=grb LED_POWER_PIN=23`. Off by default; the pin
  must differ from `LED_PIN` and a GPIO `PRESENCE_PIN` (rejected at compile time).
  See [docs/hardware.md](docs/hardware.md) and [docs/build.md](docs/build.md).
- **`USR_LED_PIN` build knob — park a nuisance onboard LED off at boot.** A new
  compile-time env knob names an optional GPIO wired to an onboard user/status LED
  that comes up lit; the firmware drives it to the LED's **off** level at boot and
  holds it. This is the **Seeed Studio XIAO RP2350**'s active-low USR LED on GP25,
  which the board's weak pull-down otherwise keeps on ([#36](https://github.com/TheMaxMur/RS-Key/issues/36)).
  Build it `USR_LED_PIN=25` (add `USR_LED_ACTIVE_HIGH=1` for an active-high LED).
  Off by default and independent of the addressable LED, so it also works on a
  `LED_KIND=none` build; the pin must differ from `LED_PIN`, `LED_POWER_PIN`, a GPIO
  `PRESENCE_PIN`, and the display `WAKE_PIN` (rejected at compile time). See
  [docs/hardware.md](docs/hardware.md) and [docs/build.md](docs/build.md).
- **`KVMAIN` build knob — fit the firmware on a 2 MB flash.** The KV main partition
  size is now a compile-time knob (default 1408K, the checked-in layout). A **2 MB**
  board (Seeed XIAO RP2350, Waveshare RP2350-Zero-CM) can't fit the ~900K image under
  the default KV store, so shrink it: `FLASH_SIZE=2M KVMAIN=896K` (896K creds + 128K
  counters + 1024K code) ([#36](https://github.com/TheMaxMur/RS-Key/issues/36)). build.rs
  bakes the size into both `memory.x` and `flash_storage.rs` so the two partitions
  never drift, and rejects a split that leaves under 1 MB for code with a fix hint.
  A fully provisioned key needs only a few hundred KB. See [docs/build.md](docs/build.md).

### Changed

- **Faster `authenticatorCredentialManagement` enumeration with many distinct RPs.**
  `enumerateCredentials` re-read every resident-credential slot on each per-RP call,
  so listing a store of *N* credentials spread over *N* distinct RPs was O(N²) flash
  reads — on hardware a 256-passkey / 256-RP store took ~13 s (a store of the same
  256 passkeys under one RP took ~1.3 s). The applet now builds a small in-RAM
  slot→rpId-hash-prefix index once per enumeration (invalidated by a new `Fs`
  mutation counter, so any add/delete rebuilds it) and reads flash only for the
  target RP, making the walk O(N). Enumeration results and order are unchanged; a
  4-byte prefix hit is still confirmed by the full rpId-hash compare. bcdDevice bump
  only (no wire change).

### Fixed

- **Post-quantum ML-DSA-65 `makeCredential` no longer hard-faults the device.**
  Requesting an ML-DSA-65 (COSE alg `-49`) credential wedged the FIDO worker on the
  RP2350: the compute worker ran nested under `main`'s ~95 KiB one-time init stack
  frame (it was `await`ed at the tail of `#[embassy_executor::main]`), which left
  ML-DSA-65's ~92 KiB keygen chain flush against the shared main-stack ceiling — the
  next USB/keepalive interrupt overran it into the heap and halted the core. (ML-DSA-44
  fit with ~27 KiB to spare and was unaffected, which is why only the larger parameter
  set failed.) The worker now runs as its own thread-executor task, so `main` returns
  and that init frame is reclaimed, restoring ~90 KiB of headroom. Firmware-only; no
  wire-format or at-rest change. Latent in shipped builds (ML-DSA is not advertised
  without `advertise-pqc`, so no platform requested it).
- **`always-uv` and `strict-up` built together no longer break `ssh-sk`.** With both
  features on, `ssh -i` failed with "device not found": the platform's silent
  `up:false` pre-flight (credential discovery) was refused with `CTAP2_ERR_PUAT_REQUIRED`
  because the alwaysUv gate keyed on the `strict-up`-forced presence flag rather than the
  request's raw `up` option. It now keys on `up` (CTAP 2.1 §6.2.2 step 5), so the probe is
  exempt from the PUAT refusal regardless of `strict-up`. `strict-up` still polls the
  button on the probe (its deliberate two-touch behavior); only the spurious refusal is
  gone. Reported for v0.3.7 ([#34](https://github.com/TheMaxMur/RS-Key/issues/34)).
- **`strict-up` no longer weakens `alwaysUv` for the `up:false` pre-flight.** On a
  `strict-up` build with alwaysUv enabled, the silent `up:false` discovery probe was
  returned as a *usable* assertion with the user-presence (UP) flag **set** — because
  `strict-up` forces the button poll and the emitted UP flag followed that poll rather
  than the request's `up` option. A relying party that does not require user verification
  would accept it, so a stolen key could authenticate without the PIN, defeating the
  alwaysUv guarantee (a plain `always-uv` build was unaffected — it returns the probe with
  UP clear). The emitted UP flag now follows the request's raw `up`, so the probe stays
  inert (UP=0) even while `strict-up` still polls the button, and `ssh-sk` keeps working
  (the platform discards the pre-flight regardless). No shipped flavor enabled this by
  default (`firmware-strict-up` ships with alwaysUv off); found by an internal security
  review — a follow-up to the [#34](https://github.com/TheMaxMur/RS-Key/issues/34) fix above.
- **PIV stays detectable by OpenSC after the OpenPGP applet has been used.** The
  PIV `SELECT` application property template placed the NIST RID directly under
  tag `79` instead of the required nested `4F`. OpenSC's `piv_match_card` then
  failed to re-detect PIV whenever another applet was selected first (e.g. by
  `gpg`/`scdaemon`), so `p11tool` / Chrome mTLS saw only OpenPGP until a
  `ykman piv info` forced PIV back — a real YubiKey re-detects PIV fine. The
  template now matches NIST SP 800-73-4 (and a YubiKey's response) for tags
  `4F` / `79`.
- **OpenPGP RSA key import can no longer halt the device on a zero-valued prime.**
  A `PUT DATA` key import (admin/PW3) whose `P` or `Q` prime MPI was present but
  numerically zero (a non-empty `00` that the applet's `is_empty()` check let
  through) reached `RsaPrivateKey::from_p_q`, where computing `(p-1)(q-1)`
  underflowed num-bigint's unsigned subtraction and panicked. Under `panic-halt`
  that wedged the authenticator until replug. `rsa_from_pqe` now rejects a
  degenerate prime as a bad key (`EXEC_ERROR`). Found by the new `openpgp_key_load`
  fuzz target.
- **The TUI cockpit can no longer be hung by a counterfeit device.** `rsk-tui`'s CCID
  `get_data_full` chained `61xx` GET RESPONSE with no bound, so a device that answered
  every GET RESPONSE with a bare `61 00` spun the synchronous event loop forever (and a
  data-carrying variant grew memory without limit) — reached unauthenticated on startup
  and on every 5 s refresh. The chaining is now bounded by a round and byte cap.
  Host-tool only (`tools/tui` → 0.3.1); found by an internal security review.

## [0.3.7] - 2026-07-17

### Added

- **`rsk-tui` cockpit — richer applet reads, a passkey count, LED preview, and
  scrollable output (`0.3.0`).** Four host-only additions, no firmware change:
  the FIDO section can **count resident passkeys** over credMgmt
  `getCredsMetadata` (PIN-gated — the count needs the FIDO2 PIN, but not the
  enumeration); OpenPGP and PIV surface real metadata pulled in the same gather —
  OpenPGP parses its `6E` DO (card serial, PW1/RC/PW3 retry counters, populated
  key slots) and PIV reads the PIN GET METADATA (retries + default-PIN flag); the
  LED section paints a live colour swatch per state; and long **message modals**
  (audit journal, verify report) now scroll (arrows / `PgUp` / `PgDn` / `Home` /
  `End`). The new fields also appear in `rsk-tui --once` / `--json`. See
  [docs/guides/tui.md](docs/guides/tui.md).
- **Differential interop harness — diff RS-Key against a real YubiKey.** New
  `tests/interop/{capture,diff,divergences,normalize,parity}.py`: capture a
  read-only snapshot of each key (both can stay plugged; an identity guard keys
  off the `RSK` marker and the FIDO AAGUID), then classify every field against a
  known-divergence allow-list so a fidelity gap stands out from the ~160 fields
  that legitimately differ. Host-testable engine (`python -m pytest
  tests/interop/test_diff.py`). A first macOS run against a YubiKey 5C NFC found
  85 identical / 76 expected-divergence / 1 unexpected field (see
  [docs/interop.md](docs/interop.md) → "Differential against a real YubiKey").

### Changed

- **Faster PIV SELECT — skip the redundant default-file scan after the first.**
  `scan_files` provisions the PIV defaults (PIN/PUK/retry/management/attestation)
  on the first SELECT and re-probed all five on every subsequent SELECT. Those
  files only ever go away by a path that recreates them (PIV reset) or reboots
  (trusted-display factory wipe), and `authenticatorReset` leaves them, so a RAM
  guard now runs the scan once per power-cycle and the wire response (the APT) is
  byte-identical. Shaves the five flash probes off every re-SELECT (`ykman`,
  OpenSC, `age-plugin-yubikey`, PIV sign).
- **Faster SHA-512 on the Cortex-M33 (the FIDO key-derivation ratchet).** SHA-512
  and SHA-384 now come from a new `rsk-sha512` crate instead of the `sha2`
  soft backend, leaving every digest **byte-for-byte unchanged** — the compression
  function is the only thing swapped, so `hmac`/`hkdf` compose over it identically
  and no stored credential key changes. On-device profiling had found the FIDO
  getAssertion ratchet (8× HKDF-SHA512, ~96 SHA-512 blocks) dominating every
  assertion at ~191 ms of ~241 ms: `sha2` fully unrolls SHA-512 into a ~28 KB
  straight-line body that overflows the RP2350 XIP cache and re-fetches over QSPI
  flash on every block. The replacement compiles to an ~866-byte rolled loop that
  fits the cache. Output identity is gated on the host by a randomized differential
  against `sha2`/`hmac`/`hkdf` plus NIST/RFC 4231 KATs; SHA-256/SHA-1 stay on
  `sha2` (already fast on the M33) and Ed25519 (dalek) is unaffected.
  `bcdDevice` → `0x0820`.

- **Faster P-256 ECDSA signing (fixed-base comb + no wasted public-key derivation).**
  Two changes to the P-256 credential path, both leaving the RFC 6979 deterministic
  signature **byte-for-byte unchanged** (a KAT test pins the result to the `p256`
  crate's output), so this is a pure speedup with no wire or behaviour change:
  (1) the ephemeral `k·G` now uses a precomputed width-4 Lim–Lee comb table — the
  fixed-base technique already used for P-521 — instead of the crate's generic
  `mul_by_generator`; (2) a P-256 credential key is held as the bare scalar (like
  P-521), so getAssertion no longer builds a `SigningKey` that eagerly derives the
  public key `d·G` — a second fixed-base mul it never uses when only signing (the
  public key it does need, at makeCredential, comes from the same comb). Measured on
  the RP2350: a silent `up:false` P-256 assertion drops from ~303 ms to ~241 ms
  (about 20 % — the removed `d·G` was ~40 ms, the comb ~22 ms). Costs ~1 KB of flash
  for the table (`build.rs`-generated). P-384 / secp256k1 / P-521 are unchanged
  (P-521 keeps its comb + random nonce). `bcdDevice` → `0x081F`.

- **FIDO2 signature counters are now per-credential (privacy).** Each resident
  credential (passkey) keeps its own counter in a new packed `EF_CRED_CTR` flash
  file, starting at 0 and advancing only on its own assertions — colluding relying
  parties can no longer read a shared global counter to correlate how much the key
  is used across sites (WebAuthn §6.1.1). Non-resident (second-factor) credentials
  keep no device state and report signCount 0; legacy U2F keeps its global monotonic
  counter. Migration is forward-safe for passkeys: a credential created before
  `EF_CRED_CTR` seeds its counter from the frozen global value on first use, so the
  reported count never decreases. A pre-existing non-resident credential now reports
  0, which a site that strictly enforced counter monotonicity may treat as reason to
  re-register. Found by the RS-Key ↔ YubiKey differential harness (finding #4:
  RS-Key's shared counter at ~105 vs a real YubiKey's per-credential counter).
  `bcdDevice` → `0x081D`.

- **getInfo no longer advertises `U2F_V2` while `alwaysUv` is on.** CTAP 2.1 §7.2.4
  disables the CTAP1/U2F interface whenever alwaysUv is enabled (via the `always-uv`
  build feature or the runtime `toggleAlwaysUv`), and the `versions` list now drops
  `U2F_V2` to match — a platform is no longer told CTAP1 is available while every U2F
  request is refused. The CTAP2 versions and the default (alwaysUv-off) advertisement
  are unchanged.

### Fixed

- **`alwaysUv` no longer breaks the silent credential-discovery pre-flight (fixes
  `ssh -i` "device not found" on an `always-uv` build).** `getAssertion` rejected
  every request without a `pinUvAuthParam` under `alwaysUv` with
  `CTAP2_ERR_PUAT_REQUIRED` — including the platform's silent `up:false` probe that
  OpenSSH's `ssh-sk` middleware (and WebAuthn platforms) use to locate which
  credential/device to sign with. CTAP 2.1 §6.2.2 step 5 guards that error on the
  `up` option being *present and true*, so the silent probe must be exempt (it
  returns a silent assertion or `NO_CREDENTIALS`); a real YubiKey and pico-fido do
  exactly that. The `alwaysUv` gate now keys on `want_up` (honoring `up:false`,
  and — under the `strict-up` build — still demanding UV on every call), so a
  silent pre-flight succeeds while an interactive `up:true` request without UV is
  still refused. The real assertion then correctly prompts for the PIN each use
  (`alwaysUv` as designed). `makeCredential` is unchanged: registration can't be
  silent (§6.1.2 has no `up` guard). Reported in
  [#34](https://github.com/TheMaxMur/RS-Key/issues/34). `bcdDevice` → `0x0823`.

- **`EF_CRED_CTR` per-credential counter now churns the counter partition, not the
  secret one.** The per-credential signature counter file (`0xC001`) is rewritten on
  every getAssertion, but `is_counter_fid` routed only the global `EF_COUNTER`
  (`0xC000`) to the dedicated counter partition, so the new file appended to the
  **main** partition — the one holding sealed credentials and keys, which the
  two-partition split deliberately keeps off the per-operation hot path to avoid a
  multi-second cold-migration stall during authentication. Adding `0xC001` to the
  predicate restores that isolation. Internal routing only (no wire, key, or
  signCount change), and fixed before the per-credential counter shipped, so no
  provisioned device re-seeds. `bcdDevice` → `0x0821`.

- **`rsk-tui` starts in the Linux dev shell again.** The dev-shell launcher is a
  bare `cargo run` of `tools/tui`, whose binary carries no nix RPATH, so its
  `DT_NEEDED` `libudev.so.1` / `libpcsclite.so.1` were only satisfied at build
  time (pkg-config) and missing at run time — `error while loading shared
  libraries: libudev.so.1`. The shell now also exports `systemd` (libudev) and
  `pcsclite` on `LD_LIBRARY_PATH` on Linux. Host-only; `nix run .#rsk-tui` was
  unaffected. Reported in [#31](https://github.com/TheMaxMur/RS-Key/issues/31).

- **READ CONFIG now clamps `USB_ENABLED` to the supported capabilities.** The
  management DeviceInfo (`0x1D`) echoed a host-written `EF_DEV_CONF` blob verbatim,
  so a persisted enabled-applications mask wider than `SUPPORTED_CAPS` (e.g. a newer
  `ykman` that knows capability bits this firmware lacks) was reported as-is —
  `enabled ⊄ supported`, which a real YubiKey never does. `config_tlv` now masks the
  `USB_ENABLED` TLV down to `SUPPORTED_CAPS` on read, healing already-persisted
  devices without a rewrite. Found by the new RS-Key ↔ YubiKey differential harness
  (`enabled = 0x3A3B` vs `supported = 0x023B` on a live board). `bcdDevice` → `0x081C`.

## [0.3.6] — 2026-07-16

### Added

- **`always-uv` build feature — ship with CTAP 2.1 `alwaysUv` on by default.** A new
  opt-in cargo feature (`cargo build --release -p firmware --features always-uv`) bakes
  the `alwaysUv` option on, so the key demands user verification for every
  makeCredential / getAssertion out of the box — no post-flash `ykman fido config
  toggle-always-uv`. OFF by default; the shipped image is unchanged (its alwaysUv still
  starts off until a platform toggles it). The stored state is now tri-state — an
  explicit `toggleAlwaysUv` override (`EF_ALWAYS_UV` = `[1]`/`[0]`, survives reboots,
  cleared by `authenticatorReset`) over the compile-time default — so the feature build
  stays fully runtime-toggleable and a reset returns alwaysUv to the compiled default.
  On a normal build the on/off representation is the same `[1]`/absent pair as before
  (no on-flash change). With alwaysUv on and no PIN set, FIDO operations return
  `CTAP2_ERR_PUAT_REQUIRED` until a PIN is configured — the standard cue for the platform
  (Windows, Chrome) to prompt for one. Whenever alwaysUv is on (via this default or a
  runtime `toggleAlwaysUv`) the **CTAP1/U2F interface is now disabled** (CTAP 2.1 §7.2.4):
  U2F only proves presence, so leaving it live would bypass the always-require-UV
  guarantee — register / authenticate return `CONDITIONS_NOT_SATISFIED`, matching a
  YubiKey. WebAuthn / CTAP2 is unaffected. bcdDevice → `0x081A`. See docs/build.md.

### Changed

- **`sequential-storage` 7.2.0 → 8.0.0.** The flash key/value backend's cache API was
  restructured upstream into a single composite `Cache` of three sub-caches (page
  states + page pointers + key pointers); `flash_storage.rs` and the fuzz harnesses
  are migrated to it. The release is on-flash-compatible with 7.x, so a provisioned
  device upgrades with no migration. The crate is vendored under
  `third_party/sequential-storage/` and wired via `[patch.crates-io]` because it
  carries one local change (below) that has no public API; the single-function diff is
  kept in `third_party/sequential-storage.patch`.
- **Higher, decoupled credential/key capacity.** All applets shared one 256-entry
  dynamic-file budget, so filling PIV key slots shrank the passkey ceiling — a HW
  stress test hit `KEY_STORE_FULL` at ~80 passkeys (not the logical 256) once ~48 PIV
  files were provisioned, and `remainingDiscoverableCredentials` over-reported the
  free slots. The shared budget (`MAX_DYNAMIC_FILES`) is raised 256 → 1280 to exceed
  the union of every applet's own cap, and the storage key-pointer cache
  (`MAIN_CACHE_KEYS`) is raised 512 → 1280 in lockstep so the freed capacity stays on
  the O(1) read/migrate path instead of falling off the flash-scan cliff. getInfo
  `remainingDiscoverableCredentials` (0x14) and credMgmt `getCredsMetadata` (0x02) now
  report an honest estimate clamped by the true free shared-file budget, so the host
  is no longer promised slots the store can't back. RAM cost ~8 KiB; no on-flash
  format change (the indexes are rebuilt from flash on boot, so provisioned devices
  upgrade transparently). bcdDevice → `0x0811`.

### Fixed

- **Run-20 audit hardening (no exploitable defect; defense-in-depth on the perf delta
  above).** Three follow-ups from the security review:
  - The boot cache-warm no longer trusts a partial walk after a flash *read* fault. The
    vendored `sequential-storage` page-advance loop swallowed a page-state error and
    still cleared the "dirty" flag at the walk's end, so a read fault that skipped a
    live page could leave a stale key→address entry marked clean. It now skips only an
    interrupted-erase page (always a fully-migrated source, so enumeration stays
    complete) and aborts the walk on any other error, leaving the cache dirty for the
    existing `is_dirty` guard to discard. No observable change on RP2350 (in-range flash
    reads don't fault); the update is in `third_party/sequential-storage.patch`, and the
    vendored tree is verified byte-identical to published 8.0.0 apart from that one file.
  - `MAIN_CACHE_KEYS` is raised 1280 → 1281 (`MAX_DYNAMIC_FILES + 1`) so the one live
    main-partition key the dynamic-file budget does not count (`EF_META`) can never fall
    off the key-pointer cache on a fully-provisioned device.
  - PIV MOVE to the `0xFF` delete sentinel no longer writes an unread `0xD4FF` orphan
    public-point file: the per-slot pubkey carry is skipped when there is no destination
    slot (the source slot's cache is still dropped).
  No wire or on-flash change. bcdDevice → `0x0819`.
- **The first credential enumeration after a power-cycle is no longer slow: the boot
  scan warms the flash key-pointer cache it was already reading.** `sequential-storage`
  keeps a RAM cache mapping each key to its flash address so a read is O(1); it starts
  empty after every boot, so the first `fetch_item` of each key did a cold backward
  ring-scan — listing 256 passkeys right after plug-in measured ~9 s (vs ~2.6 s warm).
  The boot `scan` already walks the whole store once (via `fetch_all_items`) but threw
  the addresses away. The vendored `sequential-storage` (see Changed) now seeds the
  key-pointer cache from that existing walk, so the cache is warm before USB even
  enumerates and the first list is as fast as a warm one — no extra flash reads. The
  warm is completion-gated: the cache is held "dirty" during the walk and cleared only
  when the iterator runs to the end, so a walk that errors partway self-invalidates via
  the existing dirty guard rather than caching a stale pointer (power-cut-safe — the
  cache is RAM-only, rebuilt each boot). Adds ~30–120 ms of pre-USB boot bookkeeping at
  a full store. Measured on a 100-passkey device: first list after a power-cycle
  3044 ms → 1023 ms (the slowest single-cred read 2044 ms → 23 ms), now identical to a
  warm list. bcdDevice → `0x0818`.
- **OATH LIST / CALCULATE ALL are faster on a full store: the occupied-slot map is
  read from the in-RAM present index instead of scanning flash.** Enumerating
  accounts sorted the live OATH slots with a whole-partition `for_each_key` walk on
  every LIST (`0xA1`) and CALCULATE ALL (`0xA4`) — and PUT re-paid it to find a free
  slot — so a busy store (a parity fill measured `ykman oath accounts list` ~1.6×
  slower than a hardware YubiKey) spent tens of ms per call on the scan. `Fs` already
  keeps an authoritative in-RAM present index (seeded at boot by `scan`, kept live by
  every put/delete), so the slot gather (`present_creds`) and free-slot search now
  read occupancy from it in O(255) bit tests with no flash access — the same fix
  applied to FIDO `slot_map` and PIV. Occupancy-equivalent to the old `for_each_key`
  pass (same torn-migration semantics) and ascending by construction, so LIST /
  CALCULATE ALL output — including its `61xx` paging — is byte-identical. No wire or
  on-flash change. bcdDevice → `0x0817`.
- **PIV GET METADATA is fast at any slot count: each slot's public point is cached
  in its own flash file instead of a shared, capacity-bound record.** The earlier
  cache packed every EC slot's point into one EF_META blob (≤768 B for points), so
  past ~10 populated EC slots the rest kept only a bare head and GET METADATA
  recomputed the software point (`d·G`, ~30 ms) on every read — `ykman piv info` over
  24 slots measured ~1.0 s (~3× a hardware YubiKey), ~400 ms of it that d·G. Each
  slot now caches its point in a private per-slot file (`0xD4xx`, unsealed — the
  point is public) written at key generate/import and read O(1) by GET METADATA at
  any slot count; a slot without one (pre-upgrade, or a failed import derive) falls
  back to the old EF_META cache, then to deriving the point, so provisioned devices
  upgrade transparently. The redundant per-slot `has_key` probe GET METADATA did on
  top of the existing `meta_find` gate is dropped. No wire change; GET METADATA
  output is byte-identical. bcdDevice → `0x0816`.
- **credMgmt enumeration and makeCredential are much faster on a full store: the
  occupied-slot map is read from the in-RAM present index instead of scanning
  flash.** `slot_map` — run on every getCredsMetadata / enumerateRPs /
  enumerateCredentials / getNext and on every makeCredential (dedup + free-slot) —
  walked the whole flash partition each call (~84 ms on a 256-passkey device), so
  listing every credential paid it ~289 times (~24 s of a measured ~34 s walk) and
  each registration re-paid it (~336 → 480 ms as the store filled). `Fs` already
  keeps an authoritative in-RAM present index (seeded at boot by `scan`, kept live
  by every put/delete), so `slot_map` now reads occupancy from it in sub-ms with no
  flash scan and no new state — occupancy-equivalent to the old `for_each_key` pass
  (same torn-migration under-count semantics). The FIDO HID poll interval is also
  tightened 5 ms → 1 ms so a multi-frame enumerate/assertion response drains faster.
  No wire or on-flash change. bcdDevice → `0x0814`.
- **credMgmt enumeration is O(n), not O(n²): getNextRP / getNextCredential resume
  from a slot cursor instead of re-scanning from slot 0.** With the per-call flash
  scan removed (above), the remaining full-walk cost was each getNext re-reading the
  store from the first slot to the N-th match — quadratic in the credential count.
  `CredMgmtState` now carries a per-enumeration slot cursor (separate cursors for the
  RP and credential walks, each reset by its Begin and advanced by each getNext), so a
  getNext reads only the gap to the next match. On a full 256-passkey device the warm
  per-credential enumeration cost flattens (~10 ms, matching a hardware YubiKey)
  instead of climbing with slot position. No wire change; enumerate output is
  byte-identical. bcdDevice → `0x0815`.
- **OATH LIST / CALCULATE ALL now page through a full store instead of silently
  truncating.** A device holding many accounts (up to the 255 the applet stores)
  built each enumeration response into a single ~2 KiB CCID frame and stopped when
  it filled, returning `9000` — so `ykman oath accounts list` / Yubico
  Authenticator saw only the ~135 (LIST) / ~94 (CALCULATE ALL) that fit, and the
  rest were invisible even though stored and individually usable (HW-found on a
  255-account fill). LIST (`0xA1`) and CALCULATE ALL (`0xA4`) now implement the
  YubiKey-OATH `61xx` + SEND REMAINING (`0xA5`) chaining they had stubbed out: when
  a frame fills they return `61 00` and resume the sorted-credential sweep on the
  next `0xA5`, so every account surfaces. ykman / Yubico Authenticator already speak
  this and need no change; a host that ignores `0xA5` still gets the first frame
  exactly as before (no regression). bcdDevice → `0x0813`.
- **getAssertion no longer wedges the device after the capacity bump.** The
  credential-key builder (`CredKey::from_raw`) and signer (`CredKey::sign`) folded
  the lattice (ML-DSA) key-expansion / streaming-sign frames — ~106 KiB and ~50 KiB —
  into their own stack frames, so **every** assertion, including a P-256 one that
  never touches ML-DSA, reserved that ~106 KiB on the worker stack. With the capacity
  bump's extra ~16 KiB of static RAM shrinking that stack, a getAssertion overflowed
  it into the adjacent USB/IRQ wakers and hung the device hard (still USB-enumerated
  but unresponsive on HID and CCID, recoverable only by replug). The ML-DSA build/sign
  arms are moved behind `#[inline(never)]` helpers so their large frames stay off the
  EC path; a P-256 getAssertion's builder/signer frames are now negligible.
  HW-verified on the full capacity build. bcdDevice → `0x0812`.
- **PIV GET METADATA is faster: a key slot's public point is now cached in its
  metadata record** instead of being recomputed on every probe. `ykman piv info`
  and the Yubico Authenticator read `GET METADATA` (INS 0xF7) for every slot, and
  for a populated EC slot that recomputed the public key (`d·G`, ~tens of ms in
  software) every time. Key generation and import already derive that point, so
  the slot's metadata record now carries it (appended after `[algo, pin policy,
  touch policy, origin]`) and GET METADATA emits it directly. RSA slots are
  unchanged (their modulus rebuild is cheap). Keys generated by earlier firmware
  keep working and derive the point on the fly (the bare record has no trailer).
  The cached point is **best-effort**: the shared `EF_META` store reserves room for
  every slot's essential 4-byte head, so when it is near full (many populated EC
  slots) a new key stores just the head and GET METADATA derives its point on the
  fly — provisioning never fails or leaves a key without metadata because of the
  cache, and `EF_META` stays bounded regardless of how many slots are used.
  bcdDevice → `0x0810`.
- **Passkey enumeration is much faster: the credential's public key is now cached
  in its resident record** instead of being recomputed on every
  `authenticatorCredentialManagement` enumerate call. On this MCU a software
  P-256 public-key derivation (`d·G`) costs ~150–250 ms, so listing passkeys — as
  the Yubico Authenticator "Passkeys" tab does — spent that per credential every
  time (a measured ~1.2 s for four passkeys). makeCredential already computes the
  point for authData, so the record now carries it (a length-prefixed trailer on
  a new **v3** resident record) and enumeration emits it directly, dropping the
  per-credential cost to a flash read. The one-time clientPIN unlock (an ECDH, not
  cacheable) is unchanged. Records already on a device (v1/v2) keep deriving on
  the fly and stay byte-for-byte compatible; passkeys created by this firmware get
  the cache. EC curves (P-256/384/521, secp256k1, Ed25519) are cached; the lattice
  schemes derive as before (their public keys exceed the record). bcdDevice → `0x080E`.

## [0.3.5] — 2026-07-14

### Changed

- **`makeCredential` now ships `fmt:"none"` attestation by default**, fixing
  `ssh-keygen -t ed25519-sk` enrollment on Windows / OpenSSH 10.0p2 (issue #26).
  RS-Key previously returned packed **self**-attestation, so an Ed25519 credential
  carried an Ed25519 self-attestation signature. libfido2's
  `fido_cred_verify_self` rejected it with `FIDO_ERR_INVALID_SIG` on the reporter's
  Windows box, so the enroll aborted with "Key enrollment failed: invalid format"
  (ES256 self-att verified fine on the same path, so `ecdsa-sk` worked; a genuine
  YubiKey uses basic ES256 x5c attestation and never reaches that verify). Self-attestation conveys no trust beyond
  "none" (WebAuthn §6.5.2), so shipping "none" loses nothing and is more private.
  An explicitly-requested **enterprise** attestation still emits its full x5c
  statement, and the `fido-conformance` profile keeps packed self-attestation (its
  MakeCredential tests cryptographically verify it). `getInfo.attestationFormats`
  is now `["none","packed"]`. Firmware `bcdDevice` `0x080C` → `0x080D`.

### Fixed

- **A wrong PIN in `rsk fido set-pin` / `list-passkeys` now prints a clean error,
  not a Python traceback.** python-fido2 raises `CtapError` when the device
  rejects a clientPIN operation; `change_pin`, `set_pin` and `get_pin_token` left
  it uncaught, so mistyping the current PIN while changing it dumped a stack trace
  instead of "wrong PIN". These now map the CTAP 2.1 §6.5.5 status to an operator
  message — a wrong PIN reports how many attempts remain before it blocks, and the
  blocked / auth-blocked / policy statuses get actionable text — via a shared
  `common.die_ctap_pin_error`. `rsk` `0.3.10` → `0.3.11`; host-only, no firmware
  change.
- **`rsk` now finds the FIDO HID on Linux hosts where hidapi doesn't report a
  usage page (issue #28).** `ctaphid.find()` matched a device solely by its HID
  `usage_page == 0xF1D0`, but some Linux `hidapi` builds (the libusb backend, and
  older hidraw) enumerate the device with `usage_page` left `0`, so `rsk status`
  (and every command behind it) reported `FIDO HID : not found` even with the key
  plugged in. It now keeps the `usage_page` fast path and, when that field is
  unset, confirms the FIDO usage page straight from each device's report
  descriptor — VID/PID-agnostic, so it works for every build (the default
  `0x1209:0x0001` identity and each `VIDPID` preset), unlike hard-coding a single
  vendor's VID/PID. `rsk` `0.3.9` → `0.3.10`; host-only, no firmware change.
- **New passkey registration no longer hangs on the touch after a PIN is set.**
  A zero-length `pinUvAuthParam` is the CTAP 2.1 §6.1.2 / §6.2.2 step-1 selection
  probe: the authenticator takes a device-selection touch and then reports the PIN
  state through the returned error. With a PIN configured it must return
  `CTAP2_ERR_PIN_INVALID` (0x31) — the code a platform managing device selection
  (Chrome) reads to advance from that touch to PIN entry. `makeCredential` and
  `getAssertion` returned `CTAP2_ERR_PIN_AUTH_INVALID` (0x33) instead, so once a
  PIN was set a fresh registration showed "press the button" and the press never
  advanced (the no-PIN `PIN_NOT_SET` code was already correct, which is why
  registering *before* setting a PIN worked). Both now return `PIN_INVALID`.
  Firmware `bcdDevice` `0x080B` → `0x080C`.

### Security

- **A counterfeit FIDO device can no longer inject terminal escapes through the
  clientPIN retry count.** The wrong-PIN message added above reads the remaining
  attempts from python-fido2's `get_pin_retries()`, which returns the device's
  CBOR-encoded value without type-checking it. A hostile authenticator could
  return that field as a text string of ANSI/OSC/bidi escapes instead of an
  integer, and `pin_error_message` embedded it into the `error:` line that `die()`
  prints to the terminal **without** the CLI's `sanitize()` filter — an operator
  running `rsk fido set-pin`/`list-passkeys` with a wrong PIN against the device
  would get those escapes interpreted (window-title spoof, OSC-52 clipboard write,
  Trojan-Source bidi). The retry count is now embedded only when it is really an
  `int`; anything else falls back to a plain `wrong PIN`. LOW (needs a malicious
  device + a wrong-PIN attempt); same class as the run-11/12 host-tooling escapes.
  Found by security-audit run-18. `rsk` `0.3.11` → `0.3.12`; host-only, no firmware
  change.

## [0.3.4] — 2026-07-12

### Fixed

- **OpenPGP decrypt no longer breaks after a `VERIFY` of both PW1 modes (issue
  #25).** `gpg`/`scdaemon` verifies one PIN entry into both PW1 modes
  back-to-back — mode `82` (DECIPHER/INTERNAL AUTH) then mode `81` (signing) —
  before a decrypt. `check_pin` cleared **both** PW1 latches on every successful
  verify and re-raised only the current one, so the trailing mode-`81` verify
  silently dropped the mode-`82` authorization the next `PSO:DECIPHER` needs,
  which then returned `6982` and surfaced to the user as `Bad PIN` with the
  correct PIN (typically after a replug, once `scdaemon` re-ran the full verify
  sequence). PW1.81, PW1.82 and PW3 are now treated as the independent access
  latches the card spec requires — a successful `VERIFY` raises only its own.
  Session-only state; no wire or on-flash format change. Firmware `bcdDevice`
  → `0x0809`.
- **A `put` past the dynamic-file cap no longer strands its value on flash.** A
  new runtime file (e.g. a resident credential) written once the dynamic set is
  full committed its bytes to flash *before* the cap check rejected it, so the
  caller saw `NoMemory` while the value stayed on flash — readable yet
  unregistered, and re-dropped by every reboot rescan at the same cap. The cap
  is now enforced before the write, so an over-cap `put` fails atomically and
  leaves no trace. Latent (it needs 256 dynamic files to trigger); no wire or
  on-flash format change. Firmware `bcdDevice` → `0x07FD`.
- **OpenPGP `PUT DATA` for the PW-status DO (`C4`) can no longer overwrite the
  PIN retry counters.** `put_pw_status` capped the copy at the full 7-byte
  record, so a ≥5-byte field wrote host bytes over the live PW1/RC/PW3 retry
  counters — its own doc comment says they are preserved; they were not. A host
  (malicious or a buggy 7-byte read-modify-write) could zero them and block
  every PIN across a power cycle, recoverable only by a key-destroying
  `TERMINATE DF`. The copy is now capped at the writable prefix (flag + the
  three max-length bytes); the retry counters are read-only. PW3-gated, so no
  privilege change. Firmware `bcdDevice` → `0x07FE`.
- **PIV `MOVE KEY` onto a key's own slot (`p1 == p2`) no longer destroys it.**
  A self-move wrote the sealed key/cert/metadata back into the slot and then
  unconditionally deleted the *source* — the same slot — leaving it empty while
  returning `0x9000`, silently erasing the (possibly only) key. Same-slot moves
  are now rejected with `INCORRECT_P1P2` before any write, matching real
  hardware. Management-key-gated, so no privilege change. Firmware `bcdDevice`
  → `0x07FF`.
- **OpenPGP empty-data `VERIFY` in PW2 mode (`P2=0x82`) reports PW1's retries
  again.** The `EF_RC → EF_PW1` remap was gated on a non-empty data field, so a
  status query (`00 20 00 82 00`) probed the reset-code EF instead of the shared
  PW1 verifier — answering `6A88`, or a spurious `PIN_BLOCKED` when a reset code
  was configured and blocked. The remap now applies to the status query too.
  Firmware `bcdDevice` → `0x0800`.
- **FIDO `getAssertion` no longer over-reports `numberOfCredentials`.** With more
  than `MAX_ASSERTION_CREDS` (16) discoverable credentials for one RP, the count
  reported the full match total while the `getNextAssertion` queue caps at 16, so
  a platform was told to fetch more than the device could serve and hit a
  premature `NOT_ALLOWED`. The count is now clamped to the servable queue size.
  Firmware `bcdDevice` → `0x0801`.
- **FIDO `getAssertion` binds an unscoped `pinUvAuthToken` to the request rpId on
  first use (CTAP 2.1 §6.2.2).** A token minted without an rpId (legacy
  `getPinToken`, or `0x09` with `ga` permission and no rpId) was reusable across
  arbitrary RPs for its whole lifetime — `makeCredential` bound it but
  `getAssertion` did not. It now binds on first use, so a later cross-RP
  assertion fails `PinAuthInvalid`. Firmware `bcdDevice` → `0x0802`.
- **CCID `XfrBlock` responses can no longer be silently truncated.** The applet
  response buffer (`RESP_CAP`) was sized to the full 2048-byte CCID message
  rather than its 2038-byte payload budget (message − 10-byte header), so a large
  response (e.g. a long OATH `LIST`) overran one frame and `run_xfr` dropped the
  trailing bytes including the status word. The buffer now matches the frame
  payload budget. Firmware `bcdDevice` → `0x0803`.
- **RSA keygen ignores a stale core1 prime when it did not engage the second
  core.** When the core1 entry gate timed out (`engaged=false`), the search still
  drained core1's find slots, which could hold a prime from the *previous*
  (possibly different-size) keygen — combining it would yield a malformed modulus
  with a weak factor. The search now consumes core1's finds only when it actually
  engaged core1 this keygen; stale finds are scrubbed at wind-down. Astronomically
  rare, but a real undefended race. Firmware `bcdDevice` → `0x0804`.
- **LED breathing effect no longer flickers dark at its peak.** `effect_vapor`
  divided the falling ramp by `period/2` (floor) over `half+1` steps, so for an
  odd `speed` the brightness could exceed `peak` at the apex and wrap to a dark
  value through the `u8` cast. The value is clamped to `peak` before the cast.
  Firmware `bcdDevice` → `0x0805`.
- **`updateUserInformation` no longer breaks a passkey by rotating its keys.**
  Editing a resident credential's user name (CTAP2.1 `authenticatorCredential
  Management` 0x07) reseals the credential box with a fresh IV. The signing key,
  hmac-secret and largeBlobKey were all derived from that box, so they rotated on
  every update — the relying party's stored public key stopped verifying and the
  passkey was effectively bricked. New resident credentials now stamp a **v2
  version byte** into their 42-byte resident id (a reserved header byte, outside
  the id's HMAC chain) and derive those three keys from the **stable** id instead
  of the box, so they survive the reseal. The credential id itself was already
  preserved; this extends that stability to the keys. Forward-compatible: resident
  credentials from older firmware carry an implicit v1 marker and keep deriving
  from the box, so an already-provisioned device is unaffected. No box or
  on-flash format change. Firmware `bcdDevice` → `0x0806`.
- **PIV `SET PIN RETRIES` (INS `0xFA`) now requires the PIN, not just the
  management key.** The handler gated only on the management key, then reset the
  PIN and PUK to their public defaults ("123456" / "12345678"). Because the
  default management key is public and the `9B` slot is touch-`NEVER`, a host
  that authenticated it could reset an *unknown* cardholder PIN without knowing
  it — locking the legitimate user out, and (for a touch-`NEVER` key slot) using
  their PIN-protected keys after verifying the now-default PIN. It now demands
  the current PIN as well, matching YubiKey's `set-pin-retries`. Reachable only
  by an already-management-authenticated caller, so no new privilege for a
  legitimate admin. Firmware `bcdDevice` → `0x0807`.
- **FIDO vendor `AUDIT_READ` (`0x41 / 0x07`) now requires a touch on a device
  with no PIN.** With no clientPIN the PIN gate is a no-op, so any local process
  could export the tamper-evident journal, whose per-entry `detail` is a 64-bit
  `rpIdHash` prefix — short enough to dictionary-match back to the relying
  parties a no-PIN device had been used with (the entries are only weakly
  pseudonymous, not anonymous). A physical touch is now required in that case,
  matching the sibling `AUDIT_CHECKPOINT`; a PIN-backed device is unchanged.
  Privacy hardening — no key material is exposed. The `rsk` CLI (`0.3.9`) and TUI
  (`0.2.9`) clients now prompt for that touch and map its denial. Firmware
  `bcdDevice` → `0x0808`.

### Security

- **Dual-core RSA keygen rejects a wrong-size prime at the inter-core handoff.**
  `RsaKeygen::offer_le` — the byte-transport entry the core0 drain feeds core1's
  finds through — converted whatever length it was handed, so a stale prime from
  a prior different-size keygen would have corrupted the assembled modulus. The
  mailbox is scrubbed on engage and keygens are serialized on the worker, so this
  never fires today; the length check is a belt-and-suspenders backstop that fails
  a mismatched find closed even if a future refactor reopened the handoff window.
  Defense-in-depth (found in the run-16 audit); no wire or on-flash format change.
  Firmware `bcdDevice` → `0x080B`.
- **PIV `GENERAL AUTHENTICATE` rejects a key slot with a truncated metadata
  record.** The handler read the PIN- and touch-policy bytes without checking the
  meta record was at least the 3-byte `[algo, pin, touch]` header, unlike
  `info::read_slot`; a sub-header record would have read policy from the zero-fill
  and skipped the touch gate. Every metadata writer emits ≥ 3 bytes, so no slot
  can reach this state — the guard is a defense-in-depth backstop (found in the
  run-16 audit) matching the sibling reader. No wire or on-flash format change.
  Firmware `bcdDevice` → `0x080A`.

### Changed

- **`rsk` CLI and `rsk-tui` harden their handling of device-controlled data.** A
  counterfeit or malfunctioning USB device that returned non-string/absent
  getInfo fields (`versions`, `aaguid`, `clientPin`) or a malformed soft-lock
  state could crash `rsk status` / `rsk inventory list` / `rsk lock` with an
  uncaught `TypeError`, or inject ANSI/OSC/bidi escapes into the operator's
  terminal via unsanitized `clientPin`/lock-state strings; `rsk-tui --json` left
  DEL/C1/bidi bytes unescaped. All device-controlled display values now route
  through the shared sanitizer or a type-guarded join, bool-coerced where
  appropriate, and the TUI `--json` writer escapes every control and non-ASCII
  char. Host-only (`rsk` `0.3.8`, `rsk-tui` `0.2.8`); no firmware change.

## [0.3.3] — 2026-07-10

### Added

- **ML-DSA-65 (FIPS 204, COSE `-49`) FIDO credentials.** A second post-quantum
  signature set alongside ML-DSA-44, negotiable via `pubKeyCredParams` and — like
  -44 — advertised in getInfo only under the `advertise-pqc` build; under
  `PREFER_PQC` it outranks -44. It is backed by a new in-tree, stack-optimized
  ML-DSA implementation (`crates/rsk-mldsa`, `no_std`/no-alloc, no `unsafe`) that
  **streams the FIPS 204 matrix A** on the fly instead of materializing it, so
  keygen+signing fit the RP2350's ~222 KiB main stack (~84 KiB host floor) where
  the by-value `fips204` crate's -65 (~192 KiB) overflowed it — the reason -65
  was previously dropped. ML-DSA-44 signing runs on the same crate too, and the
  `fips204` dependency has been dropped from the tree entirely. The
  implementation is checked byte-for-byte against NIST ACVP KATs (both parameter
  sets) with Kani proofs over the reductions and rounding. ML-DSA-87 (`-50`)
  remains unsupported (its response overruns `maxMsgSize`). Firmware
  `bcdDevice` → `0x07FB`.

### Security

- **CHANGE REFERENCE DATA no longer half-writes the OpenPGP reset code, and
  CTAPHID drops short reads (audit run-14 hardening).** `INS 0x24` with
  `P2=0x82` (the resetting code) verified the current RC and rewrote its verifier
  *before* the command's own `P2` check rejected it, desyncing the RC verifier
  from the `EF_DEK_RC` seal it unlocks — a self-inflicted, admin-recoverable
  state (the caller already needs the current RC), now closed by rejecting the
  unsupported `P2` before any write. Separately, the CTAPHID frame loop now
  requires a full 64-byte report instead of accepting `≥5`-byte short reads,
  whose stale buffer tail would otherwise be parsed as payload. Neither was
  exploitable; both were non-findings the run-14 audit flagged for hardening.
  Firmware `bcdDevice` → `0x07FC`.

- **Host tools neutralise terminal escapes from a counterfeit device on every
  path.** The earlier escape hardening reached only `rsk-tui --once`, and even
  there stripped only C0/C1 controls. The Python `rsk` CLI had no sanitizer at
  all, so a hostile device's USB product descriptor, getInfo `versions`, or a
  resident credential's rpId / `user.name` could inject ANSI/OSC sequences
  (screen repaint to forge a "genuine device" banner, `OSC 0` window-title,
  `OSC 52` clipboard write) into the operator's terminal on `rsk inventory` /
  `rsk status` / `rsk fido list-passkeys`. And the TUI's `char::is_control()`
  filter let Unicode bidi/format overrides (U+202E and the isolates) through,
  leaving a Trojan-Source reordering of the printed identity line. Both tools now
  route every device-controlled string through a shared sanitizer that maps C0/C1
  controls **and** Cf bidi/format characters to U+FFFD. Terminal-display integrity
  only — no device secret, PIN, or presence is involved. (`tools/rsk` 0.3.7,
  `tools/tui` 0.2.7)
- **Trusted display: the passkey manager keeps the registrable-domain suffix on
  every screen.** The earlier anti-phishing fix reached only the getAssertion/
  add-passkey ceremonies and the Confirm-Delete card; the passkey **list** row and
  the **service-detail title** still head-truncated an over-long relying-party id,
  hiding the real domain behind the ellipsis on the very screens used to review and
  delete credentials. They now head-ellipsize (`...registrable.domain`) when showing
  the rpId — a look-alike such as `accounts.google.com.attacker.com` can no longer
  read as a legitimate Google passkey. A user-set device-local nickname still keeps
  its head. bcdDevice `0x07F7` → `0x07F8`.
- **`rsk` / `rsk-tui` can no longer be hung or crashed by a hostile device.** The
  earlier host-tooling hardening bounded only the withheld-continuation-frame case;
  a malicious device could still (a) stream `CTAPHID_KEEPALIVE` frames forever to
  hang `rsk` and freeze the synchronous TUI, (b) send short continuation frames that
  made no progress, (c) return over-nested or non-UTF-8 CBOR to crash the decoder,
  (d) answer `rsk hw --transport fido`'s `CONFIG_READ` with a non-byte value to
  crash it, and (e) embed terminal escape sequences in getInfo/identity text that
  `rsk-tui --once` printed raw. The keepalive waits are now deadline-bounded, the
  CBOR decoder is depth- and UTF-8-hardened, the PHY `CONFIG_READ` path validates
  the value type (matching the LED path), and `--once` strips control bytes from
  device-controlled strings. (`tools/rsk` 0.3.6, `tools/tui` 0.2.6)
- **OpenPGP: the resetting code is no longer pre-set to the public default
  `12345678`.** Initialisation seeded the reset code (`EF_RC`) to the well-known
  admin default with an active retry counter, so an unauthenticated host could
  `RESET RETRY COUNTER` (P1=0) with `"12345678" || new-PW1` to reset the user PIN
  and then sign/decrypt with the victim's OpenPGP keys. The reset code now ships
  **deactivated** (per OpenPGP Card 3.4 §4.3.4) and is enabled only when an admin
  sets a real code via `PUT DATA 0xD3`; boot also neutralises any already-
  provisioned card still carrying the default reset code.
- **OATH: `VALIDATE` no longer fails open on an unreadable access code.** A stored
  access code longer than the read buffer made `seal_read` fail and (previously)
  unlocked the applet without the code. Reading a present-but-unreadable code now
  keeps the applet **locked**, and `SET CODE` bounds the code length.
- **OATH: `VERIFY CODE` now honours a credential's touch flag.** A touch-required
  primary HOTP credential could be exercised as a presence-free code-guessing
  oracle; `VERIFY CODE` now requests the same physical press as `CALCULATE`.
- **U2F: a `credProtect=userVerificationRequired` credential is refused on the
  U2F authenticate path**, which performs no user verification — only CTAP2
  `getAssertion` (with a PIN/UV) may exercise such a credential. Level 1/2
  credentials are unaffected.
- **Secure-PIN entry (trusted display): the on-pad PIN can no longer be diverted
  into an attacker-chosen command.** The CCID `PC_to_RDR_Secure` VERIFY template's
  class byte is now forced to `0x00` instead of copied from the host, so a host
  cannot set the ISO 7816-4 command-chaining bit to make the dispatcher buffer the
  typed PIN as a chain segment; the secure path also resets any incoming chaining
  state before dispatch.
- **Seed-moving vendor commands now name themselves on the trusted display.**
  `BACKUP_EXPORT` / `BACKUP_LOAD` and attestation import/clear were all approved
  behind a generic "Vendor config?" prompt; the master-seed export now reads
  "Export secret seed to host?" so a host cannot phish the approval for a full
  identity export behind a benign-looking touch.
- **OpenPGP GET DATA no longer over-reads the scratch buffer** for the fingerprint,
  CA-fingerprint and timestamp DOs: a present-but-short slot is zero-padded to its
  fixed width, so the DO's declared length matches what was written and no stale
  bytes from a prior command leak to an unauthenticated reader.
- **The trusted-display sign-in and add-passkey ceremonies now keep the
  registrable-domain suffix of an over-long relying-party id visible** instead of
  truncating it head-first. A relying party id is kept from the tail
  (`Label::clamp_domain`) and head-ellipsized (`...registrable.domain`), so a
  look-alike such as `accounts.google.com.attacker.com` can no longer hide the real
  domain behind the ellipsis while showing trusted-looking bait in the prefix.
- **The on-device passkey manager applies the same domain-suffix rule.** The
  earlier fix reached only the host-driven ceremonies; the passkey list, service
  detail and the destructive Confirm-Delete card still truncated the relying-party
  id head-first. They now keep the registrable-domain suffix
  (`Label::clamp_domain` + suffix-ellipsis), so a look-alike passkey cannot
  impersonate a service on the screen used to review and delete credentials.

### Fixed

- **A crafted phy record can no longer permanently brick USB.** The boot interface
  guard now falls back to enabling all interfaces unless a *management-capable* one
  (CCID or HID) survives — a keyboard-only mask previously slipped past it and
  stranded the device with no software path to rewrite the record.
- **The boot path no longer panics on a host-written LED pin.** A `led_gpio` from
  the phy record that collides with a GPIO presence pin is now ignored (the build
  default is used) instead of panicking every boot; a build whose own LED/presence
  pins collide is caught at compile time.
- **`rsk` no longer hangs against a hostile device** that announces an inflated
  CTAPHID response length and then withholds the continuation frames.
- **`rsk led --transport fido` no longer crashes** on a device that answers the
  ungated LED `CONFIG_READ` with a non-byte-string CBOR value.

## [0.3.2] — 2026-07-08

### Added

- **Releases now build and publish the trusted-display flavor** as
  `rs-key-<tag>-display.uf2` — reproducibility-gated, signed and attested like the
  other flavors (for the Waveshare RP2350-Touch-LCD-2.8; see
  [docs/guides/display.md](docs/guides/display.md)). CI also packages it as a
  build-smoke `firmware-display.uf2` artifact.

### Fixed

- **The trusted-display power button now sleeps the device from *every* on-device
  screen.** The PIN pad, the hold-to-confirm gestures, the "PIN blocked" notice,
  the success pop, and the host Approve/Deny and "Save passkey?" prompts didn't
  poll the sleep/wake button, so pressing it there did nothing (the reported case:
  the PIN-entry screen). Every blocking on-device loop now honors the button —
  sleeping blanks and, when a device PIN is set, auto-locks; a host ceremony
  interrupted this way is aborted (declined/cancelled), never approved.

- **A management-key mutual auth wrongly cleared the PIN verification, breaking
  `age-plugin-yubikey`'s first-run.** The 9B management key stores pin-policy
  ALWAYS, and a successful GENERAL AUTHENTICATE re-locked the session PIN even for
  the management key — but that re-lock should only follow an actual key-slot sign
  (it already gates the *check* on `is_key`). A client that verifies the PIN,
  mutually authenticates the management key, then signs with a pin-policy=ONCE slot
  key (age-plugin's generate order) hit `6982` on the sign. Now only an `is_key`
  slot sign re-locks the PIN, matching a real YubiKey.

- **PIV certificates over 256 bytes were invisible to `yubikey.rs`-based tools
  (e.g. `age-plugin-yubikey`).** A Case-3 `GET DATA` (command data, no `Le` — how
  `yubikey.rs` reads slot certificates) returned an oversized body whole instead
  of chaining it with `61xx` / `GET RESPONSE`. Clients with a short-APDU receive
  buffer dropped the read, so a retired-slot age identity showed as "(Empty)"
  right after it was generated. The CCID dispatcher now caps a no-`Le` response at
  256 and chains the remainder, matching a real YubiKey (`docs/protocol.md` §1.1).
  `ykman` / OpenSC were unaffected (they read with an extended `Le`).

## [0.3.1] — 2026-07-06

### Added

- **PicoForge hardware config over FIDO.** `authenticatorConfig`'s vendorPrototype
  (`0xFF`) arm now accepts PicoForge's physical-config command IDs (`PhysicalVidPid`,
  `PhysicalLedGpio`, `PhysicalLedBrightness`, `PhysicalOptions`), writing the phy
  record — so PicoForge can set VID/PID, LED and options over FIDO with no PC/SC.
  Gated by an `acfg` pinUvAuthToken. Details in `docs/protocol.md` §11.
- **Device configuration over FIDO (CTAPHID), PIN + touch gated.** A new
  `authenticatorVendor 0x41` subcommand `CONFIG_WRITE (0x0C)` writes device config
  over the FIDO HID transport — for hosts where PC/SC / pcscd can't read or write
  the CCID interface. Targets: the management enabled-apps TLV (`EF_DEV_CONF`) and
  the phy record (`EF_PHY` — VID/PID, USB interfaces, LED wiring, presence-timeout)
  and the LED config block (`EF_LED_CONF`, applied **live**); each lands in the same
  record the CCID read path echoes. Gated by a physical touch and, when a PIN is
  set, a `pinUvAuthToken` (`acfg` permission) — stronger than the CCID path's
  presence-only, since CTAPHID is reachable by any unprivileged host process.
  `CONFIG_READ (0x0D)` returns the phy / LED record (ungated) so a host can
  read-modify-write it over FIDO with no PC/SC at all; `rsk hw --transport fido`
  and `rsk led --transport fido` use this. Wire format in `docs/protocol.md` §9.
- **Firmware flash-size ratchet in the gate.** `check.sh` fails if the shipping
  image grows past a ceiling that hugs the current size (well under the 2560K
  code region) — a runaway dependency or surprise growth trips it early. Ratchet
  it down when the image shrinks; bump `FIRMWARE_FLASH_BUDGET_KIB` for a
  legitimate feature.
- **Host-crate coverage floor.** `deep-checks` gained an `llvm-cov` job that
  floors host-crate line coverage (a regression alarm; the embedded image is
  not host-measurable).
- **Cognitive-complexity ratchet in `deep-checks`.** `scripts/complexity_gate.sh`
  fails if any crate-library function crosses a cognitive-complexity ceiling — a
  daily regression alarm for new hotspots, the coverage floor's sibling. Lower
  the ceiling as the peak falls. rust-code-analysis is pulled ad-hoc, so it
  never joins the pinned dev shell.
- **`scripts/metrics.sh`** — advisory refactor reconnaissance (function
  complexity, firmware size, generic monomorphization). Not a gate; the tools
  are pulled ad-hoc so they never join the pinned dev shell.

### Changed

- **`deep-checks` runs daily** rather than weekly (Miri, fuzz, Kani, repro,
  coverage, complexity).

## [0.3.0] — 2026-07-03

### Added

- **Trusted-display build (experimental, opt-in).** A screen-and-touch RS-Key
  variant for the Waveshare RP2350-Touch-LCD-2.8, behind the `display` cargo
  feature (`firmware-display` nix flavor). The screen turns the key into a
  *trusted display* — the operations that matter happen on the device's own glass,
  not on the host:
  - **Approve / Deny** paints the *real* relying party for every touch-gated
    operation, so a signature can't be produced without a physical tap on a screen
    showing the true `rpId` (refuse → `OPERATION_DENIED`); a registration shows a
    *Save new passkey?* card. A look-alike id too long for the box is clipped with
    a truncation marker so its prefix can't masquerade.
  - **On-screen PIN entry** — built-in user verification (getInfo `options.uv`; a
    `pinUvAuthToken` minted from the on-screen pad against the same `EF_PIN`), and
    a CCID **pinpad** (`bPINSupport` / `PC_to_RDR_Secure`) so GnuPG and OpenSC
    collect the OpenPGP / PIV PIN on the panel — the PIN never crosses USB. Every
    PIN screen names which credential it collects, an eye toggle reveals the
    digits, and "N tries remaining" is shown up front.
  - A dedicated **device PIN** (separate from the FIDO clientPIN) gating the
    on-device UI, with **lock / unlock**, display **sleep** (image-retention
    guard + wake button), and set / change PIN on the panel.
  - **Passkeys** — browse resident credentials, **rename** (a device-local
    nickname that never re-seals the box) and **delete** on-device.
  - **Apps** — a read-only browser of OpenPGP / PIV / OATH state (no PIN, no
    secret, no OATH code — the device has no clock), plus on-device **PIV key
    generation** (EC P-256/P-384, Ed25519, X25519, RSA 2048/3072/4096) into empty
    retired slots.
  - **Settings** — device & FIDO PINs; a PIV PIN / PUK / unblock / **protect
    management key** (ykman `--protect`) sub-menu; on-screen **BIP-39 / SLIP-39
    recovery** export (derived on-device, never over USB) and backup-window status;
    an **audit log**; **factory reset**; a **Firmware** screen that reboots to
    BOOTSEL for an over-USB update; and live brightness / display-sleep /
    touch-timeout that persist across reboots.
  - A standard **screenless key compiles none of it** — the whole UI stack
    (`rsk-ui`, `embedded-graphics`, `u8g2-fonts`) is `dep:`-gated and the build
    asserts it absent from the default image, so an ordinary build is
    byte-for-byte unaffected. The UI model, geometry and glyphs live in the
    host-tested + Kani-proved `rsk-ui` crate. See
    [`docs/guides/display.md`](docs/guides/display.md). Built up across bcdDevice
    `0x0784`–`0x07D5`.

- **PIV: RSA-3072 and RSA-4096 keys.** Generate, import, sign / decrypt,
  attestation and metadata gained RSA-3072/4096 (the applet buffers were lifted
  off their RSA-2048 ceiling); on a display build the on-device **Generate key**
  chooser offers RSA via a 2048 / 3072 / 4096 sub-picker. RSA-1024 stays disabled.
  bcdDevice `0x07C4` → `0x07C6`.

- **PIV: Ed25519 and X25519 keys** (algorithm ids `0xE0` / `0xE1`, Yubico 5.7
  PIV). Generate (Ed25519 with an RFC 8410 self-signed cert; X25519 is
  key-agreement-only), import (raw seed / scalar, yubikit tags `0x07` / `0x08`),
  sign / key-agree, metadata and attestation — interoperating with `ykman` /
  `yubico-piv-tool` (an imported X25519 scalar is byte-flipped to the little-endian
  form standard tooling sends, so the slot's public key matches). bcdDevice
  `0x07C3` → `0x07C4`.

- **Configurable multi-LED effects engine.** Boards with a chain of addressable
  WS2812 LEDs light the whole strip with per-status animated effects (`vapor`,
  `bounce`, `flow`, `sparkle`, `legacy`) via `rsk led --effect/--speed`; the
  connected count is a runtime phy setting (`rsk hw --led-num`, TLV tag `0x0E`)
  bounded by the `MAX_LEDS` build ceiling (a value over it saturates, never
  panics). `EF_LED_CONF` grows to 17 bytes; older blocks still load. Thanks to
  @Curious-r. bcdDevice `0x0780` → `0x0783`.

- **Configurable GPIO presence button (`PRESENCE_PIN`).** The user-presence input
  can move from BOOTSEL to a dedicated GPIO at compile time (`PRESENCE_PIN=<0..=29>`,
  active-low with a pull-up by default, or `PRESENCE_ACTIVE_HIGH=1` for a touch
  sensor / button-to-VCC); the pin is guarded against colliding with the LED and is
  rejected on a `display` build. One new documented `unsafe`. Thanks to @lpiob
  ([#17](https://github.com/TheMaxMur/RS-Key/pull/17)). bcdDevice `0x0791` → `0x0793`.

- **`rsk-tui` can export the seed as SLIP-39 shares** (tools/tui 0.2.4). The Backup
  section gains "Export seed (SLIP-39)" beside the BIP-39 export, revealing the seed
  as a 2-of-3 Shamir share set (via the in-tree `rsk-slip39` crate) that recombines
  with `rsk backup restore --scheme slip39`.

### Changed

- **Touch timeout is configurable; phy tag `0x08` now follows pico-fido.** Tag
  `0x08` (previously an unused presence-button GPIO) now means `PresenceTimeout` —
  the touch-wait in seconds — matching pico-fido / PicoForge, so a PicoForge config
  or `rsk hw --touch-timeout <secs>` sets it (absent / `0` keeps the 30 s default).
  bcdDevice `0x0783` → `0x0784`.

- **`rsk-tui` gets a curated colour theme** (tools/tui 0.2.3). On truecolor / 256-
  colour terminals the cockpit uses a fixed brand palette with rounded borders and
  an explicit selection bar; a 16-colour terminal keeps the adaptive named-ANSI
  colours. Override with `RSK_TUI_TRUECOLOR=1|0`. No `--once` / `--json` change.

- **`rsk-tui` status labels are single-sourced** (tools/tui 0.2.2). The `--once`
  printer and the cockpit now share the model's label mappings, which changes three
  `--once` labels (seed lock "… disabled until unlock", secure boot "ENABLED (not
  locked)", un-probed applets "not probed").

### Fixed

- **Maximal credential requests now fit the credential box.** A registration
  within every advertised limit (a 253-byte `rpId`, a 64-byte user.id, 64-byte
  name / displayName and a 127-byte credBlob) could overflow the sealed credential
  box or its resident bookkeeping and be rejected (`CTAP2_ERR_OTHER` /
  `KEY_STORE_FULL` / `REQUEST_TOO_LARGE`), and a large credential that did register
  could then never assert. The three ceilings are now **derived** from the field
  maxima so they can't drift below what the device advertises: `CRED_BOX_MAX` (748)
  sizes create / assert / reseal, `RP_REC_MAX` (314) the resident `EF_RP` record,
  and `MAX_RAW_SUBPARA` (384) a maximal `updateUserInformation`; getInfo's
  `maxCredentialIdLength` and the published metadata report the real 748, and
  over-maximum inputs are rejected explicitly with `INVALID_LENGTH`. Older records
  load unchanged. bcdDevice `0x07E7` → `0x07EC`.

### Security

- **Additional defense-in-depth hardening** (four items, none independently
  exploitable; bcdDevice `0x07DD` → `0x07DE`):
  - **credProtect is now range-checked.** makeCredential rejected nothing for a
    credProtect value outside `{1,2,3}` and stored it verbatim; `getAssertion`
    enforces protection by exact match, so an out-of-range value silently meant
    *no* protection. It now returns `CTAP2_ERR_INVALID_OPTION` (§12.1).
  - **hmac-secret-mc empty-salt parity.** makeCredential now rejects an
    hmac-secret-mc request with an empty salt up front (`MissingParameter`),
    matching the existing `getAssertion` hmac-secret guard (previously this was
    only caught later by the length check in `hmacsecret::eval`).
  - **credentialManagement enumeration counters widened to `u16`.** The `skip` /
    `total` / begin-next counters were `u8` and saturated at 255, so on a fully
    provisioned store (`MAX_RESIDENT_CREDENTIALS = 256`) the 256th RP/credential
    was invisible to (and undeletable via) enumeration. The wire encoding is
    unchanged for ≤255 (canonical CBOR).
  - **RSA-keygen fast path resets the incoming command chain.** The CCID keygen
    fast path already dropped a stale GET RESPONSE tail (`clear_pending`); it now
    also resets a half-accumulated CLA-`0x10` command chain (`clear_chaining`,
    scrubbing it) so an interrupted chain cannot prepend onto a later command.
- **Missing-authorization fixes in the Yubico-management and rescue applets**
  (two defects in never-before-audited utility applets; bcdDevice `0x07DC` →
  `0x07DD`):
  - **Rescue OTP-fuse writes now require an on-device user-presence confirmation.**
    The two irreversible fuse burns — page-58 access lock (`INS 0x1B` `P1=0x58`,
    `"LOCK58"`) and `ROLLBACK_REQUIRED` (`P1=0x48`, `"ROLLBK"`) — were the only
    privileged rescue commands without the `require_presence` gate every sibling
    op (attestation sign, cert/phy write, reboot-to-BOOTSEL) enforces. Their magic
    payload is a source-visible constant, not authentication, so an unauthenticated
    USB host could permanently burn a fuse with no operator consent. Both now
    prompt (`6985` if declined); idempotent no-ops still return `OK` without a
    prompt. (`crates/rsk-rescue/src/lib.rs`.)
  - **Management WRITE CONFIG (`INS 0x1C`) now requires user presence.** It was
    entirely unauthenticated and the `CONFIG_LOCK` byte it stores was never
    enforced, so a USB host could persistently spoof the reported DeviceInfo. The
    write now prompts for on-device confirmation (`6985` if declined), matching
    every sibling applet's write path. (`crates/rsk-mgmt/src/lib.rs`.)
- **PIV and CCID defense-in-depth hardening** (no exploitable vulnerability
  found; three items; bcdDevice `0x07DB` → `0x07DC`):
  - **PIV `GENERAL AUTHENTICATE` challenge is now bound to its issuing
    algorithm.** A 9B mutual/single-auth challenge issued under one algorithm
    (3DES `chal_len` 8 vs AES `chal_len` 16) could structurally be answered under
    the other; AES-192 and 3DES share a 24-byte key, so the key-length gate alone
    did not separate them. This was **not** exploitable (the witness always
    requires knowledge of the management key, and every replay failed closed with
    `has_mgm` staying false), but the `Session` now records `chal_algo` at issue
    and refuses a step-2 whose algorithm differs.
  - **PIV GET DATA / MOVE KEY clamp the stored object length.** `get_data` and
    `move_key` sliced a `MAX_OBJECT` (1900-byte) buffer by the full length
    `Storage::read` returns, which would panic on a stored value longer than the
    buffer. Every host writer already caps at `MAX_OBJECT` (so this was reachable
    only by a raw flash write — a stronger attacker than the USB host), but the
    readers now clamp with `n.min(MAX_OBJECT)`, returning the prefix instead of
    panicking. Matches the existing `EF_PIVMAN_DATA` clamp pattern.
  - **CCID RSA-keygen fast path clears the GET RESPONSE remainder.** The dual-core
    `try_rsa_keygen` / `try_piv_rsa_keygen` fast paths bypass
    `Dispatcher::process`, which is what normally drops a stale chained-response
    tail, so a host interleaving `chained-response → GENERATE → GET RESPONSE` was
    re-served its own prior tail. This crossed no trust boundary (same principal;
    a SELECT to another applet clears the buffer first), but the fast paths now
    call `Dispatcher::clear_pending()` to match ordinary dispatch.

- **PIV and OATH authentication fixes** (bcdDevice `0x07DA` → `0x07DB`):
  - **PIV management-key authentication bypass via an encryption oracle
    (critical).** `GENERAL AUTHENTICATE` had a symmetric-algorithm tag-`0x81`
    ("internal authenticate") branch for slot `9B` that returned
    `E(mgm_key, caller_bytes)` with no `has_mgm`, no PIN (`9B` is not a key slot,
    so the PIN gate was skipped) and no touch (default `9B` policy is
    `TOUCHPOLICY_NEVER`). Because the management-key cipher is deterministic ECB,
    an unauthenticated USB host could chain it with the applet's own single-auth
    challenge — request a plaintext challenge `R`, ask the oracle for `E(mgm,R)`,
    submit that as the response — and the card's `D(mgm,·)==R` check would pass,
    setting `has_mgm` with **zero knowledge of the management key**. That grants
    full, persistent PIV takeover (generate/import/overwrite slot keys, `PUT DATA`,
    rotate the management key, reset PIN/PUK counters). It is a distinct-mechanism
    sibling of the earlier mgmt-key bypass, whose `ChallengeKind` binding did not
    cover it. **Fix:** the symmetric tag-`0x81` branch (which has no legitimate PIV
    client) is removed, so the only sanctioned `9B` flows are mutual-witness
    (tag `0x80`) and single-auth (tag `0x81`-empty challenge → tag `0x82` verify).
    A class-invariant test asserts no `GENERAL AUTHENTICATE` path reachable without
    prior auth can set `has_mgm`.
  - **OATH `CHANGE PIN` unlimited OTP-PIN guessing at the retry floor (medium).**
    `cmd_change_otp_pin` decremented the OTP-PIN retry counter with a saturating
    subtraction but, unlike `cmd_verify_otp_pin`, did not refuse at the floor —
    once the counter reached 0 it stayed 0 and the PIN comparison kept running on
    every request, an unlimited online brute-force of the store-unlocking OTP-PIN
    (a residual sibling of the earlier `CHANGE PIN` finding). **Fix:** both `VERIFY`
    and `CHANGE` now go through a single `spend_and_match_otp_pin` chokepoint that
    refuses at `rec[0]==0`; legitimate recovery after lock-out is `RESET` (which
    wipes the store), not more guesses. **Behavior change:** a correct old-PIN no
    longer recovers a locked-out OTP-PIN via `CHANGE`; use `RESET`.
- **OTP, OpenPGP, U2F and audit-journal hardening** (bcdDevice `0x07D9` →
  `0x07DA`):
  - **OTP `SLOT_SWAP` access-code bypass (high).** `cmd_swap` was the only
    slot-mutating OTP command that did not check the per-slot access code that
    `cmd_configure`/`cmd_update` enforce: it unsealed both target slots (the seal
    read never compares the access code) and relocated/deleted them unconditionally.
    An unauthenticated USB host (CCID or the HID keyboard frame, no PIN/code/touch)
    could `SLOT_SWAP` a programmed, access-code-protected slot to **silently delete
    or relocate** it — persistently breaking a challenge-response credential used
    for LUKS / KeePassXC / pam_yubico. An unbounded swap offset could also orphan
    the slot at an FID outside the addressable 1..=4 range. `cmd_swap` now requires
    the access code of every non-empty slot it touches (an unprotected slot's code
    is all-zero, so a plain `ykman otp swap` of unprotected slots is unchanged) and
    rejects out-of-range offsets; the same offset bound is applied to
    `cmd_configure`/`cmd_update`/`cmd_calculate`. Integrity/availability only — the
    config stays GCM-sealed (no secret exfiltration).
  - **OpenPGP `read_public` unclamped stored length (hardening).** `read_public`
    returned the value's full `Fs::read` length without `n.min(out.len())` — the
    6th member of the OpenPGP stored-length family. Latent only (`EF_PB_*` is not
    host-writable beyond its bound), now clamped like every other reader.
  - **U2F attestation-chain read (hardening).** The org-attestation branch sliced
    `cert[..n]` on the full stored length with only a size margin; now clamps
    `n.min(cert.len())`, matching the sibling `EF_EE_DEV` branch.
  - **Audit-journal meta window (hardening).** `load_meta` now fails closed to
    genesis when a persisted `EF_AUDIT_META` claims a window wider than
    `AUDIT_RING_SLOTS`, so a flash-corrupted meta can't overrun the export buffer.
  - **`BACKUP_EXPORT` docstring corrected** to match behavior (only
    `BACKUP_FINALIZE` seals the window; repeat export before finalize is safe).
- **FIDO, OpenPGP and OATH fixes** (bcdDevice `0x07D8` → `0x07D9`):
  - **FIDO `getNextAssertion` user-presence bypass (high).** `getAssertion` armed
    the multi-credential `getNextAssertion` queue during resident discovery
    *before* its user-presence gate, and no path tore the queue down when that gate
    failed; `getNextAssertion` performs no presence check of its own. So on a
    device holding ≥2 discoverable credentials for one RP, after the user
    **declined or ignored** the touch, a host could still pull valid `UP=1`
    assertions for credentials #2..N with no touch — defeating the test of user
    presence. `get_assertion` now calls `gna.reset()` on any error return (CTAP 2.1
    §6.3: getNextAssertion only continues a *successful* getAssertion).
  - **OpenPGP `GENERATE` OOB panic on a short algorithm attribute (medium).** A
    PW3-written 1–2 byte `C1/C2/C3` DO (`PUT DATA` caps no minimum length) made
    `GENERATE ASYMMETRIC KEY PAIR` index the RSA modulus-size bytes past the slice
    → panic/reset on every `GENERATE` for that slot. The earlier clamp only bounded
    the *over*-long case; both `generate` and `rsa_generate_params` now reject an
    attribute shorter than 3 bytes, matching the guarded sibling `info::slot_algo`.
  - **OATH OTP-PIN counter glitch-hardening (defense-in-depth).** `VERIFY PIN` /
    `CHANGE PIN` now persist and read back the retry-counter decrement *before* the
    PIN compare (mirroring the FIDO clientPIN gate), so a fault-injected or failed
    flash program can't widen the 3-try OTP-PIN limiter.
  - **FIDO `verify_pin_hash` self-guards the retry decrement (defense-in-depth).**
    Added an in-function `retry == 0` check before `pin_data[0] -= 1` (matching
    `verify_pin_at`), so no future caller can underflow the PIN retry budget in a
    release build without overflow-checks.
- **OpenPGP, OATH and FIDO fixes; `rsk` receipt binding** (bcdDevice `0x07D8`;
  `rsk` 0.3.1; `rsk-tui` 0.2.1):
  - **OpenPGP `GET DATA` unclamped length → OOB brick (high, ×2 sites).** Both the
    generic top-level Flash DO (`login`/`url`/private DOs) and the `C1/C2/C3`
    algorithm-attribute path returned the value's full stored length, so an
    over-long PW3-written object panicked the device on every read (persistent
    DoS reached by `gpg --card-status`). `get_data` now clamps `data_len` to the
    scratch buffer at the single chokepoint, plus a defensive clamp at the extend.
  - **OATH access-code / OTP-PIN bypasses (high, ×2).** `SET PIN` now requires a
    validated session (an unauthenticated host could mint the unlock secret on a
    locked applet); `CHANGE PIN` now spends a retry on a wrong old-PIN (it was an
    unlimited brute-force oracle that recovered the OTP-PIN and unlocked the store).
  - **FIDO `setMinPINLength` truncation (medium).** A `newMinPINLength` above the
    max PIN length is now rejected before the `as u8` store, which otherwise
    truncated (e.g. 256 → 0) and silently defeated the monotonic enterprise floor.
  - **`rsk offboard` receipt binding (medium).** The signed wipe receipt is now
    bound to the journal window it presents (recompute + compare the head, hard-fail
    a missing RESET), matching `rsk audit`; the verify ceremonies also validate
    device-supplied checkpoint fields instead of raising a traceback.
  - **Defense-in-depth (low).** Clamped five remaining `Fs::read` readers
    (`phy`/`largeblobs`/vendor `unlock`/`makeCredential` att-chain/OpenPGP DEK) to
    their buffers; fixed the OpenPGP `GET DATA 0x7A` stale-scratch over-read;
    rejected the 2-byte TLV tag form in OATH `PUT`; hardened the `rsk-tui` audit
    view and `rsk led` against malformed device responses.

- **Full-tree audit fixes.** Found and fixed:
  - **PIV management-key authentication bypass (critical).** `GENERAL
    AUTHENTICATE` shared one session challenge field between the single-auth
    (plaintext challenge) and mutual-auth (encrypted witness) handshakes, so a
    host could read the plaintext single-auth challenge and replay it as the
    mutual-auth witness to authenticate as the card administrator with no
    knowledge of the management key — no PIN, no touch. The challenge is now
    tagged with the flow that issued it and can only be consumed by that same
    flow.
  - **OpenPGP `GET DATA` over-long-DO brick (two more sites).** The cardholder
    certificate (`7F21`) read-out and the generic `DoWriter` flash-DO builder
    sliced/advanced a fixed 1024-byte buffer by the value's *full* stored length;
    a PW3 host can `PUT DATA` an over-long cardholder cert/name, so a later `GET
    DATA 65/6E/7F21` (issued by `gpg --card-status`) panicked — a persistent
    brick. Both are now clamped to the buffer, matching the earlier `info.rs` fix.
  - **OATH `VERIFY CODE` (INS `0xB1`) now honours the access code.** It lacked the
    `validated` gate every other stored-data command has, so a locked applet
    answered it — a replayable oracle on the primary credential's current OTP
    across the access-code boundary. Now gated.
  - **Trusted-display delete-confirmation clips the identity.** The
    delete-passkey confirmation drew the untrusted rpId/account unclipped with no
    truncation marker, unlike the approve/add ceremonies; a padded look-alike
    rpId could overflow the card silently. Now ellipsized + marked to the card.
  - **OpenPGP private keys are AES-256-GCM-sealed with a fresh nonce.** The DEK
    seal used one fixed (key, IV) AES-CFB across every key slot, so the block-0
    keystream repeated and a flash-dump attacker could recover the XOR of two
    same-format scalars' first bytes; CFB was also unauthenticated. Sealing now
    uses AES-256-GCM under a synthetic per-record nonce (`HMAC(dek, fid ‖ key)`),
    adding authentication and eliminating the reuse. Keys in the old CFB format
    still load (trial-decrypt fallback) and are re-sealed to the new format the
    first time they are used — no reprovisioning needed.
  - **The release pipeline no longer ships the `no-touch` firmware.** The release
    workflow built and published four `no-touch` flavors (user-presence bypass,
    marked "never ship") as signed, SLSA-provenanced public assets. It now builds
    and publishes only the four touch-required flavors, with a guard that fails
    the release if any `no-touch` asset is present.

- **FIDO master seed sealed with authenticated ChaCha20-Poly1305.** The device
  master seed and the org attestation scalar (`EF_KEY_DEV` / `EF_ATT_KEY`) were
  sealed with AES-256-CBC under one fixed serial-hash IV shared across both
  slots, and carried no MAC — the same fixed-IV / no-authentication class as the
  OpenPGP DEK above, but at the root of the FIDO identity. They are now
  ChaCha20-Poly1305-sealed (new tags `0x02` pre-OTP / `0x12` OTP-arm) under a
  synthetic per-record nonce (`HMAC(HMAC(nonce_key, fid), value)`), so the seed
  and the attestation key never share a nonce and a flash fault or tamper is
  detected rather than silently decrypting to a corrupted seed. Records in the
  legacy CBC (`0x01`/`0x11`) and PIN-wrapped (`0x03`/`0x13`) formats still load
  and are re-sealed forward at boot / the first PIN verify — no reprovisioning,
  and every passkey survives the upgrade.

- **Pre-release cross-review hardening.** An adversarial re-review of the two
  unreleased hardening commits (the trusted-display arc and the pico-keys
  carry-over below) — the ones that had not yet been cross-reviewed before a
  release tag — found and fixed:
  - **OpenPGP over-long-DO brick, two remaining sites.** `GENERATE`,
    `rsa_generate_params` and key `IMPORT` read the algorithm-attribute DO into a
    fixed 16-byte buffer and sliced it by the value's *full* stored length; a
    PW3 host can `PUT DATA` an over-16-byte `C1/C2/C3`, so the slice panicked
    (device brick). Clamped to the buffer, matching the earlier `info.rs` fix.
  - **OTP slots and OATH credentials now survive a later OTP-MKEK burn.** Both
    seal under the device root key, which changes when the fuse MKEK is burned;
    neither had the pre-OTP recovery arm the FIDO seed / PIV / attestation key
    already use, so a secret provisioned *before* a burn became unreadable (OTP)
    or was double-encrypted and destroyed (OATH) on the first post-burn boot. The
    boot migrations now trial-decrypt under the pre-OTP arm and re-seal under the
    OTP arm.
  - **OATH OTP-PIN survives an OTP-MKEK burn.** The new OTP-rooted verifier gained
    the same `without_otp()` match-and-re-store fallback the PIV / OpenPGP / FIDO
    PINs use, so a PIN set before a burn still verifies afterwards — restoring the
    burn-immunity the legacy serial-only hash happened to have.
  - **The reboot-to-BOOTSEL user-presence gate can no longer be bypassed.** The
    vendor applet exposes the same reboot verb as the (gated) rescue applet, over
    both the CCID and CTAPHID transports; its `1F/01` (BOOTSEL) is now gated
    identically. A warm restart (`1F/00`) stays ungated.
  - **Trusted-display: the Add-passkey (enrollment) screen marks a truncated
    relying-party id.** The makeCredential screen dropped the truncation marker
    for a clamped look-alike id whose prefix fit the box — the phishing vector the
    Approve screen already closed. It now forces the marker like the Approve path.
  - **`rsk-wipe` rejects a degenerate `FLASH_SIZE`.** `FLASH_SIZE=0` passed the
    remaining build asserts and made the erase a silent no-op that still signalled
    success; a lower bound now rejects it.

  bcdDevice 0x07D3 → 0x07D4. Host CLI (`tools/rsk`) 0.2.0 → 0.3.0: `rsk hw` and
  `rsk reboot bootsel` now prompt for the on-device approval the firmware requires
  and explain a `6985` decline instead of failing cryptically.

- **Carry-over hardening from a pico-keys upstream audit.** A review of the upstream
  pico-keys C firmware surfaced design flaws; each was re-verified against the RS-Key
  Rust source. The overwhelming majority were already handled by the port (OATH gate,
  PIV key sealing + admin-auth gates, parser totality, HMAC-DRBG, constant-time
  compares), and this wave closes the remaining gaps:
  - **Yubico OTP slot secrets are now sealed at rest.** The 52-byte slot config —
    which carries the AES-128 key, private UID and the HMAC-SHA1 / OATH-HOTP secret —
    was the one applet still written to flash in the clear. It now goes through the same
    `KeyFid` AES-256-GCM chokepoint as FIDO / PIV / OpenPGP / OATH; a boot pass re-seals
    any pre-existing plaintext slot, so a flash-dump thief no longer recovers the token
    secrets.
  - **The OATH OTP-PIN verifier is OTP-rooted, not a fast serial-only hash.** The
    Nitrokey-style OTP PIN now stores `pin_derive_verifier` (rooted in the OTP MKEK,
    exactly like the OpenPGP / PIV PINs) instead of the legacy `double_hash_pin`; a
    legacy record still verifies and is upgraded on the next successful use.
  - **The device attestation key is AEAD-sealed.** `EF_DEVCERT_KEY` moved from raw
    AES-256-CBC under a public fixed IV with no MAC to AES-256-GCM (random nonce, auth
    tag); a bit-flip in the sealed scalar is now detected rather than silently accepted,
    and legacy CBC records are re-sealed at boot.
  - **Privileged rescue commands require user presence.** Attestation signing over a
    host-chosen digest, attestation-cert overwrite, phy/identity write and
    reboot-to-BOOTSEL now need an on-device confirmation (a touch, or an on-screen
    Approve on the trusted-display build), so a hostile USB host can no longer drive
    them silently. Read-only status and a plain restart stay ungated.
  - **OpenPGP MSE touch policy follows the repointed slot.** The UIF (touch) check for
    PSO:DECIPHER / INTERNAL AUTHENTICATE now follows an MSE key-reference repoint, so a
    cross-wired DEC↔AUT key can no longer be used under the wrong slot's touch policy.
  - **FIDO credMgmt `updateUserInformation` requires an exact userId match** (CTAP 2.1
    §6.8.3), closing a min-length-prefix compare where a prefix (or empty id) matched.
  - **`rsk-wipe` erases the whole target flash.** It reads the same `FLASH_SIZE` build
    knob as the firmware instead of assuming 4 MB, so a 16 MiB board is fully wiped.

  bcdDevice 0x07D2 → 0x07D3. (`rsk-wipe` is a separate binary and carries no bcdDevice.)

## [0.2.8] — 2026-06-21

### Changed

- **A WebAuthn login is a single touch by default.** RS-Key now honors the
  platform's silent pre-flight probe — a `getAssertion` with the `up` option set
  to `false` — by returning the credential-discovery assertion **without**
  polling the button and with the UP flag clear, as the CTAP2 spec and YubiKey
  do. Previously the `up` option was ignored and every assertion polled the
  button, so an `allowCredentials` (non-resident) login — the common security-key
  second-factor flow — cost **two** touches: one for the browser's silent
  pre-flight, one for the real assertion. Resident-credential / passkey logins
  were, and remain, a single touch. A new `strict-up` cargo feature (off by
  default) restores the touch-on-every-assertion behavior for anyone who wants an
  explicit gesture per assertion; `fido-conformance` enables it implicitly so the
  conformance image keeps its validated behavior. See
  [build.md](https://github.com/TheMaxMur/RS-Key/blob/main/docs/build.md).
  bcdDevice 0x077F → 0x0780.
- **Requiring a touch is the unconditional default, not a cargo feature.** The
  `up-button` feature (which was on by default) is gone — the shipped image
  demands a BOOTSEL touch for FIDO / OpenPGP-UIF operations with no flag. The
  no-touch test image, for the automated suites that cannot press a button, is
  now the explicit opt-in **`--features no-touch`** (previously
  `--no-default-features`). The secure default no longer depends on a feature
  being left enabled; the default firmware binary is unchanged.

## [0.2.7] — 2026-06-21

### Security

- **A pre-OTP seed remnant survived OTP provisioning, readable from a flash
  dump without the fused key — now physically scrubbed at the first OTP boot.**
  RS-Key seals the FIDO seed under the device root (`kbase`): chip-serial-only
  before OTP provisioning, the fused MKEK after. Burning OTP re-seals the seed
  from the weaker root to the fused one (`migrate_keydev_boot`), but the
  `sequential-storage` flash log is append-only — an overwrite leaves the prior
  value in place and `remove_item` only flips a header CRC, so the superseded
  *chip-serial-sealed* copy lingered in flash until natural compaction (rare on
  the cold credential partition). Because that root derives from the chip id
  alone — no fuse secret — an attacker with a flash dump plus the chip id could
  recover the seed, and with it every derived FIDO credential, **bypassing the
  OTP hardening entirely.** This is the same class of issue as the upstream
  pico-fido/pico-keys-sdk `flash_clear_file` finding (their "clear" zeroes only
  the length field, leaving the payload); here `sequential-storage`'s logical
  delete is the equivalent, and the device-root seal is the only thing that made
  the steady state safe. Fix: the first boot with the OTP key present now runs a
  one-shot `Fs::compact` — a full garbage-collection lap over the credential
  partition that migrates live records forward and sector-erases every page,
  physically destroying the superseded pre-OTP copies. It is gated by a new
  `EF_HARDENED` flash marker (runs once, before USB attach) and is crash-safe
  (an interrupted lap leaves the marker unset and re-runs next boot). A device
  provisioned OTP-first never creates the remnant and the pass finds nothing to
  scrub. A host-side proof on the real `sequential-storage` + mock-flash stack
  scans raw flash to confirm the remnant is present before the lap and gone
  after (`fuzz/tests/churn_compaction.rs`, mutation-checked). `production.md`
  now documents the pass and recommends burning OTP before enrolling; the
  threat-model/limitations caveats are corrected (the lingering record was
  described as "moot against anything but a fused-key compromise", true only for
  the already-fused soft-lock case, not this one). bcdDevice 0x077E → 0x077F.

## [0.2.6] — 2026-06-21

### Fixed

- **ML-DSA-44 (COSE `-48`) FIDO `getAssertion` hard-wedged the device — the
  post-quantum credential key is now heap-boxed off the worker stack.** The
  optional ML-DSA-44 signature scheme (negotiable from a request's
  `pubKeyCredParams`, unadvertised by default) held fips204's ~16.6 KiB of
  NTT-form keys *inline* on the worker stack, directly below the stack-heavy
  rejection-sampling `sign`. A `.bss` growth since v0.2.5 (the power-cut
  tri-state present-cache + the hybrid ML-KEM-768 seed-backup) had lowered the
  RP2350 worker-stack ceiling from ~238 KiB to ~222 KiB, so an ML-DSA-44
  `getAssertion` overflowed it → memory corruption → `panic-halt`, leaving FIDO
  dark until a USB replug. Reachable as a denial of service: an explicit `-48`
  `makeCredential` followed by `getAssertion` wedges the authenticator even
  though `-48` is unadvertised. `makeCredential` survived because key generation
  is a shallower frame than signing. The keypair is now `Box`-ed onto the
  firmware heap — idle during a FIDO request, since applet keys are reconstructed
  per-operation — freeing ~16.6 KiB at signing depth and restoring a measured
  32–64 KiB of stack margin (verified on hardware by flashing deliberately
  stack-starved builds: passes at −32 KiB, wedges at −64 KiB). The heap stays
  128 KiB, so there is no RSA impact, and a `size_of::<CredKey>()` guard fails
  the build if the key ever regresses back inline. HW-verified on RP2350
  (`tests/60` raw CTAPHID + `tests/61` python-fido2/OpenSSL, ML-DSA-44
  register+login). `bcdDevice` `0x077D` → `0x077E`.

- **`ssh-keygen -t ed25519-sk` (and any Ed25519 FIDO2 credential) failed on
  Windows — EdDSA is now advertised in `authenticatorGetInfo`.** The device has
  always *supported* EdDSA (COSE `-8`): `makeCredential` negotiates it from a
  request's `pubKeyCredParams` and signs with Ed25519. But `-8` was omitted from
  the advertised `algorithms` (0x0A) list, kept out alongside ES256K (`-47`) so
  the FIDO Conformance tool — whose `verifySignatureCOSE` only maps `-7/-35/-36` —
  wouldn't fail trying to verify an EdDSA self-attestation. The Windows WebAuthn
  API (the path Windows OpenSSH takes) **intersects the requested algorithms with
  the advertised list**, so it silently dropped `-8` and the credential create
  failed; macOS/Linux OpenSSH go through libfido2, which sends `-8` directly, so
  it worked there. The shipping/default build now advertises `-8`. The capability
  is unchanged — only the advertisement was added. ES256K (`-47`) stays
  unadvertised (still negotiable from a request). For the conformance run, the new
  `fido-conformance` build feature suppresses `-8` again and
  `metadata/rs-key.conformance.metadata.json` is the matching EdDSA-free Metadata
  Statement (verified by `tests/62` to be the shipping statement minus EdDSA).
  `bcdDevice` `0x077C` → `0x077D`.

- **Two power-cut data-durability bugs in the flash file system, both surfaced by
  the `power_cut` / `fs_ops` fuzz targets (deep-checks) and latent since the
  present-cache landed in v0.2.3.** Neither affects the shipped, verified v0.2.5
  artifacts — both are power-cut-edge, not artifact-integrity.
  - **`delete` orphaned metadata.** `Fs::delete` dropped a file's `EF_META`
    record only when the file's *own* data was present, so a file given metadata
    (`meta_add`) but never written (`put`) kept its metadata after deletion — the
    record read back alive across a reboot, diverging the live key set from the
    model. `delete` now drops metadata unconditionally (O(1) when there is none),
    and `meta_delete` skips the `EF_META` rewrite when the FID had no record, so
    the absent-slot reset sweep stays write-free.
  - **The present-cache could go false-absent after a torn migration.** The boot
    `scan` seeds its negative cache from a bulk `for_each_key`, which can silently
    under-count a key when a power-cut interrupts a `sequential-storage` page
    migration — while the per-key `fetch_item` still recovers it. A clear cache
    bit was trusted as "absent", so committed data/metadata read back lost, and a
    `meta_add` over a false-absent `EF_META` wiped every existing record. The
    cache is now tri-state (`present` + a `decided` authority bit): a clear bit is
    trusted only once a backend probe confirms it, otherwise the reliable
    `fetch_item` decides and the answer is memoised — a false-absent is now
    impossible. Cost: a one-time-per-boot first probe per absent FID (the PIV-tab
    lag returns once after a plug-in, then stays O(1)). `fetch_item` durability is
    pinned by a new `kv_durability` fuzz target (the storage layer in isolation);
    `power_cut` and `fs_ops` now run clean. `bcdDevice` `0x077B` → `0x077C`.

## [0.2.5] — 2026-06-20

### Added

- **Runtime LED hardware config — pin, driver, and wire order are now set at
  runtime via the `phy` record (`rsk hw` / PicoForge), no reflash.** The
  `LED_KIND` / `LED_PIN` / `LED_ORDER` build knobs (below) become *boot
  defaults*: a non-`none` build now compiles all three backends and, at boot,
  applies the data pin (`led_gpio`), driver (`led_driver` — 1=gpio / 2=pimoroni /
  3=ws2812, matching pico-fido / PicoForge), and an RS-Key vendor wire-order tag
  (`led_order`, `0x0D`) from `EF_PHY` — the same record that already drives the
  USB identity. The pin reaches the PIO state machine through a `match` over GPIO
  `0..=29` (embassy has no `PioPin for AnyPin`, but doesn't need one); the wire
  order is a runtime red/green swap, so one binary serves both RGB- and GRB-wired
  parts. New **`rsk hw`** command (`--led-pin` / `--led-driver` / `--led-order` /
  `--get`) does a read-modify-write of only the LED fields (any USB identity is
  preserved) and warm-reboots to apply. A `none` build stays headless and ignores
  the phy LED fields. `bcdDevice` `0x077A` → `0x077B`.

- **Selectable LED backend (`LED_KIND` build knob) — the indicator is no longer
  WS2812-only.** The status engine (boot/processing/touch/idle blink + the
  runtime-configurable colour/brightness in `EF_LED_CONF`) was already
  backend-agnostic; only the render half was hard-wired to the Waveshare's
  addressable WS2812. The render is now chosen at build time: `ws2812` (default —
  the addressable RGB on `LED_PIN`), `gpio` (a plain on/off LED on `LED_PIN`;
  hue/brightness collapse to lit/unlit, but the blink *pattern* still tells the
  statuses apart — so RS-Key now runs on boards with a simple LED, e.g. a bare
  RP2350 or Pico 2), `pimoroni` (a 3-pin PWM common-anode RGB, Pimoroni Tiny 2350)
  or `none` (headless). Only the selected driver and its PIO/PWM dependencies are
  compiled. `bcdDevice` `0x0778` → `0x0779`.

- **`LED_ORDER` build knob — the WS2812 wire byte order is now selectable.** The
  reference Waveshare RP2350-One is unusually **RGB**, the project default; but
  standard WS2812B parts (e.g. the TenStar RP2350-USB) are **GRB**, and driving
  one with the wrong order swaps red↔green (blue is unaffected). `LED_ORDER=grb`
  picks the standard order for such boards; `rgb` (default) keeps the Waveshare
  behaviour. Verified on a TenStar RP2350-USB (16 MB, WS2812 on GP22):
  `LED_KIND=ws2812 LED_ORDER=grb LED_PIN=22 FLASH_SIZE=16M`. `bcdDevice` `0x0779`
  → `0x077A`.

- **Hybrid post-quantum seed-backup channel — the vendor MSE key agreement is now
  P-256 + ML-KEM-768.** The seed-backup channel (`authenticatorVendor` `0x41`,
  `MSE`) is the one place the device hands out a normally non-exportable key — the
  32-byte master seed — so a recorded exchange is the prime harvest-now-decrypt-
  later target: break the ephemeral P-256 ECDH with a future quantum computer and
  the wrapped seed falls out. The handshake now accepts an optional ML-KEM-768
  (FIPS 203) encapsulation key in subCommandParams key 2; when present the device
  encapsulates to it and derives the channel key as
  `HKDF-SHA256("RSK-MSE-PQ-v1", z ‖ ss_mlkem, dev_pub ‖ ct)`, returning the
  ciphertext as response key 2. Both shared secrets feed the KDF, so the channel
  stays confidential unless *both* P-256 and ML-KEM-768 are broken (defense in
  depth — never PQC-only). Only the cheap `encapsulate` direction runs on-device;
  the host keeps the ML-KEM keypair and decapsulates. A host that sends no key 2
  gets the classical channel byte-for-byte, so existing hosts keep working.
  `bcdDevice` `0x0777` → `0x0778`.

- **`alwaysUv` (always require user verification) is supported.** `getInfo`
  advertises the `options.alwaysUv` flag (reflecting its state, `false` at reset)
  and the `toggleAlwaysUv` (`0x02`) `authenticatorConfig` subcommand. While enabled
  (flipped via `authenticatorConfig` toggleAlwaysUv, gated on a pinUvAuthToken with
  the `acfg` permission), every `makeCredential` / `getAssertion` requires a verified
  pinUvAuthToken — an up-only (touch) request is refused with
  `CTAP2_ERR_PUAT_REQUIRED`, even when no PIN is configured. The state persists until
  `authenticatorReset`, which clears it. Completes the FIDO conformance "featureful"
  CTAP2.3 profile's authenticatorConfig requirement. `bcdDevice` `0x0774` → `0x0775`.

- **`getInfo` advertises five optional informational members.** `transports`
  (0x09, `["usb"]`), `maxRPIDsForSetMinPINLength` (0x10, `8`),
  `remainingDiscoverableCredentials` (0x14, the live free resident-key-slot count),
  `attestationFormats` (0x16, `["packed"]`) and `maxPINLength` (0x1D, `63`). Purely
  informational — no behaviour change — and mirrored in the metadata statement (the
  FIDO conformance Authr-Generic test strict-compares each member to it).
  `bcdDevice` `0x0776` → `0x0777`.

### Fixed

- **CTAPHID: an init-type frame received mid-transaction is rejected as
  `ERR_INVALID_SEQ` regardless of its length field.** The `bcnt > maxMsgSize`
  check ran first, so a continuation frame whose sequence byte had the INIT bit
  set — the FIDO Conformance Tools' `HID-1 F-4` corrupts the last frame's seq to
  `CTAPHID_PING + 1` (0x82), leaving random payload bytes as the "bcnt" — usually
  tripped the length guard and returned `ERR_INVALID_LEN` (0x03) instead of the
  required `ERR_INVALID_SEQ` (0x04). The out-of-sequence check now precedes the
  length check. `bcdDevice` `0x0767` → `0x0768`.
- **U2F authenticate resolves the key handle before requesting a touch.** An
  unknown handle (wrong AppID / not minted by us) and a check-only (`P1=0x07`)
  request must be answered immediately — `0x6A80` and `0x6985` respectively —
  without user presence; we prompted for a touch first on `P1=0x03`, so a
  conformance negative test (`U2F-Authenticate F-2`) hung on the button and the
  stream of `UPNEEDED` keepalives desynced the tool's response reader (seen as
  "sequence out of order"). Shares the `0x0768` bump.
- **No `PROCESSING` keepalive before a fast U2F response.** U2F (CTAPHID_MSG) is
  quick apart from the touch wait, but the worker runs on a lower-priority
  executor, so the 100 ms keepalive timer could fire once before a near-instant
  reply (check-only, unknown handle) — and U2FHID hosts, including the FIDO
  Conformance Tool, read that stray `PROCESSING` frame as the response's first
  frame and desync (`U2F-Authenticate P-3`/`F-2`: "sequence out of order"). MSG
  now stays silent unless a touch is pending (`UPNEEDED`); CBOR keeps
  `PROCESSING` for its genuinely slow operations. `bcdDevice` `0x0768` →
  `0x0769`.
- **`CTAPHID_CANCEL` aborts an in-flight request's user-presence wait.** While
  the worker blocked on the touch wait the transport never read further frames,
  so a `CANCEL` sat unread until the (up to 30 s) wait ended — the FIDO
  Conformance Tool's `HID-1 P-10` (cancel during `makeCredential`) and `P-15`
  (cancel during `authenticatorSelection`) timed out. The transport now watches
  for a `CANCEL` on the active channel concurrently with the worker and signals a
  cross-executor abort; the cancelled command returns `CTAP2_ERR_KEEPALIVE_CANCEL`
  (0x2D). A `CANCEL` is also no longer acknowledged with its own frame (per the
  CTAPHID spec).
- **`authenticatorMakeCredential` input validation.** A non-text `rp.name`
  (`Req-2 F-2`) and a `pubKeyCredParams` entry missing its `alg` (`Req-4 F-4`)
  are now rejected instead of accepted.
- **`authenticatorMakeCredential` accepts `options.up=true`.** An explicit
  `up=true` is the default and now succeeds (`Req-6 P-3`); only `up=false`
  remains an `INVALID_OPTION` (`F-1`).
- **getAssertion withholds user name/displayName without user verification.** On
  a multi-credential discovery the response `user` map now carries only `id`
  unless `uv` is set (CTAP §6.2.2 privacy rule, `Discoverable P-2`); the full
  identity is returned once the user is verified. Applies to
  `authenticatorGetNextAssertion` too.
- **credentialManagement enumerateCredentials always reports `credProtect`.** The
  `0x0A` field was emitted only when a non-default level was set; it now always
  appears, defaulting to level 1 (`userVerificationOptional`)
  (`CredMgmt-EnumerateCredentials P-1`).
- **largeBlobs accepts `get=0`.** A read of zero bytes is valid and returns an
  empty fragment instead of `CTAP2_ERR_INVALID_PARAMETER` (`LargeBlobs-1 P-2`).
- **credentialManagement updateUserInformation keeps the credentialId stable.**
  Resealing a credential draws a fresh IV (nonce reuse is forbidden), so the box —
  and the resident id previously re-derived from it — changed, staling the
  platform's stored credentialId; a later `deleteCredential` with that id then
  returned `CTAP2_ERR_NO_CREDENTIALS` (`CredMgmt-UpdateAndDelete P-2`). The update
  now rewrites the credential in place, preserving its stored 42-byte resident id,
  and `getAssertion` returns that stored id instead of re-deriving it (CTAP2.1
  §6.8.5). The signing key / hmac-secret / largeBlobKey are still box-derived, so
  they rotate on an update — full stability needs a per-credential nonce and is
  deferred. `bcdDevice` `0x076F` → `0x0770`.
- **A `pinUvAuthToken` request while a forced PIN change is pending now returns the
  correct per-subcommand error.** With `forcePINChange` set (via `setMinPINLength`
  subcommand param `0x03`), both `getPinToken` (0x05) and
  `getPinUvAuthTokenUsingPinWithPermissions` (0x09) refuse to issue a token until the
  PIN is changed. The FIDO conformance ClientPin forcePINChange tests assert a
  *different* code for each: legacy `getPinToken` (0x05) → `CTAP2_ERR_PIN_INVALID`
  (0x31) (`ClientPin1-NewPin F-1`, `ClientPin2-GetPinToken F-5`); the
  permissions-based `getPinUvAuthTokenUsingPinWithPermissions` (0x09) →
  `CTAP2_ERR_PIN_POLICY_VIOLATION` (0x37)
  (`ClientPin2-GetPinUvAuthTokenUsingPinWithPermissions F-1`). Previously both
  returned `PIN_POLICY_VIOLATION`. The PIN verify itself still succeeds first, so the
  retry counter is untouched. `bcdDevice` `0x0773` → `0x0774` (0x05 fix); the 0x09
  branch followed at `0x0776`.

### Changed

- **Enterprise attestation: `ep` advertised + reflects state, type-1 eligibility
  enforced.** `getInfo` and the metadata statement carry the `ep` option (`false`
  until `authenticatorConfig` enableEnterpriseAttestation flips it `true`), so
  platforms and the conformance tool exercise the enterprise profile. EA is now
  performed only when warranted — platform-managed (type 2) for any RP,
  vendor-facilitated (type 1) only for an RP on a built-in list (empty in shipping
  firmware). Any enterpriseAttestation request now yields a basic_full (x5c)
  attestation: the org/EP cert + `epAtt` when EA is performed, or a non-enterprise
  basic_full with the device's own cert and no `epAtt` for a non-listed type-1 RP
  (CTAP2.1 §6.1.3, conformance Enterprise-Attestation F-6, which requires x5c). A
  request without enterpriseAttestation keeps the default self-attestation. The FIDO
  conformance test RPID is added to the type-1 list **only** under the
  conformance-only `ea-conformance-rpid` build feature, never in a shipped image.
  The metadata `upv` gains `{1,2}` and `{1,3}` and drops the non-MDS3
  `legalHeader`. `bcdDevice` `0x0770` → `0x0772`.
- **EdDSA (-8) and ES256K (-47) are no longer advertised in `getInfo.algorithms`
  or the metadata.** The FIDO conformance tool's shared `verifySignatureCOSE` maps
  only `-7`/`-35`/`-36` for elliptic curves, so it throws "hashFunction missing"
  verifying a packed self-attestation over an EdDSA or secp256k1 credential
  (`MakeCred-Resp P-06`). Both stay fully implemented — makeCredential negotiates
  `-8`/`-47` from a request's `pubKeyCredParams` — only the advertisement is dropped
  (the same approach as ML-DSA-44), leaving the advertised set at the
  tool-verifiable NIST curves ES256/ES384/ES512. getInfo, `authenticationAlgorithms`
  and `authenticatorGetInfo.algorithms` kept in sync (`tests/62`). `bcdDevice`
  `0x0772` → `0x0773`.
- **`getInfo` advertises the `authenticatorConfigCommands` member (`0x1F`).** It
  lists the supported `authenticatorConfig` (0x0D) subcommands —
  `enableEnterpriseAttestation` (0x01), `toggleAlwaysUv` (0x02) and `setMinPINLength`
  (0x03). The FIDO conformance AuthenticatorConfig suite requires it (the
  enable-enterprise-attestation test asserts the array contains `0x01`, the
  "featureful" CTAP2.3 profile requires `0x02`, and the suite's `before` hook reads
  it). Mirrored in the metadata statement. Shares the `0x0774` bump (`0x02` arrived
  with alwaysUv at `0x0775`, below).

## [0.2.4] — 2026-06-19

### Added

- **The `rsk` CLI can run without Nix.** A `tools/pyproject.toml` packages the
  CLI so it installs from any Python ≥ 3.9 toolchain —
  `uvx --from ./tools rsk …`, `uv tool install ./tools`, `pipx install ./tools`,
  or plain `pip`. The Nix dev shell stays the primary, pinned path; this mirrors
  its CLI runtime deps (`hidapi`, `cryptography`, `pyscard`, `fido2`,
  `mnemonic`, `shamir-mnemonic`) for hosts without Nix. See
  [tools/README.md](tools/README.md). Host-tool only; no `bcdDevice` bump.

### Changed

- **FIDO2 PIN entry is now uniform across the CLI.** Commands disagreed on how
  to take a PIN: most accepted only `--pin` (and aborted on a PIN-protected
  device when it was omitted), while `fido list-passkeys` and `fido set-pin`
  prompted interactively with no flag at all. Every PIN-gated command (`backup
  export`/`restore`, `audit log`/`verify`, `lock enable`/`disable`, `inventory
  verify`, `fido list-passkeys`/`set-pin`/`attestation import`/`clear`) now
  accepts the PIN **either** way — `--pin` flag **or** an interactive prompt —
  through one chokepoint (`rsk.common.resolve_pin`) that only prompts when the
  device actually has a PIN, so touch-only devices are never asked. Host-tool
  only; no `bcdDevice` bump.
- **The `rsk-tui` cockpit now routes PIN entry through one chokepoint too.** Its
  four per-action PIN steps collapsed into a single `App::gate_pin` +
  `Step::PinThenRun`, so "prompt for the FIDO2 PIN iff the device has one, else
  run" lives in exactly one place (mirroring the CLI's `resolve_pin`). PIN-vs-
  phrase collection in the modal flow is now explicit instead of a catch-all (a
  stray text input can no longer land in the PIN buffer), and the four
  `device requires a PIN` strings were unified. No behaviour change for users;
  host-tool only, no `bcdDevice` bump.

### Fixed

- **`rsk secure-boot` no longer refuses provisioning on a chip with a benign
  `LOCK_NS`.** `pages_locked()` read the whole OTP lock row, so a pre-set
  non-secure-page lock (`LOCK_NS=1`, `0x040404`) looked like a bootloader lock
  and wrongly blocked `load-key`; it now masks `LOCK_BL` specifically. Host-tool
  only; a mutation-proven regression test was added.

### Security

- **Transparency-log monitoring for our release signing identity.** A scheduled
  GitHub Action (`sigstore/rekor-monitor`) watches the Rekor log for entries
  signed under our release workflow's OIDC identity, so illegitimate use of it —
  a signature we did not produce — becomes detectable, complementing the SLSA
  Build L3 provenance. CI only; see `docs/supply-chain.md`.
- **OATH credential secrets are now sealed at rest.** Every other applet
  (FIDO, PIV, OpenPGP, rescue) AES-encrypts its keys before they reach flash;
  OATH alone stored its TOTP/HOTP shared secrets — and the SET CODE key — as
  plaintext TLV. They are now AES-256-GCM-sealed under the device `kbase`
  (`HKDF(serial_hash, kbase, "OATH/KEYS")`), the same device-seal the PIV slot
  keys use. A one-time boot migration re-seals any credential enrolled before
  this release, so existing accounts keep working. With the OTP MKEK burned, an
  extracted flash image no longer reveals OATH secrets. `bcdDevice` `0x0765` →
  `0x0766`.
- **The at-rest seal path is now enforced by types, not convention.** A slot
  that holds a sealed secret is a `KeyFid`, distinct from a plaintext `u16` file
  id, and the only writer that accepts one is `Fs::put_key(KeyFid, Sealed)` —
  where `Sealed` is produced only by a seal routine. A stray
  `fs.put(key_fid, raw_secret)` no longer compiles (asserted by a `compile_fail`
  doctest). This is the chokepoint whose absence let OATH ship its secrets in
  the clear; every applet's key FIDs were moved onto it.
- **Resident-credential RP domains are now boxed at rest.** A discoverable
  credential's `EF_RP` record stored the relying-party id (the site's domain)
  in cleartext, so a flash dump revealed the *list of sites you hold passkeys
  for* — a privacy leak, even though the keys themselves were sealed. The domain
  is now ChaCha20-Poly1305-boxed under the device seed (the same seal the
  credential body uses), with the rpId **hash** kept in cleartext as the O(1)
  lookup key. A boot migration re-boxes records enrolled before this release.
  Honest residual: the rpId hash remains, so a dump can still *dictionary-attack*
  guessable domains — but the plaintext site list is gone. `bcdDevice` `0x0766`
  → `0x0767`.

## [0.2.3] — 2026-06-18

### Changed

- **LED turns green (idle) as soon as the host configures the device**, instead
  of staying on the red boot status until the first applet command arrives. A
  healthy, enumerated key that nothing is talking to yet — e.g. a Linux host with
  no PC/SC daemon running — used to look dead (red) even though it was ready. A
  device-level USB `Handler::configured` callback now flips the status on
  configuration. `bcdDevice` `0x0764` → `0x0765`.

### Fixed

- **~90 s boot stall (LED stuck on the red BOOT status) on some RP2350 boards.**
  `FidoRng::new` seeds the HMAC-DRBG with 48 bytes from the hardware TRNG, and
  the embassy driver runs an autocorrelation health-check on every generated
  block — on a failed check it soft-resets and re-samples in a loop. At the
  default `sample_count` of 25, consecutive ROSC samples on a marginal unit are
  too correlated, so the check failed almost every time and seeding blocked a
  variable 30–105 s on **every** boot (init runs before the USB pull-up, so the
  device was simply absent from the bus that whole time — looked dead, worst on
  strict hosts). Raising `sample_count` to 1000 decorrelates the samples so the
  check passes first try: **~1.5 s boot, HW-verified** on the affected board.
  Entropy quality is unchanged — the NIST health checks stay enabled and the
  source is the same; the seed is just gathered reliably. `bcdDevice` `0x0763`
  → `0x0764`.

- **PIV tab *still* slow after the present-cache fix below: `GET METADATA` over
  empty key slots.** That bitmap guarded `read` and `size`, but `has_data` — a
  third absent-probe method — still called the backend directly, so a missing
  FID scanned the whole partition. PIV `GET METADATA` checks `has_data(slot)`
  first, and `ykman piv info` / Yubico Authenticator's PIV tab read metadata for
  ~24 mostly-empty slots (`9A/9C/9D/9E` + 20 retired), so each tab switch paid
  ~24 full scans ≈ 4 s of green-blinking even though every individual APDU
  answered in ~30 ms. `has_data` now consults the same bitmap → `O(1)` for an
  absent slot; measured `ykman piv info` **4.16 s → 0.26 s** (~16×) on hardware.
  `bcdDevice` `0x0762` → `0x0763`.

- **Slow applet listing (PIV especially), seen as long green-blinking when
  switching tabs in Yubico Authenticator.** A backend `read`/`size` of an
  *absent* file scanned the entire ~1.4 MB KV partition to confirm absence, so
  enumerating a sparse object range was `O(slots · flash)` — opening the
  Certificates tab probes ~25 mostly-empty PIV certificate slots, each a full
  scan. (OATH had the same class of bug, fixed earlier; PIV/others did not.) The
  filesystem now keeps a fixed present/absent bitmap of all FIDs (rebuilt on
  boot, maintained on every write/remove), so an absent `read`/`size` returns
  without touching the backend — `O(1)` instead of a full scan. `bcdDevice`
  `0x0761` → `0x0762`.

- **USB enumeration race at boot (first field report).** On a Waveshare RP2350
  the device would "blink red and not be recognised," recovering only after
  several replugs. `builder.build()` asserts the bus pull-up, so the host begins
  enumerating the moment the device attaches — but the task that answers control
  transfers (`usb_task`) was spawned only after a block of per-boot init (seed +
  attestation cert + OpenPGP DEK + flash writes, heaviest on a fresh device). The
  host enumerated into an attached-but-mute device and timed out the first
  descriptor request; a lenient host (macOS) usually won, a strict one often did
  not. Boot now completes all that init **before** attaching, and spawns
  `usb_task` immediately after `build()`, so enumeration is serviced with no
  blocking gap. `bcdDevice` `0x0760` → `0x0761`.

## [0.2.2] — 2026-06-15

No firmware change — `bcdDevice` stays `0x0760` and the eight `.uf2` images are
bit-identical to 0.2.0. This release ships the fixed, hardened release pipeline:
0.2.0 published its GitHub Release without provenance, because the SLSA
generator's "append the provenance to the release" model is incompatible with
GitHub's immutable releases (the late asset upload is rejected — even on a draft).

### Changed

- Build provenance now uses GitHub's native `attest-build-provenance`, generated
  from inside a **reusable workflow** (`release-build.yml`). Running the build
  and the attestation in an isolated, identity-bound reusable workflow raises the
  release to **SLSA v1 Build Level 3** (an inline attestation step alone is only
  Build L2). Each `.uf2` is attested keyless (Sigstore/Fulcio + the Rekor log)
  into the **attestation API** instead of being uploaded as a release asset, so
  it stays compatible with immutable releases. Verify with
  `gh attestation verify --signer-workflow …` (`docs/supply-chain.md`).
- All GitHub Actions bumped to their current major versions (off the deprecated
  Node 20 runtime).

## [0.2.0] — 2026-06-15

The cycle since 0.1.0. USB `bcdDevice` is now `0x0760` (incremented once per
firmware change along the way).

### Added

- **Own AAGUID + FIDO Metadata Statement.** The authenticator reports its own
  model identity (`2479c7bf-6b30-5683-9ec8-0e8171a918b7`, a reproducible UUIDv5)
  instead of the inherited pico-fido one, and ships a self-published FIDO
  Metadata Statement (`metadata/rs-key.metadata.json`) with a drift guard.
- **Supply-chain provenance.** Releases now carry SLSA build provenance
  (slsa-github-generator, keyless) and pass a release-time reproducibility gate
  that rebuilds all eight flavors bit-identical before anything is published.
- **Dependency review.** A `cargo-vet` gate (Mozilla / Google / ISRG / Zcash
  audits + recorded exemptions) blocks new unreviewed crates; a new
  `docs/supply-chain.md` documents the whole chain.
- **Versioned documentation site** — `main`, `develop` and tagged versions are
  published side by side with a switcher.
- **Kani proofs** that the OpenPGP import (BER) parser is panic-free and
  terminating, plus a CI guard that `flake.lock` stays in sync with `flake.nix`.

### Changed

- Every GitHub Action is pinned to a commit SHA, kept fresh by Dependabot.
- The physical-attack posture docs are reframed around the published RP2350
  hacking challenges (threat model / OTP fuses / limitations).

### Fixed

- **U2F routing.** A vendor-AID SELECT over CTAPHID_MSG no longer leaves a sticky
  applet selection that routed later U2F REGISTER / AUTHENTICATE / VERSION into
  `0x6D00`; the MSG selection is dropped on every CTAPHID_INIT.
- **OATH performance.** RESET / LIST / CALCULATE-ALL / lookup probed all 255
  credential slots, and each absent slot rescanned flash; they now touch only
  present credentials — OATH RESET dropped from ~39 s to ~0.5 s.
- **USB transport wedge.** Bounding the CTAPHID/CCID IN-endpoint writes stops an
  abandoned transaction from wedging the interface until a replug.
- The OpenPGP card-status self-test now follows GET DATA response chaining.

### Security

- **Constant-time audit fixes** — RSA base blinding on the raw path and
  constant-time OTP access-code comparisons (`docs/ct-audit.md`).
- **Fault-injection fences** on the PIN and secure-boot gates, so a glitched
  single comparison can't skip the check.

## [0.1.0] — 2026-06-13

First public release — an open-source security-key firmware for the Raspberry Pi
RP2350 (Cortex-M33), a behavioral reimplementation of the AGPL-3.0 pico-keys
family that keeps the "enterprise" features in the open tree.

### Security keys / protocols

- **FIDO2 / WebAuthn / U2F** — passkeys (discoverable credentials), second-factor,
  `ssh -t ed25519-sk`, hmac-secret and largeBlobs; user presence gated on the
  BOOTSEL button (the default touch build).
- **OpenPGP card 3.4** — sign / decrypt / authenticate; EC (Ed25519, NIST, brainpool)
  and on-card RSA keygen (2048/3072/4096) accelerated across both cores.
- **PIV** — X.509 slots, attestation, the Yubico management extensions; works
  through PKCS#11 / OpenSC and the OS-native stacks.
- **OATH (YKOATH)** — TOTP / HOTP credential store.
- **Yubico OTP** — slot programming and challenge-response over CCID, plus the
  HID-keyboard typing path.

### Enterprise features, in the open tree

- forceChangePin enforcement, a SHA-256-chained signed audit trail, an opt-in
  `fips-profile`, organizational attestation (import key + chain), and host-side
  fleet inventory / verification / offboarding tooling.

### Hardening

- Secure boot + anti-rollback (RP2350 OTP), keys sealed under an OTP-burned
  device root, and an at-rest soft-lock of the FIDO seed.

### Tooling

- The `rsk` CLI and the `rsk-tui` ratatui dashboard; guided primary + backup
  device pairing; secure-boot key-rotation tooling. Run without the dev shell via
  `nix run .#rsk`, `.#rsk-tui`, and a one-command flasher `.#flash`.

### USB identity

- The default build presents this project's **own** pid.codes identity
  (`0x1209:0x0001`, "RS-Key Security Key") — not a YubiKey masquerade. An opt-in
  `VIDPID=Yubikey5` flavor borrows the YubiKey identity for `ykman` / Yubico
  Authenticator interop.

### Assurance

- 39 fuzz targets, Kani proofs, a Miri pass, power-cut torture, bit-reproducible
  `nix build` images (per platform, per `flake.lock`), and a hardware-verified
  interop matrix ([docs/interop.md](docs/interop.md)).

### Release artifacts

- Eight firmware flavors (`up-button` × `advertise-pqc` × `fips-profile`), each a
  reproducible **unsigned** `.uf2` — on a secure-boot device, seal it with your
  own key before flashing (`nix run .#flash`, or see
  [docs/production.md](docs/production.md)).
- `SHA256SUMS` over every artifact, a keyless [cosign](https://docs.sigstore.dev/)
  signature of it, and a CycloneDX SBOM. See
  [docs/releases.md](docs/releases.md) to verify a download.

[Unreleased]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.9...HEAD
[0.4.9]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.8...v0.4.9
[0.4.8]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.7...v0.4.8
[0.4.7]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.6...v0.4.7
[0.4.6]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.10...v0.4.0
[0.3.10]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.9...v0.3.10
[0.3.9]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.8...v0.3.9
[0.3.8]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/TheMaxMur/RS-Key/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/TheMaxMur/RS-Key/compare/v0.2.8...v0.3.0
[0.1.0]: https://github.com/TheMaxMur/RS-Key/releases/tag/v0.1.0
