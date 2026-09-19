<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Changelog

All notable changes to RS-Key are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and **releases** are
versioned with [SemVer](https://semver.org/).

Two other version numbers live in the firmware and are deliberately **not** this
tag: the USB `bcdDevice` build counter (bumped on every behavior change), and
`FW_VERSION` — the YubiKey-compatibility version reported to host tools (5.8.0).

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

## [0.4.11] - 2026-09-08

The catch-up release, and the one where the instruments were audited harder than
the firmware — then it kept going for two more weeks, and the second half is one
defect repeated. Everything CTAP 2.2 and 2.3 added that RS-Key was missing is
here — including FIDO over the card interface, so `ykman` and `python-fido2` can
drive the same device the browser does — along with ML-DSA-87, a trusted display
that antialiases, and a PIN policy that finally refuses the shapes it always
claimed to. Then the store's own spelling of *absent* was read as a class rather
than as the site it was reported at: a flash read that failed and a record that
was never written answer the same `None`, and every gate whose absent arm means
*not provisioned yet* is in the sweep below. The rest is the verification layer:
the formal model replays against a real device's recorded state, and the gates
that hold *it* honest found that several earlier instruments had been proving
nothing at all.

**RS-Key is not formally verified.** Entries below say what evidence a change
added; none of them says a whole-system theorem exists. `scripts/claims_gate.py`
holds every page naming three or more registered properties to that sentence,
and to the statuses it quotes.

### TL;DR

If you read nothing else:

- **A flash read that FAILED was spelled "nothing is stored there", and closing
  that is the largest thing in this release.** `Storage::read` answers the same
  `None` for "no such record" and for "that read failed", and an absent record is
  how this firmware says *not provisioned yet* and *no gate configured* — so the
  two collapse where it costs most. One faulted probe re-seeded the factory PIV
  PIN, PUK and management key at an unauthenticated `SELECT`; another minted a new
  FIDO device seed at **boot**, over every credential derived from the old one;
  others handed a host every OATH secret, erased the tamper-evident audit trail
  and left it looking freshly initialised, and re-opened a sealed seed-export
  window. Swept as a class, not fixed where it was reported: `Fs::try_read` and
  its three siblings answer `Err` for a probe the backend could not complete, and
  **50 guards in 25 functions across four crates** take the fallible form.
- **The CTAP 2.2/2.3 gap against a YubiKey 5.8 is closed.** `encIdentifier`,
  `transportsForReset`, `longTouchForReset`, `pinComplexityPolicy`,
  `attestationFormatsPreference`, `encCredStoreState` with conditional mediation,
  and an enterprise-attestation RP-ID list you can actually aim. Two members are
  deliberately absent and say why at the skip.
- **Host tools read firmware `5.8.0` now, not `5.7.4`.** One default in
  `crates/rsk-sdk/build.rs` feeds getInfo, CTAPHID `INIT`, the management
  `DeviceInfo`, the PIV, OATH and OTP applets and OpenPGP's vendor `VERSION`
  command, so they move together; `FW_VERSION` still overrides it. The reference
  key RS-Key is measured against is a YubiKey 5.8.0 now, and `ykman` reads the
  newer `DeviceInfo` fields through defaults rather than version gates, so it
  needs no tag RS-Key does not emit. It is a compatibility constant, not a build
  identity — that is `bcdDevice`, below.
- **FIDO now answers on the card interface too.** CTAP 2.x as ISO 7816 APDUs over
  CCID, so tools that never learned CTAPHID reach the same authenticator.
- **`gpg`'s `kdf-setup` ran both OpenPGP references down to blocked
  ([#104](https://github.com/TheMaxMur/RS-Key/issues/104)).** The `00F9` DO went
  down the generic PUT DATA arm and was stored as opaque bytes, so the two
  password hashes it carries for exactly this purpose were never adopted — and
  `gpg` issues no `CHANGE REFERENCE DATA` of its own, so the card was the only
  party that could move them. The only way back was a factory reset. Sixteen
  questions run against a real YubiKey 5.7.4, sixteen identical answers.
- **Two defects broke OATH and Passkeys in Yubico Authenticator for Android
  ([#111](https://github.com/TheMaxMur/RS-Key/issues/111)).** On a
  Yubico-identity key, OATH answered `6A82` on every connection: Yubico's
  Android SDK selects by the full 8-byte instance AID, and since 0.4.10 a SELECT
  must name a prefix of a registered AID, while OATH and OTP were registered by
  the 7-byte form `ykman` sends. Passkeys never loaded either: the SDK's CBOR
  decoder takes no integer above 2³¹−1, so the 64-bit ids 0.4.10 put in
  getInfo's `vendorPrototypeConfigCommands` failed the whole response. Both
  applets take either form now, as a YubiKey 5.8.0 does. getInfo sends that
  member empty, where a YubiKey omits it; the ids still work. Checked against
  YubiKit's own AIDs and CBOR decoder, not yet on a phone.
- **ML-DSA-87 (COSE `-50`)** joins -65 and -44, byte-exact against the ACVP
  vectors. Still not advertised by default: shipping Firefoxes reject a getInfo
  carrying an unknown COSE id, and that is measured, not assumed.
- **The trusted display got a retained, DMA-driven compositor — and it
  antialiases, and its PIN pad can scramble.** One scene build records the
  laid-out frame, per-boot keyed tags keep unchanged 32×32 tiles on the panel, and
  a TX-only PIO link at 80 MHz takes a full frame's wire time to **15.36 ms**. The
  DMA bands live on the active stack, so that flavor has a gate row of its own for
  the half the linker cannot see. It also runs `clk_sys` at 160 MHz, **past the
  RP2350's rated 150**, because the PIO transport takes its wire rate from
  `clk_sys / 2` — the trade and what it does not cover are in
  [limitations.md](docs/limitations.md). Scrambling the pad is off by default: it
  costs muscle memory, and that trade is the owner's.
- **A relying party could pick a name that halted that display.** What a passkey
  list costs in drawing commands is a property of the *glyphs*, not of the byte
  count — 48 copies of `j` cost 14630 bytes where the mixed-ASCII label the
  capacity census used costs 10683 — and two of the 95 printable glyphs
  `Label::clamp` passes were already over the 12 KiB buffer, an unauthenticated
  `makeCredential` away from a panic on the screen whose whole job is to be
  trustworthy. The buffer is sized to the measured worst glyph now, and the census
  sweeps all 95 against every full-frame renderer instead of the one hand-picked
  label that let it certify a ceiling it never reached.
- **`ssh-keygen -O resident` no longer opens a PIN pad on a display board
  ([#107](https://github.com/TheMaxMur/RS-Key/issues/107)).** Before enrolling,
  OpenSSH looks for an existing credential with a silent `up:false` probe,
  adding `uv: true` when it was given no PIN and the key advertises `uv`. On a
  display board with a PIN that ran built-in UV — a modal PIN pad inside a probe
  the user never sees — and libfido2 gave up with `FIDO_ERR_RX`, so `ssh-keygen`
  stopped there. `uv` is dropped on such a probe now rather than refused:
  OpenSSH's `sk_enroll` goes on only when the probe answers `NO_CREDENTIALS`.
- **Every applet reset re-arms the at-rest scrub now; none did before.** FIDO,
  PIV, OATH and OpenPGP — five wipe-sweep sites, measured at zero — so a factory
  reset could tombstone a verifier still rooted in the public chip serial and
  leave `EF_HARDENED` latched over it, with no later boot ever lapping. The
  re-arm is deliberately best-effort, because on a wipe "leave the record in
  force" means leave the secrets live: it cannot refuse the reset, so a wipe that
  could not re-arm says so out of band and never in its own answer, and the
  re-arm survives a wipe that faults on the way. A tombstone is not an erase
  either — a dropped record's bytes wait in the ring exactly as a superseded
  one's do — so the two commands that revoke a pre-OTP credential by deleting it
  re-arm the lap too.
- **The `rsa` crate is out of the trust base**, and RUSTSEC-2023-0071 with it.
- **Three more fixes you may have felt.** An OpenPGP password charged its retry
  *after* the comparison, so a decrement lost to a power cut made the guess free;
  an RSA-3072/4096 PIV key is usable again under Windows' own minidriver; and a
  registration that failed part-way left an RP entry — and the discoverable-
  credential slot under it — that nothing ever reclaimed.
- **`age` has a route that needs no smart card, and now a guide that says so**
  ([`docs/guides/age.md`](docs/guides/age.md)). `age-plugin-fido2-hmac` goes over
  CTAPHID and asks only for `hmac-secret`, which every shipped build advertises —
  no PKCS#11, no reader name, no PIV slot spent. What it trades away in exchange
  is on the page.
- **A downgrade-fix release says so in a form a flasher can read**
  ([#100](https://github.com/TheMaxMur/RS-Key/issues/100)). The project signs no
  images and assigns no epochs, so all it can do is flag which releases fix a
  downgrade-exploitable bug — and that flag was a sentence in a changelog. It is a
  machine-readable line in the release body now, spelled in
  [`docs/anti-rollback.md`](docs/anti-rollback.md) and held by a gate. Absence is
  the answer, not "unknown".
- **`bcdDevice` is `0x09D6`.** A firmware-behaviour change bumps it; the counter
  counts builds, not features. The row that holds it could not tell an entry
  recording a bump from a file that merely moved, and three shipped builds went
  through that hole.

Everything else is grouped below in the usual sections, `Security` and
`Internal` last — 311 entries, most of them in `Fixed` and `Security`, because
the sweep above is written out site by site. The `Internal` one is where the
instruments that could not fail are written down, each with what it missed.

**This release is a downgrade-fix, and carries the marker that says so.** Every
image the project has published before it reads a flash probe that *failed* as a
record that was never written, and the entries below measure what that buys
somebody who can produce one — the factory PIV PIN, PUK and management key
re-seeded at an unauthenticated `SELECT` among them. So if you run secure boot,
raise your own floor by one after flashing: seal with `--rollback <your counter +
1>`. The project assigns no epoch and a tool must not burn one on your behalf —
the release carries the flag, the decision stays yours
([anti-rollback](docs/anti-rollback.md)).

<!-- @increase-anti-rollback-epoch{"reason": "an older image reads a failed flash probe as an absent record, which re-seeds the factory PIV PIN, PUK and management key at an unauthenticated SELECT"} -->

> ### ⚠️ Upgrading a 16 MB key provisioned before 0.4.8 still wipes it
>
> **Export your seed first** ([seed backup](docs/guides/seed-backup.md)). 0.4.8
> moved the store 4 KB down on 16 MB parts to clear the RP2350-E10 block, so a
> key provisioned by an older 16 MB build comes up factory-empty. The `display`
> and `16mb` flavors and the `abrobot-16m` / `waveshare-touch-lcd` presets are
> the affected ones; **4 MB and 2 MB keys upgrade in place.**

### Added

- **`age` encryption has a route that needs no smart card, and now a guide that
  says so ([`docs/guides/age.md`](docs/guides/age.md)).** The only `age` story
  the docs told was the PIV one, and it comes with a caveat that has nothing to
  do with the card: `age-plugin-yubikey` matches on the "Yubico YubiKey" reader
  name, so the stock RS-Key build needs `opensc-pkcs11.so` or the opt-in
  `VIDPID=Yubikey5` image before it is even seen. `age-plugin-fido2-hmac` goes
  over CTAPHID and asks only for the `hmac-secret` extension, which every
  shipped build advertises — no PKCS#11, no reader name, no PIV slot spent, and
  the credential it mints is non-discoverable, so the credential store is
  untouched. The page carries the `secretspec` layer on top of it, and the
  trade the FIDO2 route makes in exchange: `hmac-secret` unwraps an `age`
  identity into host memory, where PIV keeps the private key on the card, so
  this one gates access rather than confining the key.
  Measured against `tools/emu` by reproducing the plugin's CTAP exchange
  call-for-call from its source: the `getInfo` filter it applies passes, its
  `makeCredential` is served for `es256` and `eddsa` and refused for `rs256`
  (RS-Key advertises no RSA), and its `getAssertion` returns the deterministic
  32-byte output it checks for. `secretspec`'s `age` provider was driven
  through `set`/`get`/`run` and does spawn the plugin for a plugin identity.
  Not measured, and the page says so: the plugin against a real board —
  `libfido2` wants a USB HID device and the emulator is a socket.

- **A downgrade-fix release says so in a form a flasher can read
  ([#100](https://github.com/TheMaxMur/RS-Key/issues/100)).**
  [`docs/anti-rollback.md`](docs/anti-rollback.md) already made this the
  project's one job — there are no project-signed images, every owner signs and
  picks their own floor, so all the project can do is flag which releases fix a
  downgrade-exploitable bug — but the flag was a sentence in a changelog. It is
  now also a one-line HTML comment in the release body, named
  `increase-anti-rollback-epoch` and optionally carrying a `reason` for the
  owner; [`docs/anti-rollback.md`](docs/anti-rollback.md) spells both forms, and
  they are deliberately **not** spelled here — the release step greps this file's
  section as plain text, so an example written to explain the format would flag
  whatever release the entry sits in. Absence is the answer, not "unknown": a
  release without it is not a downgrade-fix. It stays a recommendation to raise
  *your* floor by one — the project assigns no epochs and a tool must burn
  nothing on its own.

  It is written in this file, inside the released version's section, and
  `release-build.yml` copies it into the body. **Lifted out of the FULL section,
  not left to survive the shortening path**: a section over GitHub's 125000-char
  body limit is cut back to its TL;DR, so a marker written at the end of a long
  release — the release most likely to have one — would have been dropped exactly
  when it mattered. A test runs the workflow's own shell over a fixture past the
  limit and reads the marker out of the result; deleting the lift turns that one
  case red and leaves the short-section cases green, which is the shape of the
  behaviour it is measuring.

  `scripts/rollback_marker_gate.py` is a new `check.sh` row, because a marker is
  invisible when it is wrong — an HTML comment renders as nothing whether or not
  a tool can parse it, so a typo here, a drifted grep in the workflow and a doc
  example the parser would reject all fail the same silent way, on a release,
  after the tag is pushed. It parses every marker in this file, reports a
  near-miss rather than skipping it (a space before the metadata, a `reason` that
  is not a string, an unknown key), holds the workflow's pattern to the same
  spelling, and requires both documented forms to appear in the docs and to
  parse. Twenty-two mutations in its table, and the parser is deliberately
  STRICTER than the readers: the workflow's grep and a third-party tool are
  lenient, and what the project must not do is publish a second spelling.

- **The PRF round trip a password manager depends on had no test.**
  `hmac-secret-mc` (CTAP 2.2 §12.5) lets a platform read the PRF value at
  registration time; the follow-up assertion reads it again, and a vault key is
  those two being equal. They travel different code paths — makeCredential's
  key-derivation input is the credential box or the resident id it has just
  minted, getAssertion's is whatever the lookup found — and §12.5 selects a
  different half of `cred_random` off the response's UV bit, so both ceremonies
  have to agree on both. Nothing held them to it: `hmacsecret_tests.rs` pins the
  UV split inside `eval`, and `tests/24_extensions.py` drives an assertion with
  no PIN at all, so the pair was never compared. Two conformance cases drive it
  through `process_cbor` now — the value read back on the assertion is the one
  registration returned, and a UV registration does **not** share a `CredRandom`
  with an unverified assertion, which is what stops the first case holding
  vacuously.

  Written while looking for
  [#109](https://github.com/TheMaxMur/RS-Key/issues/109), which they do not
  reproduce: the shipped answers agree across pinUvAuthProtocol 1 and 2, one and
  two salts, `allowList` and discoverable, and credProtect 0/2/3. One thing the
  new case did surface, and it is behaviour rather than a defect — registration
  spends the pinUvAuthToken it rode in on (GHSA-wqjm-653g-hgw3), so the follow-up
  read needs a fresh one, which is what a platform's second PIN prompt is.

- **The counter/main partition table is derived from the applet crates now, and
  every hand-written copy of it is held to what they say.**
  `rsk_store::is_counter_fid` decides which partition a record is written to and
  read back from, and it is a `matches!` over four bare literals whose named
  homes are in three other crates: `EF_COUNTER` and `EF_CRED_CTR` in `rsk-fido`,
  `EF_SIG_COUNT` in `rsk-openpgp`, `COUNTER_FID` in `rsk-vendor`. Nothing linked
  a literal to its constant, so the table and the constants drifted with no
  compile error — and the set has already moved twice in copies nothing derived:
  `EF_CRED_CTR` joined the table at `0x0821`, after `0x081D` had been writing
  that FID to the main partition, and `fuzz/fuzz_targets/power_cut.rs`'s mirror
  listed three of the four while its selector was `& 7` over nine entries, so
  the ninth — `0xCC01` — could never be written by any input while the sweep
  asserted it absent on every one. A record on the wrong side reads absent from
  the partition it is fetched from while its old value stays live in the other
  ring, and every `for_each_key` yields a copy nothing can delete.

  `scripts/partition_routing_gate.py` reads the constant NAMES out of the doc
  comment over `is_counter_fid` and resolves each to a `const … : u16` in a
  crate that is **not** `rsk-store`, then holds all four copies to the values
  that come back: that doc comment's own numbers, the `matches!` arms read out
  of `is_counter_fid`'s own body, the two loops in
  `crates/rsk-store/src/tests.rs` — found by what they assert rather than by the
  test's name, which spells a cardinal of its own — and the fuzz mirror's
  `FIDS`, a superset there, plus the rule that every index into it ENDS in
  `% FIDS.len()`, which is the half a list check cannot see. An arm the reader
  cannot parse is reported rather than skipped, and a doc comment naming fewer
  than three constants trips a floor, because a derivation that resolves nothing
  compares an empty set to an empty set. The one tree change it needed is that
  comment: the vendor counter was described and not named, so `COUNTER_FID` is
  spelled there now.

  Driven through the `check.sh` row, exit taken with no pipe: a literal changed
  in each of the four copies, a copy dropping a member, a fifth constant named
  over the table and listed nowhere, a constant renamed at its home, the
  selector masked back to `& 7`, and a member slid into the "must stay in main"
  loop — each `rc 1` naming that copy and that direction, each restored
  byte-exact, and the clean tree `rc 0`; run under `check.sh`'s own
  `set -euo pipefail` and `run()`, the red row stops the script before the next
  one.

  An adversarial review then found **six ways past the first version**, three of
  them the guard's own subject: the reduction was a SUBSTRING test, so
  `((b >> 3) as usize % FIDS.len()) & 7` reintroduced the exact defect the row
  exists for at `rc 0`, as did `% FIDS.len() / 2`; the `matches!` and the `FIDS`
  array were each read by the FIRST match in their file, so a decoy above either
  one let the real copy misroute `0xCC01` at `rc 0`; and one reduced `let`
  vouched for every `FIDS[index]` in the file. It also measured four false reds
  whose message stated something untrue — an `#[inline]` between the doc comment
  and the function read as "has no doc comment", a `pub(crate)` or
  `= SIG_BASE` home as "no crate defines it", an inlined reduced index as "never
  indexes `FIDS`", and the drift story's own `0x0821` — written directly above
  `is_counter_fid`, which is where it belongs — as "the table and the applet
  crates have drifted". All ten redden or go green correctly now, and three
  clauses that survived their own mutation table (`matches!` missing, `FIDS`
  missing, a loop missing) have cases. The table is
  `scripts/test_partition_routing_gate.py`, 34 cases, six of them controls that
  must stay GREEN.

  What the row deliberately does not decide is whether a FID *belongs* in the
  counter partition — that is `rsk-store`'s judgement, and dropping a member
  from the doc comment and every copy in one edit is green — and the ROSTER is
  that doc comment, so a hot record declared at its home and named nowhere over
  the table derives nothing. It is the derivation `assurance/platform.toml`'s
  `PLAT-STORE-004` asks for, and that row's `discharge` says so instead of "no
  script does"; its `status` stays `pending`, since both limits above are what
  its statement is about and an `evidence_commit` cannot name a commit yet.

- **The real-power HIL run asks the board whether the reset had started, and
  refuses to call a cut a tear until it answers.** `PLAT-FLASH-001`'s discharge
  is "a recorded PASS of `tests/29_reset_power_cut.py`", and `main` asserted
  only that the device was fail-closed after the reboot. A device on which the
  reset never began is fail-closed for free, so a cut landing before the RESET
  request reached the board satisfied every assertion and printed PASS —
  driven, not reasoned: with the new gate removed, a cut at t=0 and a write the
  host stack buffered into a void both come back `PASS`, exit 0.

  The device settles it. `rsk_usb::ctaphid`'s `run_with_keepalive` is entered
  only after the whole CBOR request has been reassembled, and it writes its
  first `CTAPHID_KEEPALIVE` one `KEEPALIVE_MS` (100 ms) later, so one frame
  carrying `STATUS_PROCESSING` says the request arrived AND the handler had
  been running that long; `STATUS_UPNEEDED` says the opposite — a touch
  ceremony, which stands ahead of every flash write in `reset`. Without a
  `PROCESSING` frame the run is now `INCONCLUSIVE` rather than PASS. It is not
  proof that an erase landed: nothing on this wire separates the ceremony's
  return from `wipe`'s first tombstone, and the signal exists at all only
  because this operation is slower than 100 ms — 487.2 ms measured on the board
  the row cites. The relay's default delay moves 25 ms → `2 * KEEPALIVE_MS`,
  since at 25 ms no cut can be confirmed at all.

  Each cut also appends one JSON object to a record — one run is one cut, so a
  sweep is a series of runs — defaulting outside the checkout, with
  `RSK_POWER_CUT_LOG` to aim it at a file meant to be committed. Four instants
  go in, none of them the moment the supply went: when the device was first
  seen inside the reset, the newest frame that came back (a LOWER bound, and an
  empty read is not a frame — hidapi returns an empty list on a timed-out read
  rather than raising), the sender's transfer death, and the host-observed
  disappearance. The transfer death bounds the cut only when the handle itself
  failed; one that died of `ctaphid.read`'s own 20 s budget is recorded as
  bounding nothing, because it does not — driven, it otherwise reports a cut
  269 ms before the tear, at a verdict that excludes it. The record is written
  from `cut_during_reset`'s `finally`, in its own `try`, over a directory it
  creates: so a relay that failed, a key that never disappeared and a key that
  never came back are recorded too, and a record that cannot be written costs
  the line instead of replacing the assertion underneath it.

  The manual prompt is unchanged, and that is a decision rather than an
  omission: the `CUT POWER NOW` line reaches the operator at most 0.11 ms after
  the window opens — the widest value over every run measured across three
  sessions, where an earlier draft quoted "under 0.1 ms over seven runs" and
  two of the first twelve were not. Stated as a ceiling and not an interval
  because the floor carries nothing and kept moving: a later session read
  0.006 ms. So a 200–300 ms reaction to it lands inside the
  487.2 ms window and above the 100 ms floor, where a yank riding the Enter
  press lands at ~0 ms — under the floor, in the one part of the window this
  instrument cannot tell from a cut that never reached the board. That part is
  not small and `docs/reset-refinement.md` now says what it costs: the handler
  starts at 0 and the confirmable band opens at 100 ms, so the first
  `KEEPALIVE_MS` of `reset()` — `request_rescrub` and the first tombstones — is
  un-PASSable by construction. On a simulated board over a 1 ms grid the flip
  is at the floor exactly — last `unconfirmed` 100 ms, first `torn` 101 — and
  a real board adds USB and host latency nothing here measures, so the
  false-red band starts at 100 ms and ends somewhere above it this cannot
  name. The 200 ms default is 100 ms clear of the floor.

  Two repairs ride along, both inside the same instrument's blast radius.
  The read comment saying the device "sends one upfront keepalive, not a
  stream" — it streams one every `KEEPALIVE_MS` and the first is not upfront,
  and that sentence is why the signal read as unavailable — is fixed in BOTH
  copies, `tests/ctaphid.py` and `tools/rsk/ctaphid.py`. One site was left
  alone in an earlier draft on the grounds that it is a different package; the
  tree's own rule is to sweep a defect by class rather than by site, and the
  `tools/rsk` copy contradicted itself in place, three lines from its own
  `KEEPALIVE_DEADLINE_S = 120` comment describing the stream. No
  `tools/rsk/__init__.py` version bump rides with it: CONTRIBUTING.md scopes
  that to a **user-facing** change, and a comment reaches no build a `pipx`
  user could be stale against. And `SEC-FIDO-006A`'s and `SEC-FIDO-006C`'s
  references to the sibling clauses' folded assertion were bare `:NNN` outside
  backticks, a form `citation_gate` reads as nothing at all — and which, once
  backticked, would have resolved against the last file their paragraph named
  instead. They are spelled in full now, and `formal/citations.lock` carries
  the lines that prove the gate can see them.

- **The cut instrument is a gate row, and the keepalive it trusts has to be
  ours.** Three of the guard's clauses were falsified by nothing: a review drove
  a board that never saw the RESET, with `PROCESSING` keepalives arriving on
  channel `aabbccdd`, and got `verdict: torn`, `wipe_observed: true`, PASS at
  exit 0. `TappedHid.read` tested the KEEPALIVE command byte and read the status
  at offset 7 without ever comparing `frame[0:4]` to the channel it had asked on
  — and hidraw and IOHIDManager hand every input report to every open handle, so
  a second host process with a slow CBOR in flight is enough. The tap is scoped
  to `cid` now (the same reason `ctaphid_init` matches its nonce), frames on
  another channel are counted rather than credited, and a run refused for that
  reason says so. `cut_lower_ms.last_frame` is deliberately NOT scoped: any
  frame on any channel is the board answering, which is all that bound claims.

  The falsification lives in the tree instead of a scratchpad. `tests/29_*.py`
  is board-only and no `check.sh` row runs it, so the whole guard could have
  been deleted with the gate green — the shape `scripts/test_sram_residue_dump.py`
  already covers one script over. `scripts/test_reset_power_cut.py` is that
  table: 58 checks over 26 scenarios against a model of hidapi's contract, and
  25 mutants that each name the checks which must go red for them, so a kill is
  read by WHICH assertion fell. It runs in the `pytest (gate scripts)` row in
  ~23 s, five of which are one scenario waiting out the subject's own
  `worker.join(5)`. Three defects it now catches were invisible to the scratchpad version:
  `processing_at()` answering the LAST keepalive rather than the first (the
  field is `first_keepalive` and the docs call it the earliest instant),
  that number replaced by a hard-coded `0.0`, and the `CTAPHID_KEEPALIVE` test
  deleted — which the old fake board could not see, because it only ever
  returned one response body, and a real device answering CTAP `0x01` to the
  RESET donates a byte 7 that reads as `PROCESSING`.

  And a roster for it, because the family had none. `test_gate_scripts.py`
  holds every guard to a mutation table, but both halves of that roster are
  about `check.sh` ROWS — and a board-only script is not one, which is why it
  needed a table in the first place. Measured: with the new table truncated to
  its SPDX line, `python -m pytest scripts -q` was rc 0, 70 passed, the same as
  the control. `BOARD_TABLES` names the two of them — this one and
  `tests/54_sram_residue.py`'s, which sat in the same blind spot — and asserts
  the opposite direction too: `check.sh` must NOT grow a row for a script that
  needs a real supply cut. The three counts this entry publishes are held
  against the tables themselves by a case in the new file, for
  `run_count_gate.py`'s reason one region over: a number whose only copy of the
  truth is the moment somebody typed it.

  Four smaller repairs to the same instrument. An `INCONCLUSIVE` now says WHICH
  of its three worlds it is in — a board that ANSWERED (`0x30` past the CTAP 2.1
  §6.6 window comes back well under the keepalive floor, and the old remedy,
  "cut later than 100 ms", was the wrong advice for it), a board still waiting
  for a finger, or a cut that arrived before the request. `STATUS_UPNEEDED` was
  assigned and never read; it is what tells the second world from the third. The
  record carries a `run_id`, printed beside `PASS` too, and a `records` field
  saying in as many words that the verdict is the CUT's: it is written before
  `main`'s post-reboot assertions, so a run that FAILED them leaves the line a
  passing run leaves, and the pasted record cannot be read alone. The write and
  its console summary have their own scopes, because one `try` spanning both
  printed "no cut record written" over a record already on disk. And the default
  record path is per-uid, created `0700`, appended through `O_NOFOLLOW`: it is
  a predictable name in a shared temp, and unlike `tests/54_sram_residue.py` it
  cannot use a fresh `mkdtemp`, because a sweep that enumerates its delays needs
  the lines to accumulate in one file.

- **The boot-hardening module's three mutation switches are co-mutants now, and
  the exclusion that hid them was covering two sites nobody had opened.**
  `formal/comutants.toml` pairs every model mutant with a real Rust patch that
  must make a named host test fail — 76 entries, and not one of them was
  `RSKeyBootHardening`'s. The mechanism was worse than an omission:
  `comutate.py`'s `PREFIXES` closes the world over the prefixes it lists, and
  `BootMut_` matched none, so the family was invisible in BOTH directions — no
  "configuration without an entry", no "entry without a configuration" — while
  `scripts/comutate.py --lint` printed ok on every gate run.

  The exclusion's stated ground was that two of the three defended sites live in
  `firmware/`, which has no host tests by construction. **One did.** The
  scratch-word carry's model conjunct is `Boot`'s `lock' = recorded`, and that
  assignment is `restore_pin_lock` in `crates/rsk-fido/src/state.rs:449-452`;
  `firmware/src/pin_lock.rs` holds the register encode, not the restore. The
  marker-after-lap order really was in `firmware/` — where a patch scores
  `build-broke` and never a kill — which is why the entry under *Changed* moved
  it first.

  All three measure `killed`, each failure read for its DIRECTION rather than
  its colour: the marker SURVIVES a re-key that should have cleared it; the
  marker is PRESENT over a torn lap; a live sub-limit batch is ERASED by the
  restore (`left: 0 right: 2`). `BugPartialLockCarry` is patched conditionally
  on `engaged` for that reason — the model's switch diverges only at
  `recorded = "batch"`, and an unconditional drop killed on an assertion whose
  model image is unchanged behaviour, which is a kill for the wrong reason. The
  roster is **79 entries: 75 executable patches killed, four unreachable**, and
  `SEC-BOOT-001` / `SEC-BOOT-002` leave `co = 0` for 2 and 1.

  `scripts/test_comutate.py` drives an unregistered `BootMut_*.cfg` through
  `lint()` so the prefix tuple is wiring a test holds, not prose.

- **The bounds table is emitted from the bundles instead of typed beside them.**
  Stage 4's exit asks that the scope table's content be *derived* from the slice
  bundle. It was not: fourteen rows sat under `The bounds` in
  `docs/authorization-slice.md`, `grep -rn "authorization-slice" scripts/*.py`
  found no reader, and six mutations driven across eight gates were exit 0 on
  every one — a docs bound moved from 5 to 9999 while the bundle still said 5,
  a docs `model Channels` moved to 77 while the `.cfg` still assigned 2, both
  bundle values moved while the docs stood still, a row renamed after a constant
  that does not exist, and a row deleted outright.

  `scripts/bounds_gate.py` now writes `docs/assurance-bounds.md` from
  `assurance/bundle/*.toml` and byte-diffs it, the shape `evidence_gate.py`
  already uses. It renders **every** `bound_*` key of **every** bundle —
  attributed to its property, its `[[method]]` obligation and its artifact — and
  which bundles those are is measured rather than chosen: all eight are
  `p0-launch` rows of `assurance/configurations.toml`, and the nine rows of that
  tranche with no bundle are derived onto the page rather than listed in it.

  Two things it deliberately does not hide. The consequence column — *what stops
  being proved* — belongs per bound and is carried as `stops_<name>` beside
  `bound_<name>`, the way `shipped_relation` already travels with a method row;
  **no bundle carries one yet**, so the page prints the shortfall as a number and
  falls back to each row's `shipped_relation` printed under its table. And three
  of the fourteen deleted rows named no bundle key at all — the two
  `cfg(not(kani))` compile-time assertions, the symmetry argument and the
  credential cardinality — so they are gone rather than silently kept, which is
  what "derived from the bundle" costs. A fourth was stale: the at-call-site
  harness row still read "to be chosen" while the bundle recorded its four
  bounds.

  The guard closes the parallel-writing direction too, in both spellings: the
  slice page's section must carry no table of its own and must say where the
  table went, and the table's header may appear in no other tracked markdown.

- **The two applet-policy properties with no threat behind them have one.**
  `SEC-POL-003` (a key surviving a change of its slot's algorithm attribute) and
  `SEC-POL-006` (a Yubico OTP's replay position) were `[[untraced]]`
  `missing-clause` findings: the page stated neither threat in any form, so both
  read as "against the threat model" and named nothing.
  `docs/threat-model.md` gains `TM-HOST-ALGO-CHANGE` and `TM-HOST-OTP-REPLAY`
  under the hostile-host section, `FLOOR_CLAUSES` moves 48 → 50 and
  `CEILING_UNTRACED` 3 → 1 in the same diff, and the finding register is down to
  the one row whose verdict says the clause may never be written at all.

  **Both clauses were verified against the code before they were written, and
  they are weaker for it in ten places.** Three sentences never reached the draft:
  an at-rest erase (the store's append-only caveat already governs that), an
  unconditional "a counter never repeats", and a rule that would have covered
  `TERMINATE DF`, whose sweep runs in flash-ring order and can leave a key beside
  a cleared attribute when it fails partway. Seven more were weakened when an
  independent review read the same code again — and that is the finding worth
  keeping, because every one of the seven had already been checked once. The
  attribute is read at operation time for the RSA-versus-EC byte and nothing more,
  so the curve and the modulus size come from the stored blob and only a
  *within-family* change goes undetected; a cross-family one leaves the blob
  unparseable and the operation fails. The two-step RSA generate reads the
  attribute when it starts the prime search and not again when it stores the key,
  which the applet does not close and the worker's one-command-at-a-time dispatch
  does. On the OTP side: a freshly configured slot persists its counter on the
  first press with no session wrap; of the eight paths that write the counter only
  two advance it, and one of those two is open-coded beside the module that owns
  the step; the cold-boot bump skips a slot whose sealed read faults and
  discards a re-seal the store refuses; and the residual list is six, not
  four — the sixth is the swap above, which the review of these very clauses
  found.
  All of it is named in the clauses rather than rounded away, because a threat
  model stronger than its firmware is the one direction this page may not be
  wrong in.

- **Four of stage 10's eleven platform-assumption categories had a name in the
  vocabulary and no row anywhere.** `scripts/platform_gate.py`'s `CLASSES`
  already listed `trng`, `timers`, `multicore-xip` and `display`; nothing used
  any of them, so "no platform statement without a registry entry" was satisfied
  over a set that did not contain the entropy source, the clock every timeout
  rests on, the core-1 pause around flash erase, or the panel. `PLAT-TRNG-001`,
  `PLAT-TIMER-001`, `PLAT-XIP-001` and `PLAT-DISPLAY-001` are written, each with
  its owner, its route and its failure direction. The registry is 32 rows over
  33 derived candidates now, 30 of them pending.

  What they cannot do is force themselves: none of the four derivations produces
  a hardware peripheral, so all four are hand-written with no `covers`. That is
  the honest shape and it is also the weakness, and it is said on the page.

  `PLAT-XIP-001` is also a correction. `unsafe:firmware/src/core1.rs` was claimed
  by `PLAT-TOOLCHAIN-002`, whose statement is about `unsafe` upholding an
  invariant the compiler cannot check — a different question from whether the
  silicon pauses core 1 for the whole of a flash erase. The row is separate now
  and says why.

- **`check.sh` compiled a display image no package ships.** `build firmware
  (display)` set `LED_KIND=none` and left the flash geometry at the default
  4 MB, while `nix/firmware.nix` gives `firmware-display` `flashSize = "16M"`
  and `ledKind = "none"` together. The row builds `FLASH_SIZE=16M` now. The
  matrix column's own settling question had named this; it is updated to say
  that the BUILD half is answered and the EVIDENCE half is not — `Display.cfg`,
  the `rsk-ui`/`rsk-display` host tests and the three co-mutants all still run at
  the default geometry, and one of them runs in `rsk-fido` with no display
  feature at all. The three `SEC-DISP-*` cells stay `gap` for that reason.

- **The delete ledger carried the record half of the contract and not the value
  half.** Stage 5A п.6 of the formal programme asks the `Fs` contract to
  distinguish three outcomes — "value removed, metadata left", "both removed",
  "the medium refused" — and to name which each `force_delete` site requires.
  The three are already typed in `rsk-fs` as `Removal { value, record }`, and
  `assurance/deleters.toml` already recorded the record half in its `metadata`
  field. What nothing recorded is that the VERBS differ in the value half:
  `delete` and `delete_key` skip the backend removal when the present cache
  reads absent, `force_delete` and `force_delete_halves` do not.

  `scripts/deleter_gate.py` derives that from the verb — not a new field, because
  a field a caller could set independently of the call it describes is a second
  copy of the call — and holds one rule on it: a `wipe-sweep` site may not use a
  conditional verb. The reason is in `force_delete`'s own rustdoc: a
  re-enumerating wipe reads the backend directly, so a delete that no-ops on a
  torn-migration false-absent key keeps re-finding it and the wipe does not
  terminate. Measured: 43 sites, **33 conditional and 10 unconditional**, and all
  five `wipe-sweep` sites are already on `force_delete_halves` — so the rule is a
  pin, not a repair.

- **The image has a heap, and until now nothing held that surface.**
  `firmware/src/main.rs` declares `#[global_allocator] static HEAP:
  embedded_alloc::LlffHeap` over 128 KiB — `docs/unsafe.md` site 4 is its
  initialisation — so AGENTS.md's "no_std, no alloc" is a rule about new code and
  not a description of the tree. A second allocator, or a `malloc` arriving
  through a dependency, was invisible.

  `scripts/elf_gate.py` + `assurance/image.toml` + the `check.sh` row `image
  segments and allocator` close stage 11A's ELF-segment and allocator/FFI works
  for the DEFAULT profile: every LOAD segment's run AND load address inside a
  `firmware/memory.x` region, none of them overlapping the KV store the partition
  table fences from BOOTSEL and nothing fenced from the linker, the vector table
  at the FLASH origin, the entry point inside FLASH, exactly the registered
  writable-executable segment, exactly the registered allocator symbols, and no
  undefined symbol in a fully linked image.

  Measured on the shipped image: 5 LOAD segments over 4 regions, 1
  writable-executable (`.data`, deliberately — it carries the routines that must
  not run from XIP flash, and a blanket "no W+X" rule would be red on a correct
  image), 3 allocator symbols, 0 undefined. The row sits beside the constant-time
  one and for the same reason: the 16 MB, display and no-touch builds below
  overwrite that path. The other profiles are a named gap in the registry, not a
  silent one.

  **…and what compiled it is held too, after an audit found the sentence that
  said so was false.** `ct_gate.py` published the MAJORITY DWARF producer as
  "built by" and its comment said `elf_gate.py` held the whole set; `elf_gate.py`
  had no producer code at all. Measured on a default-profile build: **165 compile
  units, 164 from the pinned rustc and one from a 2021 nightly** — the prebuilt
  `cortex-m` `asm/lib.rs` blob — so a third compiler arriving through a
  dependency was invisible to both. `assurance/image.toml` holds the set, the row
  derives it from the image (`--dwarf-depth=1`, 0.09 s) and reddens on any
  difference in either direction, and the two scripts now share one parser.

  Two defects in the mutation table itself, both from the same audit: 7 of its 13
  cases were `skipif`'d on a built firmware — `6 passed, 7 skipped`, **rc 0**, in
  a checkout with no `target/` — and in the gate they read the NO-TOUCH image the
  later rows leave behind, not the one the row certifies. One case also wrote
  `assurance/image.toml` and restored it in a `finally`. The cases run on
  recorded tool output and a handed-in registry now: **19, none skipping, none
  touching the tree**, with the row's position in `check.sh` held as its own
  case. `scripts/conftest.py` is the general answer — `pytest scripts` fails when
  any case skips, since a table neutralised to skips was green in every rule the
  repo had.

- **The model's five permission subsets were a scope claiming to be a
  description, and both halves of stage 2 п.7 now answer for it.** `PermSets`
  carried five of the sixteen subsets of its four permission elements with a
  comment calling them "the sets a host actually asks for". Measured by driving
  `client_pin` over all 256 requestable permission bytes on both
  permission-bearing subcommands: all sixteen are obtainable.

  `WidePerms` is now a Boolean model constant registered in
  `assurance/assumptions.toml`, `FALSE` in every configuration the tiers are
  about and `TRUE` in the new `PermWide.cfg`, which draws the token's permission
  set from `SUBSET Perms` and checks the whole invariant set. It came back GREEN:
  the eleven subsets the model never built reach no violation.

  It is a separate configuration rather than a widening of `Shipped.cfg` because
  the price was measured rather than guessed. On `AlwaysUv.cfg`'s own constants
  the wide domain costs **×4.16 wall** (527 s → 2194 s) and ×2.48 distinct
  states, which projects `Shipped.cfg` to roughly 7754 s and the safety tier past
  its CI ceiling. At one relying party and the two channels `formal/scopes.txt`
  requires for the invariant it checks, the same question costs **559 s**.
  Symmetry over permutations of `Perms` was not taken: `ConfigGuard` names
  `acfg` and `OpGuard` is called with `mc` and `ga`, so a permutation is not a
  symmetry of this spec.

  The half no widening can do is the three bits outside the model's alphabet —
  `be`, `lbw` and `pcmr`, whose admission rules are cross-bit — and that is the
  512-case sweep already in `crates/rsk-fido/src/clientpin_perms_tests.rs`.

- **The constant-time audit is now read out of the shipped ELF, not asserted in
  prose.** `docs/ct-audit.md` says the canonical comparator's inlined copies
  "lower to a loop whose only branch is governed by the *public* length counter"
  and that every PIN/MAC/verifier surface routes through it. Both were true when
  somebody disassembled the image once; nothing re-read it afterwards, and the
  page's own "42 candidate sites were examined" describes a table that has never
  existed in any revision of the file — the only table there has three rows, the
  three fixed findings.

  `scripts/ct_gate.py` + `assurance/ct_sites.toml` + the new `check.sh` row
  `constant-time sites in the image` replace the first sentence with a rule over
  `arm-none-eabi-objdump -d -l --inlines`: for every conditional branch in
  `.text`, the flag-setter it reads is found and each of that instruction's
  operands is traced to its last definition; a definition that is a load from a
  buffer, whose own DWARF inline chain names a registered site, is a
  secret-dependent branch. The second sentence becomes a derived table: the
  first-party frames those chains name are held against the registry both ways,
  so a surface that stops routing through the comparator reddens — which is the
  direction that matters, because the finding this page records twice is a
  compare that BYPASSED it.

  Driven through the row's own command after a rebuild: the shipped tree reports
  **0 secret-dependent branches over 39 attributed runs and 26 conditional
  branches**, exit 0; with `if diff != 0 { return false; }` compiled back into
  `ct_eq`'s accumulate loop, **27 over 60 runs**, exit 1, each naming its own
  `cmp` of two byte loads. `crates/rsk-crypto/src/mac.rs` restored
  byte-identical and the control re-run green.

  Two rules the first version got wrong, both found by reading which assertion
  fell rather than the colour: matching `cmp` exactly missed the loop's
  `cmp.w fp, #32`, landed the walk-back on the secret `eors`, and reported the
  shipped comparator as secret-dependent — the inverse of the truth; and
  restricting the search to branches *inside* the site's own address runs missed
  the early-exit mutant entirely, because the secret `cmp` is the last
  instruction the site's chain covers and the back edge carries the enclosing
  applet's frame. The taint hangs on the load, not on the branch. Host-only: no
  image line moves.

- **More than half of the fallible-probe conversion was held by no test, and the
  count was worse than the review said.** Reverting each converted guard on its own
  and running the owning crate's whole suite: **11 killed, 27 survived** — a diff
  where 27 of 38 guards could be deleted with a green suite. The independent review
  put it at 18; the extra 9 are the OpenPGP `scan_files` guards it grouped as one
  `read_file` row, plus PIV's `have_meta` — which the review had right and this
  measurement first got wrong (below).

  The mechanism is shadowing: a persistent fault on the first record a function
  probes is caught by that first guard, so every later one never runs, and a test
  aimed at one record therefore proves nothing about its neighbours. Three
  mechanisms close it, and none of them is "assert harder":
  `ProbeMedium::stick_after(fid, skip)` lets N probes of a record through before
  faulting, which is the only way to reach a guard standing behind another probe of
  the SAME record (`EF_PW1` twice, `EF_PW_PRIV` three times); each sweep aims at the
  guard's own fid rather than the function's first; and the guards whose record is
  legitimately absent are driven over a **truncated boot walk**, because a complete
  scan decides the whole FID space and `try_*` then short-circuits an absent record
  before the backend — no fault can reach those guards at all on a fully scanned
  store. Re-measured after: **38 killed, 0 survived**, every mutant proven compiled
  in and every kill a test that RAN and FAILED.

  That last clause is a correction, and the instrument was the thing that needed
  it. The first two tables scored a mutant KILLED on `rc != 0`, and a mutation that
  does not TYPE-CHECK exits 101 with zero tests run — so PIV's `have_meta` read as
  killed twice while nothing had exercised it, and the review that called it a
  survivor was right. Fixed by requiring a line matching `^test .* FAILED`, and by
  giving that reversion a spelling that compiles: it then survives the whole crate
  suite, so the counts above are 11/27 and not 12/26. One row of 38 was affected;
  the other 37 all carried a real panic. The guard is held now by a test that has to
  arm the fault **once** rather than stick it — a persistent `EF_META` fault is
  caught further down by `meta_add`'s own guard, which answers the same
  `MEMORY_FAILURE`, so a stuck-fault test would have passed with the guard reverted
  and rested entirely on its neighbour.

  Two smaller findings fell out. `Fs::delete` skips the backend when the present bit
  is clear, and a truncated walk clears every present bit — so a test that plants and
  removes a record across such a walk must use `force_delete` or the record silently
  survives. And the first `try_*` over an absent record CACHES the absence, so a
  second guard probing the same absent record answers from RAM with no probe to
  fault: two guards over one record need it present to be separable.

- **A paragraph naming no run could restate every number the run-count regions
  publish, and did, at exit 0.** The scan's four shape rules are armed by a word
  in the same PARAGRAPH, so the price of a hand-typed run-count was not writing
  `safety`, `liveness`, `run-tlc`, `comutate` or `--tiers` near it — five lines
  restating the row count, the wall clock, the tally, the invariant count, the
  model count, the core count and the workers, green. Four of those were under no
  rule at all in any paragraph: `invariants` and `models` are deliberately out of
  the noun list and 8, nine, 18 and 2 are far under the value floor, which is
  floored by magnitude because a bare small number is every other number in the
  tree. A value WITH THE UNIT the region put beside it is not, so two more
  generated rules hunt `<value> <unit>` and the provenance a region prints
  verbatim — the run's date and `WORKERS=`, which wears its unit on the left.
  Neither needs a trigger, a noun list or a floor. Measured: 21 pairs, two
  verbatim strings and ONE occurrence outside a region, `docs/formal.md`'s "all
  nine shipped baseline configurations", reworded rather than registered. The
  same paragraph is seven findings now. Dropping the trigger instead was measured
  and refused: 41 literals to 549, of which 505 want a home. A unit matches in
  its KIND, not only in the generator's own word — `3225 seconds` is `3225 s` and
  `71 entries` is the `71-entry` roster, which is the sentence a commit in this
  series had to hand-correct from 69 — widened only into the two vocabularies the
  shape scan already enumerates, for four more occurrences of which two are real.

- **Six things the record's own kept sentences said and nothing read.** `date`,
  `host` and `workers` had no second source at all and were each driven to an
  absurd value and republished on three pages; TLC prints all three, in the
  banner and the start line `--record` already parsed and threw away, and both
  are kept per row now. `queue` was captured and compared to nothing, so a GREEN
  row could claim an exhaustive run while its own next words said 999 999 999
  states were never reached. `states` was never held to `distinct`. A GREEN row
  could report no state count at all, which took it out of `floors.txt` and lost
  the published table's numbers to an em dash. And the per-row wall-clock bound
  was on a quantity the published sentence ADDS UP: every row at its own clock
  plus the slack put the legal safety total at [3064..8914] s against a recorded
  3225 and published `3225 s` as `8914 s`. The tier's summed gap is bounded now,
  at three seconds a row with one cold start on top — measured mean 0.83 s.

- **The gate refuses a record whose model has moved under it.** It reads model
  CONTENT for two things only, the `Bug*` switch names and `Shipped.cfg`'s
  `INVARIANTS`, so a `.tla` edit that changed the state space without moving the
  roster or the floors left every published count stale and the row green. The
  record carries the commit, and the row asks it over the modules, the
  configurations, the floors and the two scripts. Empty over the 32 commits since
  the recorded run.

- **Every citation the transport model made had rotted, and the pages carrying
  its evidence made none.** `formal/RSKeyTransport.tla`'s eight
  `ctaphid.rs:NNN` were all correct at `a6eff75`, the commit that wrote the
  module; `c91dff0` shifted six of them by +19, one by +15 and one by +1, and
  the lock was regenerated over the result, so `NoCrossChannelSplice`'s `:433-435` named the INIT-type
  arm's `ERR_INVALID_SEQ` return and `:437-440` named `ERR_INVALID_LEN` — the
  guards next door to the ones the module is about, which is the worst kind of
  wrong citation because it still reads plausible. All eight re-derived by
  CONTENT and re-locked. The bridge itself — `transport_assurance.rs`, the five
  `transport_refinement_kani.rs` harnesses and `ctaphid_tests.rs` — carried no
  `file.rs:line` at all, so none of it was a citation page; all three are now,
  and inserting one line above `feed` reddens the row naming each of them.

- **`SEC-TRANS-001..003` reach the production dispatcher, not only the
  reassembler.** `CtapHid::on_frame` is the only caller of `feed` in the image
  and carries all three `Refines` tags; `dispatch`, whose every arm reads
  `asm.message()`, carries the two ghosts. The published evidence counts do not
  move — `scripts/assurance_gate.py` counts tagged FILES, not tag sites.

- **The reassembler's shipped-size relation is a compile-time obligation instead
  of a sentence.** It was prose in `transport_assurance.rs` ("`Cap` chunks is
  `INIT_DATA + Cap * CONT_DATA` bytes here"), and the sentence beside
  `PROBE_MAX` had the number wrong: `formal/Transport.cfg` runs `Cap = 3`, and 2
  is `formal/scopes.txt`'s FLOOR, so the harnesses pose one chunk *under* the
  configuration TLC walks — stated now rather than claimed the other way round.
  `PROBE_CHUNKS` writes the chunk count out independently of `CTAP_MAX_MESSAGE`
  and three `const _: () = assert!` hold them together. Measured: moving either
  side alone fails the build on `PROBE_MAX == INIT_DATA + PROBE_CHUNKS *
  CONT_DATA`, and a width of 1200 frames fails `CTAP_MAX_MESSAGE <= u16::MAX` —
  the obligation that keeps the over-length INIT refusal reachable at all. No
  `bcdDevice` bump is owed and none was taken: every changed line is a comment,
  a `cfg` attribute or an anonymous const, which is what `scripts/bcd_gate.py`
  excuses. The row reading green on the shared tree was NOT evidence for that —
  a concurrent change had already bumped to 0x09B7, and reverting
  `firmware/src/main.rs` to HEAD makes the row exit 1 naming `crates/rsk-otp/`
  and nothing of this change's.

- **`--relock` now says what it launders, which is the mechanism that made the
  rot above.** `scripts/citation_gate.py --relock` is a RECORD, not a repair, and
  it printed one line — "rewritten; read the diff" — over a 549-row tab-separated
  file. That is exactly how eight citations were re-locked at their new lines
  with the pages left saying the old thing. It runs the audit against the OLD
  lock first now and prints every complaint the rewrite will bury, prefixed
  `rewritten:`. Measured on the repaired tree: one line inserted above `feed`
  took it from 1 line to 25. `scripts/test_citation_gate.py` gains the three
  cases, including the control that a quiet tree buries nothing.

- **`scripts/transport_bridge_gate.py`, because Rust cannot read `formal/`.**
  The two `const _: () = assert!` tie `PROBE_CHUNKS` to `CTAP_MAX_MESSAGE` and
  nothing tied either to the model. Measured: `Cap = 3 -> 4` in the generator and
  all seven `Trans*.cfg` leaves `config_gen_gate.py` and `scope_gate.py` both at
  exit 0 — the scope row is a `>=`, and 4 clears it — with no Rust file touched.
  The new row holds four numbers against each other: the recorded floor, the
  configuration's `Cap`, and `PROBE_CHUNKS` under each `cfg`. Its own table is 19
  cases including three controls, and the row itself is red on that mutation and
  green without it. A third `const _` — the `cfg(kani)` multiple-of assertion — is
  gone: it is implied by the first and could never fire alone.

- **The emulator's dispatcher carries the tags too.** `on_frame` is the only
  `feed` caller in the IMAGE, but `tools/emu/src/hid.rs`'s `serve` is a second
  one, arm for arm the same down to `lock.refuses`, and it is what every
  `tests/*.py` actually runs against. Tagged and cross-cited both ways; the
  firmware comment now says "in the image" rather than "nowhere else".

- **Three more transport defects, measured against the row CI actually runs.**
  `formal/comutants.toml` carries three transport twins and is closed-world
  against `TransMut_*.cfg`, so a fourth needs a configuration and a TLC tier
  pair. The three classes stage 8A names and no entry covered — wrong channel on
  the INIT-type arm, premature completion, and the copy bound — are measured in
  `ctaphid_tests.rs`'s own table instead: each anchor resolves exactly once,
  each patch compiled and ran all 62 tests, and each kill is recorded with the
  assertion that fell and its DIRECTION. Premature completion fells seven tests
  and three of them fall the wrong way round ("should have completed"); the
  witness is `multi_frame_reassembly`, which says a message completed that had
  not arrived.

- **The seam model's OATH default-open exemption is refutable now — five places
  it is stated, five switches, and a measured code twin for each.**
  `assurance/model_exceptions.toml` carried sixteen rows saying `owes`, and five
  of them were one fact restated: `validated = !code_set`
  (`crates/rsk-oath/src/lib.rs:214-215`) appears in `RSKeyAppletSeams`'s initial
  predicate, in `ClearedFor`, in `AllCleared`, in `FactoryWipe` and inside
  `NoStatusOutsideItsSelection` itself, and deleting any of them changed the
  input of no gate. Each has a `Bug…` switch now, all five aimed at the existing
  seam invariant, and all ten generated configurations are RED on it — each on
  the trace its own row describes, read rather than taken from the colour: a
  provisioned OATH keeping its unlock across a re-SELECT and across a card
  reset, a fresh card handing out the OTP PIN beside the access code, a factory
  wipe taken without the reboot its callers queue (a PIV status standing at
  `sel = NoApplet` over freshly-defaulted verifiers), and the invariant's own
  exemption removed, which reddens the SHIPPED tree at the initial state and is
  what says that clause is reached rather than decorative. Each was also run
  with its switch OFF and is GREEN over the whole 410-distinct space, so none
  reddens for something else. `formal/comutants.toml` is closed-world over
  `SeamMut_*`, so each switch also carries a code twin, and those were measured
  too: four are `killed` (the witness assertions and their directions are in the
  entries) and **one is a recorded GAP** — dropping the trusted display's
  `request_reboot` after a completed factory wipe leaves all 127 `rsk-display`
  tests green, so nothing at host level asserts that the wipe asks for the
  reboot the model folds into the same step. Only one direction of each clause
  is refutable here and the rows say so: a status that goes FALSE is never one
  held outside its selection, so a code-less OATH that LOCKS still owes a
  requirement-side statement rather than a switch. `MX-POL-001` was in the same
  wave and is left owing on a measurement rather than an argument:
  `BugNeverSlotSpendsFreshness` — a PIN-policy-NEVER slot that spends the
  freshness it never established — was built and run at `Policies.cfg`'s
  constants against all six invariants and is GREEN over a state space
  *identical* to the shipped one, 9 200 521 states and 331 776 distinct in both
  arms, because spending there reaches no state the other two policies do not.
  Only the edges differ, so no state predicate can see it and the debt is a
  recorder at the step.

- **Settings → Security → "Scramble PIN pad", off by default**
  ([#90](https://github.com/TheMaxMur/RS-Key/issues/90)). On, the ten digit keys are
  laid out afresh at random for every PIN entry — and again between the "New PIN" and
  "Confirm PIN" steps — so a fingerprint trail, a worn patch of glass, or an onlooker
  who sees the hand but not the panel learns nothing from *where* the taps landed.
  The order comes from the hardware RNG through Fisher–Yates with rejection sampling,
  not `% 10`, which would have favoured the low digits by up to 6/256 and made the pad
  leak a little of what it exists to hide. **It buys nothing against a screen
  recording** — anyone who can see the panel reads the digits off it — which is why the
  guide says so rather than implying broader cover. Off by default because it costs
  muscle memory, and a mistype is expensive against a limit of three wrong PINs per
  power cycle: that trade is the owner's. One `PinLayout` value both paints the labels
  and answers the hit-test, so a pad drawn in one order and tapped in another (which
  would type digits nobody pressed, with nothing on screen looking wrong) is not a state
  the types can reach. The setting rides a spare bit of `EF_DISPLAY`'s existing flags
  byte, so the record does not grow and a provisioned device keeps every field —
  including a record written before this bit existed, which loads with scrambling off.
  The shared settings rows shrink from 36 px to 32 px (gap 6 → 4) to fit a seventh
  Security row; the compile-time layout assert is what refused the taller pitch.
  **bcdDevice → 0x0983.**

- **The store sweep's middle recorder had no teeth, and the reason it could not
  be a Kani proof was the wrong reason.** Both found by review. The faulting
  medium failed writes as well as reads, and `NoRecordLostToMetaWrite`'s loss
  needs the EF_META read to fail while the rewrite LANDS — so
  `BugMetaAddDropsOnFault`, its own co-mutant, **survived**. Read-only faults now,
  which is what the docstring always claimed, and all three recorders have a kill
  from their own co-mutant. The sweeps also passed while driving nothing: `drive`
  ignores every `Result`, so making `put` and `meta_add` inert left ~26 000 dead
  steps green. Four live-read counters per sweep are the host's `kani::cover!`,
  and they are what would have caught the write-fault blinding without a mutant.
  And the claim "no metadata path can run under `cfg(kani)` at all" is **false**:
  the blocker is `EF_META`'s value, not the map's width, and a one-line
  `#[cfg(kani)]` alias makes the probe pass in 0.244 s with two fault-site
  obligations at 0.107 s each — what genuinely times out (>420 s) is the clauses
  over a MEDIUM. Recorded as a cheap win not taken here, because it redefines a
  public constant and moves two registry rows.
- **And the faulted-`Delete` carve-out was hiding a broader defect than it
  described.** Not a meta-only-file curiosity: over a medium whose EF_META read
  fails once and then works, `Fs::delete` of a file that HAS data returns `Ok(())`
  with the value gone and the record standing — the 0x077C end state, no power
  cut. Reachable on hardware, and `rsk-piv`'s `files.rs:302-310` already reaches
  for `force_delete` because of it. Two ways to close it are named in
  [store-refinement.md](docs/store-refinement.md); both change what `delete`
  returns to every applet, so both are the maintainer's.

- **The `changePIN` length pair is driven at last, and the mutation that stood
  open turns out to reach an unauthenticated panic.** `clientpin.rs:241-243`
  refuses `newPinEnc` and `pinHashEnc` together; a cargo-mutants MISSED row
  widened the `||` to `&&` and survived every test with "the consequence is not
  yet determined". It is determined now: `pinHashEnc` comes straight from the
  CBOR decoder with no bound, `macd` is `[0u8; 112]`, and `clientpin.rs:256`
  copies `newPinEnc ‖ pinHashEnc` into it **before** the MAC is verified — so the
  widened guard admits a request that panics with `range end index 128 out of
  range for slice of length 112`. Driven at both PIN protocols, because 112 is
  `80 + 32` on two and `64 + 48` on one.

- **`RSKeyStore`'s persistent half has a bridge to the code at last, and the two
  reasons it could not have the obvious one are both measured.** The per-FID
  state projection was refuted last round — every predicate came out as the same
  boolean function as its `powercut.rs` twin. The second reason is new and is
  this pilot's own doing: **no metadata path can run under `cfg(kani)` at all.**
  Every one opens with `known_absent(EF_META)`, `EF_META` is `0xE010`, and the
  `cfg(kani)` present map is three bytes, so the index is 7170 of 3 — measured on
  a harness that does nothing but `meta_add`: `1 of 164 failed … index out of
  bounds … fs.rs:118`, in 0.11 s. So `store_steps_tests.rs` is an exhaustive HOST
  sweep instead: three step recorders (`NoOrphanedMetadata` at a `Delete`,
  `NoRecordLostToMetaWrite` across FIDs at a `MetaAdd`, `NoFalseMetaAbsent` at a
  `MetaDelete`), read after every step of every three-step sequence over twelve
  operations at three FIDs, again after a reboot with no `scan`, and again over a
  medium that fails for the duration of each step. The projection reads `meta`
  and `val` from the MEDIUM and `metaAbsent` from the CACHE, which is the model's
  own split and the only one under which `NoFalseMetaAbsent` is statable: read
  through the caches, a false-absent erases its own evidence. Co-refuted:
  `BugDeleteMetaOnlyUnderPresent` gives `NoOrphanedMetadata: [MetaAdd(0)] then
  Delete(0) left a record over a gone value`; `BugDeleteValueBeforeMeta` survives,
  correctly — the completed state is identical and only a power cut sees the
  order. The three properties stay `MODELLED-ONLY`, because the registry reads
  `BOUNDED` off a Kani harness name and there cannot be one.

- **A RED row may now name the invariant it must break, and the runner compares
  it.** A mutant can go red for a defect it does not model — 2 of 24
  co-refutation patches in this tree once scored a kill that way — and the review
  measured it happening here: flipping `MutateAlwaysUvArm` to the INVERSE defect
  kept `TraceSecurityBadAlwaysUvArm.cfg` red, at a different boundary and in the
  other direction, with `run-tlc.sh` satisfied. `floors.txt` gained a fifth
  column for it. Repairing that turned up why nobody had noticed: the runner's
  `Invariant [A-Za-z]+ is violated` matched **no name with a digit in it**, so
  every `R4*` trace row had been printing the raw error line in its verdict
  column since the day it was written, reading RED coarsely and naming nothing.
  A GREEN trace row's floor is `TraceSteps + 1` now and `security_trace.py`
  asserts it — `run-tlc.sh` compares a floor with `-lt`, and only one of the two
  GREEN rows gets the mapper's exact distinct-count check, so the other could
  have stopped short of its evidence and read GREEN.

- **The phase-4 replay's gate rule was refuted by the first session that
  recorded `alwaysUv`, and now states both arms of §6.1.2's token-less gate.**
  The rule was `pin.set /\ rk` — CTAP §6.1.2 step 10 — and step 6's arm was left
  out on the argument that stating it from `gate.alwaysUv` alone would be false
  on a display build. It was: with a pad, step 6.3 UPGRADES a token-less request
  to built-in UV instead of refusing it. The answer is to record the pad's
  availability and REFUSE such a boundary, not to leave the arm out, so
  `SecurityTraceSnapshot`'s sibling `security_trace_builtin_uv` joins the
  recording (trace schema 4 → 5) and `scripts/security_trace.py` dies on a
  token-less makeCredential recorded with a pad rather than guessing. Measured on
  the new recording: with `alwaysUv` on and no pad the device answers
  PUAT_REQUIRED for **both** `rk` values, where the old rule predicts served —
  `TraceSecurityBadAlwaysUvArm.cfg` is that rule kept, and it is RED at the
  boundary that refutes it (`tracePc = 36`, `alwaysUv` TRUE, `rk` FALSE).
  `tests/16_always_uv_gate.py` is the session; the mapper learned `ConfigOp` and
  a `GetPinToken` that reads its own permission set, and the issuance branch now
  requires the token to have MOVED — without that a clientPIN answering
  PIN_AUTH_INVALID over an already-live token matched it and B reported
  Authorized against a refusal. Coverage: commands 21 → 32, steps 49 → 60,
  distinct actions 21 → 22, **gate boundaries 3 → 5**, AMBIGUOUS still 0.
  `bcdDevice` 0x097C → 0x097D: `crates/rsk-device/src/ctap.rs` gained the
  accessor, and `scripts/bcd_gate.py` asks whether a line can reach the image
  rather than whether this feature is on — the same call `250be31` made.

- **The citation gate reads the citations written in code now, and derives which
  files those are.** It held the `formal/` pages and nothing else, so the 42
  `file.rs:line` citations in Kani proof headers, two test files and one fuzz
  target were unchecked — and 19 of them named code the prose was never about
  (repaired in the commit before this one). Any tracked `.rs` under `crates/`,
  `firmware/` or `fuzz/` that cites by line is a page now, derived rather than
  transcribed, so the next proof header is covered without anyone remembering a
  tuple. A bare basename on a page that is itself code resolves against its own
  directory first — without that every `lib.rs:207` in a proof header is
  ambiguous across four search roots and the one it means is the sibling; the
  `formal/` pages hold no `.rs` siblings, so nothing that predates the rule moved
  (measured: the relock added 35 entries and removed none). `CHANGELOG.md` stays
  outside on purpose — its entries cite the tree as it stood and must be allowed
  to rot — as do the guard's own fixtures and one docs page that writes an
  unresolvable path fragment, since repaired to a real path. 572 citations across
  13 model pages and 7 code pages when it landed.

- **The 187 generated TLC configurations are now held against their generator.**
  Every one of them opens with "Generated by formal/gen-configs.sh -- do not edit
  by hand" and nothing made that true: **delete all three `BootCarryMut_*.cfg`
  and every gate row stays green**, because `assurance_gate.check_tiers` compares
  the tier union against what `formal/` holds and `run-tlc.sh` names whole
  families with `ls`, so both sides shrink together. Editing a constant inside a
  generated file was silent for the same reason — nothing compared the file to
  its source. `scripts/config_gen_gate.py` regenerates into a temp directory and
  diffs; `gen-configs.sh` takes an output directory for it, and defaults to its
  own so `./gen-configs.sh` is unchanged. A deleted file, a hand-edited file and
  a generator changed without regenerating are one finding, because all three
  mean the committed matrix is not the one the generator describes.
  `TokenExport.cfg` is the single hand-written configuration and is registered as
  such, checked in both directions — including that it may not carry the
  generated header, and — found by the review, not by the first table — that the
  187 generated ones DO carry it, which the row is named after and checked
  nowhere. Nineteen mutations across 22 cases in
  `scripts/test_config_gen_gate.py`, each driving the real generator over a copy
  of `formal/`, and the generator itself is a `NAMED` entry in the meta-guard so
  the table cannot be deleted with the suite green.

- **Two induction probes, and the store's named a conjunct the model relies on
  and never stated.** Running an invariant as TLC's INIT predicate with `Next` as
  the next-state relation asks whether one step from ANY state the invariant
  admits lands inside it — a proof that needs no reachability argument, and no
  second tool. `RSKeyBootHardening` is inductive as it stands (48 admitted
  states, GREEN). `RSKeyStore` is not: from a type-correct state where the cache
  says `EF_META` is absent while a record stands, `MetaAdd` trusts it and rebuilds
  the blob from empty — SEC-STORE-004's damage arriving from a state rather than
  from the step that made the cache lie. `CacheHonest == metaAbsent => \A f :
  ~meta[f]` is the conjunct the counterexample named; it is `SEC-STORE-005` now
  and `Store.cfg` checks it on the reachable states too, because an induction
  step without `Init => IndInv` proves nothing (and it costs nothing: 364
  distinct, unchanged). Two things fell out beside it: `"NoFalseAbsent"` was an
  `InvNames` member no step ever wrote, and the runner's rule for these rows
  is `depth = 1` — every successor already being initial IS the claim, where
  the first version's `states > distinct` could never fail. One mutant probe per
  module rather than nine: `Init` satisfies `IndInv`, so the induction rows fire
  on a superset of their `*Solo_` twins' conditions and cannot see a mutant that
  stopped firing. **TLAPS stays "not now"**, and the reason is the measurement:
  the result it would be bought for arrived in a second, and the useful half was
  the counterexample. Formal artefacts and host tooling only.

- **The store model's persistent half cannot be bridged the obvious way, and the
  measurement says so.** Writing `RSKeyStore`'s per-FID steps as Rust predicates
  and holding them against `powercut.rs`'s four `*_landed` rules produces the
  SAME boolean function each time — 0 disagreements over a five-valued domain —
  because `delete_landed`'s `untouched` disjunct expands to the model's stutter
  plus `k = 1`, and its other disjunct is `k = 2`. It is a copy compared to
  itself. The module's own comments say why: two of the three unbridged
  properties are step recorders (a meta-only file legally has metadata and no
  value, so a state predicate over one record is a stronger, wrong claim that
  panics on correct behaviour) and the third is cross-FID. A real bridge needs a
  multi-FID projection with step recorders. Recorded in `formal/README.md` and
  `docs/store-refinement.md` so the next attempt does not repeat it — and one
  power-cut shape nothing had driven is closed on the way: the delete of a
  metadata-only file, from both sides of the cut.

- **The assumption's other arm is exercised by the mutants, and the rule that
  says so now checks what its message claims.** `358755f` measured that all three
  boot mutants redden on the `FALSE` arm of `PowerOnClearsScratch2` too, and on
  the same invariant each — then kept no configuration that would say so again.
  `BootCarryMut_*.cfg` runs each of the three there, one invariant apiece, so a
  RED names the same defect its `BootSolo_*` twin does rather than a sibling
  reporting a mutant gone unreachable: `MarkerNeverLies` in 2 and 20 distinct,
  `TheWholeLockRides` in 20, against 2/26/26 on the arm that clears. Separately,
  `assumption_gate.py`'s third rule asked whether the module mentions the
  constant *anywhere*, while its message promised an action reads it. It walks
  the definition graph from the names the configurations run or check now, over a
  body with block comments and everything past the module terminator stripped
  out — six shapes that satisfied the weaker rule while being exactly as inert,
  each refused by its own case: a bare `ASSUME`, an orphan definition, a
  `(* … *)` comment, a line below `====`, a one-hop walk, and a root the keyword
  list had forgotten. Formal artefacts and host tooling only.

- **The trace replay had stopped following the recording fifteen steps from the
  end, and every observer said GREEN.** `TraceSecurity.cfg` reached 44 of 59
  states: the reset expansion emitted one step per live record, while the model's
  seed arm empties `cred` and `rpent` with the seed in the same step. Three things
  had to line up — `scripts/security_trace.py` ran TLC with `-deadlock`, so the
  divergence the whole pipeline rests on was not checked; `TraceComplete` is
  `tracePc <= TraceSteps`, a tautology that can only catch a replay running PAST
  its evidence; and the floor was 30. `-deadlock` is gone, the two GREEN rows are
  pinned at `TraceSteps + 1`, and the runner asserts the reported distinct count.
  Host tooling and formal artefacts only.

- **The replay answers the gates the model expresses by disabling an action
  (R4c), and `AMBIGUOUS` is 0.** Two recorded boundaries could only be shrugged
  at, both a `makeCredential` carrying no `pinUvAuthParam`: a refusal and a
  successful non-discoverable registration write nothing either way, so their raw
  footprints are identical and only `rk` separates them (CTAP 2.1 §6.1.2 steps
  7/10). Trace schema 4 records that flag and whether a `pinUvAuthParam` was
  offered — inputs, decoded by the applet's own parser — B states the gate rule
  over its own variables, and `R4cGateAnswers` holds the recorded outcome to it.
  The reset window is the second gate: a refused reset over an emptied store has
  the exact footprint of a second successful wipe, and that refusal had been
  replayed as one. Two configurations take one half each of the rule out and are
  required RED. Host tooling and formal artefacts only.

- **`MODELLED-ONLY` was reading as "no evidence below the model", and for 27 of
  42 rows that was wrong.** The status ladder's only code-facing rung is
  `BOUNDED`, which a Kani harness sets — so a property whose concrete face is
  carried by an exhaustive unit suite looked identical to one carried by nothing.
  Measured from the other side: 27 of the 42 modelled-only properties have a model
  mutant whose **code twin** was patched into the real tree and caught by the real
  suite. The whole retry lattice is one — and driving five further mutations of
  PIV's `check_ref` counter arithmetic by hand killed five of five, one by a test
  module written for precisely the glitch its read-back guards. A derived
  `Co-refuted` column now states this, reusing `comutate.py`'s own invariant
  lookup rather than a second copy; whether it deserves a rung of its own is left
  as a maintainer decision. Host tooling and formal artefacts only.

- **The CTAPHID reassembler's three properties are proved against the real
  `feed`, and the proof found a test the suite was missing.** `RSKeyTransport` was
  modelled but unbridged; five Kani harnesses now drive the real `Reassembler`
  from a symbolic live transaction. Six mutations of `feed`'s guards, and the
  survivor is the interesting one: the copy bound `CONT_DATA.min(bcnt - cur)`
  relaxed to `CONT_DATA` was killed by nothing, because
  `CTAP_MAX_MESSAGE - INIT_DATA` divides by `CONT_DATA` **exactly** — every
  continuation of a maximum-length message is full, so the `min` never bites and
  the edge test is blind by construction. Kani caught it; the fix was the test it
  pointed at, a message whose last frame is part-full, and the table is 6 of 6 at
  the PR gate. First measured case here of the weekly proof catching what the
  pull-request suite could not. `CTAP_MAX_MESSAGE` is two continuations under
  `cfg(kani)` — at the shipped width CBMC ran out of memory, not merely slowed —
  and the definition stays an expression, so the documented 7609 is untouched.
  `SEC-TRANS-001/002/003` rise to BOUNDED. The verification code is `cfg`-excluded
  from every firmware image; what the production build gained is one compile-time
  assertion and one `cfg` attribute, so `bcdDevice` 0x096B → 0x096C is a refactor
  with no behaviour change.

- **ML-DSA-87 (COSE `-50`), the NIST category-5 parameter set.** All three FIPS 204
  sets now have in-tree backends: `rsk-mldsa` gained `MlDsa87`/`mldsa87_verify` over
  `ExpandedKey<8, 7>`, checked byte-for-byte against NIST ACVP keyGen/sigGen/sigVer
  vectors like its siblings. Under `advertise-pqc` getInfo lists `-50` ahead of `-49`
  and `-48`. Measured on the RP2350: `mldsa87_from_raw` reserves 123,160 B and
  `mldsa87_sign` 66,628 B, so a makeCredential peaks near 144 KiB against the
  210,152-byte main-stack ceiling — the earlier "-87 overflows the stack" note was
  measured before the worker moved off `main`'s init frame and did not survive
  re-measurement.

- **FIDO answered on one transport, and `ykman`/`python-fido2` could reach the
  other one.** CTAP2 and U2F are now served over CCID as well as CTAPHID, as ISO
  7816 APDUs — the CTAP 2.1 §11.2.1 encoding `python-fido2`'s `CtapPcscDevice`
  speaks, and PC/SC does not distinguish an NFC reader from the device's own CCID
  interface, so it works over plain USB. SELECT `A0000006472F0001` answers
  `U2F_V2`; `80 10` carries a CTAP2 command; interindustry-class APDUs take the
  CTAP1 path. Chaining runs both ways and a client needs both — a bare getInfo is
  ~520 bytes, so it arrives over `61xx` + GET RESPONSE.

  **The two transports share one `FidoState`, and that is the load-bearing part.**
  Giving the new one its own would have been the obvious shape and a security
  regression: the per-boot PIN-mismatch batch lives in that state, so a second copy
  hands a host six guesses per power cycle instead of three — the restart-by-reboot
  attack `restore_pin_lock` exists to close. It is now borrowed rather than owned,
  from the worker, by both handlers; forking it is what
  `both_transports_answer_from_one_session_state` fails on. One PIN/UV token, one
  credential-management walk, one soft lock.

  Both applications stay separately gated: `ykman config usb --disable fido2` and
  `--disable u2f` name them apart, so the *commands* are gated rather than the
  SELECT — the AID stays selectable for whichever half is still on, and the
  disabled half answers `6986`. With neither enabled the AID is gone. No `91 00`
  keep-alive is emitted: a touch blocks inside the exchange under T=1 time
  extensions, as OATH's touch-flagged CALCULATE and OpenPGP's UIF already do.
  The transport ceiling is one CCID frame (2038 bytes) against CTAPHID's 4078, so
  an ML-DSA credential's attestation stays CTAPHID-only.
  **Reachability changed, so [threat-model.md](docs/threat-model.md) says so.**
  ⚠️ On the default `0x1209:0x0001` identity most hosts never bind the CCID
  interface, so none of this appears there — a `VIDPID=Yubikey5` build or the
  `ccid-rs-key` overlay is what makes it visible. `bcdDevice` 0x096A → 0x096B.

- **A platform had no way to know its credential cache was stale.**
  CTAP 2.3's `encCredStoreState` (getInfo `0x1E`) was absent, so a platform that had
  enumerated a key's discoverable credentials could only find out whether anything
  had changed by enumerating them all again. It now carries the same
  `iv ‖ AES-128-CBC(HKDF-SHA-256(persistent pinUvAuthToken, "encCredStoreState"))`
  construction `encIdentifier` uses, over a 128-bit tag that moves on **every** change
  to the discoverable set: a create, a `deleteCredential`, an `updateUserInformation`,
  and the delete driven from the trusted display — that fourth path is a real one and
  was not in the plan. Reads never move it. Two properties earn the member its keep
  and both are tested: the tag lives in flash rather than in `Fs::write_gen`, which
  restarts at zero on every boot and would let a changed store read as unchanged
  across a replug; and it is written *ahead of* the change it describes, so a torn
  write leaves a tag that over-reports (one wasted re-enumeration) instead of one
  that under-reports (a cache nothing corrects). Absent until a persistent
  pinUvAuthToken exists, like `encIdentifier` — only its holder can read it, which is
  the whole privacy story — and cleared by `authenticatorReset` with the credentials
  it summarises. `bcdDevice` 0x0969 → 0x096A.

- **Enterprise attestation could be switched on, but never aimed at anyone.**
  Vendor-facilitated (type 1) enterprise attestation matched a list that was
  hardcoded and empty outside the conformance build, so `enterpriseAttestation: 1`
  never produced an `ep` flag on a shipping key no matter how it was configured —
  only type 2, which grants any RP at once. The list is now a stored record
  (`EF_EA_RPIDS`, up to **8** `sha256(rpId)` entries), written by a new
  `authenticatorConfig` vendorPrototype command `0x0e6841934e719be7` taking the
  rpIds as text at subCommandParams key 4 and hashing them on the device, so the
  stored form and the makeCredential lookup cannot drift apart. `rsk fido
  attestation rpids` drives it. **An absent record is an empty list**, which is
  what every already-provisioned device reads: type-1 keeps qualifying nobody
  until an administrator writes the list, and nothing else changes across the
  upgrade. A list past 8 entries is refused with `CTAP2_ERR_KEY_STORE_FULL` rather
  than stored truncated, and `authenticatorReset` clears the list along with the
  enterprise-attestation flag itself. `bcdDevice` 0x0966 → 0x0967.

- **A platform that asked for no attestation got one anyway, and paid for it.**
  CTAP 2.2's `attestationFormatsPreference` (makeCredential request `0x0B`) was
  ignored. It is now honoured in the one way a single-format authenticator can: a
  list of exactly `["none"]` yields `fmt:"none"` with an empty attStmt, and the
  ES256 attestation signature and the device-certificate read are **skipped**, not
  computed and discarded. Measured on the host, a registration drops from 450.6 µs
  to 293.4 µs — 34.9% — though the split on the RP2350 will differ, where the
  signature costs relatively more.
  Every other shape is unchanged: absent, empty, `["packed"]`, and any list of two
  or more — including `["none","packed"]` — still return the full packed statement,
  because choosing by lowest supported index needs more than one supported format.
  `attestationFormats` (getInfo `0x16`) therefore stays `["packed"]`: "none" is the
  absence of a statement, and listing it would make this a multi-format
  authenticator subject to that rule. An enterprise attestation that was actually
  performed outranks the preference — it is explicitly enabled in flash, strictly
  stronger, and answering it with an empty statement would discard what an
  administrator turned on.
  **Why this is safe when `fmt:"none"` was withdrawn before:** an empty statement
  broke OpenSSH < 10.0, which verifies any x5c-less credential unconditionally. It
  was withdrawn because this device emitted it *unasked*. It is now reachable only
  when the platform names it, and a client that does not send `0x0B` cannot observe
  any change. The empty attStmt is written rather than omitted: field 3 is
  required, and a reader that finds none sees an incomplete attestation object.
  `bcdDevice` 0x0965 → 0x0966.

- **A paired platform had no way to tell one RS-Key from another.** CTAP 2.2's
  `encIdentifier` (`0x19`) is how an authenticator lets a platform that already
  holds its persistent pinUvAuthToken recognise it again, without handing every
  caller a stable serial to track. RS-Key now emits it: 32 bytes of
  `iv ‖ AES-128-CBC(k, id)`, where `id` is a 128-bit device identifier and `k` is
  `HKDF-SHA-256(salt = 32 zero bytes, IKM = the persistent token,
  info = "encIdentifier", L = 16)`.
  **The IV is regenerated on every getInfo.** A fixed one would have turned the
  member into precisely the cross-origin fingerprint it exists to avoid — served
  to anyone who asks, since getInfo needs no authentication. The test that guards
  this asserts both halves at once: consecutive responses must differ, *and* must
  decrypt to the same identifier. Either half alone passes for the wrong thing —
  random noise identifies nobody, a constant identifies everybody.
  The identifier is HKDF-derived from the device master seed under its own label,
  which decides one user-visible behaviour: `authenticatorReset` mints a fresh
  seed, so a reset device stops being linkable to its pre-reset self. Deriving it
  from the silicon root instead would have survived the reset and quietly defeated
  it. The member is **absent** until a persistent token exists, and while a soft
  lock keeps the seed unreadable — it is optional, and a placeholder built from
  some other value would be a claim no platform could detect as false.
  `bcdDevice` 0x0964 → 0x0965.

- **getInfo did not say whether a reset needs a long touch, and the answer was
  believed to be contested.** CTAP 2.2's `longTouchForReset` (`0x18`) is a boolean
  a platform reads to know whether the reset ceremony wants a held touch rather
  than a tap. RS-Key requires no such gesture, so it now answers `false` —
  explicit, and one line away from `true` if the gesture is ever built.
  The reason this sat unanswered was a supposed standard-versus-implementation
  conflict: CTAP 2.2 specifies a 10-second hold while a shipping YubiKey holds 5.
  There is no conflict. **CTAP 2.3 itself reduced the hold from 10 seconds to 5**,
  so the 5-second device is conformant to the version it implements and the
  10-second figure is superseded text. RS-Key advertises `FIDO_2_3`, so 5 s is the
  number that would apply here too — recorded now so the question does not have to
  be re-opened if the gesture is ever wanted.
  `bcdDevice` 0x0963 → 0x0964.

- **A `strong-pin` build enforced a PIN policy it never told anyone about.**
  CTAP 2.2's `pinComplexityPolicy` (`0x1B`) reports whether the authenticator
  applies a PIN rule *beyond* `minPINLength` — which `0x0D` already carries, so a
  raised floor is not one. The `strong-pin` and `fips-profile` images do apply
  one: on top of the six-code-point floor they refuse a repeated code point and a
  ±1 run (`123456`, `654321`), on the host `setPIN` path and on the trusted-display
  PIN pad alike. Nothing in getInfo said so, so a platform could not distinguish
  those builds from a default one with a longer minimum. `0x1B` now answers
  `true` there and `false` on the default build. Its optional companion
  `pinComplexityPolicyURL` (`0x1C`) is deliberately not emitted — a documentation
  link that rots is worse than none, and the member is optional.
  The advertisement is tied to the behaviour by a test that drives `setPIN` with
  the exact ±1 run the rule is about and requires the two to agree, so a build
  cannot claim a policy it does not enforce, nor enforce one it does not claim.
  `bcdDevice` 0x0962 → 0x0963.

- **getInfo never said where a reset can be driven.** CTAP 2.2's
  `transportsForReset` (`0x1A`) tells a platform which transports will accept an
  `authenticatorReset`, so a platform that can only reach the key over a transport
  the authenticator refuses resets on learns that before it prompts. The member was
  absent entirely, leaving the platform to assume. RS-Key is USB-HID only, so the
  answer is `["usb"]` — the same list `transports` (`0x09`) already carried, and
  both now come from one `TRANSPORTS` const through one writer, so the two cannot
  drift into saying different things. Note the wire type: an **array of
  AuthenticatorTransport strings**, not the bit field Yubico's capability page
  describes (that is their pre-personalization storage). The metadata statements
  and their drift guard (`tests/62_metadata_statement.py`) carry it too.
  `bcdDevice` 0x0961 → 0x0962.

- **The store model's in-RAM half had no evidence at all, and its clauses are
  the ones that read as obvious.** `RSKeyStore`'s persistent variables were
  already covered — `powercut.rs`'s four `*_landed` predicates, their Kani
  proofs and the `power_cut` fuzz target are what the module was lifted from —
  but `present` and `decided` are private to `fs.rs`, invisible to a power-cut
  oracle, and one of their obvious clauses (a faulted read cached as a decided
  absence) is audit run-36 and shipped. Six harnesses now carry them, one per
  model action, against a projection that reads the real bitmaps and calls the
  real primitives. Each carries a **second symbolic FID**: the model says one
  element moves and every other stands, while the code reaches its bit through
  `fid >> 3` and `1 << (fid & 7)`, so a mismatched shift would alias two files
  onto one bit and a delete on one would read as a decided absence for the other.
  `FID_PRESENT_BYTES` is 3 under `cfg(kani)` — measured: at full width two of the
  six ran past the 5-minute FAST cap (520 s and 794 s), at three bytes all six
  run in 0.04–0.08 s — and what the shrink stops proving is a compile-time
  assertion instead, which is the stronger form because it is about the shipped
  width. `SEC-STORE-002` rises to BOUNDED. `SEC-STORE-001`, `SEC-STORE-003`,
  `SEC-STORE-004`, `SEC-STORE-005` and `SEC-STORE-006` stay MODELLED-ONLY and say
  why — the family has six members, and "the other three" stood here until
  `scripts/claims_gate.py` read this file. The verification code is `cfg`-excluded from every
  firmware image; what the production build gained is one compile-time assertion
  and one `cfg` attribute, so `bcdDevice` 0x095F → 0x0960 is a refactor with no
  behaviour change — the emitted image does the same thing with the same 8 KiB
  map.

- **The model's one hardware assumption was an axiom nothing could vary, and
  running it the other way says what it actually buys.**
  `PowerOnClearsScratch2` — whether a real RP2350 power-on clears
  `WATCHDOG.scratch2` — was an `ASSUME` that all seven Boot configurations
  pinned `TRUE` and that no action read: deleting the line left `Boot.cfg`
  bit-identical at 77 states, 24 distinct, depth 5. `ColdReset` reads it now and
  `BootCarry.cfg` runs the `FALSE` arm in the safety tier. Both arms are GREEN on
  both invariants, and all three boot mutants redden on both and on the same
  invariant — so the assumption buys **reachability, not safety**: six distinct
  states, and no verdict. Its risk direction is usability rather than security,
  because a scratch word that rides a power cycle carries the PIN mismatch batch
  with it and locks harder, not softer. `assurance/assumptions.toml` records what
  would discharge it, and `scripts/assumption_gate.py` is a new gate row refusing
  an assumption every configuration pins the same way or that no action reads —
  driven against the pre-change model, it reports both. Formal artefacts and host
  tooling only.

- **The formal trace went from one demo suite to a session, and its coverage is a
  ratchet.** The phase-4 replay ran `21_pin_webauthn` alone and reached 13 of the
  model's 50 actions, because a second suite could not be added: the replug
  between suites moves security state outside every CBOR boundary, and the
  replayer — correctly — refused the discontinuity. `tools/emu` now records the
  power cycle as its own boundary (`command_raw` `0xFF`), which is also the only
  way `PowerCut` is ever reached. With the reset path mapped, the committed trace
  is three suites through one emulator lifetime: **21 boundaries** — the step and
  action counts it landed with were re-measured by the R4c entry below, which
  found the reset expansion emitting steps the model was refusing. The replayer
  keeps a small ledger of what B holds, updated only from actions it has itself
  emitted, because a relying party's real credentials fold onto one model element
  and the raw slot counters cannot say how many. The three coverage floors moved
  out of the script
  into `floors.txt` beside every other ratchet, where the file's own header says
  how to move one deliberately; each was driven red on its own, and deleting a
  ratchet line is fatal rather than permissive. Host tooling and formal
  artefacts only.

- **`FidoState`'s zeroize-on-drop roster is exhaustive at compile time.** The
  `Drop` impl scrubs four secret fields, and no host test can observe it: reading
  a value whose destructor has run is the very thing Miri reports as a defect, so
  replacing the whole body with `()` survives every suite. The risk that mutant
  stands for is a *new* secret field added without a scrub line, which is a
  compile-time question — `drop` now destructures `self` naming all eighteen
  fields with no `..`, each non-secret one bound to `_` beside the reason it is
  not one. A nineteenth field stops the crate compiling. Same four scrubs, and
  `fs_usage`'s 512-file window is a named constant beside it: refactor, no
  behaviour change — `bcdDevice` 0x095E → 0x095F because both lines reach the
  image.

- **A 512-file window, a dispatch arm and a ceremony entry, none of them ever
  crossed.** `fs_usage` sums the first 512 files and counts them all; no test had
  ever held more than two, so relaxing its bound to `<=` — an out-of-bounds write
  on the 513th file — survived. `process_cbor`'s dispatch is a second roster over
  the same commands as its canonical-form gate, and every vendor test calls
  `vendor()` directly while the gate's own row for `0x41` sends a malformed body
  that never reaches the match: deleting the arm left the suite green with the
  command answering INVALID_COMMAND. And a touch ceremony opens by dropping a
  cancel an earlier wait left behind — the fake board's own comment says so, which
  is why `cancel_in` exists — but nothing read it back, so the whole entry could
  be skipped. The model does hold that last rule
  (`NoCrossTransportTouchConsumption`), and its co-mutant patches the BOOTSEL
  wait in `rsk-device`; the display half is a second implementation of the same
  rule and had no cover at either level. No firmware behaviour change.

- **The device-config cap's arithmetic is 18 bytes of slack, and the test that
  looked like it pinned it measured the cap against itself.**
  `EF_DEV_CONF_MAX = MIN_CONFIG_RES_CAP - CONFIG_TLV_FIXED` is documented as
  making the writer's cap and the smallest transport's response meet exactly, and
  nineteen mutations of that arithmetic all survived. Five are equivalent — the
  capability bits are disjoint, so `|` and `^` agree. The other fourteen move the
  cap only within 28..46, and every one of them is above the widest record the
  writer's *own* validator accepts: since `well_formed_writable` gained per-tag
  widths (run-34 #25) that is 24 bytes against a 42-byte cap. The existing edge
  test sizes its blob **by the cap**, so it can only observe that the cap equals
  itself, and its over-wide entry fails the read gate and routes to the
  synthesised fallback rather than the echo path it means to exercise. The new
  test scans the writable tag set instead, so the record widens with it, and
  asserts both halves against it. No firmware behaviour change.

- **The panel's key grids and the certificate date helper were both untested.**
  Thirteen `rsk-ui` rows are the touch hit-test — loop bounds in `hit_pin` and
  `hit_rename`, both `+` in `t9_key_rect`, the centring in `T9_LEFT`, and
  `hit_del_hold` replaced outright; nine fall to one grid-walking test and four
  do not compile. The obvious test cannot fail: a key's own centre hits that key
  even under a wrong rect formula, because the centre moves with it. What bites
  is checked from outside — keys inside the panel, columns and rows advancing by
  exactly one gap, the block centred — plus taps past the last row AND the last
  column, without which both column bounds survive. And `days_from_civil` had
  four free operators including the `- yoe / 100` Gregorian century rule, which
  only differs once the year-of-era reaches 100, so the table carries 1900 and
  2100 as well as two February 29ths. No firmware behaviour change.

- **`SLOT_UPDATE` repeated every CONFIGURE validation rule and had none of
  them.** The slot bound, the length floor, both RFU bytes, the CRC and the
  `base + p2` that decides which slot is addressed — eight mutations, all
  surviving, every rule already pinned on the CONFIGURE path by
  `configure_validates_crc_and_rfu`. One test closes all eight. That completes
  `rsk-otp`: all 25 of its rows on cited lines are triaged — 20 killed by four
  tests, 3 equivalent (`(stored & !MASK) | (data & MASK)` folds complementary
  bit sets, so `|` and `^` cannot disagree), 2 unviable. No firmware behaviour
  change.

- **The OTP slot's third flag merge was observable nowhere.** `SLOT_UPDATE`
  merges `ext`, `tkt` and `cfg` each under its own update mask, and the existing
  test pins two of them through `status-ext` — which carries no ext byte, so
  both mutations of that merge survived. `EXTFLAG_UPDATE_MASK` is `0xFF`, so the
  shipped semantics is replacement rather than merging; reading the stored
  record directly and asserting the byte stands alone closes it. A second row in
  the same crate is the conjunction that keeps a challenge-response slot silent
  on a press: relaxed to `||` it silences a slot carrying only one of the two
  bits, and no slot in the suite carried one alone. No firmware behaviour change.

- **The CCID wipe wrapper's answer was asserted by nothing.**
  `CcidApplets::factory_wipe` returns whether the wipe completed and its caller
  turns that into a reboot; replacing the whole function with `true` or with
  `false` left the suite green, and the `true` direction is audit run-32 — a
  wipe reporting a range clear it never enumerated, with the trusted display
  painting "RS-Key erased" over live credentials. The honest direction is pinned
  now; the laundering direction needs a backend that can fail, and the shared
  `Env` fixture is wired to `RamStorage`, so it stays open. The same pass closed
  two rows as non-gaps rather than defects: the five `|` → `^` mutations on
  `SUPPORTED_CAPS` are equivalent because the capability bits are disjoint
  powers of two, and `persist_dev_conf`'s merged-size check is unreachable — the
  cap is 42 bytes and the APDU layer refuses an unknown-tag blob outright, so no
  merge the current tag vocabulary can build reaches it. No firmware behaviour
  change.

- **Every slot index in `decrement_rp` could have had the wrong sign.** Read,
  delete, nickname-delete and write-back all address `EF_RP + j`, and the suite
  killed none of them — nor the match beside them relaxed to `||`, which would
  decrement whichever slot matched on length alone. The cause is the same one
  the model's scope record names one layer up: the credential-management tests
  ran at cardinality one, where `EF_RP + 0` and `EF_RP - 0` are the same file.
  Two relying parties in distinct slots, one holding two credentials so the
  write-back path is reached, and a nickname planted on each, close four; a
  malformed-slot case closes two more in `for_each_rp`'s skip. One row stays
  open as a decision rather than a test: a record of exactly `RP_PREFIX` bytes
  is enumerated today as a relying party with an empty `rp_id`, because
  `unseal_rp_id` falls through to its legacy cleartext domain. No firmware
  behaviour change.

- **Two paths the tree already tested one applet over.** `rsk-fido`'s
  `reset::sweep` deletes in 64-key batches exactly as PIV's reset does, and PIV
  has `reset_sweeps_more_files_than_one_batch` while FIDO's had nothing — the
  bound that keeps the batch index in range was untested, and the mutation that
  breaks it indexes past the array. Likewise `rsk-openpgp`'s `check_pin` accepts
  a PIN record only at `n >= 3 && rec[0] != 0`, the same poisoned-record shape
  PIV pins with `a_poisoned_reference_keeps_every_exit_it_had`, and neither half
  of the guard was tested: a record too short to hold `[len, fmt, verifier]`, or
  with a zeroed length byte, was read as a verifier. Both closed with tests
  proved by driving their real mutations. Neither gap needed a new idea, only the
  question "who else does this". No firmware behaviour change.

- **The PIV PIN gate's last `&&` was held by no test, and the path behind it
  accepts a wrong PIN *and stores it*.** `check_ref` ends in `!matched &&
  otp_key.is_some() && ct_eq(without_otp_verifier, stored)`; because `&&` binds
  tighter than `||`, relaxing the **second** one leaves `(!matched &&
  otp_key.is_some()) || ct_eq(..)` — on an OTP-provisioned device any wrong PIN
  satisfies the left side, skips the comparison, and lands in the migration body,
  which calls `put_pin_verifier` with the PIN just offered. Nothing caught it
  because the fallback needs `otp_key.is_some()` and every PIV test that offers a
  wrong PIN runs without one; the single test that does provision an OTP key only
  ever offers the correct PIN. `a_wrong_pin_is_refused_on_the_kbase_fallback_path`
  closes it. The FIDO twin at `clientpin.rs:761` reads identically and is not the
  same shape — its `ct_eq` is inside the block, so a widened guard still cannot
  write. The tree as shipped is correct; this is the test that was missing. No
  firmware behaviour change.

- **The clientPIN suite spoke one protocol, and two PIN-path defects hid behind
  that.** `PinProto::One` appeared once in `clientpin_tests.rs` against
  twenty-five uses of `Two`, so every length rule in `changePIN` was measured at
  `PADDED_PIN_LEN + 16` and never at `+ 0` — where the same expression written
  `*` instead of `+` refuses **every** protocol-1 changePIN. The second: the
  legacy `getPinToken` (subCommand 5) takes neither permissions nor an rpId, and
  `issue_token` is handed `req.rp_id` whatever the subcommand, so relaxing that
  one guard mints a legacy token bound to an rp the caller named — CTAP 2.1
  §6.5.5.7 does not allow it and nothing tested the refusal. Both now have tests.
  A third, in `rsk-sdk`: every fake applet took `_reselect` and ignored it, so
  the dispatcher's `current == Some(i)` — the flag PIV and OpenPGP branch on to
  keep or drop a session — was handed to nobody who looked; inverting it is what
  the model calls `BugReselectResetsStatus`. Each proved by driving its real
  mutation, one failure each, always the intended test. The tree as shipped is
  correct throughout. No firmware behaviour change.

- **Three defects the test suite could not tell from correct code, on lines the
  model already covers.** The reverse pass reached the other 23 property-tagged
  files (4 357 mutants, 3 124 measured, 572 MISSED, 78 of them on a cited line).
  Three were triaged, chosen because each maps onto an invariant the model
  claims: `request_rescrub` emptied — the at-rest scrub is never re-armed, which
  `BugRekeyKeepsTheMarker` reddens; and OATH's and PIV's `deselect` emptied — a
  VALIDATE unlock and a verified PIN outliving their selection, which
  `BugSelectKeepsOtherApplet` reddens. All three now have tests
  (`requesting_a_rescrub_clears_the_hardened_marker`,
  `a_deselect_drops_the_validate_unlock`, `a_deselect_drops_the_pin_status`),
  each proved by driving its real mutation with the whole suite watched — one
  failure each, always the intended test. The first also narrows a recorded
  exclusion: co-refutation skips the boot module because `firmware/` has no host
  tests, but `request_rescrub` is in `crates/rsk-fs`, host-testable, and was
  covered by nothing. The tree as shipped is correct throughout. No firmware
  behaviour change.

- **Five more `rsk-fs` paths the suite could not tell from broken.** The same
  reverse pass that found the `meta_delete` guard flagged the boot scan's
  dynamic-file registry (three separate mutations), `has_data`'s zero-length
  test, `factory_wipe`'s 64-key batch bound and `delete`'s registry retain — all
  on lines the model cites, none killed by any test. These are closed as test
  gaps rather than model gaps on purpose: the capacity budget's bookkeeping and a
  loop bound are not what `RSKeyStore` carries. Four tests own them, each proved
  by driving its real mutation with the whole suite watched — six for six,
  exactly one failure each, always the intended test. One of the six SURVIVED the
  first attempt because the new test asserted a *count*: the inverted retain
  keeps one entry too, just the wrong one, so the registry listed a deleted key
  and had dropped a live one while the number held. Re-writing the survivor is
  what separates them. No firmware behaviour change.

- **A faulted `meta_delete` could cache EF_META as absent, and nothing at either
  level held it.** `Fs::meta_add_reserve` refuses a FAILED EF_META read; its
  sibling `Fs::meta_delete` has the identical guard and no test killed its
  removal, while the model's `MetaDelete` was an unconditional write with no read
  to fail. The damage lands on the *next* write, not the delete: a cached false
  absence makes `meta_add` trust `known_absent` and rebuild the blob from empty,
  dropping every other applet's record. Closed at both levels — the model gains
  `metaAbsent`, the fault disjunct and `NoFalseMetaAbsent` (SEC-STORE-004, a step
  recorder, because once the cache has lied the losing write is correct code),
  and `a_faulted_ef_meta_read_never_caches_the_blob_as_absent` closes the Rust
  half with the co-refutation patch measured `killed`. Found by running
  co-refutation **backwards** for the first time: `cargo-mutants`' MISSED set
  intersected with the lines the model itself cites — 394 mutants, 88 missed, 12
  on a modelled line, of which this was the sharpest. The tree as shipped is
  correct; this closes the hole that let a regression through unseen. No firmware
  behaviour change.

- **The FIDO security model runs at the firmware's own PIN constants now.**
  `MaxRetries` : `MismatchLimit` was 3 : 2 against a shipped `MAX_PIN_RETRIES`
  8 : `PIN_MISMATCH_LIMIT` 3, and the gap was the largest recorded caveat on the
  model — "an argument, not a proof". `SYMMETRY` closed it: relying parties and
  channels are interchangeable, so TLC may quotient by `Permutations`, which
  takes the reduced-constant run from 61 215 504 distinct states to 25 829 584.
  The real constants then cost **48 679 968 — fewer than the reduced scope
  explored before** — GREEN and exhaustive at depth 55 in 539 s, with all 28
  mutants and both historical configurations still RED on their own invariant.
  Applied to the safety configurations only, because TLC's liveness check is not
  sound under symmetry; `Liveness*` and `Fairness*` keep their smaller constants.
  `Shipped.cfg`'s floor is unchanged at 20 000 000 — still under the measurement,
  and stricter than the "near a third" rule. Model and tooling only, no firmware
  behaviour change.

- **The model's CONSTANTS are under a gate now — two mutants were GREEN one
  element below the shipped scope.** `floors.txt` watches whether a run got
  smaller; nothing watched whether the scope it ran over was big enough to hold
  the defect. `BugCmWalkIgnoresChannel` explores 43 M+ distinct states at one
  CTAPHID channel without a counterexample and falls at two, and
  `BugContIgnoresChannel` is the same shape at the reassembler. The transport's
  `Channels` and the admin `Caps` were literals inside their modules until now,
  so no configuration could say what scope it ran at; both are CONSTANTS now,
  emitted by
  `gen-configs.sh`, and every count is unchanged. `formal/scopes.txt` records
  two hand-written columns per constant — the measured minimum and the invariant
  it was measured against — and `scripts/scope_gate.py` derives everything else,
  including which module owns a configuration. The profile also shows every one
  of the thirty security configurations firing with a *single* relying party,
  against a module comment asking for two. Tests and tooling only, no firmware
  behaviour change.

- **Co-refutation now covers the applet models, and found four rules the host
  tests could not hold.** The roster gains the 24 seam, retry-lattice and policy
  mutants — the three families excluded until now — taking it to 67 entries with
  63 executable patches killed and four unreachable. The gaps were the one-shot
  PW1 rule at PSO:CDS, the OATH access-code removal gate (SEC-SEAM-006's Rust
  half, whose model half was closed two revisions earlier) and both directions of
  a refused OATH VALIDATE; five regression tests close them and assert the PW
  status byte's outer gate at the wire. An adversarial review of the batch found
  two further verdicts were kills for the wrong reason — the patches modelled the
  inverse or a wider defect than their switch — and their faithful versions are
  recorded `unreachable` with evidence. The lint gains two closed-world guards:
  a name collision across the eight mutant families (which would overwrite a
  roster entry instead of colliding) and a Solo configuration with no mutant of
  its own family (which steals the invariant that mutant is judged by). Tests and
  tooling only, no firmware behaviour change.

- **Formal-verification phase 6 adds a cross-reset refinement pilot over the
  real `rsk-fs` power-cut stack.** `ResetNeverWeakensSurvivingState` and its
  PIN, alwaysUv and backup-seal clauses now have bounded one-step Kani proofs,
  byte-granular reset/reboot fuzz coverage, and a destructive real-power HIL
  harness. A measured full-`FidoState` Kani expansion established the tool
  boundary; the security-visible projection solves in under a second, so
  Verus/Creusot is deferred. Verification-only refactor, no firmware behaviour
  change. **bcdDevice → 0x095E.**

- **Formal-verification phase 5 adds a bounded token-lifecycle refinement
  chain.** A canonical outcome-labelled TLA+ relation now drives native B→A
  state/outcome refinement and the generated exhaustive Rust edge table used by
  Kani for R0/R2/R3. Emulator traces record the raw wire outcome and reject
  ambiguous B classifications; tree-derived completeness gates cover volatile
  writers, persistent writers and outcome producers. The host-only projection
  is excluded from firmware and a poison-control gate proves its source cannot
  affect loadable bytes: refactor, no behaviour change. **bcdDevice → 0x095D.**

- **Formal-verification phase 4 now checks real emulator state against the full
  security model.** A host-only `--security-trace` mode exports non-secret raw
  FIDO state; an independent β mapper replays real `21_pin_webauthn` traffic
  through `RSKeySecurityState`, while the implementation's untrusted α is
  compared with a single canonical TLA+ γ. CI floors commands, model steps and
  distinct actions and reports every model action not reached. Two artificial
  divergences are pinned: shifting one raw retry field is caught by R4a, and
  shifting α is caught only by R4b. The first replay found and corrected a real
  model-fidelity gap: B had failed to retain Rust's first-use rpId binding after
  makeCredential consumed the token permissions. The production path gains only
  the abstraction surface consumed by host instrumentation: refactor, no
  behaviour change. **bcdDevice → 0x095C.**

- **Formal-verification phase 3 is closed across the stateful workspace.** Six
  roadmap modules now cover the flash layer, PIV/OpenPGP retry lattice,
  management/rescue surface, trusted display, cross-boot hardening and CTAPHID
  reassembly; `RSKeyAppletPolicies.tla` adds the remaining four-app operation
  policies without inventing retry counters for OATH/OTP codes. Its single
  exhaustive graph is 2,268 distinct states at depth 14, and all seven mutants
  hit their named invariant. The three pre-existing shape holes are structural
  now (`pin_fresh`, one-shot PW1 and OATH code removal), with recorded firing
  counts. `PowerOnClearsScratch2` is an explicit open hardware assumption.

  The assurance gate now requires production `Refines` tags for every shipped
  model (including `firmware/`), validates cross-model `Supports` edges from
  `RSKeyStore` to the two FIDO persistent-state properties, and generates the
  full 26-crate coverage ledger beside the property table. A workspace member,
  model property or owner can no longer disappear silently.

- **Co-refutation: the model's mutants, re-made as code defects, measured
  against the unit tests.** The TLC matrix proves the *model* catches all 28
  `Bug*` defects; nothing measured whether the *code level* catches the same
  ones. `formal/comutants.toml` records one entry per mutant — an exact-snippet
  patch that re-injects the defect, `unreachable` (with the evidence a shipped
  fix made it so), or floored `pending`; `scripts/comutate.py run` applies each
  in a throwaway worktree (carrying the working-tree diff, so a just-closed gap
  reads killed before a commit) and demands the recorded verdict, while
  `--lint` (a `check.sh` row) holds the file against the `Mut_*.cfg` roster and
  resolves every patch anchor against today's code. **The whole roster is
  measured and closed: 28 mutants — 26 killed, 2 unreachable, zero open gaps,
  every kill carrying real test output.** A complete measured run can publish
  the generated 28-row model↔code table in `formal/README.md`; ordinary lint
  rejects a stale table and refuses to publish one from a partial run. The
  weekly `deep-checks` workflow now measures the expanded 43-entry roster next
  to `cargo-mutants`: all 41 executable patches are killed and two are
  unreachable. A patch that fails to *compile*
  scores `build-broke`, never killed — the trap the first `BugPpuatIsAGate`
  patch fell into (`EF_PAUTHTOKEN` is a `KeyFid`, not a `u16`) and the reason
  the verdict logic tells the two apart.

  Six gaps were surfaced by the measurement and every one was closed with a
  harness in the same pass. Beyond batch 1's two: the warm-boot `PinLock`
  carry had no boot-path test (`a_warm_boot_carries_the_soft_lock_in`); the
  torn-reset harness tore the flash but never asked when the SESSION died
  (`a_torn_reset_never_leaves_the_session_running_on_a_wiped_seed`, asserted
  at every tear budget including 0 — the E76 regression's exact shape); the
  changePIN grant revocation
  (`change_pin_deletes_the_persistent_grant_record`) and the revoke-before-
  write order (`a_torn_change_pin_never_leaves_the_grant_under_the_new_pin`,
  a mutating-op tear over the PIN flow).

  The last two carried a finding of their own: the revoke is enforced
  **twice** — authoritatively inside `write_pin_verifier` (the run-37 fix
  moved it into the storage core) and redundantly in each caller — so the
  first single-layer patches measured the depth of that defence rather than
  a gap: everything stayed green because the inner revoke held. The faithful
  mutants remove both layers, and the torn-changePIN harness is the one
  instrument that distinguishes the write orders (exactly one test fails
  under the reorder). Batch 1's two, for the record:

  - `BugTokenSurvivesPinChange` — changePIN leaving the in-RAM session token
    alive — was caught by the model and by *nothing* at the code level: the
    existing test covers the persistent `pcmr` grant through a different door.
    Closed with `change_pin_revokes_the_session_token`.
  - `BugDeleteRpBeforeCred` — a torn deleteCredential stranding a credential
    whose `EF_RP` entry is gone — same shape: the registration twin's harness
    tears writes, and nothing tore a delete. Closed with
    `a_torn_delete_never_leaves_a_credential_without_its_rp`, a
    mutating-op-budget tear (`write` and `remove` both count; `Fs::delete`
    interleaves a swallowed `EF_META` write with the backend remove) over a
    sole-credential RP, asserting at every tear point that a live credential
    implies a live `EF_RP` record.

  Both re-measured killed. These are the first fidelity numbers the
  model→code direction has ever carried.

- **A security-property registry, held against the tree by a gate.**
  `assurance/properties.toml` names every property TLC checks — 47 entries:
  45 invariants and temporal properties across nine modules, plus the two
  maintainer-ruled accepted risks, so a ruled-away risk reads as a decision
  rather than a hole. Hand-written fields are only id, statement, source and
  status; everything else — defining module, checking configurations, targeting
  mutants, Kani harnesses, fuzz targets, Rust files and device tests carrying
  the name — `scripts/assurance_gate.py` derives and prints. The registry's own
  worked example is why: a hand-written evidence record for the tree's
  best-documented property was wrong in three of six fields before any code
  existed.

  The gate closes the graph in both directions: nothing TLC checks may be
  unregistered, nothing registered may be unchecked, a status must equal the
  evidence ceiling (a Kani harness forces BOUNDED; PROVEN is refused until that
  evidence class exists), every `formal/*.cfg` must sit in a `run-tlc.sh` tier
  or carry a named exemption, and `assurance/crates.toml` classifies all 26
  workspace members — the ledger exists because two roadmap drafts enumerated
  crates from memory and missed four, including the second-largest in the tree.
  New `check.sh` row `assurance registry`; mutation table in
  `scripts/test_assurance_gate.py`, now 31 cases. Its measured evidence table
  and crate ledger are generated into `formal/README.md`; the ordinary gate
  rejects a stale block instead of trusting a hand-maintained baseline.

- **A "Formal model" page in the book** (`docs/formal.md`, Security section):
  the map of `formal/` — the nine modules, the checks-of-the-checks (mutants,
  floors, vacuity, lint), the property registry and tags, how to run each tier
  and where CI runs them. The deep prose stays in `formal/README.md`; the page
  says what is and is not claimed and points at the measured paragraph in
  Testing.

- **Property tags in production Rust.** The owner functions the phase-1 models'
  ownership tables document now carry a doc line —
  `` Refines `RSKeySecurityState!<Invariant>` — SEC-FIDO-NNN. `` — so a
  property greps from the model to the code that owns it in both directions,
  which was the one all-zero column of the traceability table. The gate
  validates every tag (module exists, defines the invariant, id is registered,
  and id↔invariant pairing matches) and ratchets the other way: every invariant
  in all shipped baselines must be named in production Rust somewhere. The
  shared rule runs from both the assurance and citation gates.

- **The TLA+ model is checked by CI.** `deep-checks` gained a weekly `formal`
  row running `formal/run-tlc.sh safety` — nine models, 71 mutation switches, their
  `floors.txt` verdicts and the vacuity check. Until now none of that ran in any
  workflow: the matrix was a ratchet whose only puller was whoever remembered
  the command, on the one machine holding a jar at a hardcoded `/nix/store`
  path. The row also fires on any push touching `formal/`, so an edit to the
  model is checked at once rather than up to a week later.

  `tlaplus` therefore joins the pinned dev shell, which exports
  `TLA2TOOLS_JAR`. Advisory measurement tools are still pulled ad-hoc and stay
  out of it; a **gating** tool belongs in the shell beside `cargo-audit`,
  `cargo-deny` and `gitleaks`. The 208 MB is the closure — the tool is 2.2 MB
  and the rest is the JDK it wraps, which is the gain: `run-tlc.sh` took `java`
  from the host PATH before, so the prover's runtime differed per contributor.
  The pinned jar is byte-identical to the hand-realized one, so `floors.txt`
  still describes the TLC that measured it.

  `run-tlc.sh` grew tiers (`safety` / `liveness` / `all`), drawn by heap rather
  than taste. `liveness` is deliberately not in CI: `Liveness.cfg` needs the 12g
  `floors.txt` gives it, and 11.1 GB is where the same workflow's `kani` `heavy`
  runner has already died twice. `scripts/test_run_tlc.py` keeps the row's
  verdict boundary reproducible in the merge gate: the roadmap's four
  artificial corruptions, plus direct RED and FLOOR cases, are persistent.

### Changed

- The version reported to host tools moves from **5.7.4 to 5.8.0**. It is one
  default in `crates/rsk-sdk/build.rs` (`FW_VERSION` still overrides it) and every
  applet derives from it, so CTAP getInfo 0x0E, the management DeviceInfo TLV,
  PIV, OATH, OTP, OpenPGP and the CTAPHID INIT bytes all move together. The
  reference key this project is measured against is a YubiKey 5.8.0 now, and the
  CTAP 2.2/2.3 surface it gained is the surface RS-Key already implements.
  `ykman` reads the newer DeviceInfo fields through defaults rather than version
  gates, so nothing on the host requires the tags RS-Key does not emit.
  **bcdDevice → 0x09CC.**

- getInfo publishes `encIdentifier` (0x19) and `encCredStoreState` (0x1E) from
  provisioning, not from the first `pcmr` request. Both are sealed under the
  persistent pinUvAuthToken, so a platform without that token could never decrypt
  either — withholding them bought no privacy and hid them from the CTAP 2.3
  conformance runner, which reads getInfo before it is in a position to ask for a
  token. A YubiKey 5.8.0 publishes both on a key with no PIN set at all. The grant
  is now minted where the seed it accompanies is, so a completed
  `authenticatorReset` *rotates* it instead of leaving the record absent — which is
  what closes an old holder out — and it authorizes nothing until a PIN exists
  (`credmgmt::authorized_by_ppuat`). **bcdDevice → 0x09CB.**

- `hmac-secret` on an `up:false` getAssertion is refused with
  `CTAP2_ERR_UP_REQUIRED` instead of `CTAP2_ERR_UNSUPPORTED_OPTION`. The refusal
  itself is unchanged — a silent probe still never receives PRF material. CTAP 2.1
  §12.5 names the latter, but a YubiKey 5.8.0 answers the former in every shape
  measured (allowList with and without a token, and a discoverable walk), and a
  client can act on "retry with user presence" where "unsupported option" invites
  it to abandon the extension. Relevant to
  [#109](https://github.com/TheMaxMur/RS-Key/issues/109). **bcdDevice → 0x09C9.**

- **Trusted-display page changes now use a retained, framebuffer-less DMA
  compositor.** One scene build records the laid-out frame. Per-boot keyed
  128-bit tags keep unchanged 32×32 visual-state tiles on the panel. Typed UI
  components also produce exact damage rectangles before they are composed. The
  ST7789 receives one continuous RAM write per rectangle from two alternating
  8-row RGB565 buffers while the CPU composes the next band. A TX-only PIO link
  runs at 80 MHz, reducing full-frame wire time to 15.36 ms. Static raster rows
  in flash avoid regenerating common page backgrounds.
  Text now lays out glyphs once and rasterizes coverage by row through RGB565
  lookup tables; fixed antialiasing masks and speed-optimized display crates
  remove the other repeated pixel math. The spinner's 15 exact phases use a
  flash lookup table. RLE checkpoints and a vertical command index skip work
  from earlier bands. Narrow rectangles use the full fixed DMA buffer, semantic
  damage skips unused tile hashing, and hold progress paints only its new strip.
  The DMA buffers use the active stack, not permanent RAM. A scene overflow or
  display transfer error stops input instead of leaving an active prompt with
  incomplete pixels — by halting, so the retained stream is sized to make that
  unreachable rather than survivable (see the capacity fix below). That flavor
  also runs `clk_sys` at 160 MHz, past the RP2350's rated 150, because the PIO
  transport takes its wire rate from `clk_sys / 2`; the trade it makes and what
  it does not cover are in [limitations.md](docs/limitations.md).
- **The display build's stack has its own gate row, and one retained frame has a
  compile-time ceiling.** The existing row measures the space left *over* after
  `.data`/`.bss`, which is the wrong instrument for this change: moving a 4 KiB
  static pixel buffer onto the stack improves that number while the peak grows by
  ~26 KiB. `rsk_ui::scene::RETAINED_FRAME_STACK_BYTES` bounds the half the linker
  cannot see — `size_of::<Scene>()` plus the two DMA bands plus the tag array — at
  32 KiB, held by a const assert, and `display_stack_floor` spends it against the
  171 KiB that build has.

- **The TRNG row asked for a number nobody has published, and carried three
  claims of very different reachability under one id.** `PLAT-TRNG-001`'s PASS
  clause read "min-entropy at or above the datasheet figure" at "every qualified
  corner", and neither half exists: the RP2350 datasheet of 29 July 2025 asserts
  compliance and publishes a generation *rate*, records that Raspberry Pi's own
  software does not configure the ROSC settings Arm's characterisation procedure
  provides, and the part holds no NIST ESV or ENT listing. That is
  `PLAT-TIMER-001`'s 584,542-year run a second time — a route no passing world
  walks.

  Split in three, and two of the old row's premises were false rather than
  merely unreachable. The raw source needs no bench rig: the datasheet's own
  bootrom listing streams it with two register writes, so the entropy
  measurement is REACHABLE and is `PLAT-TRNG-002`, maintainer-owned, whose
  record argues its own floor — half a bit of min-entropy per raw bit, read at
  the SHIPPED sample spacing and not the bootrom's period-0 one — instead of
  citing a figure that is not there. And the failure is not silent: the three
  health checks are continuous and fail closed, so a source that has DIED stalls
  the boot before USB comes up. That half is read, so `PLAT-TRNG-001` is
  **discharged** and reclassed `build-configuration`. What is genuinely
  invisible is a source that is DEGRADED and still passes, and that is all the
  security row still carries.

  The corners are `PLAT-TRNG-003`, `accepted-risk` and the registry's first row
  owned by `vendor`: the missing half is a characterisation only Raspberry Pi
  can publish, and a `planned` record for a run no equipment here can take would
  be one more dead route. It is published in
  [limitations](docs/limitations.md) — the TRNG is not characterised, and there
  is no vendor number to check a result against.

- **The at-rest scrub lap left the boot glue, because the property it carries
  could not be measured where it lived.** `MarkerNeverLies` (SEC-BOOT-001) is
  about a write ORDER — the `EF_HARDENED` marker is written only after a
  `compact()` that returned `Ok`, so a torn lap leaves it absent and the next
  boot retries. That order sat in `firmware/src/main.rs`, the one workspace
  member with no host tests by construction, so no code-level mutation could
  ever falsify it: a patch that compiles firmware scores `build-broke`, which is
  not a kill.

  The gate, the lap and the ordered `put` are `rsk_fs::run_at_rest_lap` now;
  `firmware/` keeps the OTP gate (`mkek.is_some()` is a firmware value) and the
  placement of the stall before USB attach. Behaviour is unchanged — the
  short-circuit chain becomes an early return plus the same `is_ok()` guard.

  What is new is that it can now go red.
  `the_at_rest_lap_writes_its_marker_only_after_a_completed_scrub` drives a
  `Storage` whose `compact()` fails on demand and reads the marker's absence off
  the MEDIUM, past `Fs`'s present cache — a cache-level check passes over a
  write that never happened. Driven with the real defect (the `is_ok()`
  short-circuit dropped) it is the only test that falls, and it falls in the
  direction of the defect rather than its inverse: *a torn lap claimed
  completion*, the marker PRESENT over a failed lap.

- **An adversarial review of the whole fidelity-debt stage returned CHANGED, and
  three of its findings are fixed here.**

  *The permission oracle was build-blind.* It wrote the advertised option set
  down as a constant including `largeBlobs`, while CTAP 2.1 §6.4 forbids that
  option beside the 2.3 large-blob extension and `getinfo.rs` drops the key
  under `--features largeblob-ext` — a flavour `scripts/check.sh` runs. Under it
  `lbw` stops being a permission this authenticator implements, so §6.5.5.7.2
  step 2 says to refuse it and the code admits it: a whole divergence class the
  constant agreed away. `advertised()` reads `LARGE_BLOB_EXT` now and the
  recorded count is two measured numbers, **48** on the default build and **72**
  under the extension.

  *Six never-varying trace fields had no disposition.* Measured on the committed
  session: **35 of its 81 fields are constant across all 40 events**, and among
  them are `soft_lock_raw` and `token_user_present_raw` — the antecedents of BOTH
  clauses of `NoAuthorizationBypass`. A conjunct whose antecedent is never true
  in the recording is one the replay agrees with for free, and the agreement
  reads exactly like evidence. Two members of the class had rows of their own;
  `PLAT-TRACE-001` holds the class, and a case recomputes the constant set from
  the trace so it cannot go stale in either direction.

  *A two-armed model constant had no inertness guard.* `assumption_gate` asked
  "is it read", which an arm that models nothing new satisfies — the defect
  `fc7491a` shipped and had to delete by hand. It now also asks whether the two
  branches of that `IF` are the same text. The first version of the new rule was
  itself green over its own mutation, because it searched `definitions()`, which
  holds the names a definition references and not its body; driving the mutation
  is what found that. The limit is driven too and recorded: branches SWAPPED are
  different text, so an inverted scope constant is caught by nothing here.

  And eight derived counts the new configuration moved, which the previous
  commit's "five hand-written numbers" understated: two in `formal/README.md`
  (in the paragraph the commit before it had just repaired), four on
  `docs/authorization-slice.md`, one in a bundle header, and three in `scripts/`
  docstrings — one of which was wrong before this session too, at 41 where the
  derived page says 43.

- **The constant-time row was green over two real defects, and an independent
  review found both.** Its taint was depth-1 — the branch's flag operand had to
  be a load ITSELF — so `if diff & 0x80 != 0 { return false; }` inside `ct_eq`,
  which lowers to `orrs` / `sxtb` / `cmp` / `bgt`, reported zero and exited 0.
  The mutant that WAS caught was caught only because LLVM folded it back into a
  compare of two loads: a property of the optimiser, not of the rule. The trace
  is now transitive through data-processing instructions, bounded at four steps,
  and that arm reports **32** violations.

  And its caller half keyed on the OUTERMOST frame, so a bypass added BESIDE a
  surviving call in the same enclosing function was invisible: the review
  reproduced this page's own Medium finding — `rsk-otp`'s `cmd_update` back to a
  slice `!=` over the access code with `cmd_configure` untouched — and the row
  stayed green with the page still listing the surface as routing through the
  comparator. EVERY first-party frame is registered now, 28 of them, and that arm
  reddens naming `cmd_update`.

  Three smaller corrections from the same review: the page said "built by" the
  compiler on the PATH rather than the one in the image's DWARF; a third floor
  counts branches the rule actually TRACED, because most in-site branches were
  excused before the buffer question was put; and the mutation table wrote
  `assurance/ct_sites.toml` from a case and read whichever firmware `target/`
  happened to hold. The table now touches neither, and runs in 3.8 s instead of
  36 s.

- **The present/decided bitmap arithmetic has one definition and a theorem about
  it.** `fid >> 3` and `1 << (fid & 7)` were spelled out at five sites —
  `present_bit`, `decided_bit`, `mark_present`, `mark_absent`, and a fifth copy
  inside `scan`'s closure, which cannot borrow `self` — so the arithmetic could
  drift at one site and leave any assertion about the other four passing. All
  five now call one `const fn slot(fid) -> (usize, u8)`.

  What that buys is stage 5A п.5 of the formal programme: the aliasing clauses
  `store_refinement_kani.rs` proves are drawn from `0..FID_LIMIT`, and under
  `cfg(kani)` that limit is 24 of 65 536 bits. A `const _: () = assert!` beside
  `slot` now enumerates all 65 536 FIDs and states that its two halves recompose
  `fid` — i.e. `slot` is injective, which IS "a put never aliases another file",
  over the whole shipped domain and in the shrunk arm too. Behaviour-preserving;
  the bump is for the five call sites, not for a change the image makes.

- **`Fs` carried a boot-scan flag that nothing read, so it recorded nothing.**
  `over_cap` was set by `scan` when the backend held more dynamic-eligible keys
  than `MAX_DYNAMIC_FILES`, and it replaced a `debug_assert!` for the stated
  reason that the assert is compiled out of the release image — but no reader was
  ever added, in `Fs` or out of it, and `factory_wipe` reset every other cache
  field and not this one, because nobody maintaining that reset had a reason to
  think about a field with no readers. Removed, and the knowledge it stood for is
  a test instead: with `MAX_DYNAMIC_FILES + 1` keys on the medium, the key that
  loses its registration still reads, `free_dynamic()` reports 0, a `put` to it
  answers `NoMemory` while a registered key still writes, and `factory_wipe`
  still takes it. Each of the four was driven red on its own. Refactor, no
  behaviour change: nothing branched on the field, so no image behaviour moves —
  the counter moves because the counter counts builds.

- **Two faulted-read probes keep collapsing on purpose, with the reason recorded
  at the site.** `rebuild_att_cert`'s freshness probe rewrites the attestation
  leaf when it cannot judge the stored one — which reads like the class above,
  and is not: the rewrite is built from the seed the caller already holds, so
  everything but the serial and the signature is a fixed template and the
  attesting key, the AAGUID and the subject come out byte-identical. Skipping the
  rewrite instead was tried and refuted by measurement — a truncated `scan` leaves
  `EF_EE_DEV` undecided, so the probe reaches the medium on a first boot too, and
  the skip then left the device with no certificate at all, or let
  `VENDOR_BACKUP_LOAD` install a new seed and report success over the leaf that
  certifies the old one. `clear_force_change`'s probe stands for the mirror
  reason: a refused read leaves the forced-change flag SET, which is the
  restrictive answer, at the cost of one more changePIN onto a third value —
  while propagating reports a FAILED change over a PIN `store_new_pin` has
  already committed. **bcdDevice → 0x09AF.**

- **The transport model claimed a liveness guard it does not have.** Its header
  said the bounded IN-endpoint write was "guarded by the FrameSink seam's own
  mutation-tested regression over the async `run` loop". Measured: the two
  regressions are over `write_frames`, the response path, and neither enters
  `run`; `write_frames`, `FrameSink` and `TX_TIMEOUT` appear nowhere in
  `formal/comutants.toml`, `formal/floors.txt` or `formal/runs.toml`, and
  `scripts/comutate.py` excludes liveness switches from the roster by design. The
  header now names the two tests, says no liveness proof is claimed from CTAPHID
  evidence, and says no mutation record stands behind either. Swept by CLASS:
  the same sentence stood in `assurance/crates.toml`'s `rsk-usb` row, which also
  said the keyboard framing was "Kani-proved" — `crates/rsk-usb/src/kbd.rs` has
  **zero** occurrences of `kani`. Both corrected there; `formal/README.md`
  carries the third and fourth copies and is regenerated from the registry.

- **A `SYMMETRY` quotient over the transport's channels: considered, rejected,
  and the reason kept beside `emit_trans` in `formal/gen-configs.sh`.** It would
  erase the identity the properties are about — `owner` ranges over `Channels`
  and `Cont`'s first arm is `c # owner`, which is the distinction
  `NoCrossChannelSplice`'s ghost is written on and the reason `formal/scopes.txt`
  records `Channels 2` for it. And there is nothing to buy: the quotient in
  `emit` is priced at 61 215 504 distinct states to 25 829 584, while
  `Transport.cfg`'s whole graph is 13 distinct states at depth 4 in under a
  second. `RSKeyTransport` defines no `Symm` either, so it would be a model
  change and a re-run of all seven transport rows to halve thirteen.

- **The `strong-pin` / `fips-profile` PIN policy refuses three more families, and counts
  code points like the floor beside it** ([#89](https://github.com/TheMaxMur/RS-Key/issues/89)).
  It caught a repeated code point and a ±1 run; `121212`, `123123` and `112211` walked
  through. It now refuses any PIN that is a repeated period (which subsumes the old
  repeated-code-point rule at period 1), a ±1 run in either direction, one with **two or
  fewer distinct code points**, or one of ten denylisted keypad shapes — the 3×3 lines and
  diagonals (`159753`, `147258`, `258369`) plus the mirror/stutter runs people reach for
  when told "not 123456" (`123321`, `112233`, `112358`). The two-symbol rule is not a
  length argument: two symbols leave two smudges on the glass, and the space an onlooker
  or a fingerprint leaves is then the orderings of two marks, however long the PIN.
  Every rule reads **code points**, so a repeated multi-byte character (`АААААА`) is
  refused where the old byte-wise check passed it, and a PIN that is not UTF-8 is refused
  rather than measured. The default build is untouched — it keeps the CTAP-standard
  four-code-point floor with no complexity rule. **bcdDevice → 0x0982.**

- **The trusted display now antialiases the full GUI.** Text uses generated
  four-bit IBM Plex Sans and Mono coverage data. Icons, circles, status arcs,
  rounded cards, and controls use integer coverage blending against their real
  surface colour. This is always active in display builds and needs no setting,
  framebuffer, heap, or new firmware dependency. Text, icons, and AA shapes are
  streamed as contiguous RGB565 blocks so page changes do not issue a long series
  of small SPI writes. **bcdDevice → 0x097E.**

- **The release signature is `SHA256SUMS.sigstore.json`, and the build
  provenance now ships as a file too.** Five signed releases read as *unsigned*
  to anyone matching on the name: the asset was called
  `SHA256SUMS.cosign.bundle`, and `.bundle` is in nobody's list of signature
  extensions — OpenSSF Scorecard's, for one, which knows `.asc`, `.minisig`,
  `.sig`, `.sign`, `.sigstore` and `.sigstore.json`. The file was never the
  problem: it is byte-for-byte a
  `application/vnd.dev.sigstore.bundle.v0.3+json` (read off the published
  v0.4.10 asset), so `.sigstore.json` is simply its canonical extension.
  Alongside it, `rs-key-<tag>.intoto.jsonl` now carries the attestation as a
  release file — the copy in GitHub's attestation API and in Rekor stays
  authoritative, but a consumer holding only a download could not reach either.
  **The five releases already out cannot be corrected**: this repository has
  immutable releases, and adding an asset to a published one is
  `HTTP 422: Cannot upload assets to an immutable release` — measured on all
  five. So both names exist in the wild permanently, and
  [releases.md](docs/releases.md) and [supply-chain.md](docs/supply-chain.md)
  document both rather than pretending the old one is gone. Attaching at CREATE
  time is what immutability allows, which is why this works for the next release
  and not for the last one.

- **Changing an OpenPGP C1/C2/C3 algorithm attribute now invalidates that
  slot's old private/public key pair before publishing the new attribute.**
  Keeping the old key made the slot advertise one algorithm while operations
  could still reach material created under another. Same-value writes preserve
  the key; a changed value deletes both records, with a regression that fails
  on the old behavior. **bcdDevice → 0x095B.**

- **`deep-checks` runs on two cadences and across matrices.** Miri (3 shards) and
  the libFuzzer pass (4 shards) stay daily; Kani moves to Sunday as four jobs —
  the three `light*` shards of `scripts/kani.sh` plus `heavy` — so the roster's
  wall time is the slowest shard's rather than the sum of seventeen crates'. The
  `complexity` row is gone: `scripts/check.sh` already runs
  `scripts/complexity_gate.sh` on every pull request, so it re-proved a merge
  gate a day later.

- **A weekly `cargo-mutants` sweep, advisory.** Line coverage says a line ran;
  this says a test would notice if it changed. The first full sweep — 13 232
  mutants over `crates/` — found `rsk-fido`'s `require_pin_inputs` replaceable by
  `Ok(())` with the gate green (its removal turns a missing parameter into a
  panic, and no host test drives that path), and the trusted display's four
  applet loaders exercised by no test at all. It reports rather than gates:
  most survivors are not defects — code behind an off `cfg`, a guard a deeper
  guard masks, a coordinate no test pins on purpose — so a gating row would be
  red every week. `scripts/mutants-all.sh` fails on its own apparatus instead: a
  shard that tested nothing, or a run that produced no summary.

- **The weekly `cargo-mutants` sweep runs in 12 shards, not 8, and the shard
  denominator is derived.** `--shard` takes a **contiguous** slice rather than
  every n-th mutant — measured, by reproducing the tool's own list at the commit
  CI ran — so where the boundaries fall decides a shard's crate mix, and with it
  how much build output piles up on the runner's ~14 GB. At 8, the 6th slice was
  1802 mutants over six crates ending in `rsk-rsa-asm`, and it took the hosted
  runner down twice: SIGTERM at 85 % of the shard, the same 358 survivors both
  times, the tool healthy to its last line (`Auto-set test timeout to 44s`, 14
  timeouts reported and survived). Both of the shard's suspect crates were then
  re-run locally at that commit and completed clean — 255 `rsk-rsa-asm` mutants
  with the same 12 timeouts CI saw, 264 in `rsk-sha512` + `rsk-slip39` in three
  minutes — so nothing in the shard is poisoned and what died was the host. At 12
  the slices are ~1201 over five crates. **A reduction in pressure, not a proven
  fix:** the runner's own resource state was never in the log, and this entry
  does not claim to have found the cause. The denominator is
  `${{ strategy.job-total }}` so it cannot drift from the matrix — two numbers
  that must agree by hand is how a shard space silently loses a slice.

- **The phase-4 replay's two blind spots are recorded now, and each was measured
  rather than argued.** `pin.set` was TRUE at every gate boundary the recording
  held, so `McTokenlessRefused`'s conjunct was true rather than falsifiable;
  `tests/09_tokenless_gate_no_pin.py` records the two PIN-less cells (a
  repeated discoverable registration, which reuses the slot and therefore writes
  nothing, and a non-discoverable one), and the grid is six cells with all six
  filled. **The proof that they carry weight is a new co-mutant:**
  `TraceSecurityBadPinSet.cfg` — a rule that forgets `makeCredUvNotRqd` — is RED
  at `tracePc = 11` against this recording and **GREEN against the recording
  without them**, replaying all 61 states. The suite holds itself to getInfo
  `0x14 remainingDiscoverableCredentials` rather than to the status word, because
  `0x00` only says the gate served the request.

  The second was the `NO-OPINION` arm: a clientPIN that re-issues a token with
  the permissions it already holds moves no raw field, so it was
  indistinguishable from a `getKeyAgreement`. Trace **schema 6** carries the
  clientPIN subcommand, read by the command's own parser
  (`clientpin::assurance`, cfg-gated out of the image like its makeCredential
  sibling), and the one such boundary in the recording is an issuance again.
  Outcome-committed boundaries: **13 with the rule, 12 without** — a floor now,
  since a mapping that retreats to `NO-OPINION` otherwise costs nothing.

  A third gap closed on the recorder's side rather than the replay's:
  `AppletHandler::security_trace_builtin_uv` is the one line §6.1.2 step 6.3's
  arm rests on, `builtin_uv` is `false` in every recorded byte, and the accessor
  had no test — a hard-wired `false` would have read identically. It has a
  two-arm one now, in the ordinary test row rather than behind the feature, and
  it is driven red by hard-wiring the accessor either way. What stays unwritten
  is the *session* with a pad, not the plumbing: the recording is produced by the
  emulator-suites row, where no display window opens.

  Coverage: commands 32 → 40, steps 60 → 74, gate boundaries 5 → 7, AMBIGUOUS
  still 0. The mapper's own tests stopped reading the recording positionally
  while doing this — six selectors by shape, the way `resets()` already did it,
  because the eight new events broke eleven cases that indexed by number.

### Fixed

- Deactivating an OpenPGP resetting code now drops its staged DEK copy as well.
  A `PUT DATA 0xD3` that tore or was refused between its two records leaves
  `EF_DEK_STAGE_RC` holding the whole DEK sealed under the code being replaced,
  and the deactivation that followed took the verifier, the committed copy and the
  retry budget — not that one. Nothing else could: the at-rest lap only reclaims
  SUPERSEDED bodies and this record is live, and `load_dek`'s stage retirement
  needs a resetting-code session, which needs the verifier the deactivation has
  just deleted. So a revoked code kept a readable copy of every OpenPGP private
  key behind it. Found by a review of the resetting-code work below.

- A flash read that fails during an OpenPGP PIN migration no longer strands the
  DEK. `migrate_pin_kbase` re-wraps the DEK copy and then moves the verifier to
  the fused root; it read that copy with the probe that answers the same "nothing
  there" for an absent record and a failed read, so one faulted read skipped the
  re-wrap silently and moved the verifier anyway. The PIN then verified for ever
  while every operation behind it answered `6A00`, with TERMINATE DF the only way
  back. The read is now the fallible one and a fault fails the VERIFY instead,
  leaving both records where they were. Same class as 0x0995 and 0x09D8; host
  tests drive both over a medium that fails one read. **bcdDevice → 0x09DA.**

- The OTP burn now re-seals the persistent pinUvAuthToken too. The boot pass that
  moves a device's secrets from the chip-serial root to the fused one carried the
  seed and the attestation key; the `pcmr` grant record was not on that list.
  Provisioning has minted that record at the first boot since 0x09CB, and the burn
  comes after a first boot, so on every device whose grant predates its burn the
  record stayed sealed under a root the public serial alone derives — and whoever
  opens it from a flash dump holds the grant: the credential directory over `pcmr`
  reads, and getInfo's `encIdentifier`.
  It now rides the same helper as the other two, which re-arms the at-rest scrub lap
  before it supersedes the weaker copy and refuses the re-seal if that re-arm cannot
  land. The token value does not change, so a platform holding the grant keeps it.
  An already-burned key upgrading to this build therefore laps once more on the boot
  that moves its grant — the same multi-second stall before USB the first post-burn
  boot runs, and once. It also settles a second thing: `clear_ppuat` re-arms nothing,
  which is right only over a record already sealed under the fused root. Host tests
  cover the re-seal, its idempotence and the lap ordering; not reproduced on a board.
  **bcdDevice → 0x09D9.**

- A flash read that fails at boot no longer replaces the persistent
  pinUvAuthToken. Since 0x09CB the boot of every unlocked key ends provisioning by
  making sure the `pcmr` grant exists, and a read of that record that failed
  counted as a record never written: one transient fault minted a new token over
  the live one. Every platform holding the grant lost it, and getInfo's
  `encIdentifier` stopped matching the key those platforms had paired with. A
  `pcmr` request has done the same over a faulted read since the grant became
  persistent (0x086E), and so did a record that was there but would not open under
  that operation's key. That last case is refused too rather than repaired: the
  OTP root is read per operation and a failed read of it looks unprovisioned, so a
  record that will not open is no proof the grant is gone. Only a confirmed absence
  mints now. A boot leaves the record alone and carries on, a vendor backup load
  answers an error with the loaded seed already installed (a retry completes it),
  and a `pcmr` request answers `0x7F`. Host tests drive the boot
  and `pcmr` paths over a medium that fails one read, and the unopenable record
  under a key without the OTP root; not reproduced on a board.
  **bcdDevice → 0x09D8.**

- An HOTP code is no longer sent when the store refuses to advance its counter,
  and U2F no longer signs a counter it could not advance. OATH `CALCULATE` built
  the code into the response before writing the bumped counter, and the response
  goes out whatever the status word says: a refused write sent the code with
  `6581`, and the next `CALCULATE` sent it again. The counter is now written
  first, as the `only increasing` mark already was, and a refused write sends no
  code. U2F `AUTHENTICATE` dropped a refused counter bump under `9000`, so the
  next sign-in signed the same counter, which a relying party reads as a cloned
  key. It now advances the counter before signing and answers `6581` when it
  cannot read or advance it; the read fault answered `6400` until now. Checked
  for the same shape and already in order: the OTP keyboard stores its use counter
  and HOTP factor before typing, and CTAP2 signCount and the OpenPGP signature
  counter send no body when their write fails. Host tests drive both commands
  over a medium that refuses the write; not reproduced on a board.
  **bcdDevice → 0x09D7.**

- The OTP keyboard interface reports the firmware version from its first poll.
  Until the worker seeds the real status record, the frame protocol answers a
  placeholder, and that placeholder still said 5.7.4. USB is already serving by
  then, and a display build blocks for at least ~370 ms on panel and touch init
  before the worker starts, so a host polling that early could read a version no
  other interface reports. Found by reading the boot order, not measured on a
  board. The placeholder takes `rsk_otp::VERSION` now and a host test pins it;
  its program sequence and slot bits still wait for the worker.
  **bcdDevice → 0x09D6.**

- The published metadata statements mirror getInfo again. Three firmware changes
  had moved the device without them: `transports` and `transportsForReset` gained
  `smart-card` once getInfo reported the FIDO AID's CCID route (`0x09D1`),
  `firmwareVersion` became 5.8.0 (`0x09CC`), and `encIdentifier` and
  `encCredStoreState` are published from provisioning (`0x09CB`). Both statements
  now say `smart-card`, carry `329728` in `firmwareVersion` and
  `authenticatorVersion`, and hold the empty placeholders MDS3 takes for the two
  encrypted members, whose value changes on every call.
  `tests/62_metadata_statement.py` requires a placeholder for each member the device
  sends; `tests/17_cred_store_state.py` and `tests/19_enc_identifier.py`, which
  still expected both absent after a reset, expect them published, and the pico-fido
  case listed as failing for that reason is no longer listed. Metadata and tests
  only; no firmware change.

- getInfo publishes `vendorPrototypeConfigCommands` (`0x15`) empty, so Yubico
  Authenticator for Android can read it again. Its CBOR decoder takes no integer
  above 2³¹−1 and failed the whole response on the seven 64-bit vendorCommandIds,
  which left its Passkeys section dead on a Yubico-identity key (issue #111).
  §6.11.3 still gets what it requires, the member present beside `0xFF` in
  `authenticatorConfigCommands`, and §6.4 lets the list be empty; only the SHOULD
  to list the ids is given up. The arm answers the same ids, and
  `docs/protocol.md` lists them. A host test walks the whole response through the
  subset of CBOR that decoder accepts.
  **bcdDevice → 0x09D5.**

- OATH and OTP select by their full 8-byte instance AIDs again, the form Yubico's
  Android SDK sends: Yubico Authenticator for Android got `6A82` for OATH on every
  connection (issue #111). Since `0x088C` a SELECT must name a prefix of a
  registered AID, and both applets were registered by the 7-byte prefix ykman
  sends, so the whole AID stopped matching; that change lengthened PIV's
  registration and not these two. A YubiKey 5.8.0 selects both forms and refuses
  `…01 00` and a ninth byte, and so does this build; the 7-byte form every RS-Key
  host tool sends still selects.
  **bcdDevice → 0x09D4.**

- makeCredential answers `CTAP2_ERR_MISSING_PARAMETER` again when `rp` or `user`
  is sent without its `id` sub-field. Splitting the mandatory-parameter guard by
  field regressed those two: an absent sub-field leaves exactly the empty value a
  present-but-empty one leaves, so the shape checks read the absence as a length
  or parameter error. A YubiKey 5.8.0 calls it missing, which it is — the key was
  sent, the `id` inside it was not. The parser records whether each `id` was sent,
  the way `hmacsecret` already records `peer_present`, and absence is judged before
  shape. Found by the two-key hardware differential; the host tests and the
  emulator run both agreed at the time because neither asked.
  **bcdDevice → 0x09D3.**

- getAssertion now type-checks `credProtect`, `minPinLength` and `hmac-secret-mc`
  as well. The rule the previous entry states is narrower than the reference's
  actual one: a YubiKey 5.8.0 type-checks the value of every extension it
  *advertises*, on every command — including the three that do nothing on
  getAssertion — and ignores an unknown name whatever it carries. Measured over
  both, `credProtect` takes a uint, `minPinLength` a bool, `hmac-secret-mc` a map
  or a boolean, and each answers `CTAP2_ERR_CBOR_UNEXPECTED_TYPE` to anything
  else, while an unregistered name is ignored as an int, a string or an array.
  Four of the seven advertised names were checked and three were skipped, so a
  malformed request completed as though it had asked for nothing. The unknown-name
  half is pinned by a test too: tightening into it would refuse requests other
  authenticators accept. **bcdDevice → 0x09D2.**

- getInfo's `transports` (0x09) and `transportsForReset` (0x1A) now say
  `["usb", "smart-card"]`. They said `["usb"]` on the reading that the FIDO applet
  lives on USB-HID only, and it does not: the FIDO AID is routed onto CCID, and
  `rsk_device::ccid_fido` forwards every CTAP2 command to the same `process_cbor`
  the HID transport calls, with no per-command filter. Measured on hardware —
  `SELECT A0000006472F0001` over PC/SC answers `U2F_V2`, `NFCCTAP_MSG` carrying
  `authenticatorGetInfo` returns the whole map, and `authenticatorReset` reaches
  the applet there too (it answers `CTAP2_ERR_NOT_ALLOWED` for the closed reset
  window, which is the applet's own answer rather than a transport refusal).
  `transportsForReset` exists to tell a platform where a reset can be driven, so
  the old value denied a path the device accepts. `docs/threat-model.md` and
  `docs/protocol.md` §5.2 had both described the CCID route all along. Still no
  `nfc`: this device has no radio. **bcdDevice → 0x09D1.**

- `hmac-secret` / `hmac-secret-mc` no longer treat *any* non-map value as an
  absent extension. The rule that an empty value asks for no evaluation was
  measured on a **boolean** and written down as "a non-map", which is wider than
  the reference: sweeping the CBOR value shapes against a YubiKey 5.8.0 gives a
  map or a boolean accepted, and an unsigned int, a negative int, a text string, a
  byte string or an array answered `CTAP2_ERR_CBOR_UNEXPECTED_TYPE` — identically
  for both extensions, fourteen cells in all. Ignoring a value of the wrong type
  let a malformed PRF request complete as though the extension had not been sent,
  where the reference refuses it. An indefinite-length map is a third case and
  stays `INVALID_CBOR`. **bcdDevice → 0x09D0.**

- A mandatory parameter that is *present but unusable* no longer answers
  `CTAP2_ERR_MISSING_PARAMETER`. Measured against a YubiKey 5.8.0, the reference
  splits those by field: a `clientDataHash` that is not 32 bytes and an empty
  `rpId` are `CTAP1_ERR_INVALID_LENGTH`, while an empty or over-long `user.id` is
  `CTAP1_ERR_INVALID_PARAMETER`. One guard per command answered all of them with
  "missing", which is the one thing they are not — the key was sent. Splitting
  them exposed a second defect underneath: the ordered-key check in both parsers
  only fires when a LATER key arrives to compare against, so a request that simply
  stops before a mandatory key (`{}`, `{1}`, `{1,2}`) walked out unjudged and was
  answered downstream by the empty value it left behind. That read as the right
  answer only while the guard also said "missing"; both parsers now judge a
  truncated map themselves. Absent keys still answer
  `CTAP2_ERR_MISSING_PARAMETER` on both keys, which is what says the guard was
  narrowed rather than moved. `RP_ID_MAX` is deliberately KEPT even though the
  reference accepts a 300-character `rpId`: that is the reference being looser,
  where parity earns no change. **bcdDevice → 0x09CF.**

- The scrambled PIN pad no longer draws its digit order from the shared DRBG, so a
  host-raised PIN ceremony cannot panic the trusted display. A CTAP command holds
  the store, the DRBG, the presence backend and the FIDO state borrowed for its
  whole dispatch and then calls the panel through them, so the pad's
  `rng.borrow_mut()` was a `BorrowMutError` — under `panic-halt`, a key that
  answers nothing until it is unplugged. It needed built-in UV, `scramble_pin` on
  and a display build, which is the other half of
  ([#107](https://github.com/TheMaxMur/RS-Key/issues/107)): dropping the probe's
  `uv` stopped the pad being raised by `ssh-keygen`, and any client that asks for
  built-in UV deliberately still raised it. The order comes from a per-panel seed
  drawn once at construction and an HMAC-SHA256 counter now, so it is still
  unpredictable across entries and no longer reads a cell somebody else is
  holding. The comment that should have caught this existed and said `fs`; a new
  `check.sh` row derives the held cells from the dispatch and the reachable
  surface from the handle, so the rule is no longer a sentence.
  **bcdDevice → 0x09CE.**

- A silent `up:false` getAssertion carrying a token-less `uv: true` no longer opens
  the trusted display's PIN pad. That pair is what OpenSSH's `key_lookup` sends
  before enrolling a resident key, so `ssh-keygen -t ed25519-sk -O resident` — and
  any browser registering a discoverable credential — turned a probe the user never
  sees into a modal ceremony: libfido2 gave up with `FIDO_ERR_RX`, and a display
  board sat on its screen until it was physically reset
  ([#107](https://github.com/TheMaxMur/RS-Key/issues/107)). `uv` is dropped rather
  than refused, because `sk_enroll` continues only when that probe answers
  `NO_CREDENTIALS`; refusing it would have swapped a wedge for a fast failure and
  left `-O resident` broken. The response's UV flag stays 0, and a client gets the
  same answer today by simply omitting `uv`. Screenless builds are unchanged — they
  do not advertise `uv`, so no client asks them for it. **bcdDevice → 0x09CD.**

- An `hmac-secret` / `hmac-secret-mc` value carrying no sub-fields — an empty map,
  or a value that is not a map — is read as if the extension had not been sent,
  instead of ending the ceremony. It used to be `MISSING_PARAMETER` for the empty
  map and `INVALID_CBOR` for the non-map, so a platform that sent either got no
  assertion and no credential; a YubiKey 5.8.0 completes both, on `getAssertion`
  and `makeCredential` alike, and does so even on an `up:false` request where a
  *present* extension is refused. An absent `keyAgreement` inside a map that does
  carry other fields is now `MISSING_PARAMETER` rather than the ECDH's
  `INVALID_PARAMETER`, matching the same device. An indefinite-length map is
  unchanged — it is a map, and still `INVALID_CBOR`. Relevant to
  [#109](https://github.com/TheMaxMur/RS-Key/issues/109). **bcdDevice → 0x09CA.**

- **A relying party could pick a name that halted the trusted display.** The
  retained scene records a frame as RLE'd drawing commands in a 12 KiB buffer, and
  a passkey list draws the rp id and user name a registration chose. How many
  commands that costs is a property of the *glyphs*, not of the byte values: 48
  copies of `'j'` cost `render_service` 14630 bytes where the mixed-ASCII label the
  capacity census used costs 10683. Two of the 95 printable glyphs `Label::clamp`
  passes were already over the line, and the far side of it is
  `Frame::drop`'s `expect` — an unauthenticated `makeCredential` away from a panic
  on the screen whose whole job is to be trustworthy. The buffer is 16 KiB now,
  sized to the measured worst glyph with a 1 KiB reserve the census asserts
  separately. The census itself is the other half of the fix: it swept one
  hand-picked `(index * 37) % 94` label and so certified a ceiling it never
  reached, and it sweeps all 95 glyphs against every full-frame renderer now,
  naming the renderer and the glyph when it goes red. **bcdDevice → 0x09C7.**

- **A display build without an explicit `BOARD=` asserted itself dead at boot.**
  The PIO transport takes the panel clock from `clk_sys / 2` and sets no divider,
  so it asserts `clk_sys == spi_freq_hz * 2` in its constructor. The board file
  moved to 80 MHz with the transport; `firmware/build.rs`'s fallback — which
  exists to mirror that same board — stayed at the pre-PIO 62.5 MHz, so every
  display build that did not name a board, including the one `check.sh` compiles,
  would have panicked in `PioDisplayTx::new` on the first boot. The fallback
  tracks the board file again, and the ratio is a `const _: () = assert!` in
  `firmware/src/main.rs` now, so a board file that moves one half of it fails the
  build instead of the device. **bcdDevice → 0x09C8.**

- **The trusted display's paint-side oracle went blind in the merge.** The
  scrambled-PIN-pad test proves the pad the owner *reads* is the pad the hit-test
  takes, by fingerprinting each finished frame off the recorded pixels. A frame
  used to end at `DrawTarget::clear`; the retained compositor replays its
  background as a `fill_solid` instead, so the fingerprint never ran and
  `pin_pads_painted` returned one pad for a three-entry flow. `zip` compared the
  one it had and would have passed on the rest. The boundary moved to
  `present_scene` where the frame now ends, and the test refuses a readback
  shorter than the flow it scripted.

- **`gpg`'s `kdf-setup` locked the owner out of both OpenPGP references
  ([#104](https://github.com/TheMaxMur/RS-Key/issues/104)).** DO `C0`'s byte 1
  announces KDF-DO support, so `gpg` offers `kdf-setup`; the DO itself (`00F9`)
  went down the *generic* PUT DATA arm and was stored as opaque bytes. From that
  write on, `gpg` sends the KDF **output** as the password on every VERIFY and
  issues no `CHANGE REFERENCE DATA` of its own (`g10/card-util.c::kdf_setup`) —
  so the card is the only party that can move the references, and the DO's tags
  `87`/`88` carry the hashes of the two factory passwords for exactly that
  purpose. Ours never read them: measured on the reporter's sequence, `PUT DATA
  F9` answered `9000`, `VERIFY 83` with the `88` hash `63C2`, `VERIFY 81` with
  the `87` hash `63C2`, and `CHANGE 83` with `hash(old) ‖ hash(new)` `63C2` —
  `change_pin` splits at the *stored* length, so it was comparing the first 8
  bytes of a 32-byte hash. Both counters then ran down to blocked, and the only
  way back was another factory reset.

  `crates/rsk-openpgp/src/kdf.rs` owns the tag now: it validates the three bodies
  `gpg` produces — `81 01 00` ("off"), the 90-byte `kdf-setup single` and the
  110-byte bare `kdf-setup` — against a table of
  offsets, then makes the two hashes the PW1/PW3 reference values, re-sealing
  each PIN's DEK copy under the new value and giving both retry counters their
  budget back. Turning KDF off is the same move in reverse, to `123456` /
  `12345678`, since that is what `gpg` starts sending again. The DO is still
  stored verbatim — the host reads back the salt and iteration count it needs.

  **Every one of those answers was then measured against a real YubiKey 5.7.4**,
  one question set run against both cards: `9000` and a verbatim read-back for
  both of `gpg`'s layouts, `9000` for `kdf-setup off` with the raw defaults back
  on both references, `6A80` for an empty body and for 109, 111 and a corrupted
  tag `87`, and `6985` with a key on the card — in both directions, on and off.
  **Sixteen questions, sixteen identical answers.** The one that started out
  different is the access status: this cleared all three afterwards, as Gnuk does
  and as `gpg`'s own cache clear (`do_setattr`, special 4) suggests, while a
  YubiKey keeps them — `PUT DATA 5E` straight after `PUT DATA F9` with no
  re-VERIFY is `9000` there. Ours keeps them now too, but it could not simply
  stop clearing: the session key a VERIFY derived is what opens the DEK, and the
  re-seal has just sealed it under a different password, so `reseed_pin` returns
  the new session key and `Session::adopt_reseeded` installs it. The status
  survives *and* still works. A failed write still drops all three, because which
  password each standing key opens is then exactly what is unknown.

  Two places it stays deliberately apart from the oracle, both in the direction
  that keeps a promise rather than breaks one. A **corrupted length byte** inside
  an otherwise well-formed DO is `9000` on a YubiKey and `6A80` here — the tag is
  checked on both, the width only here. And an existing **Reset Code** is
  deactivated here rather than left standing: the DO carries a salt for the RC
  (tag `85`) but no initial hash, so there is nothing to migrate it to, and a
  YubiKey's kept code is measurably dead — `RESET RETRY` P1=0 answers `6A80` to
  the raw code and to the KDF'd one alike, spending no retry, while `C4` goes on
  advertising three tries for it. Deactivating makes the counter honest.

  An **empty** body is refused with `6A80`, which is stricter than Gnuk: it takes
  one as the DO's delete and drops the keystrings, so an empty PUT DATA `F9`
  silently returns both references to `123456` / `12345678`. `gpg` never sends
  one — `kdf-setup off` is the three explicit bytes — so refusing it costs no
  host and takes a PIN reset out of reach of a DO-clearing loop. The gate found
  that arm, not review: the whole-16-bit-space PUT DATA walk sends an empty body
  to every tag, and the re-seed it triggered at `F9` dropped the admin session
  under the rest of the walk.

  Order is the tear budget: the DO lands first, then PW3, then PW1, then the RC.
  No order avoids a window where the DO and the verifiers disagree — a host reads
  the DO to learn which of the two passwords to send — but PW3 leading the
  references keeps it one append wide, because once the DO and PW3 agree the
  admin can re-run the command and the rest heals. Seventeen hand mutations, each
  killed by a test that names the defect rather than its inverse: no PW3 re-seed,
  no PW1 re-seed, the key guard removed, the length gate removed, the tag and the
  length byte each dropped from the field check, "off" leaving the PINs alone,
  an empty body taken as "off", the RC left live, the PW3 gate removed, the DO
  not stored, the retries not restored, the DEK not re-sealed, the generic writer
  taking `F9` again, the session keys not adopted, the statuses dropped anyway,
  and PW1's session left stale while PW3's followed. **bcdDevice → 0x09C6.**

- **A registration that failed part-way left an RP entry that nothing ever
  reclaimed, and its discoverable-credential slot with it.** `credential_store`
  writes an EF_RP entry before the credential so a truncated sequence leaves the
  harmless half; the code said that half was "reclaimed by the next
  `decrement_rp`", and it is not. `decrement_rp` deletes the record at count 0
  alone and the count rises once per credential that lands, so an entry left over
  one that never landed floors at 1 — the RP keeps a slot with nothing in it until
  `authenticatorReset`. One of the three fallible steps after the bump rolled it
  back and the first one did not, two lines apart. It needs no flash fault to
  reach: `EF_CRED_STATE` is a NEW dynamic file on a key that has never stored a
  resident credential, so `Fs::put` answers `NoMemory` at `MAX_DYNAMIC_FILES` —
  driven on a plain backend with no fault injector at all. With all 256 EF_RP slots
  so occupied and zero live credentials, every `rk=true` `makeCredential` for a new
  RP answers `CTAP2_ERR_KEY_STORE_FULL` (`0x28`) and the owner has nothing to
  delete; getInfo `0x14` then reports **256** remaining discoverable credentials
  once the owner has freed enough dynamic files for `remaining_rk`'s second term to
  stop binding, and **0** at the moment of exhaustion itself.

  Both other fallible steps after the RP bump are covered in the same change, and
  the second was found by the review of the first: `set_cred_sign_counter` had no
  rollback either, and stood AFTER the credential write — so 127 of 256 driven
  failures left a live discoverable passkey behind while the host was told
  `KEY_STORE_FULL`. It now runs BEFORE the credential (a counter for a slot nothing
  fills is inert) and rolls the count back too. The rollbacks are best-effort by
  construction — each is itself a flash write — and the comment says so rather than
  claiming every step rolls back.

  Still open, same class, and named here so the next sweep starts from a list: the
  power-cut window between the RP bump and the credential write; `delete_credential`
  removing EF_CRED and then answering `NotAllowed` when the EF_RP write fails;
  `decrement_rp`'s own `let _ = fs.delete(EF_RP + j)`, which leaves the identical
  phantom while the command answers `Ok`; the trusted-display delete swallowing the
  same failure; and `largeblobext::discard`, which drops a live credential's large
  blob before a re-registration that may then fail.

- **`CONFIG_READ` over FIDO reported a record it could not read as an empty one.**
  Found by asking the other spellings of the four fixes above the same question.
  Both targets are the baseline a host read-modify-writes: `rsk hw` and `rsk led`
  read the record, apply what the user asked for and send the result back. An empty
  answer makes `rsk hw --get` print "(build default)" for every field the owner
  actually set. It is the weakest member of the class — `rsk led` already refuses a
  block shorter than 17 bytes, and the phy answer contributes nothing to the
  device-side merge, so no field is lost — but `rsk hw --get` over CCID refuses
  after this release while the same command over FIDO showed a phantom baseline,
  and one command should not answer two ways. `CtapError::Other` now; an absent
  record still answers empty, which is what a first use of either tool needs.

- **A faulted `EF_LED_CONF` probe overwrote the owner's LED configuration with the
  build defaults, at boot and unauthenticated.** The boot load has an absent arm on
  purpose: a device that never customised its LEDs gets the live block persisted
  once, so a host `CONFIG_READ` always has a full block to read-modify-write (it
  cannot know the build defaults). A failed probe took that arm. Driven on a
  `ProbeStuck` medium over a boot walk one read fault cut short, the owner's stored
  block was replaced byte for byte by the live one.

  Both arms are proven, because they are reachable in different states rather than
  on different devices: a *complete* boot scan decides the whole FID space, so a
  legitimately absent record is answered without touching the backend and no fault
  can reach it — asserted with a fault armed **persistently**, and the defaults are
  still seeded. Only a truncated walk leaves the probe live, and there it refuses:
  nothing applied, nothing stored.

  The decision moved to `rsk_vendor::load_or_seed_led_config`, where the host can
  run it; `firmware/src/vendor.rs` keeps the four lines that marshal the LED atomics.

- **The phy read-modify-write existed in three copies, and each one read a failed
  flash probe as "no record was ever written".** `rsk_phy::merge_save` is what closes
  picoforge#102 / RS-Key#33 — a host tool that sends only the fields it changed can
  no longer wipe the VID/PID, product string or LED wiring it omitted. The FIDO
  `set_phy` and the trusted display's touch-timeout save did not call it; each
  inlined the same `load(..).unwrap_or_default()` sequence. On a `ProbeStuck` medium
  one faulted `EF_PHY` probe took the stored record from **41 bytes to 7** through
  `merge_save`, and from **29 to 7** through each of the two inlined copies — VID/PID,
  product, manufacturer, LED GPIO, LED count and wire order all replaced by the
  defaults with the one edited field on top. On the default build FIDO `CONFIG_WRITE`
  is ungated, so that path is reachable unauthenticated.

  There is one copy now: `rsk_phy::update` takes the edit as a closure and refuses
  on a failed probe — nothing is stored, which is the only safe answer for a
  read-modify-write. `merge_save` is one call to it. `load` keeps its `Option` for
  the readers that only report, and `try_load` is the fallible probe underneath.

  A fourth spelling turned up in the enumeration and is fixed with them: the rescue
  applet's READ phy is the baseline `rsk hw` read-modify-writes **on the host**, so
  reporting a synthesised default record for a probe the flash could not answer
  hands the host a phantom baseline to edit and write back, and shows the owner a
  configuration that is not theirs. It answers `MEMORY_FAILURE` now. A genuine
  absence still serializes the zeroed OPTS TLV, which is what a first run of the
  tool needs.

- **A `ykman` one-field write turned into a whole-record replacement when the
  merge could not read what it was merging onto.** A DeviceConfig write is a delta —
  every `ykman config` command sends the field it is changing and nothing else — so
  `overlay_dev_conf` reads `EF_DEV_CONF` and merges. Its probe collapsed a failed
  read into "nothing stored", and the delta then *became* the record. Driven on a
  `ProbeStuck` medium: an 11-byte record (`USB_ENABLED` + `AUTO_EJECT_TIMEOUT` 30 s +
  `CHALRESP_TIMEOUT` 15) came back as the 4 bytes of the request, with the two
  timeouts gone.

  Its comment deliberately chose replace-on-unreadable, and that reasoning is sound
  for two of the three answers a probe can give, not three. **Absent** still merges
  onto nothing, so the request becomes the record — a first write. **Unparseable**
  still keeps only the whole-TLV prefix, so a tail an older, laxer build wrote is
  replaced; those are bytes no parser can attribute to a tag. **Faulted** is neither,
  and refusing (`DevConfError::Store`, already mapped to `MEMORY_FAILURE` / `Other`)
  is the only answer that cannot lose a field. `dev_conf_unchanged` needed no change:
  it already reads a refused merge as "changed", so the write proceeds to the refusal
  instead of being acked as a no-op.

- **A flash read the applet gate could not complete re-enabled every application
  the owner had disabled.** `read_enabled_caps` is the mask the CCID dispatcher and
  the two FIDO transports are gated on, and its unreadable arm resolved to
  `SUPPORTED_CAPS` — the all-enabled set. Driven on a `ProbeStuck` medium against a
  key configured FIDO2-only, one faulted probe of `EF_DEV_CONF` brought back
  **`0x003B`**: OTP, U2F, OpenPGP, PIV and OATH, all selectable, with `WRITE CONFIG`
  reachable for as long as the cached mask lived.

  The irony is the comment three lines below the arm, which explains why the walk is
  deliberately *not* gated on `well_formed_writable`: "refusing to honour a record it
  cannot fully validate would silently re-enable applets the owner disabled." The
  `_ =>` arm performed exactly that, by the one path the author did not enumerate —
  the record is not invalid, it is unread.

  A *confirmed* absence still means the factory default (a device nobody configured
  has every supported application on); a probe the backend could not answer is
  `NO_CAPS` instead. Failing closed is recoverable in the direction that matters:
  `cap_enabled` keeps management, vendor and rescue selectable at `cap == 0`, so the
  owner can still rewrite the record, and the next boot or config write re-reads
  flash. READ CONFIG follows without a second rule — its synthesised arm takes
  `USB_ENABLED` from the same function, so report and enforcement are one answer even
  under a persistent fault, which is the run-34 #25 property.

- **`scripts/check.sh` called `mktemp` seven times over five rows and removed
  none of them on any path that mattered.** It was the one script under
  `scripts/` with no `trap` at all: the assurance-trace row's copy of the source
  plus its three cargo target dirs (~10 GB and growing) was never removed even on
  success, and the two partition tables and the sealed image with its throwaway
  EC key went the same way. The two rows that did `rm` did it on the happy path
  only, so a `FAIL:`, an errexit abort or a Ctrl-C leaked as well. One run at a
  time it took a volume to zero and stopped a session with `ENOSPC`.

  The eight neighbouring scripts each spell their cleanup as their own
  `trap … EXIT`, and repeating that per site here was not an option: bash keeps
  exactly ONE EXIT trap and the second call silently replaces the first. Each
  site registers instead, and one handler removes the lot. Two things this
  changed on the way: the store row's temp could not be removed even by hand,
  because `out=$(mktemp -d)/pt.elf` binds the file and drops the directory that
  holds it; and the assurance tree is dropped as that row ends rather than
  sitting through the ~60 rows that follow it.

  Measured on every exit path, each with the leftovers counted in a private
  `TMPDIR` and each exit code taken with no pipe: success, a `FAIL:` row, an
  errexit abort *inside* a row after its `mktemp`, an early `return`, a skipped
  row, `run_tests`' ran-no-test refusal, and HUP/INT/TERM to both the script and
  its process group. Every one of the eleven runs the old preamble was driven
  through left a temp behind, and none of the thirteen the new one was driven
  through did. One exit code moved, and it is the one that was wrong: a SIGINT
  delivered to the script alone used to let the interrupted run finish and report
  **rc 0**, and reports 130 now. That the others did NOT move had to be proved on
  its own, because a cleanup handler that fails takes the run's verdict with it —
  measured, the obvious `rm -rf …; return 0` handler exits a **green** run 1 when
  its `rm` fails, since errexit leaves the function before the `return`.

  `scripts/test_gate_scripts.py` holds the class shut: every live `mktemp` in a
  tracked `*.sh` must bind the whole path it makes and must be registered for
  removal **in the scope that made it**, and a script that makes one must trap
  `EXIT` and drain what it accumulates. Scoping is the load-bearing word — with
  the rule written file-wide, deleting a row's registration and commenting one
  out both left the suite at rc 0 with 1789 passed, because `dir` names the temp
  of three different rows and any one of them answered for the others.

- **The three `pytest` rows leaked the same way, with no `mktemp` in sight.**
  pytest puts `tmp_path` under `$TMPDIR`, `nix develop` hands every invocation a
  fresh `/tmp/nix-shell.XXXXXX` and removes none of them, and the retention that
  would have swept the scratch — keep the last three run directories, collect the
  rest — is counted per base directory, so it never met a previous run. Within one
  base it works exactly as documented; the base moving is what defeats it.
  Measured in a single day: 361 orphaned bases, 8.9 GB, on the volume the fix
  above had just been written for. 351 MB of that is one run of the gate-scripts
  row, and there is no fat fixture in it to slim — ~1400 directories, the largest
  1.5 MB.

  Each row pins a `--basetemp` of its own now, under
  `${XDG_CACHE_HOME:-$HOME/.cache}/rs-key/pytest`. That flag is not the retention
  the documentation describes: pytest removes the directory and recreates it at
  startup, so a row holds one run instead of every run and numbered `pytest-N`
  directories stop being made at all. Three things had to be right. It cannot live
  in the checkout, which was the obvious place and is the one that fails — under
  `target/` a `tmp_path` is inside RS-Key's own repository, `git rev-parse HEAD`
  answers there, and `test_verdict_gate.py`'s "git answers None rather than
  nothing when it cannot answer" case goes red on it: 1788 of 1789, at that
  assertion, against 1789 of 1789 for the same pin one directory outside the tree.
  pytest creates the leaf and not its parents, so the parent is made first. And it
  wipes whatever it is pointed at, which is why no row shares a leaf — two that
  did would race, the second wiping the first and then running green on the empty
  directory it had just made.

  A green run leaves 1 MB rather than 351, because a passing test's directory is
  dropped as it passes while a failing one's is kept. That is the only kind anyone
  opens, and it is what stops a base in a cache directory nobody sweeps from
  becoming the hoard it replaced.

  `scripts/test_gate_scripts.py` holds this half of the class shut as well: every
  live pytest invocation in a tracked `*.sh` pins a `--basetemp`, and no two pin
  the same one. Read at a command position with quoted spans cut, since
  `usbip-guest.sh` prints the word; and over a bare `pytest foo` as well as the
  `python -m` spelling the tree uses. Narrowing it to the long form was the
  mutation worth reading: it does not leave the pin rule reporting a green tree,
  it leaves it with no rows to report on, and it is the roster sentinel beside it
  that says so.

- **Three ceilings shipped with the defect their own series had measured.**
  `SCOPE_CEILING`, `SCOPE_SPAN_CAP` and `CARVE_OUT_CEILING` were upper bounds
  with headroom, and 37 → 999, 6 → 99 and 2 → 99 were all surviving mutants —
  while the FLOORS beside them are caught, because the cases that drive a floor
  drive the real tree. Each sits on what the tree holds now. The sharpest
  survivor was the digit-grouping class: the NBSP and two thin spaces added as
  the fix for a measured bypass could be deleted again with the suite green,
  because the cases asserted only that some finding fired while the rule matched
  the truncated tail and named `'563 872 rows'` — a number that is not on the
  page. Every grouping and every join asserts the whole literal now, which is
  also the only thing that sees a rule NARROWED: hollowing the class moves none
  of the five per-rule tallies.

- **A value the generator wrapped mid-number was hunted for by nothing.** The
  grouping class had a second, retyped copy inside the function that decides
  which values the value rule looks for, one character short — no newline — so a
  count `fill` broke between its groups was read as `563 872` and the real
  `77 563 872` was guarded by nothing at all, silently. One class, two readers.

- **A tracked page the scan cannot decode is reported rather than dropped**, told
  from an image by a NUL byte the way git tells them apart; a second kept summary
  for one configuration is refused; and the `?`-versus-absence agreement is driven
  both ways.

- **Four measurements this guard published about itself were wrong.** The scope
  ceiling's own comment read 27 against a constant of 37, one commit after being
  written and thirty lines from the value, in the guard whose subject is a
  hand-typed number going stale. The value rule's floor table was taken with a
  matcher later fixed. The `[Unreleased]` carve-out's stated reason — "every line
  sits under a version heading" — is refuted by a live claim that went stale under
  that very heading; the real reason is 74 historical literals nobody will
  register one at a time. And `assurance/` was said to hold no second copy outside
  `bundle/*.toml`, where the settling question `docs/assurance-matrix.md` is
  rendered FROM carries one verbatim — the rendered copy is registered and the
  hand-edited one is out of the scan, which is the wrong way round.

- **The second register of open items gained the same owner, and both of its
  record types gained the field list neither had.** `assurance/threat_clauses.toml`
  keeps the P0-family properties that trace to no threat-model clause; its five
  `[[untraced]]` findings now name an `owner` from the same four roles, borrowed
  from `scripts/platform_gate.py` with the identity asserted. No second deferral
  field: `verdict` already types what would end the finding — `missing-clause`
  means write the clause, and `defends-nothing` is a decision rather than a
  deferral — so adding one would be two answers to one question. All five are
  `contributor`, because a `missing-clause` finding is a page standing behind code
  that already defends the threat. Asking the field-allowlist question of this
  file found **neither** `[[clause]]` nor `[[untraced]]` had one, and neither did
  the file's own tables; all three are refused now, and the owner is printed in the
  report rather than only held. Six mutations in `scripts/test_threat_gate.py`.

- **Every open question in the build-configuration ledger names who owes the
  answer and what would end the deferral, and neither is a date.** Stage 0's last
  exit bullet asked for an owner and a decision, or a deferral with a review date;
  all 28 `[[question]]` records had `column` and `text` and nothing else.
  `owner` is now required and is `scripts/platform_gate.py`'s four-role
  vocabulary **borrowed rather than re-picked** — the identity is asserted, so a
  copy that would drift is a red row. `settled_by` is the review point and it is
  typed, not dated: `evidence`, `absence`, `sameness` or `ruling`, which is this
  file's own disposition table read backwards, each naming the `[[cell]]` the
  question would become. The calendar half is refused with `platform_gate`'s own
  argument plus one narrower: enforced, a `review_by` reddens `check.sh` on a day
  nobody touched the tree and the repair is to move the date; unenforced, it is
  the field-nothing-reads a `[[cell]]` is already refused for carrying. Two of the
  four routes are ones the tree can disagree with — `sameness` where the derived
  closure delta is non-empty (the exact answer three columns had been parked on),
  and `absence` on a column that enables no gating feature and compiles every open
  row's owner, which is every board preset. Populated: 26 `contributor`, **2
  `maintainer`** — `abrobot-4m`, whose 8 open rows all ask whether a GPIO button
  on 23 has BOOTSEL's Confirmed/Cancelled semantics (a board measurement, and no
  `PLAT-*` entry covers it), and `waveshare-touch-lcd`, whose ask is whether the
  tree should build the preset at all or fold it into `firmware-display`.
  Routes: 23 `evidence`, 4 `absence`, 1 `ruling`, **0 `sameness`** — the
  vocabulary is the exits from the disposition table and has to be total, so a
  column whose honest route is an equivalence is not made to write a wrong
  answer; what earns the value's place is its refusal, which fires either way.
- **A `[[question]]` had no field allowlist, so a key added to one was read by
  nothing and printed by nothing** — including a `review_by` somebody adds because
  the criterion says "date". `[[cell]]` has refused a stray field since it
  shipped; `[[question]]` does now too, and asking the same question one level out
  found the ledger's *tables* unguarded as well, so a `[[review]]` section nobody
  reads is refused. Twelve mutations in `scripts/test_matrix_gate.py`, both
  directions: inverting the `sameness` rule reddens the CLEAN fixture, which is
  how the inverse defect is told from the real one. Asking "what here is read by
  nothing" of *this* diff found the answer inside it — `SETTLES` stored, for each
  route, the `[[cell]]` bases it reaches, and only its KEYS were ever read. The
  values are load-bearing now: the vocabulary is asserted total over `ALLOWED`,
  so a sixth basis with no route is a red row rather than `evidence` quietly
  becoming the answer for everything.
- **Four candidate rules for telling a real settling question from six nonsense
  words were measured against the questions already in the tree, and the tree
  refuted all four.** Requiring a `?` — 14 of 28 carry none and read as
  statements. Requiring no two alike — the `-pqc` siblings honestly share a route,
  and six `[[cell]]` `why` bodies are already word for word. Requiring a token the
  derivation knows (a column, a property id, a feature, a crate, a `check.sh` row
  label) — 7 of 28 are about flash geometry and GPIO pins and name none of the
  228. And capping a maintainer-owed question so it is answerable in a sentence,
  which is backwards: what saves the maintainer from re-deriving is the
  measurement, and the one question that needs a ruling carries 105 words of it.
  Recorded rather than quietly dropped; the word floor still catches `TODO` and
  nothing catches a bad question.

- **Three build-configuration columns were parked on "is a build nobody ships in
  the supported set at all", and the answer was a derivation rather than a
  ruling.** `keygen-bench`, `core1-stats` and `bench` are measurement-only cargo
  features with no flake package, and between them they hold 111 of the assurance
  matrix's 958 `gap` cells. Measured with the gate's own feature resolution: the
  hoped-for `equivalent` is **refuted** — none of the three resolves the default
  build's per-crate closure, and no cargo-feature column ever can, because the
  feature naming the column is in that column's own closure by construction. What
  the measurement does buy is the size of the delta, and it separates the three:
  `keygen-bench` and `core1-stats` move `firmware` and nothing else (the crate set
  is identical, and 1 of each column's 37 open rows is owned by a crate that
  moved), while `bench` also turns on `rsk-fido/bench` and pulls `rsk-bench` into
  the image (8 of 37). The publication argument is refuted in the ledger from
  both ends by columns already in it: `firmware-pico` is unpublished and disposed
  of in full, and **8** columns are told "never ship" in `firmware/Cargo.toml`'s
  own words — four of them the `no-touch` packages the matrix exists for. So all
  111 cells stay honest `gap`s and the questions now carry the measurement
  instead of the parked ruling. Asking the same question of the parked ruling's
  other spellings found a **fourth** column carrying it: `fido-conformance` also
  asked "is a conformance-only build in the supported set". Rewriting it surfaced
  a second thing that sentence never said — the derived closure shows
  `fido-conformance` implies `strict-up`, so that column demands a touch on every
  assertion and inherits `firmware-strict-up`'s transport-arity question too.
- **`docs/assurance-matrix.md` derives what each column compiles unlike the
  default build**, instead of leaving it to a sentence someone has to keep true:
  the Columns table gains the per-crate closure delta, and Open gaps gains how
  many of a column's open rows are owned by a crate inside it. Both come from the
  *same* function the `equivalent` rule refuses a cell on, so the page cannot
  print an emptiness the gate has stopped agreeing with; a fork of it is one of
  the six mutations the four new cases in `scripts/test_matrix_gate.py` were
  driven against. Immediately visible: the six
  board presets and the two flash-geometry packages move **0** owner crates
  (their whole delta is knobs), `firmware-display` pulls four workspace crates in,
  and `ea-conformance-rpid` transitively enables `fido-conformance` **and**
  `strict-up`.

- **The threat model states the power-cut threat and the revocation threat it
  had been defending against without stating.** Two clauses under *1. A hostile
  host*: a flash write can be interrupted and the host picks which one is in
  flight — with what the device owes across a cut, the write ORDER that buys it,
  and the fact that the silicon half underneath is `PLAT-FLASH-001`, a **pending**
  board measurement rather than a defence this firmware implements; and that you
  must be able to see and revoke every credential the device holds, which is what
  `EF_RP` reachability is for. Both were `[[untraced]]` findings against the page:
  `SEC-FIDO-005` and `SEC-STORE-001` now name a clause instead. Measured:
  `threat_gate.py` goes from *45 clauses (32 defence, 13 context), 33 of 40
  P0-family traced, 10 served, 7 untraced* to *47 (34 defence, 13 context), 35 of
  40 traced, 12 served, **5** untraced*, with `FLOOR_CLAUSES` 45 → 47 and
  `CEILING_UNTRACED` 7 → 5 in the same diff. No heading is added and no clause id
  is a rendered anchor, so the five pages that link this page's headings are
  untouched, and the `citation-gate` count is unchanged at 636 — the page carries
  no line citations at all.
- **Three of the four store rows were filed against the wrong threat, and the
  registry said so in prose nothing had checked.** `SEC-STORE-003/-004/-005` were
  recorded as wanting a power-interruption clause; only `SEC-STORE-001` does. Four
  independent readings, each re-derived: `formal/RSKeyStore.tla` says of `Put` and
  `MetaAdd` that *"neither carries a cut point; only Delete does"*; the writers
  that violate `-003` and `-004` are `BugMetaAddDropsOnFault` and
  `BugMetaDeleteDropsOnFault`, both **faulted EF_META reads**; `Reboot` sets
  `metaAbsent' = FALSE`, so a power cycle structurally cannot reach the false
  absence `-004` forbids; and `crates/rsk-store/src/lib.rs:236` states outright
  that a read fault is *"which a NOR power cut never produces (a torn write yields
  deterministic bytes, not a read error)"*. Their `why` now says that, names
  `TM-HOST-POWER-CUT` as the clause it is **not**, and pins the sentence it rests
  on — the new clause's *"Scope: the interrupted write"* — so deleting that
  sentence reddens the row rather than silently making all three verdicts wrong.
  The threat those three are actually against, a `Storage::read` that fails,
  remains stated nowhere on the page and is still their open finding.

- **A threat-model clause is locked below its first line now, and which
  sentences are locked is derived rather than remembered.**
  `assurance/threat_clauses.toml` pins each clause by its `where` — the first
  line, verbatim — and saw nothing under it, so a verdict argued from a sentence
  further down could be falsified by an edit no gate reads. The worked example is
  a clause that scopes itself away from a neighbouring threat: delete that
  sentence and every verdict resting on it turns wrong while the row exits 0. A
  whole-body hash was measured and rejected — over this page's history 34 clause
  bodies changed with their first line intact against 12 first lines reworded, so
  it would have fired on **20 of 30** commits and been suppressed like any alarm
  that is usually noise (corrected below; the first pass used an ad-hoc body
  function rather than the gate's own, and only the 12 reproduced). Instead an entry carries `rests_on`, a list of
  sentences held against the body of the clause it argues from,
  whitespace-normalised so a re-wrap is not a rewrite. The completeness half is
  read off the tree, not maintained: an `[[untraced]]` whose `why` names a clause
  id owes a pin inside that clause, and a clause body that hands part of its
  claim to a `PLAT-…` assumption of `assurance/platform.toml` owes a pin on the
  sentence naming it — so a new dependency arrives owing a pin instead of
  arriving unlocked. It does not reach a sentence load-bearing for a reason no
  entry states, and that limit is written where the field is defined. 20 cases in
  `scripts/test_threat_gate.py`, every spelling of the edit driven both ways:
  reword, deletion, a dropped full stop, smart quotes and a weakened emphasis go
  red; a reflow, a re-indent and a trailing space stay green by design. Two came
  out of writing the table — a sentence wrapped in `<!-- -->` leaves the page and
  stays in the source byte for byte, so bodies are stripped of HTML comments
  before anything is matched (and a comment *spliced* mid-sentence renders as
  nothing, so it correctly stays green); and U+00A0 substituted for a space is
  invisible to `str.split()` and therefore to this rule, which the table records
  rather than hides.

- **Every published run-count is written from a recorded run now, and seven
  were stale when it was.** A run-count is a number saying how much a roster
  run covered or produced, and this tree typed them: `safety` published as
  **190 rows** where `run-tlc.sh --tiers` lists **195**; **78** mutation
  switches with a configuration family of their own where **79** have one, of
  **80** that exist; `194 configurations — 20 that must come back GREEN and 174
  that must go RED` in the weekly workflow against **195 / 21 / 174**; a
  phase-2 baseline of **28 rows** and a **69**-entry live roster against **30**
  and **71**; a slice page at **57 properties … 194 tiered** against **59** and
  **199**; and `Shipped.cfg` at `48.7 M distinct states — 539 s` in that same
  workflow against **77 563 872** and **1869 s**. The seventh is the worst,
  because `docs/testing.md` introduces it as *the paragraph to quote*: TLC
  checked its invariants over **48,679,968** distinct states there, against
  **77 563 872** — 63 % of the measured count, in the sentence a release is meant
  to copy. None is a typo: each is a number whose only copy of the truth was the
  moment somebody typed it.
- **`formal/runs.toml` is the record they are written from.** Produced by
  `python scripts/run_count_gate.py --record <log>` over a capture of
  `formal/run-tlc.sh`, it holds the runner's own matrix per tier and stores no
  total beside it: the row count, the wall clock and the GREEN/RED tally are
  counted out of it on every gate run, so no total in it can disagree with the
  rows it totals. A run is a run of the tier as `--tiers` lists it TODAY —
  every listed configuration must be in the matrix, every verdict must be the
  one `floors.txt` requires, no row may sit under its floor, and a row the
  runner marked `!!` is refused. The first record is `./run-tlc.sh safety` and
  then `./run-tlc.sh liveness`, which is what `all` does, on 2026-08-27: **195
  safety rows in 3225 s** and **4 liveness rows in 2118 s**, 22 GREEN and 177
  RED, not one row short of its floor.
- **`formal/README.md`'s two "the tree as it stands" baseline rows are held to
  the gates that print them.** Each opens a mutation table by quoting a
  `check.sh` row's live summary verbatim — `config_gen_gate.py`'s and
  `verdict_gate.py`'s — and nothing had ever compared the quote to the output.
  Both rotted: once at `eaf29a5`, once at `8cb0a74`, whose own subject line
  says the count "went stale again, in fifteen lines". No run-count rule
  reaches them either: a markdown table row names no runner, so the shape scan
  never arms, and 200 is far under the value rule's floor. The numbers are
  **live**, so they are held exactly rather than scoped — the test asks each
  gate for its summary and requires the page to carry it.
- **Both registries added above shipped with the defect they were added to
  close, and both are fixed here.** The carve-out list — the second exemption
  registry on this row — had reasons nothing read and no ratchet on its size,
  which is word for word the finding against `SCOPED`; it is held to the same
  word floor and has a ceiling now. And the value rule enumerated **whole
  spellings** of a number, so `77 563 872` re-wrapped by an editor to `77 563`
  / `872` across a line break was invisible to the rule whose whole point is
  that it does not enumerate shapes. It is a separator *class* now, newline and
  tab included: measured over the corpus, 0 occurrences today and 0 new false
  positives, so it costs nothing and closes the spelling before it lands. Its
  guards were also too loose in the other direction — `0x4000` and `abc4000`
  matched a derived `4000`, while a value ending a sentence had to keep
  matching, so a word character on either side is refused and a trailing `.` is
  refused only when a digit follows it.
- **Eleven numbers on two pages that no rule reaches, corrected by hand.**
  `docs/authorization-slice.md` was measured at the commit it landed in and the
  assurance registry has grown since: **57 → 59** properties, **44 → 46**
  modelled-only and **194 → 199** configurations tiered on its registry-wide
  line; **44 → 45** configurations checking `NoAuthorizationBypass` at four
  sites; **1 → 4** Kani harnesses in `SEC-FIDO-001`'s row; **2 → 3**
  configurations for `SEC-FIDO-007` and `SEC-FIDO-008` in two places each. The
  page's own falsifying command was wrong too — plain `grep -l
  NoAuthorizationBypass` prints **47** because it also matches the tier-A
  `NoAuthorizationBypassA` in two configurations, so the page now prints
  `grep -lw`, which agrees with the registry's own derivation at 45. And one
  sentence was **inverted**, not merely stale: `SEC-FIDO-001` was said to lead
  on three evidence columns "though not on harness count"; it now leads on all
  four, uniquely, with `SEC-STORE-002` second at three. Separately,
  `formal/README.md` still said the co-mutant roster is **69 entries: 65
  patches** where `comutants.toml` holds **71: 67 patches** — the same figure
  the generated paragraph in `docs/testing.md` prints correctly, which is what
  a second copy does. None of these is in the run-count gate's reach: they are
  the *assurance* registry's numbers and generating them is a different
  criterion's stage 0, noted where the exemption for one of them already says
  so.
- **Twelve spellings the shape rules walked past.** Each measured at exit 0
  and each now a case: `195 states` and `195 mutants` (what a run *produced* is
  a run-count by the same definition as what it covered — and `77.6 M states`
  is a **rounded** second copy that the value rule cannot reach, so this is the
  only rule that gets there); `190+ rows`; `_195 rows_`, where `_` is a word
  character so the leading `\b` never fired; `195 — rows` with an em dash;
  `GREEN: 20, RED: 174`; `finished in 00:53:45`; `3 hours`; `a 54-minute run`;
  `a 3225-second run`; and a number grouped with a NBSP or a thin space —
  `NUM`'s own class held the plain space **twice** and neither of those, while
  its comment said three characters. A literal is also reported whole now:
  `48.7 M-state GREEN` came out as `'7 M-state GREEN'`, the finding naming a
  number that is not on the page. Ten sites the widening reaches are registered
  with what each is, and the exemption ceiling is raised in the same diff.
- **Two spellings are still open, and are cases saying so.** `about an hour`
  (no number for a numeric rule to find) and `21 passed, 174 failed` (not this
  tree's vocabulary). Widening either costs more than it buys — dropping the
  paragraph trigger takes the scan from **41** literals to **549**, of which 505
  want a home. `A run of the safety tier` stood here as a third and was never a
  spelling: it is the trigger being a paragraph-local word list, which is the
  general escape and is closed below. The rules that do not play that game are
  the generated ones, bounded to what the regions actually print.
- **The scope registry's labels are read now, and the silence one entry buys
  is bounded.** `SCOPED`'s values were never looked at at all, so a brand-new
  stale literal kept its exemption with the label `""`, `None`, `"history"`,
  six nonsense words — or *a description of an entirely different run*. The
  last of those still passes and always will: no rule tells a right scope from
  a wrong one, and that is written where the floor is defined rather than
  claimed away. What is checked is that a label exists (eight words, against a
  measured minimum of ten and a median of twenty-four), was written for its own
  entry rather than pasted from another, and names a page this gate actually
  reads — three entries that named `CHANGELOG.md` or a page that does not exist
  passed before. A fragment must also exempt at least one literal and at most
  six (measured maximum today: five), because one entry had been silencing an
  unbounded number, and the registry as a whole has a ceiling so the exemption
  surface only widens where somebody can see it.
- **A second rule, inverted: a value the generated regions PRINT may not be
  written anywhere else.** The four rules above hunt for run-count-*shaped*
  text — a roster noun, a `GREEN`/`RED` adjacency, a wall clock beside a tier's
  name — and the shapes are unbounded, so each new spelling is a new hole:
  `195 states`, `195 mutants`, `190+ rows`, `_195 rows_`, `GREEN: 20, RED: 174`,
  `about an hour`, `77,563,872 distinct` were all measured bypasses. This rule
  is generated **from the number**, so it needs no noun list, no paragraph-local
  trigger and no guess about phrasing, and it covers every grouping — including
  the NBSP and the two thin spaces the shape rule's own class has never held.
  It is floored by magnitude, and the floor was chosen by measurement rather
  than taste: over the scanned corpus the rule finds **10 862** occurrences at
  no floor, **2 236** over ten, **264** over a hundred, **140** over a thousand
  (about 130 of them the copyright year), and **11** over ten thousand — every
  one of those eleven a real second copy of a number the regions print, a
  false-positive rate of **0**. What it cannot see is stated where it is
  defined: a **rounded** copy (`77.6 M` is in this tree) and a **stale** number,
  whose value matches nothing derived today. The shape scan sees those, which is
  why both rules are kept and neither is a supplement.
- **The eleven it found.** One was a hand-typed copy of the derived state count
  that the run-count work itself had added to `docs/testing.md` about 75 lines
  above the generated paragraph, where rotting both its numbers left the gate
  green — that sentence now points at the paragraph instead of restating it. The
  other ten are live figures restated in the narrative that argues about them
  (the fingerprint-estimate paragraph, the before/after comparison with the
  reduced scope, the `COVERAGE=1` sweep, `Policies.cfg`'s and `Liveness.cfg`'s
  own rows, `floors.txt`'s justification for a floor, `gen-configs.sh`'s note on
  why the real constants were kept) and are registered with what each is: not
  rewritten, because the number carries the argument in each, but now a **known**
  list of the prose that goes stale the next time the model widens.
- **The scan reads the directories the criterion names, instead of a suffix
  whitelist under each.** `docs/**/*.md` + `formal/README.md` alone +
  `.github/**/*.{yml,yaml,md}` + two named root pages left 22 measured places a
  run-count could be typed with the row green — a new `formal/*.md` page,
  `floors.txt`'s own header prose, a `\*` comment in a `.tla`, a `#` one in
  `run-tlc.sh` or a registry `.toml`, a `.json` or a `.sh` under `.github/`,
  `SECURITY.md`, `COMPLIANCE.md`, `AGENTS.md`, `CODEX.md`, a `docs/` page that
  is not markdown — and inside a workflow only `#` comment lines were read, so
  a count in a `name:`, an `env:` or the `$GITHUB_STEP_SUMMARY` line a workflow
  actually publishes was invisible too. All driven, all exit 0. The set now
  comes from `git ls-files` over `docs/`, `formal/` and `.github/` plus every
  tracked page at the root, with `formal/runs.toml` (the record itself) and
  `CHANGELOG.md` (whose version headings are the scope label) carved out and
  held to still exist. Widening it cost **0** literals over this tree: `.tla`,
  `.cfg`, `.sh`, `.txt`, `.svg` and `.lock` contribute nothing, so the narrow
  list had been buying no quiet at all. Reading `git ls-files` also makes "not
  the untracked planning document at the root" the MECHANISM rather than a
  two-name whitelist whose own test gave untrackedness as the reason.
  `scripts/check.sh` stated that rule in a form that was false in all four of
  its parts, six lines above the row it describes; it now says what the code
  does.
- **Both halves of the scan gained the ratchet the other half already had.**
  The set of generated regions was floored by nothing at all, so dropping one
  entry from the generator, deleting its two markers and retyping its sentence
  by hand left the row green over the exact state count this work is named
  after — the table-DELETED family one layer out, where the tested case was a
  region the generator does not own and nothing tested a sentence it no longer
  does. And one floor over four scan rules and a trigger cannot see the rule
  carrying most of them go: measured by killing each in turn against this tree,
  `COUNT` dead leaves **19** literals and `CLOCK` dead leaves **16**, both over
  the floor of 8, and `TALLY` dead leaves all **28**, because every tally is
  also a loose one. Only the trigger's death was visible. Every rule now has to
  match at least one literal of its own, and the region set has a floor —
  falsified against the real checkout at the real floors, one rule at a time,
  which is the half the fixture case could not reach.
- **A historical quotation in `formal/README.md` was corrected back to the
  number it was taken at, and the two copies of it are compared now.** The
  pre-fix reading that motivates `verdict_gate.py`'s switch-parsing cases —
  ``a defect armed in a baseline configuration while the row printed `ok — N
  configuration(s)` and exited 0`` — was transcribed into `formal/README.md`
  and `scripts/test_verdict_gate.py` by the same commit, both saying **191**.
  A later sweep retyped every `191` on the README page when the roster grew,
  and five of the six lines it moved were live claims that were right to move;
  the sixth was this one, whose whole evidentiary value is that it does not
  move. It went to **195**, which no roster ever printed: the derivation that
  produced the reading was fixed while `formal/` held 192 configurations, one
  of which is exempt. The copy under `scripts/` survived intact only because
  no sweep reaches there. Both now read 191 and a test holds the pair to one
  number.
- **Each `[[run]]` also keeps the same run in TLC's own words, and the gate
  re-derives the matrix from it.** The record was the hole under everything
  above: `states`, `depth` and the wall clock were held against nothing at all
  and `distinct` only from below, so editing `distinct=77563872` to `48679968`
  and `1869s` to `539s` and running `--write` put six published sentences
  across four files back to the exact defect this work is named after, with
  every sibling row green — driven, exit 0. So `--record` now reads the closing
  sentences of each `formal/out/<cfg>.log` while those logs still exist, keeps
  them, and the gate holds every row's states, distinct states and depth to
  them and the runner's wall clock to TLC's own (which it brackets, so the gap
  belongs in 0..30 s — measured 0-2 s over all 199 rows). `--write` refuses to
  publish from a record that does not check out, which is the step the gate's
  own message used to send people to. Two programs' accounts of one run, in one
  file: **not** a signature, and it does not make a run unforgeable — someone
  writing both halves can write them to agree. It makes a number unrottable by
  hand, which is the class this is about.
- **The recorder reads provenance out of the run instead of off itself.** It
  stamped `date.today()`, the local core count and `$WORKERS` — so
  `WORKERS=9 … --record` over a log whose banner says two published *"at the
  default `WORKERS=9`"* on three pages, and re-recording one capture
  republished it as a later run of a tree it had never seen. The date, the
  worker count and the core count now come from TLC's banner and start line,
  one tier's logs must agree about all three, the run's architecture must be
  this machine's, and re-recording an unchanged matrix moves nothing. A record
  of a tree younger than the run is refused outright.
- **A run-count typed anywhere else reddens the row.** A generated region
  cannot stop the next sentence being typed somewhere else, which is the half
  every guard in this tree has failed on, so `docs/`, `formal/README.md`,
  `.github/` and the two published pages at the root are scanned for the
  vocabulary: a tally, digits or words against a roster noun, a clause the
  tight tally cannot see, and a wall clock beside a tier's name — in prose,
  inside a fenced code block, or inside a YAML comment run. **28** literals
  match today and **19** are registered with the scope they are history to,
  each held to occur exactly once and to actually contain the number it
  excuses. `formal/README.md`'s Results table is generated too: which
  configurations share a line is a judgement and stays written down, every
  number beside them is counted out of the record.
- **The `cfg(kani)` shrinks are derived now, and the hand-written count was
  wrong.** `docs/testing.md` enumerated the production source that means
  something different under the model checker, and rotted twice doing it: it said
  "the tree's only one" while `rsk-usb`'s `CTAP_MAX_MESSAGE` was already there,
  stayed green through `rsk-fs`'s `FID_PRESENT_BYTES`, and was then retyped as
  "one of four" — which is wrong the other way, because `rsk-sdk` shrinks
  **two** constants, `CHAIN_BUF_SIZE` and `RESP_CHAIN_CAP`, not one.
  `scripts/shrink_gate.py` walks each crate's modules from its `lib.rs`, parses
  the attributes rather than grepping them, and holds the page's table to the
  result in both directions. Measured: **5** shrunk names and **3**
  `cfg(not(kani))` compile-time assertions, 13 arms over 4 crates — where a
  separate count of "14 sites" had included `store_assurance.rs`'s `FID_LIMIT`,
  which is inside a module `#[cfg(any(kani, test))]` keeps out of the firmware.
- **A shrink that carries no reason reddens the same row.** The rule is a comment
  block above the arm Kani compiles, or above the run it belongs to, since
  `rsk-sdk` writes one paragraph over both of its constants and says so. The
  floor is 80 characters against a measured minimum of 203. Requiring `///` was
  rejected — two of the five shrinks and one of the three assertions use `//`,
  all of them are real reasons — and so was requiring the word "kani" in the
  block, which `// kani` satisfies and `rsk-sdk`'s paragraph does not.
- **`gate_lines.rust_code` reads Rust for both guards, and closes a gap the one
  copy had.** `b'"'` in `rsk-usb`'s keyboard map opened a string that ran to the
  end of the file, so the module walk read `kbd.rs` as declaring nothing. 154
  `.rs` files lex differently with char and byte literals handled;
  `platform_gate.py`'s unsafe inventory is unchanged on every one of them.
- **The assumptions no model constant can carry have a registry of their own.**
  `scripts/assumption_gate.py` accepts exactly one shape — a Boolean TLA constant
  some configuration assigns both ways and a reachable definition reads — and
  that rule is what makes a model assumption falsifiable, so it was not widened.
  Measured, not argued: `M7-Q2` written into `assurance/assumptions.toml` answers
  `in the registry but no configuration assigns it`, and so does a recorded board
  PASS and so does emulator fidelity. A second FILE rather than a `class` field on
  the first, because deleting a constant from that registry reddens it in one line
  while a `class = "platform"` on the same entry would satisfy the orphan rule and
  skip the both-arms rule — an axiom passing as an assumption.
  `assurance/platform.toml` holds **18** entries and
  `scripts/platform_gate.py` holds them against the tree.
- **One of the eighteen is discharged, and the page says so in its first
  sentence.** `docs/platform-assumptions.md` is generated from the registry and
  byte-diffed, so a status cannot move without the diff that says it moved. Ten
  routes end at a board this repository must not touch — including the three the
  programme had already scheduled and had nowhere to write: the BOOTSEL-return
  question about `WATCHDOG.scratch2`, a real-power PASS of
  `tests/29_reset_power_cut.py`, and `tools/emu`'s fidelity.
- **The candidates are DERIVED — 24 of them, over four sources — and a hand list
  would have found five.** The slice bundle's own `[[assumption]]` ids and the
  design pages' prose ids (10, of which **eight said `registered = "no"`** and
  now say which entry claims them); every constant of the first registry, because
  a model assumption's own discharge is always a fact about the world; the suites
  `tests/emu.py` refuses that `scripts/usbip-guest.sh` does not run either — **5,
  where the plan named 1**, adding `51_secure_reboot`, `53_ccid_pinpad`,
  `54_sram_residue` and `90_otp_mkek_migration`; and the 7 `.rs` files whose CODE
  carries `unsafe`, which is stage 10's "firmware unsafe invariant" half. An
  unclaimed candidate reddens the row, and so does a claim on a candidate that no
  longer exists.
- **Every one of the four derivations reads a STRUCTURE, because an adversarial
  review drove nine legal spellings past the text-reading first versions.** The
  `unsafe` half produced **12** files and four of them carry the word only in a
  line saying the file has *no* `unsafe` — a fifth was a code generator emitting
  it inside a string — so Rust is read with its comments and string literals
  removed and the answer is 7. A comment in `scripts/usbip-guest.sh` could make a
  board obligation vanish *or* redden a live one, so its rows go through
  `gate_lines`. Four legal spellings of an `UNSUPPORTED` entry — single quotes,
  an implicit concatenation, an f-string, an empty reason — were invisible, so
  the shim is read through `ast`. And the whitelists became blacklists: a new
  crate at the top of the tree and a design page outside a two-name list were
  both silently uncovered.
- **The hardware axis reads the registry now, and still prints 0 for all 59.**
  It read a bundle's DECLARATION and nothing else, so a board result recorded
  where a board result actually lands — an obligation with no model constant to
  be written as — would have left the page saying "no property was measured on a
  board" over one. Any row that is `discharged` and records a real stepping is a
  second source, added rather than substituted, and both keep their own rules.
  **Keying it on the silicon CLASSES reproduced the same defect one class over**
  and the review measured it: discharging the emulator-fidelity row, whose own
  route reads "a board recording of the same session", printed 0 over ten
  properties. Nothing moves today: every row is `pending`, which is the point.
- **35 mutations of the new gate, 35 killed, 0 survivors** (the first table was
  30/30 and the review broke four of its rules with the suite green: a floor
  zeroed rather than deleted, a list narrowed, a regex loosened to the part
  number, two vocabularies widened by a member). Six also redden the real
  checkout. Six more did not apply on the first pass and the harness said so — an
  unapplied patch over a green suite reads exactly like a survivor.
- **The two registries are one graph.** Stage 1B п.3's link vocabulary less
  `contradicts`: `supports` names registry properties, `depends_on` and `refines`
  name entries here, and `discharges` names a constant of the first registry —
  with `covers`/`discharges` held to agree, so the two files cannot hold two
  answers about the same constant. `contradicts` is left out because no pair here
  contradicts another, and a link kind with no instance is a rule whose only
  exercise is its own mutation.
- **The registry's one word is a projection now, and the six questions it was
  mixing are printed apart.** The closed slice below took `SEC-FIDO-001` from one
  Kani harness to four and landed the first mutant in this tree ever to redden a
  proof — **and its `status` would have read `BOUNDED` with one harness or
  four**, because `assurance_gate.py` derives that word from a harness *name*.
  `scripts/evidence_gate.py` derives seven axes instead — model, co-refutation,
  trace, Kani, hardware, scope and freshness — and writes
  `docs/assurance-vector.md` from them, so a release sentence cannot outrun the
  axes it is about. What the vector says about the best-evidenced row in the
  registry and one word could not: `NoAuthorizationBypass` is asserted by **2**
  of the 45 configurations that name it — the other 43 are mutants and historical
  runs recorded RED — carries **no** trace evidence of its own, **no** board result, and is
  claimed on **3** of the ledger's built images.
- **Two of the six axes could not be derived as the roadmap words them, and the
  page says so rather than printing a column.** `hardware` has no source: nothing
  in the tree records a board run, so the axis reads a bundle's DECLARATION and
  the rules are about a declaration never arriving without the revision it was
  taken on. `trace` is DIRECT — a recorded session reaches a property only
  through a configuration that checks *that* property, so the refinement rows
  carry the session and the invariants they refine do not inherit it.
- **The migration is lossless because the word holds nothing of its own.** No
  configuration names it → `ACCEPTED-RISK`; a Kani harness names it → `BOUNDED`;
  anything else → `MODELLED-ONLY`. All **59** rows rebuild exactly. §4.3
  condition 11 asks on which inputs such an oracle *disagrees* with what it
  checks, and this one's answer is measured and recorded on the page: **none** —
  it reads the two derivations `assurance_gate.py` already forces the word from.
  That is the result, not a weakness: the scalar was never information.
- **Three rules the tree had only as prose.** The hand-written field set is
  closed (the registry header has said "HAND-WRITTEN FIELDS ONLY" since it was
  written, and a hand-written `kani = 4` column was free until now); a bundle
  claiming a board result — as a subject, as a `measurement` method, or by naming
  an RP2350 stepping anywhere in its text — must record `build.board_revision`,
  and a board field nothing rests on is refused the other way; and every
  derivation is floored **per session, per source** where its input exists and it
  found none of it.
- **The independent review of this row found eight defects, and every one was the
  same family: a rule closed in one spelling of the thing it is about.** The
  freshness axis reached the 2 tagged owners of `SEC-FIDO-001` and not the 5
  untagged ones its own co-refutation patches target; the hardware rule read 2
  spellings of 3, walking past a stepping written into `expires_on_stepping` —
  the bundle schema's *designated* board-dependency field; the `trace` and
  `model` axes counted configurations that are RED **by design** as evidence
  *for* the property; a "may not say" bullet templated with its own count
  inverted into "the hardware axis is **1 of 59**" the moment the axis moved; and
  a total floor stayed silent while one row's session moved into a shell variable
  and four properties quietly lost their trace evidence. All eight are closed and
  each is a case in the table.
- **30 mutations of the gate, 30 killed, 0 survivors** — one per rule *and one
  per derivation clause*, which is the criterion the review corrected: the first
  nine tested the rules the author had in mind and left the Kani-harness half of
  the freshness axis deletable with the whole suite green. The table is 52 cases;
  the seven mutations that also redden the real checkout are the seven that would
  have published a wrong number. Falsified through the row as well as the
  function: a hand-written `hardware` column in `assurance/properties.toml` was
  driven through `nix develop -c ./scripts/check.sh`, which reached
  `== evidence vector ==` after 100 other rows and exited **1**.

- **The co-refutation count had four hand-written copies and every one had
  rotted.** `assurance/properties.toml`'s header said "28 of the 44",
  `formal/README.md` said "42 modelled-only" and "27 of those 42",
  `assurance_gate.py`'s own docstring said "twenty-eight of the forty-four", and
  `test_assurance_gate.py` said "28 of 44" — while the tree has **46**
  MODELLED-ONLY rows, 28 of which carry a driven, killed code twin. The number is
  generated into `docs/assurance-vector.md` now and the four copies point at it,
  which is 1A п.2's open class closed the way §7.1 asks rather than refreshed for
  the next reader to find stale again.

- **The first closed slice's raw evidence bundle, held to stage 1A's ten-group
  contract.** `assurance/bundle/SEC-FIDO-001.toml` carries all ten groups —
  property/subject/owners, commit/build/features, method and bounds as structured
  data, tool/version/invocation/environment, principal result, raw artifact,
  assumptions and TCB, mutation verdicts, freshness triggers, and measured costs —
  with **10 raw logs committed beside it** under `assurance/bundle/logs/`, byte
  count and sha256 each. `scripts/bundle_gate.py` holds it, and the rule that
  makes "unabridged" a predicate is that it counts **leaves** per group with a
  floor: ten headings with one line each satisfy "all ten groups are present".
  419 leaves. Every cost is a number — a range is an estimate wearing a
  measurement's field — and every cost carries a `basis` saying how it was
  obtained, because one peak is a 2-second `ps` sample rather than
  `/usr/bin/time -l` and the bundle should say which.

- **An adversarial review of the slice's three guards found two blocking holes,
  and both were the family this repo has measured five times.**
  `ghost_gate.py`'s `viol'` scanner was line-anchored, so four ordinary TLA+
  spellings hid a recording action with the row GREEN — the bullet on the
  previous conjunct's line, a whole definition on one line, an assignment inside
  an `IF` branch, and a `LET`-bound set. Neither floor could see it: 21 of 22
  actions still derived. It now counts the module's own occurrences of the name
  per operator and compares them with what the routes account for, so reading
  LESS than the module has is a finding rather than a shorter roster; and helper
  inheritance runs to a fixed point, because one level left a route two calls out
  from an action derived by nobody. `bundle_gate.py` gained named required fields
  per group (a leaf floor counts volume, not fields: renaming one kept the count)
  and a `sha256` beside the byte count (which any file of the same length
  satisfied). And `token_refinement_gate.py`'s floors no longer *suppress* the
  precise finding: at the derived count, renaming the reset-window guard reported
  "the derivation stopped reading the tree" and hid the two accurate `stale
  owner` lines — a security guard deleted, reported as a broken reader.

- **The `credentialManagement` *Begin*'s own decision is proved at its call
  site.** `SEC-FIDO-001`'s only Kani harness ran a symbolic five-operation
  interleaving over the walk cursor and asserted an equality about
  `may_walk_rps` — but it called neither production caller: `begin_rps` and
  `begin_creds` reproduced the cursor writes, so the Begin's own gate, the
  `pinUvAuthParam` MAC and the `cm` permission bit and the rpId binding, was
  never evaluated. The harness proved what follows an authorization it assumed;
  the property is about the authorization. Three new harnesses in
  `crates/rsk-fido/src/credmgmt_kani.rs` drive the real `verify_cm_token` and
  `check_rp_binding` in `authorize_cm`'s own order, behind the `cm.reset()` the
  subcommand demux performs first, and then the cursor writes verbatim from
  `enumerate_rps` / `enumerate_creds`. Five claims, all equalities. Two of them
  close divergences the design page had only "checked by hand": the two call
  sites write their totals on **opposite sides of `load_keydev()`**, so a seed
  failure after an authorized Begin leaves the RP walk live and the credential
  walk dead; and `cm.rp_id_hash` — a cursor field the demux reads back to serve
  a *Next*, which `begin_creds` never wrote — is the rp the Begin was authorized
  against.
  **Its own first run refuted its own D5**: the claim was written as "the rp the
  TOKEN is bound to" and an unscoped token is authorized for any rp, so the
  cursor legitimately held one the token was never bound to — 305 s to find, and
  the wording is "the rp the request named" now. And the `state` Kani tier's cost
  more than doubled with them: 546 → 1341 s of solving, 9.3 → **15.3 GiB** peak,
  which is over what a hosted runner has and is recorded in `docs/testing.md` as
  a decision rather than a margin.

- **The first of the authorization slice's eight assumptions is registered, and
  both its arms run.** `AS-AUTH-2` — the shipped image is built without
  `--features always-uv`, so `gate.alwaysUv` is a free state variable rather than
  the compiled default every reset restores — is now `AlwaysUvShipped` in
  `assurance/assumptions.toml`, read by `Init`, `GatesLive` and `ResetSweepGates`
  and assigned **both ways**: FALSE by the 89 configurations the shipped image
  was about on the day this landed (the roster grows; count them in `formal/`,
  not here), TRUE by the new `AlwaysUv.cfg`, which runs the nine invariants its
  own `INVARIANTS` block names, with alwaysUv on — GREEN over 23 521 512
  distinct states at depth 51. An assumption no run can vary is an axiom, which
  is the rule `assumption_gate.py` already carried and nothing this slice needed
  had met. `GatesLive` reads `gate.alwaysUv # AlwaysUvShipped` rather than
  `gate.alwaysUv`, and that is closer to the tree, not further: `EF_ALWAYS_UV`
  exists only as an OVERRIDE, so there is a record for the reset sweep to delete
  exactly when the two differ.
  **`Shipped.cfg` was re-run and came back at 77 563 872 distinct — bit-identical
  to its count before the constant existed**, which is the measurement rather
  than the argument that the arm the image ships did not move. The
  `firmware-always-uv` settling question records the other half: its model arm is
  answered and its code arm is not, and the cost of the second is now a number —
  `cargo test -p rsk-fido --features always-uv` was 446 passed and **172 failed**
  at `f52b720` on 2026-08-27, over the 619 tests the suite held that day, which is
  the run `assurance/bundle/logs/cargo-test-always-uv.log` records. That reading
  is dated because it is this entry's and stays this entry's: the suite grows, so
  a later count is a second true measurement and not a correction of this one,
  and a bare pair cannot say which of the two it is. alwaysUv with no PIN answers
  `PUAT_REQUIRED` and the suite is written against the default door.

- **A recorded mutant reddens a Kani harness, for the first time.** All 67
  co-refutation slices ran `cargo test -p …`, so no proof in this tree was
  falsified by any recorded defect — the property's single harness was the same
  shape as a guard whose wiring nothing exercises, one layer in. A `patch` entry
  in `formal/comutants.toml` may now carry a `proof` (a second command, run in
  the same worktree after the slice killed) and `proof_names` (the check one of
  its failures must carry). `BugCmWalkIgnoresChannel` carries the first: it drops
  the channel conjunct out of `may_walk_rps`, so `no_authorization_bypass_walk_owner`'s
  `NoAuthorizationBypass/B1` equality must fail on the non-owning probe
  specifically, and a different check falling is a different defect. Three traps
  are refused by name rather than counted as kills: `--target <host>` now goes on
  a `cargo test` and nowhere else (`cargo kani` answers a clap error, which this
  file's own classifier read as "the patch does not compile"), and a CBMC timeout
  or an unsupported Rust construct ends in the same `VERIFICATION:- FAILED` a real
  refutation does. The weekly `comutants` job gains the out-of-band Kani install
  the `kani` job already had.

- **And its verdict word could not tell a green harness from one that never
  ran.** `proof_verdict` read `proof-survived` off the ABSENCE of
  `VERIFICATION:- FAILED`, so "the harness ran and stayed green" and "the harness
  reached no verdict at all" were the same answer. The half's first CI run is
  what said so: `BugCmWalkIgnoresChannel` came back `proof-survived` from the
  Linux runner, and repeated it on the next push, while the same patch reddens
  `NoAuthorizationBypass/B1` on the maintainer's host — re-measured there, still
  `Failed Checks: NoAuthorizationBypass/B1`. That verdict is read off
  `VERIFICATION:- SUCCESSFUL` now and off nothing else; an output carrying
  neither line is `proof-broke` with the tool's own first `error` line attached,
  so the next run names what broke instead of crediting the mutant with a
  survivor. `proof_problems`' three ways to name a harness that cannot redden are
  unchanged and are all STATIC — this is the fourth, and no static answer reaches
  a tool that does not run on the host. Why the runner reaches no verdict is not
  answered here: the proof is the one command in this pipeline that runs
  `cargo kani` inside `nix develop` — the `kani` job is rustup-based — and the
  line the row now prints is what settles it.

- **And the line it printed named the tool, not its reason.** The runner's answer
  was `the harness reached no verdict: error: goto-cc exited with status exit
  status: 1`, with goto-cc's own words gone: Kani suppresses a child's output
  unless the command asks for `--verbose`, as its `--quiet` says in as many words.
  The roster's proof asks now, and a run that reaches no verdict prints the tool's
  last lines before the worktree it ran in is removed — `proof-broke` with a
  wrapper's message and nothing under it was one round trip of a weekly row.

- **And what it said, when it could: a nix library in front of a toolchain that
  is not nix's.** `goto-cc: /lib/x86_64-linux-gnu/libc.so.6: version
  `GLIBC_ABI_DT_X86_64_PLT' not found (required by
  /nix/store/…-glibc-2.42-61/lib/libm.so.6)` — the dev shell exports
  `LD_LIBRARY_PATH` for the binaries it builds, and `cargo kani setup` downloads
  CBMC's, built against the runner's own glibc. A nix libm beside the system libc
  is exit 1 and no verdict, which is how `BugCmWalkIgnoresChannel` spent three
  weekly rows as a survivor. The proof half runs with that path dropped and every
  other slice keeps it, because a `cargo test` slice IS nix-built and its
  libudev, libpcsclite and libSDL2 are on it. The rule that made this readable at
  all is the one above: the row printed the tool's own words instead of a verdict
  it had not earned.

- **The weekly `formal` row stopped finishing, and said `cancelled` rather than
  anything about the model.** The safety tier outgrew the single job it ran in:
  one configuration took most of that job's budget, the row reported it and was
  killed for time, and 223 others went unwatched behind a verdict that named
  none of them. The tier is sharded now — `TLC_SHARD=i/n`, beside `MIRI_SHARD`
  and `MUTANTS_SHARD` — with one difference: membership is by RECORDED COST, read
  from `formal/runs.toml`, because round-robin puts the heaviest configuration
  and the next-heaviest in one shard (they sit 7 apart in the lister, and
  0 == 6 mod 3) and that shard then carries most of the tier. By cost the three
  are within a minute of each other, and none can come under the heaviest single
  configuration, which is what the job's cap leaves room for rather than the
  tier's sum. `scripts/test_run_tlc.py` holds the property sharding silently
  breaks — the shards of a tier are a PARTITION of it, so a configuration no
  shard runs cannot hide behind a matrix of green ones — plus the balance, a bare
  `TLC_SHARD=3` (which both of the runner's expansions read as 3/3), and a matrix
  wider than its tier.

- **Three quarters of `NoAuthorizationBypass` had no ownership ledger, and now
  do.** The invariant is four clauses — the token and its permission, the retry
  budget's soft lock, the reset window, the walk's owning channel — and
  `assurance/token_refinement.toml` owned only the first, so "the ledger covers
  the property" was a sentence about a quarter of it.
  `scripts/token_refinement_gate.py` gains three GUARD axes beside its three
  writer axes, and every site is derived: the walk's guard is a `CredMgmtState`
  method that compares the cursor's channel with the request's; the soft lock's
  vocabulary — its wire type and the two `FidoState` fields it is made of — comes
  out of `FidoState::pin_lock` itself; the window's guard is the `reset.rs`
  predicate that reads both halves of the power-up. **The scan covers three
  units, not one, and that is a measurement rather than a preference:
  `pin_lock`/`restore_pin_lock` have ZERO callers inside `rsk-fido`** — the board
  marshals the lock across a warm reset — so an applet-only scan derives 2 sites
  of 12 and silently loses the half the clause is about. Each axis carries a
  floor, which is the rule the file did not have before: a derivation that finds
  nothing satisfies every other rule over the empty set. 18 new owned sites, each
  `out-of-scope` with its formal basis, because tier A carries no channel, no
  retry counter, no soft lock and no clock — the complementary source obligation
  the A map names.

- **`NoAuthorizationBypass`'s ghost clause is mechanised, not asserted.** The
  invariant leads with what can be read out of state and keeps a ghost — `"…"
  \notin viol` — only for the part that is genuinely about a STEP, which makes
  it exactly as strong as the completeness of the actions that write the name.
  The model named those actions in a comment and called the list **eleven**. The
  tree has **21, over 24 routes**, and nine of them the comment named nowhere.
  `scripts/ghost_gate.py` derives both out of the module — the actions `Next`
  reaches, the aliases that stand for the name (`TokenBypass`), the routes inside
  each `viol'` assignment, and a helper's routes inherited by its callers, which
  is how `PinAttempt`'s one route reaches `GetPinToken`, `WrongPin`, `MintPpuat`
  and `ChangePinStart` — and holds them against `assurance/ghost_actions.toml`
  both ways. **Routes are counted rather than names** because `RegisterStart`,
  `RegisterNdStart` and `AssertStart` each record by two independent routes: a
  name-set equality is green after one of the two is deleted, over a
  half-deleted guard. A second axis holds the `*Policy` operators each assignment
  consults, so a route kept and its guard swapped is a finding rather than an
  edit. The mutation table drives all 24 single-route deletions and all 21
  delete-every-route cases against the real module.

- **Tier A of the authorization slice now has an oracle that is not the model
  it checks.** `formal/RSKeyTokenGate.tla` carries `RequiredGate`, one line per
  abstract operation, transcribed from CTAP 2.3 §6.1/§6.2/§6.5/§6.6/§6.8/§6.11 —
  never read off `AllowedEventRel`, because a postcondition that transcribes its
  subject satisfies every other condition and still cannot fail (§4.3's eleventh,
  and the per-FID projection that reported 0 divergences over 5⁴ inputs is this
  tree's own instance of it). `NoAuthorizationBypassA` says every event the
  relation admits as `Authorized` had the gate its operation's requirement names.
  Four generated configurations: `TokenGate.cfg` GREEN at a floor of **44** — a
  pin, because the invariant is asserted over the relation's slice at the current
  state and so covers `AllowedRelation` only if every A state is reachable;
  `TokenGateOracle.cfg`, a probe whose initial states ARE the set on which the
  requirement and the relation disagree, floored at **22**; and
  `TokenGateDisagreement.cfg`, registered **RED** because a GREEN there is the
  degenerate oracle. `TokenGateMut_BugUnauthorizedEdge.cfg` adds one `Authorized`
  edge the requirement forbids, so the invariant is known able to fail.
  **Measured before the row was accepted: 31 disagreeing (state, operation) pairs
  over 22 states, in two families** — every state disagrees on `ClearPin`, where
  the relation's `pre.pinSet` is a frame condition and §6.6's real gate is a
  window and a touch that tier A cannot see; and nine also disagree on `UseCm`,
  where §6.8.2 lets the persistent grant authorize on its own and RS-Key
  additionally demands `EF_PIN`. The second family is the shipped tree being
  **stricter than the requirement**, which an oracle taken from the code could
  not have shown.

- **The first P0-launch assurance slice, written down before its proof code
  exists.** [`docs/authorization-slice.md`](docs/authorization-slice.md) fixes
  the scope and the measurement plan for `SEC-FIDO-001` /
  `NoAuthorizationBypass`: the A/B/C maps, the callers, eight named assumptions
  with the class each belongs to, thirteen bounds each with what it stops
  proving, a mutant table per level, nine exit **predicates** and one named
  guard-rail each with what would make it fail, and the ten-group raw-bundle
  contract the implementation must emit unabridged.
  It closes nothing and moves no status — the row stays `BOUNDED` — because the
  point is to make the cost of closing it *observable*: `SEC-FIDO-001` leads the
  57 on the three axes this slice is about (44 configurations, 11 model mutants,
  11 co-refuted), so any figure taken on it is a **floor and not a price**, and
  the weak-end counterpart `SEC-FIDO-007`/`-008` is designed beside it for that
  reason.
  **An adversarial review refuted the page's own strongest negative claim**, and
  the repair is in it: the bounds table said no `cfg(kani)` constant shrink was
  reachable from this slice. **Three are.** `rsk-usb`'s `CTAP_MAX_MESSAGE` drops
  from 129 frames to 3 and `crates/rsk-device/src/ctap.rs` defines `RESP_CAP` as
  exactly that constant, so all seven `presence_kani.rs` harnesses prove over a
  two-continuation transport; `rsk-sdk`'s `CHAIN_BUF_SIZE`/`RESP_CHAIN_CAP` drop
  2038/2048 -> **16**, and `rsk-device`'s FIDO CCID applet is an
  `rsk_sdk::Applet`. The census is 14 sites across four crates. The same review
  refuted the assumption split — `PowerOnClearsScratch2` is registered in
  `RSKeyBootHardening` and the overlap between the 13 configurations that assign
  it and the 44 that check `NoAuthorizationBypass` is **zero**, so this slice has
  **0 of 8** assumptions registered, not 1 — and five of nine exit criteria that
  could not go red, including one satisfiable by pasting a doc comment into five
  files, because `assurance_gate.py`'s `rust` column greps whole file text.
  **Four further things it measured, none of them fixed here.**
  `NoAuthorizationBypass`'s own comment names eleven actions and calls that "the
  whole list"; **21 of the model's 53 actions** record it, and the nine it names
  nowhere are three for the on-panel ceremony, two for the token-less
  registration arm, three continuations of flows whose *Start* it does list —
  and `SetPinStart`, a whole flow it omits. Nothing compares the
  sentence to the set — `R1oOutcomeCoverage` is the only completeness equality
  in the models and it guards a different set of 23 names.
  **No `slice` in `formal/comutants.toml` runs `cargo kani`**: all 67 patched
  co-mutants are `cargo test -p …`, so no Kani harness in this tree is reddened
  by a recorded mutant and the property's single proof is falsified by nothing.
  The recorded session reaches **22 of 53** model actions and **10 of this
  invariant's 21** — the whole `credentialManagement` family, which is what that
  one harness is about, is unreached — while `@TraceSecurityActionsMin` ratchets
  the count and never asks which actions. And five of the seven files
  co-refutation already patches for this property carry no
  `Refines … — SEC-FIDO-001` tag, which is the whole reason the derived owner
  column reads 2.

- **The model refused a registration the firmware serves.** CTAP 2.1 §6.1.2
  steps 7/10 — `makeCredUvNotRqd` — create a NON-discoverable credential on the
  touch alone even where a PIN is set
  (`crates/rsk-fido/src/makecredential.rs:543-545`), and `RSKeySecurityState`'s
  `RegisterStart` conjoined `OpGuard("mc", r)`, which is `TRUE` only where
  `~UvRequired`. So the exhaustive model met a token-less registration only on a
  PIN-less key and **never the carve-out itself** — the one region a defect in
  step 10 could live in was reachable on the device and not in `Next`.
  `TraceSecurity`'s R4c had been stating the rule against a recorded session
  since the gate grid closed, and its own comment named folding it in as the
  next widening. Folded in: `RegisterNdStart` / `RegisterNdTouched` /
  `RegisterNdRefused`, which write nothing because
  `makecredential.rs:777-778` stores only under `req.rk`, and carry no `rp` for
  the same reason — a credential the device does not record is one it cannot
  tell from another RP's. `Shipped.cfg` stays **GREEN, exhaustive**, at
  77 563 872 distinct against 48 679 968 and depth 55 -> 58.
  **Falsifiable at both halves, one switch each**, the split `TraceSecurity`
  already draws with `MutateUvNotRqd` / `MutateAlwaysUvArm`:
  `BugUvNotRqdIgnoresRk` (the carve-out forgets it is non-discoverable only, so
  a resident credential is created with a PIN set and no token) and
  `BugTokenlessIgnoresAlwaysUv` (§6.1.2 steps 6.2/6.4 dropped). Each is RED on
  `NoAuthorizationBypass`, and they fall at DIFFERENT actions — the first at
  `RegisterStart`, the second at the new `RegisterNdStart` — so a RED names
  which half was load-bearing. `McTokenlessGuard`/`McTokenlessPolicy` is a
  Guard/Policy pair for that reason: fold them together and a widened gate widens
  the requirement with it, and neither mutant can fire.
  **The tie to the production owner is a `check.sh` row, not a sentence.** Both
  code co-mutants patch `makecredential.rs::enforce_pin` — the function item 9's
  rescan registered in `assurance/token_refinement.toml` twice, as the `UseMc`
  volatile writer and as its outcome producer — and `comutate.py --lint`
  re-resolves both anchors against the tree on every run. Both measure `killed`
  (28/30 code-level kills now).
  **Read for direction, not for colour:** the kill first reported
  `Err(Other)` against `Err(PuatRequired)`, which reads as "still refused". It
  was the response encoder running out of a 256-byte buffer *after* the gate had
  already let the request through; sized for a served response the same tests
  report `Ok(770)` and `Ok(802)` — a credential minted. The three refusal tests
  in `makecredential_tests.rs` carry 1024-byte buffers now, so the mutant's
  evidence is the registration and not a changed status code.
  **What stays narrow is one conjunct, and it is named:** `~tok.live`. Above
  `state.rs:530` the same touch SPENDS a live token without binding it, and tier
  A has no word for that edge — its `UseMc` admits an authorized event only
  under `~pinSet \/ (live /\ permissionMc)` and its `Consumed` requires the rpId
  binding this path never makes. Under `~tok.live`,
  `consume_after_user_presence` is a no-op, so B and the firmware agree exactly
  and the refinement clause is `Noop`, an equality rather than a widening of A.
  Widening A belongs to the token-refinement work and is recorded in
  `formal/README.md` with the other places the model is narrower than the
  firmware. No `bcdDevice` bump: the only Rust that moved is behind
  `#[cfg(test)]`.

- **The two EF_META fault sites are Kani harnesses now, and the two registry rows
  they belong to did not move.** `docs/store-refinement.md` had measured a win and
  recorded it as not taken: a probe that does nothing but `meta_add` fails under
  `cfg(kani)` on `index out of bounds ... decided_bit`, and the blocker is
  `EF_META`'s VALUE (`0xE010`, index 7170 of a map `FID_PRESENT_BYTES` shrinks to
  three bytes) rather than the map's width. Re-measured on this tree: the same
  probe with `#[cfg(kani)] EF_META = 0x0017` is `SUCCESSFUL` in **0.223 s**.
  `crates/rsk-fs/src/store_meta_kani.rs` takes the two obligations that sit there
  — `meta_add` refusing a FAILED EF_META read instead of rebuilding from an empty
  blob (0.317 s), `meta_delete` never caching that read as a decided absence
  (0.156 s) — over the `FaultBackend` the cache clauses already use, both
  directions of each as separate clauses, because Kani 0.67 reports every
  `assert!` message in this crate as "a placeholder message" and the failing LINE
  is then the only thing that tells a kill from its inverse. Driven, not assumed:
  `BugMetaAddDropsOnFault` and `BugMetaDeleteDropsOnFault` each fail their
  harness on the FAULTED arm, which is the defect and not its mirror.
  **`SEC-STORE-003` and `SEC-STORE-004` stay `MODELLED-ONLY`**, deliberately, and
  the harnesses are named so that they stay: `assurance_gate` forces `BOUNDED`
  off a harness function name carrying the property's, without looking at domain,
  bound or `cfg`. A `FaultBackend` holds no blob, so what verifies is the guard at
  the fault site and not "no record was lost" — both clauses over a MEDIUM still
  time out, re-measured at **420 s** (`CBMC timed out`, 419.9 s and 420.7 s of
  solving) with a single-blob backend and `META_MAX` shrunk 1024 -> 32. The redefinition costs a
  boundary, and it is written down where the shrink is: at `0x0017` the blob sits
  INSIDE the symbolic FID domain instead of outside it, so three things stop being
  proved — that EF_META indexes within the shipped map (the compile-time assert in
  `fs.rs` owns that), that EF_META is disjoint from every FID an applet writes (an
  over-approximation the shrink invents, assumed away by name), and that `scan`
  registers every file it is handed, since its `fid == EF_META` skip now refuses
  FID 23, inert only because no harness reaches `scan`. `VIEW_FIDS` is untouched:
  it never lands in the 24-bit map, it is read under `cfg(test)` only, and the
  seven-alternative measurement that chose it stands. `scripts/kani.sh`'s floors
  and the `docs/testing.md` tier table move with the two harnesses (`pr` 61 -> 63
  and 31 -> 35 covers, `state` 24 -> 26 and 26 -> 30, `all` 87 -> 89 and
  51 -> 55, `light2` 27 -> 29 and 8 -> 12).
  **bcdDevice -> 0x0994** — the image cannot reach a `#[cfg(kani)]` constant, but
  `bcd_gate` reads cfg-gated FILES rather than cfg-gated REGIONS and the new
  `pub const` line carries no cfg of its own, so the counter moves rather than the
  guard.

- **The TLA verdict registry is held at merge time now, not only by the weekly
  matrix.** `formal/floors.txt` records what each of the 192 TLC configurations
  must produce — GREEN or RED, a state floor, and for some RED rows the invariant
  they must break — and the only thing that read it was `run-tlc.sh`, which runs
  in the weekly `deep-checks.yml` safety tier and nowhere else. So between two
  weeklies the file could be weakened and every gate row stayed green. Measured,
  not assumed: the two layers that did reach it (`security_trace.py --check-data`
  and `scripts/test_run_tlc.py`) name **two** of its 25 wildcard families, so
  **23 families covering 102 of the 192 configurations** had no merge-gate
  witness at all — and flipping `SeamMut_*.cfg` from `RED` to `GREEN` left
  `./scripts/check.sh` passing all 98 rows.
  `scripts/verdict_gate.py` is the new `TLA verdict registry` row, and it derives
  what the registry should say rather than keeping a second copy of it: the
  verdict comes from a configuration's own CONSTANTS (a `Bug*`/`Mutate*` switch
  on means RED, unless a `Check*` observer is off — which is what makes
  `TraceSecurityBadAlphaNoR4b.cfg` a GREEN control), solo-style is read off the
  INVARIANTS block instead of off the `Solo_` in a filename, an entry may not be
  missing, orphaned, masked by an earlier wildcard or contradicted by a second
  row, and a floor is compared with the newest committed registry that differs
  from the working tree's — so a decrease has to say so in the file. It also
  holds `run-tlc.sh`'s own extractor to the names the registry gives it: the
  `[A-Za-z]+` that could not read a digit, and left every `R4*` row printing a
  blank verdict column for its whole life, is a static disagreement between two
  files now, and so is a `floors.txt` saved with CRLF endings — which makes the
  runner read `[ "$distinct" -lt "200\r" ]` as an integer error, take the
  non-zero for "not below the floor", and pass every floored row. 241 cases in
  `scripts/test_verdict_gate.py`, parametrized over families **derived** from
  `floors.txt` rather than listed, so a new family arrives covered instead of
  arriving unwatched. Six of the rules are review findings on the finished
  guard: 26 of 32 mutations of it died against the table and the six survivors
  were the holes, including one assertion that read `[] == []` once its rule was
  removed.
- **The same row, after a second review refused it.** The verdict was derived
  with `value == "TRUE"`, which two TLA+-legal spellings defeat — a trailing
  `\*` comment and a value wrapped onto the next line — so a defect switched on
  in a **baseline** configuration derived GREEN. Measured against real TLC rather
  than read off the source: `Boot.cfg` with `BugMarkerBeforeScrub = TRUE  \* E-arm
  kept` came back `RED: MarkerNeverLies … !! expected GREEN` from `run-tlc.sh`
  while the row printed `ok` and exited 0, and routed through `gen-configs.sh`
  the config generator's own gate stayed green as well. Both spellings are read
  now, and a switch value that is neither `TRUE` nor `FALSE` is a finding rather
  than a shrug. With it: a shipped `Fix*` taken back out owes RED (the exclusion
  that kept `Shipped.cfg` from reading as a mutant had made a Fix-only mutation a
  silent GREEN), a directory named `*.cfg` is reported instead of raising,
  trailing whitespace after an invariant name is stripped the way `read` strips
  it, `PROPERTY` is read as well as `PROPERTIES`, and a committed registry that
  parses to nothing is a finding rather than a comparison of nothing with
  nothing. The table gained the four arms on the ten **exact** RED rows that had
  none, and four cases that run the script over a throwaway git checkout —
  because every case called `audit()`, and `run()` returning 0 with all fourteen
  findings printed survived all 182 of them.
- **A gate row can no longer be commented out, and a mutation table can no longer
  be emptied, with the suite green.** Both are properties of the whole set of
  guards rather than of any one of them, and both were measured across it: all
  **eleven** `scripts/*_gate.py` rows commented out of `check.sh` at once left
  `pytest scripts -q` identical to its baseline, because every assertion that a
  row is wired in compared the file's RAW text — the roster's own comment-cut was
  applied to one half of it and eight guards each kept a copy of the same raw
  check. And all **nineteen** mutation tables could be truncated to their SPDX
  line, because the roster asked only whether the file exists. Deleting the line,
  or the file, was caught in both cases, which is what made the pair look
  covered. One comment-aware reader in `scripts/gate_lines.py` now, a floor on
  the cases each table carries, and the mutation driven at all 11 + 8 + 19 sites.

- **Every caller of the delete family carries a written decision now, over a
  roster nothing hand-keeps.** `assurance/deleters.toml` disposes of all 43 sites
  outside `crates/rsk-fs` — 24 `Fs::delete`, 9 `delete_key`, 10 across the two
  `force_delete` spellings —
  each classed, each naming whether its fid can carry an EF_META head (the axis
  `force_delete`'s postcondition differs on, and the one the 0x077C databug turned
  on), and each saying whether discarding the deleter's answer is an allowed
  best-effort wipe there or a device reporting success over something still in
  flash. The roster under those decisions is **derived**: `scripts/deleter_gate.py`
  reads the tree for the sites, the verb each calls and whether the statement
  reads or discards the `Result`, and holds the file to it in both directions —
  so a new caller arriving unaudited, a `must-read` site quietly becoming a
  `let _ =`, or a relabelling in place of a re-decision all redden the new
  `delete-caller dispositions` row. It derives the head-minting crates too,
  because every `drops-head` decision rests on that set being `rsk-piv` alone.
  19 cases in `scripts/test_deleter_gate.py`, and the row itself was driven red
  through `./scripts/check.sh` (EXIT=1 at `== delete-caller dispositions ==`)
  rather than only through the function — five of the five guards this repo
  shipped before it had a hole of that family.

- **A security property is claimed about an *image* now, not about "the
  firmware".** The tree builds **19** named `firmware*` flake packages of which
  `release-build.yml` publishes **14**; `firmware/Cargo.toml` carries **6** cargo
  features no package expresses — `largeblob-ext` swaps the CTAP 2.1
  `largeBlobKey` pair for the 2.3 `largeBlob` extension and holds **four**
  `check.sh` rows at zero packages — and `firmware/boards/` is a third axis of
  **6** presets under both. Every entry in `assurance/properties.toml` was
  measured on exactly one of those **31** configurations and read as a claim
  about all of them. The sharpest case is not hypothetical: "the no-touch image"
  is **four** packages, and they replace the physical-consent gate the P0-launch
  authorization properties are *about* with an instant auto-confirm.
  `docs/assurance-matrix.md` is the disposition — **40** P0-family properties ×
  31 configurations = **1240** cells, each `covered`, `equivalent`,
  `conditional`, `out-of-scope` or `gap`. It is generated, never written:
  `scripts/matrix_gate.py` derives the columns from `nix/firmware.nix`,
  `firmware/Cargo.toml` and `firmware/boards/`, the rows from the registry, and
  diffs the page on the new `build-configuration matrix` row, so a new package,
  feature, board or P0-family property arrives as declared gaps rather than as
  silence. `assurance/configurations.toml` holds only the half no derivation can
  produce. `equivalent` takes **one** basis and both of its halves are
  machine-checked: the two columns' derived per-crate cargo-feature closures
  must be equal — `firmware-display` cannot be equivalent to `firmware`, its
  closure moves six crates — **and** the cell must write down the build knobs
  that still differ, with their values. That second half is a review finding on
  the finished guard, and the measurement that earned it: all 143 `equivalent`
  cells compared an *empty* feature set with an empty one (that is what "the
  delta is knobs" means), so the rule was vacuous on every cell it guarded while
  `FLASH_SIZE`, `KVMAIN`, `LED_KIND` and `led_order` — real `rustc-env` /
  `rustc-cfg` inputs, and a regenerated `memory.x` — moved unread. Five more of
  the same pass: a package written `attr =` / newline / `mkFirmware {` (a break
  this very file already uses twice, and nothing runs `nixfmt --check`) was
  invisible, and reformatting one onto a single line *erased its knob* and made
  it read as the default build; a hand-declared `disposition = "gap"` took its
  column out of the rule that makes a gap owe a question; a board in a
  subdirectory was no column though `build.rs` builds it; one `elif` could not
  fail; and the weak `dep?/feat` resolution depended on alphabetical order.
  **958 of the 1240 cells are `gap` and say so**; every column carrying one owes
  the question that would settle it, because a gap with no question is a shrug
  with a verdict column. 72 cases in `scripts/test_matrix_gate.py`, and the row
  was driven red through `./scripts/check.sh` (EXIT=1 at
  `== build-configuration matrix ==`) rather than only through the function.

  An independent review of the finished guard then found the seventh hole of
  the shape the six above have, and it is the sharpest: **the machine-checked
  rule was walked past by writing a STRONGER word.** `equivalent` was refused on
  a prose basis because it asserts sameness — but `covered` asserts that the
  evidence was produced *here*, which is more, and it took prose on trust. Every
  un-placed cell re-declared `covered` was EXIT=0 over 995 of them; so were
  `conditional` and `out-of-scope`, one word over. **No disposition rests on
  prose now**: `covered` names the `check.sh` rows that produced it, and a row
  counts only if it builds *that* column — same cargo features, same build
  knobs — *and* selects a crate whose Rust carries the property's tag, because
  a row that merely compiles an image is not evidence about a property.
  `gate-compiled-out` names the `cfg` site instead of proving the feature exists
  somewhere (eight store rows were out-of-scope on `firmware-fips` for a PIN
  policy in rsk-fido); an `equivalent` chain is followed to a `covered` cell and
  a cycle is refused; a `cargoFlags` token that is not `--features` is a knob
  rather than nothing, and `cargoFlags= [` is read like the canonical spelling —
  it erased a *published* flavor's whole feature set; two `mkFirmware` blocks
  under one `name` no longer replace each other in silence; the artifact is
  diffed as bytes, so a CRLF rewrite is not "equal"; the axis floors sit at the
  counts rather than half of them; and `"?"` is no longer a settling question.
  **One cell moved the other way**: `SEC-DISP-001/002/003 × firmware-display` is
  a `gap`, not `covered` — its evidence is real but was all produced at the
  default 4 MB geometry, and that column also pins `flashSize = 16M`.

- **And which *threat* it is against.** `docs/threat-model.md` is the root of
  every evidence chain the registry describes, and **33** rows cited it by the
  file name and nothing else — which names no threat, so a property with none
  behind it was indistinguishable from one with a threat that was simply not
  written down. Each P0-family row now names a **clause**:
  `docs/threat-model.md#TM-…`, an id of the new
  `assurance/threat_clauses.toml`, and the bare file name is refused on those
  rows. The clause set is not a hand roster — `scripts/threat_gate.py` derives it
  from the page's own headings and list items (**45**, of which **32** state a
  defence and **13** are the title, assets, an out-of-scope declaration, a stated
  residual, a third-party result or a process) and holds the file one-to-one
  against it, so
  a new bullet arrives as a clause nobody classified and a reworded one as a
  citation gone stale. The lock is the clause's first line, not a line number:
  text inserted above it does not rot the reference, which is the failure mode
  `formal/citations.lock` pays for.
  **The mapping is the finding.** **33** of the **40** P0-family rows trace, and
  **19** of those land on one clause — the `Protocol gates` bullet, whose one
  sentence enumerates five gates and is the most load-bearing line on the page.
  **Seven** do not trace at all, and each records which of exactly two things
  that is: `missing-clause` or `defends-nothing`. All seven are the first, and
  **four of them name the same absent clause** — `SEC-STORE-001`, `-003`, `-004`
  and `-005`, because the page states **no power-interruption threat** though a
  host can cut USB power at a chosen instant and the whole `RSKeyStore` module
  exists for that attacker. The other three: `SEC-FIDO-005` (nothing says the
  owner must be able to see and revoke what the device holds), `SEC-POL-003`
  (nothing covers key material surviving a slot's re-parameterisation) and
  `SEC-POL-006` (no Yubico OTP clause exists at all — the OTP slot access code is
  missing from the `Protocol gates` enumeration for the same reason).
  From the other end, **21** of the 32 stated defences have no registered
  property and one more is answered only by an out-of-queue ruling: the P0 family
  covers the hostile-host protocol surface and none of the at-rest, secure-boot,
  anti-rollback, supply-chain or post-quantum half, which is where stages 9–11
  live. Every one of those is printed on each run rather than refused, because
  minting a false mapping to empty the list is the failure this row exists to
  stop. **One docs finding falls out of the mapping**: the `Protocol gates`
  clause enumerates FIDO touch, OpenPGP UIF, OATH access codes and PIV
  management-key auth, and no Yubico OTP gate at all, though `SEC-POL-005`
  enforces one.
  Nine of the rules are review findings on the finished guard, each a spelling
  the first draft could not see: `*`, `+` and ordered list markers; headings
  outside `##`/`###`; `~~~` fences; a setext heading — refused out loud rather
  than missed, and the first draft of *that* refusal demanded `-{3,}` while
  CommonMark makes a single `-` an H2; a blockquote, table row or HTML list, any
  of which can carry a clause; trailing whitespace read as a rewrite; a reference
  spelled `#tm-host-gates` or `./docs/…`, which fell through every rule while
  LOOKING traced; a missing or unparseable input arriving as a traceback rather
  than a sentence; and two roster entries claiming one clause. Two more were
  judgement, not code: the `SEC-POL-006` verdict rested on the enumeration gap
  above while `SEC-POL-005` cited that same clause, and `SEC-STORE-004` said it
  inherited a threat from a row that is traced — so the rule for when a property
  traces is now written down in the registry instead of applied by feel.
  56 cases in `scripts/test_threat_gate.py`, every red arm read in full for
  direction and collateral, the three ratchets pinned at the tree's own counts
  (zeroing all three left the whole table green), and the row driven red through
  `./scripts/check.sh` — EXIT=1 at `== threat-model traceability ==`, 90 rows
  green before it — rather than only through the function.

- **The number that justified the whole lock design did not reproduce.** The
  choice of a per-sentence pin over a whole-body hash was argued from "39 clause
  bodies changed with their first line intact against 12 first lines reworded, so
  a hash would have fired on 24 of 30 commits", written into three places. Only
  the **12** reproduces: the first pass measured with an ad-hoc body function
  rather than `threat_gate.clause_bodies`, which strips HTML comments and fenced
  blocks and so counts fewer changes. Re-derived with the gate's own function over
  `git log --reverse 3d6ec61 -- docs/threat-model.md` — the page as it stood when
  the choice was made — it is **34 / 12 / 20 of 30**. The argument is unchanged
  (a hash still fires on two thirds of the page's commits) and the conclusion
  stands, but the numbers are corrected and the METHOD is now recorded beside
  each of them, which is why they moved: nothing said how to reproduce them.

- **The clause lock approximated a renderer, and lost to it three ways.** The
  pin promises a sentence is on the page, so the body it matches against had
  HTML comments and fenced blocks removed. A review agent drove the rest of that
  surface and found three more GREEN against the shipped tree: a `<!--` opened
  under one clause and closed under a later one (neither end is in the body being
  stripped, so the whole hidden run still matched); `<span hidden>`,
  `style="display:none"`, `<details>` and `<script type="text/plain">` around the
  sentence (each renders it away and leaves it byte-for-byte in the source); and a
  `PLAT-…` pin degraded to the bare id, which satisfies "the pin names the
  assumption" while the sentence around it is replaced by its own opposite.
  Comments are now blanked over the WHOLE page before any body is sliced, a pin's
  clause may not carry raw HTML at all — refused rather than interpreted, because
  a rule enumerating which tags hide is a renderer with a shorter list than a
  browser's — and a `PLAT-…` pin must be a sentence rather than an id. Code spans
  are removed before the tag test: `Fs<S>` in backticks is the page's only `<` and
  hides nothing. The `clause_bodies` docstring no longer claims to give "the PROSE
  a reader gets"; it gives the page's prose as far as markdown decides it, and
  says where it stops. Also: a malformed `assurance/platform.toml` (`assumption`
  holding strings) raised `AttributeError` instead of a finding.

- **The revocation clause claimed a reset ordering the firmware does not have.**
  As first written it said every path that creates or destroys a credential —
  "registration, credential-management delete, and each of the resets" — is
  ordered so an `EF_RP` entry can outlive its credential but never the reverse.
  Registration and credential-management delete are (`bump_rp` before
  `fs.put(EF_CRED + slot, …)`; `delete(EF_CRED + slot)` before `decrement_rp`).
  **The resets are not**: `reset.rs` sweeps `EF_CRED` and `EF_RP` in one phase and
  its own comment says "ring order otherwise reaches `EF_RP` before `EF_CRED`" —
  what leads there is the SEED, so a torn wipe still strands a credential and what
  the order buys is that the survivor is undecryptable. `reset_tests.rs` says the
  same ("the strand itself still happens"), and so does this changelog at the
  commit that shipped it. Two more overstatements in the same bullet:
  `enumerateCredentials` and `deleteCredential` do **not** read `EF_RP` — they scan
  `EF_CRED` on an rpIdHash the host supplies, so a strand is still reachable by a
  caller who knows the rp and what is lost is *discovery*; and an `EF_RP` entry
  outliving its credential is neither invisible nor reclaimed — both walks filter
  on the stored count (`buf[0] > 0`), and every `decrement_rp` call is paired with
  a credential deletion, so it lists an rp with no passkeys until the next reset.
  The clause now says all three, including the part that is a residual rather than
  a defence. Found by a review agent on the commit that landed it; a threat model
  stronger than its firmware is the one direction that must not ship.

- **One typo bought the exemption the new clause-lock rule exists to refuse.**
  The rule that makes a pin *owed* reads the `[[untraced]]` entry's `why` for a
  clause id — naming a clause is the dependency, so the pin arrives with it. But
  the demand was keyed on ids that RESOLVE: write `TM-HOST-POWERCUT` for
  `TM-HOST-POWER-CUT`, drop the `rests_on`, and the entry argues from nothing the
  gate recognises, so nothing is owed. Measured on the shipped tree, that edit
  exited **0**. A `TM-…` id in a `why` that is no clause of the registry is now a
  finding in its own right. This is the shape the guard was written to close,
  found inside the guard — the same "bypassed by a spelling nobody enumerated"
  that `threat_gate.py`'s markdown parser has been bitten by before.

- **Two more spellings of "the sentence is gone" that the clause lock read as
  present.** `rests_on` matches a pinned sentence against a clause's body with
  HTML comments stripped, because commenting one out takes it off the page and
  leaves it in the source byte for byte. Enumerating the rest of that family
  found the rule one character short in two directions, both measured GREEN
  against the shipped tree: an `<!--` with **no closing `-->`** hides everything
  after it from the reader and is stripped by nothing, and a sentence moved
  inside a fence is still matched verbatim while it renders as a code sample
  rather than a claim the page makes. A clause body now drops fenced lines — the
  same treatment `clause_units` already gives them, because what is in a fence is
  a sample and not a sentence the page asserts — and everything after an
  unterminated `<!--`. Re-driven on the real page: every defeat-spelling red
  (reword, deletion, dropped full stop, smart quotes, weakened emphasis,
  zero-width space, either comment form, the fence, a move to a nested bullet),
  every deliberate one still green (reflow, re-indent, trailing space, a comment
  spliced mid-sentence, an unrelated fenced sample added to the body).

- **The threat gate's own docstring claimed a refusal it has never had, and the
  refusal cannot be built.** It read that "an `[[untraced]]` entry for a property
  that has since gained a clause is a stale exemption and is refused"; what
  `scripts/threat_gate.py` implements is *untraced AND citing a clause*, which is
  a different edit. Measured both ways on a scratch clone: adding a clause to
  `docs/threat-model.md` while leaving the stale exemption in place exits **0** on
  the `threat-model traceability` row, and reddens `pytest scripts` only on
  `FLOOR_CLAUSES` — the CLAUSE count, not the exemption — so bumping that floor
  the way the failure asks leaves **both rows green with the exemption still
  standing**. Which clause serves which property is a judgement `why` records and
  nothing reads for truth, so there is nothing to derive the refusal from. The
  docstring now says what the code does and names the gap instead of hiding it.

- **`direction = "inverse"` was publishable as evidence.** `bundle_gate.py`
  vocabulary-checks a mutation row's direction, and `"banana"` is refused with
  *"a red run is not evidence until the direction is read"* — while `"inverse"`,
  the word that says the kill was for the **opposite** defect, passed at
  **EXIT=0**. Measured history: **2 of 24** co-refutation patches in this tree
  modelled the inverse defect and scored a kill, and the tell was that every
  failure said *"should have succeeded"* and none said *"should have been
  refused"*. That is a finding about the mutant, not a result about the
  property.
  *Admitted with a recorded disposition rather than refused outright, and the
  argument is the point.* Refusing the word makes the honest answer the
  expensive one: the cheapest way past a refusal is to type `modelled`, which
  nothing in this tree resolves against a real run, so the gate would certify
  the lie it was added to prevent. It would also collapse `DIRECTIONS` to one
  member — a field nothing branches on is a comment with a type — and unsay the
  exact case the field was created to make sayable. So an `inverse` row owes a
  `disposition`: `superseded`, which must name **another** row of the group as
  the corrected mutant (its own name would satisfy a plain membership test), or
  `kept-as-a-finding`. **Every** inverse row owes the `reading` that argues it,
  whichever disposition it takes — the code has always demanded that and this
  line said `kept-as-a-finding` alone. The success line counts them apart —
  `9 mutation verdict(s) and 1 disposed as inverse` — so a disposed row cannot
  be read as a kill. All 10 current rows are `modelled`; nothing in the bundle
  moved.
  *And the hatch had no cycle rule and no ratchet.* Self-reference was excluded
  and cycles were not: A `superseded_by` B with B `superseded_by` A printed
  **"8 verdict(s) and 2 disposed as inverse"** at **EXIT=0**, a three-row cycle
  the same, and **all ten rows inverse in a ten-cycle** printed *"0 mutation
  verdict(s) and 10 disposed as inverse"* — a table that killed nothing,
  published as one that killed ten. Also green: all ten `kept-as-a-finding` with
  `reading = "x"`, every inverse row carrying the **same** reading, and a
  `disposition`/`superseded_by` sitting on a **`modelled`** row, accepted and
  unvalidated. A `superseded` chain must now reach a corrected mutant — a row
  that is not itself inverse — the group has a verdict floor of 8 against the 10
  it carries, one `reading` may not be copied across rows, and the register's
  two keys belong to the row they are about. Refusing `reading` there as well
  was the obvious third and was **refuted** by the bundle: all ten `modelled`
  rows carry one, because it argues whichever direction the row records.
  *And the published contract did not name any of it.* `docs/authorization-slice.md`
  §8 — which `bundle_gate.py`'s docstring calls **the** contract — still asked for
  *"the verdict, the assertion that fell and its direction"* and named no
  `disposition`, `superseded_by` or `reading`, so the gate demanded three fields
  the document it enforces had never mentioned. Item 8 now says what the code
  does, including that both dispositions owe the `reading` and that a
  `superseded` chain must end at a row which is not itself `inverse`.
- **One rule about "which silicon", enforced in one of the two places it is
  asked.** `platform_gate.py` holds its own registry's `board_revision` to a
  concrete RP2350 stepping, and `evidence_gate.py` shares the *token* — it reads
  `platform_gate.BOARD_REVISION` — but shared the token and not the rule: a
  bundle's `build.board_revision` was accepted on being non-empty, while every
  *other* leaf of the same bundle was searched with the regex. Measured:
  `board_revision = "a red Pico 2 I had lying around"` beside a `hardware`
  subject published **"1 of 59 carry a result measured on a board, each naming
  the revision it was taken on"** at **EXIT=0**. The declaration is held to the
  same vocabulary now, and the axis counts a stepping rather than a string, so
  the sentence and the finding cannot disagree. Ten table cases over the value
  spellings — a description of a desk, a lowercase `rp2350 a2`, the part with no
  stepping, the bare `A2`, and `B1`, which is a Kani claim's name and not
  silicon.
  *Which the first fix did in one of the two senses.* It shared the token and
  matched with `search`, so a desk that NAMES a part kept publishing:
  `board_revision = "a red Pico 2 (an RP2350 A2) I had lying around"` read the
  hardware axis 1 at **EXIT=0**, and so did `"not an RP2350 A2 at all"`. The
  whole value must be the part now, through `platform_gate.names_a_stepping` —
  a shared RULE and not a shared pattern, because the anti-drift arm the first
  fix added *could not fail*: it asserted the two compiled tokens were the same
  object, and `re` CACHES compiled patterns, so `re.compile(t) is re.compile(t)`
  is `True`. Driven — writing the forbidden second `re.compile` into
  `evidence_gate.py` left that case, both suites and the gate at **EXIT=0**. The
  arm holds a function now, which has no such cache. Which steppings *exist* is
  Raspberry Pi's roster and still not this tree's: `RP2350 A9` passes.
- **The bundle demanded a scope *sentence* and not the structured bounds it is
  about.** Roadmap §7.2 stores a proof's bound as data — sequence length,
  symbolic bytes, cardinality, unwind, `cfg`/features, the shipped-domain
  relation — and the eight method rows do carry it, as **30** `bound_*` keys.
  Nothing read them: stripping all 30 from all 8 rows took the leaf count
  **419 → 389**, cleared every floor, and left `slice evidence bundle` at
  **EXIT=0**. `REQUIRED` now carries `bound_*`, with a trailing `*` read as a
  prefix, because bounds are per method and naming one key would be requiring
  the wrong one — per row rather than per group.
  *That last clause credited a mechanism that cannot carry it.* The table
  parametrizes over `REQUIRED`, so it is a **drifter**: removing `bound_*` from
  `REQUIRED["method"]` removes the case with it — 150 collected became 149, and
  the two failures that arrived came from hand-written arms. Dropping
  `mutation.fell` the same way was caught by **nothing**. `REQUIRED` is asserted
  equal to a hand-written roster now, which is the pin a drifter cannot be.
  *And the same field one spelling over.* `shipped_relation` refused a dropped
  key, an empty string and a whitespace-only one — and took `"n/a"` at exit 0,
  which is the same dropped field wearing three characters. The method row's two
  prose fields are held to a non-answer vocabulary now (`n/a`, `N / A`, `none`,
  `nil`, `TBD`, `todo`, `unknown`, `-`, `—`, `?`, `.`, `…`, a non-string).
  A string-valued `bound_*` is held to it as well, and that too was the fix's own
  hole: half the bounds are numbers and `bound_totals` is a sentence, so
  requiring the *key* was satisfied by a row whose only bound read `"n/a"` —
  measured green before the extension. A numeric bound is never a non-answer,
  because `bound_reset_window = 0` is a real one.
  *And the scoping reached 18 of the bundle's 348 string leaves.* A sweep
  setting each leaf to `"n/a"` in turn measured **57** refusals, of which the
  non-answer rule owned **18** — all `[[method]]` — and **266** at **EXIT=0**:
  `mutation.fell`, `mutation.verdict`, `mutation.expected`, `build.commit`,
  `tool.version`, `property.statement`, `cost.basis` and `freshness.measured`
  among them, while `bundle_gate.py`'s own docstring says every `[[mutation]]`
  records the assertion that **fell**. Every string leaf answers something now;
  all 348 refuse `"n/a"`. The exemption the scoping was argued from is two
  leaves and is written per VALUE, not per field — `method.cfg` and
  `method.features` may say `none` (five rows and four, not "four each") and
  `cfg = "n/a"` is still a finding.
  *And the vocabulary was bypassed by punctuation.* It compared with whitespace
  removed and a trailing `.!?…` stripped, so `;` and `:` bought a second
  spelling: `n.a.`, `t.b.d.`, `N/A;`, `todo:`, `not-applicable`, `(none)`,
  `N.A` and `tbd;` were all **EXIT=0**. Compared on alphanumerics only now, with
  `tba`, `noanswer`, `seeabove` and `ditto` added. Still a blacklist and still
  incomplete — `n/a (none)` normalizes to `nanone` and passes, and refusing a
  one-character word was tried and **refuted**: `mutation.level` is `A`, `B` and
  `C`, so a bare `0` or `x` gets through. What carries the weight is the leaf.
  *And 10 of the vocabulary's 18 members were held by nothing.* Deleting `n\a`,
  `null`, `nothing`, `unspecified`, `undefined`, `unclear`, `tobedetermined`,
  `xxx`, `pending` and `wip` left the suite at **EXIT=0, 150 passed**: the table
  beside them hand-wrote 19 values that reached 8. The roster is written by hand
  in the test and asserted **equal** to the constant, and each of its words is
  driven from the HAND copy — parametrizing over the constant would delete the
  case along with the member, which is the drift, not the guard.
  *And the `bound_*` roster's own ratchet was one key.* Reducing all 8 rows to a
  single `bound_nothing = 0` was **EXIT=0** over 397 leaves, as were
  `bound_x = false`, `bound_x = ["n/a"]` and a key named literally `bound_` —
  which `any(k.startswith("bound_"))` is true of. There is a floor per row (2)
  and over the group (24), both under the measured 30 across 8 rows with the
  smallest row at 2; a flag is not a bound; and the bare prefix is not a name.
- **The `[result]` group transcribed five gates' output and nothing compared it
  — and one of the five counts was wrong the day it was typed.** The commit that
  closed `method.artifact` named `gate_registry = "… kani=4 …"` as the other
  symptom of the same hole and left it standing: editing it to `kani=99` was
  **EXIT=0** in `bundle-gate`, in `evidence-gate` and in `assurance-gate`,
  because `REQUIRED["result"]` named no field at all and the group was held only
  by a leaf floor of 18. Every `name=<number>` pair in a `gate_*` line is now
  compared against the emitting gate's own derivation, and every other integer
  against the integers that gate produces — the pair rule for
  `cfgs=45 mut=11 co=11 kani=4 …`, the number rule for `21 actions … over 24
  routes` where the line carries no pairs; the prose after them stays the row's
  to write. This belongs here and not in `run_count_gate.py` because that file
  says in as many words that it does not reach `assurance/`, *"which is itself a
  record of measurements and has `bundle_gate.py`"*. And both of those rules
  compare the numbers a line **has**, so a line with none satisfies them:
  `gate_registry = "assurance-gate: all good"` cleared the roster, the leaf floor
  and the non-answer rule while transcribing nothing, which is the roster
  satisfied by one key wearing a different field. A transcribed gate line owes at
  least one number.
  *What it found on the first run.* `gate_assumption` said
  `AlwaysUvShipped … FALSE=88 cfgs`, and `formal/` has held **89**
  `AlwaysUvShipped = FALSE` configurations at every commit from `58df09d` through
  `f52b720` to HEAD — so the figure was never right, not stale. Corrected to
  **89** in all three places that carried it: the `[result]` line, the
  `[[assumption]]` `AS-AUTH-2` row, and this file's own entry above.
- **`[[cost]].artifact` was a foreign key nothing joined.** `[[artifact]].path`
  carries 10 values and `[[cost]].artifact` 11 — **10 of the 11 byte-identical**
  to a path and the eleventh deliberate prose, *"the work that produced no
  artifact of its own"* — and nothing compared them: re-pointing all 11 at
  `"a log that does not exist anywhere.log"` was **EXIT=0**. A cost row naming
  something shaped like a path must name an `[[artifact]]`'s, and the other
  direction is held too, because item 10 is three numbers **per artifact** and a
  log nothing costs is a run whose cost was dropped.
- **The finding for "this row is not a table" was written and never printed.**
  `bundle_gate.py` built a filtered `rows` list for the `[[mutation]]` group and
  then iterated the **unfiltered** one, and the `[[cost]]` and `[[artifact]]`
  loops never filtered at all — so `mutation = ["a string, not a table"]` came
  out as `AttributeError: 'str' object has no attribute 'get'`. Nothing passed
  silently, which is why it went unnoticed: **EXIT=1** for the wrong reason, out
  of the file whose whole job is naming the reason. All three loops skip a
  non-table row now and the roster rule's finding is what prints.
- **A bundle's `method.artifact` named a proof nothing resolved against the
  tree.** The first closed slice's evidence register names, per method row, the
  artifact that discharged the obligation — `crates/rsk-fido/src/state_kani.rs::no_authorization_bypass_walk_owner`
  among them — and `bundle_gate.py` required the *field* and read nothing inside
  it. Measured: renaming that one harness left `slice evidence bundle` at
  **EXIT=0**, and the bundle's own `gate_registry = "… kani=4 …"` line green at
  three. Every reference resolves now, and token by token rather than by pattern,
  because the eight rows spell one **six** ways: a repo path, a bare `Name.cfg`
  (four rows — `formal/` is never written), `path::symbol`, an elided `…suffix`
  continuing the file the token before it named, and two rows trailing off into
  prose. A `.rs` file named *without* its `::harness` is refused as well: the
  file outlives any one of them, so naming it alone is the spelling that would
  have walked past this rule. Nine table cases, each killed by neutering the new
  rule and nothing else — every one failing with an EMPTY finding list, which is
  the direction that says the gate stayed silent over a broken bundle rather than
  fired over a whole one.
  *And the rule's own first version had the defect it was closing.* It asked
  whether the harness name occurred in the file's raw text, and
  `credmgmt_kani.rs` names `no_authorization_bypass_walk_owner` **in a doc
  comment** — so pointing the walk row at the wrong file resolved at EXIT=0. A
  `.rs` target is read as code now, through `gate_lines.rust_code`, and matched
  against what the file DECLARES; the suffix match the `…` elision needs is
  scoped to the elision, because everywhere it would make `::owner` resolve
  against `no_authorization_bypass_walk_owner`.
  *And it was closed for two of the eight rows.* Instrumented: rows 1, 2, 3, 4,
  7 and 8 carry no `::` at all, so for six of eight the rule degenerated to "a
  file of that name exists" — the walk row re-pointed at `CHANGELOG.md`, at
  `README.md` and at the bundle itself were each **EXIT=0**, and so were
  `state_kani.rs::STEPS` (a const), `::StepRng` (a struct) and `::OP_STOP`,
  because `DECLARED` matches a const, a struct and anything inside a
  `#[cfg(test)]` block. A row's `method` word is now held to §4.1's vocabulary
  and read: a `model-check` row must resolve a `.cfg` and a `bounded proof` must
  name a `#[kani::proof]` — `kani_gate.HARNESS`'s own token, so deleting the
  attribute and keeping the name reddens THIS row rather than only a global
  count floor one row over (92 → 91, blind to which harness went).
  *The elision resolved on any suffix, and a bare `…` on nothing.*
  `…_creds_begin_at_call_site` shortened to `…site`, `…e`, `…n` and to `…`
  alone were all **EXIT=0**; `…site` ends the antecedent's OWN harness, so the
  second reference was discharged by the first — the self-reference
  `superseded_by` refuses one function away. An elision must end exactly one
  declaration the row has not already named, and an empty one is a finding.
  *And a reference the resolver did not recognise said nothing at all.*
  `formal/RSKeySecurityState.tla` typed `.tlaa` in row 8 was **EXIT=0**: the
  extension is in no list, so the token was read as prose, and the row's other
  token resolved. A file-shaped token with an unknown extension is a finding
  now — "unresolvable, so fine" is the same hole with more code.
  *And one branch of the new pattern could never match.* `gate_lines.rust_code`
  blanks string literals BEFORE the regex runs, so `extern[ \t]+"[^"]*"` had
  nothing to match and `pub extern "C" fn X` was reported as **undeclared** — a
  branch nothing can take, wrong in the direction that refuses real code.
- **A green exhaustive TLC run was reported `VACUOUS`, and the reason was a hole
  in its own log.** `formal/run-tlc.sh` pulled `states`/`distinct`/`depth` out
  with plain `grep -oE`, and one NUL byte anywhere makes grep call the whole file
  binary and print no match — so all three came back empty and the `< 2` rule
  fired. Measured on `Shipped.log` after a real `COVERAGE=1` run: **1550 NUL
  bytes, the first at offset 153**, over a run that had completed exhaustively at
  699 350 223 generated, 48 679 968 distinct, depth 55. The two implementations
  get it wrong differently — GNU 3.12 (the dev shell, and so CI) sends `binary
  file matches` to **stderr** and the columns print `?`; BSD 2.6.0-FreeBSD sends
  it to **stdout**, the columns print `Binary`, and `[` adds `integer expression
  expected` — but both end at `VACUOUS: nothing was enabled  !! expected GREEN`
  and exit 1. It fails safe, which is why it survived.
  *The hole is not a stale file, and that matters for the fix.* `>` truncates at
  open, so a short predecessor cannot leave a gap; reproduced byte-for-byte —
  1550 NULs at offset 153 — only by two writers on one path, where the second's
  `O_TRUNC` resets the size and the first's next write lands at the offset it
  still holds. The second writer was `scripts/test_run_tlc.py`, which drives the
  **real** runner against a fake `java` and wrote into the **real**
  `formal/out/`. So each log is truncated at open and then **appended** to —
  `O_APPEND` has no offset to go stale — the battery writes into its own
  `TLC_OUT` directory instead, and `grep -a` sits under both as the backstop, on
  all six reads of the log rather than the three that were measured. A merge-gate
  run and a TLC run may now share a tree.
  *`grep -a` alone would not have been enough, and the mutation table says so.*
  Four cases were added, each killed by reverting exactly one layer: the fields
  (`states=699350223` across the hole, not the stale `22920`), a RED row's
  invariant name, the `COVERAGE=1` dead-action reader, and the mechanism itself —
  the stand-in re-truncates its own log mid-run and the result must carry no NUL.
  What no layer buys: a hole that **straddles** a line takes that line with it,
  which is the `RED:` with no invariant name that the same defect can also print.

- **Three of the eight closures above were themselves defective; the review that
  found the fourth sweep found these too.**
  *PIV counted the wrong population.* `wipe_piv` sweeps its two predicates
  separately, and the re-aimed guard compared the **total** fid count (264) with
  the batch while only the secrets phase (260) wraps — so `SWEEP_BATCH: 32 →
  260…263` left the test green with the wrap never crossed. Counted over the
  secrets phase now; driven at 260 it fails "the fill no longer spans more than
  one sweep batch: 260 secret fids".
  *The `credentialManagement` assertion was one step too strict, and its message
  was false where it fired.* `PER_RP * N < N * N` demands `N ≥ 9`, but the
  measured pre-index cost is `N² + N`, so `N = 8` still kills the regression at 72
  vs 64 — the entry below records that measurement and the assertion contradicted
  it. Held to `N * N + N` now: `N = 7` (56 = 56, the value measured as blinding)
  is a build failure and `N = 8` compiles.
  *The emulator's third relation was left as prose.* `REPLY_TIMEOUT` must stay
  above `MENU_INACTIVITY_MS` or a never-yielding screen fails on a receive timeout
  instead of on the yield bound — a red for the wrong reason in the one moment you
  are diagnosing a yield defect. `MENU_INACTIVITY_MS: 60_000 → 120_000`, which the
  constant's own doc invites, now stops the build.

- **The sweep class has five members and the entry below closed three.** An
  adversarial review of that commit ran `grep -B3 for_each_key` over `crates/` and
  found six batched collectors, not three: `rsk-rescue`'s already derives its test
  fixture from `FS_USAGE_WINDOW`, but **`rsk_oath`'s `sweep` (`[0u16; 32]`) and
  `wipe_openpgp` (`[0u16; 64]`) had no wrap test at all** — every fixture in both
  suites puts FIVE records live, so the bound that keeps `fids[n]` / `keys[k]` in
  range was never approached. Measured: delete `n < fids.len()` and `k <
  keys.len()` and the two crates report **120 passed, 0 failed** and **199 passed,
  0 failed**. That is worse than the three that were fixed, which at least had a
  test with a stale premise, and it is reachable rather than theoretical — OATH's
  255 credential slots exceed a 32-fid batch, so a full card's RESET would index
  past it in a `no_std` image. Both batches are named `SWEEP_BATCH` now, and each
  crate has the wrap test its three siblings already had, sized off the constant.
  Driven: with the bound deleted the two new tests are the *only* failures in
  their suites (120/1 and 199/1), panicking `index out of bounds: the len is 32 /
  64`; at a batch of 128 / 200 the fill follows and they still panic; and a batch
  past the fixture's own fid window is a compile error rather than a misleading
  survival.

- **Three more boundary probes copied from constants they could not see.** Each
  test straddles an edge that arithmetic elsewhere decides, and each wrote the
  answer down instead of deriving it, so an ordinary edit to the source constant
  moves the edge out from under the probe with the row still green.
  *OATH.* `mark_has_room_matches_raise_mark` probes 957/958/959 because
  `CRED_MAX − MARK_LEN − 2 == 958`; at `CRED_MAX = 1200` the edge is 1134, every
  probe lands in the "fits" region, and `<=` → `<` in `mark_has_room` passes. The
  edge is computed now — driven, the same off-by-one fails at "a blob of 1134
  bytes" and the widening alone stays green.
  *FIDO.* `enumerate_credentials_reads_are_linear_not_quadratic` passes at
  `total <= 8 * N` and names `N * N` as the quadratic figure, which separates them
  only while `N > 8`. Measured, the finding's own `N: 32 → 8` does **not** blind
  it — the pre-index cost is `N² + N`, so 72 > 64 still fails — but `N = 7` does:
  56 ≤ 56, mutation green. A `const _: () = assert!(PER_RP * N < N * N)` makes
  both 8 and 7 build failures.
  *CTAPHID.* `roundtrip`'s 56/57/58/116 are `INIT_DATA ∓ 1` and the first
  continuation boundary. At `HID_RPT_SIZE = 68` — where the whole suite still
  reports 31 passed, 0 failed — an `in_tx = bcnt > CONT_DATA` slip survives every
  test in the file; derived, the probe moves to `len = 62` and kills it there.
  `multi_frame_reassembly`'s 126 and the two `frames.len() == 4` fixtures are
  derived from the frame widths too, and the two "part-full last frame" premises
  are compile-time assertions rather than trailing comments.

- **The panel's host-yield bound had one end measured and the other written
  down.** `tools/emu`'s two menu-yield tests separate "the menu handed the
  executor back" from "the menu timed out" with a 20 s bound that only works
  while it sits strictly between `UI_YIELD_FLOOR_MS` (2.5 s, public) and
  `MENU_INACTIVITY_MS` (60 s, private to `rsk-display`) — and the file said so:
  "the upper end is prose until it is not". Measured: at
  `MENU_INACTIVITY_MS = 15_000` a Settings menu with the
  `host_request_pending_after` yield deleted — a host command waiting out the
  whole modal, which is what these tests exist to catch — passes both of them,
  because 15 s is inside the bound. `MENU_INACTIVITY_MS` is `pub` for the bench
  now, as `UI_YIELD_FLOOR_MS` already was, and each end of the bound is its own
  `const _: () = assert!` so a build failure names which one moved. Driven: at
  `MENU_INACTIVITY_MS = 15_000` the upper assert stops the build, at
  `UI_YIELD_FLOOR_MS = 25_000` the lower one does. Visibility only, no behaviour
  change.

- **The PIN entry row's overflow test hand-copied the constant that selects the
  branch it tests.** `render_pin_dots` must clear the "+" overflow marker when
  `entered` drops, and the test mirrored `ENTRY_X0` / `ENTRY_MAX_SHOWN` /
  `ENTRY_STEP` out of `render/pin.rs` "so the edge test does not force a wider
  re-export". Measured: `ENTRY_MAX_SHOWN: 10 → 12` and both setup assertions and
  both teardown assertions still pass with the overflow branch never taken —
  including with the clear strip narrowed so it no longer covers the "+" slot,
  the exact regression the test is named for. The row's geometry is read out of
  `render/pin.rs` now (`pub(super)`), and the probe positions and entry counts
  derive from it. The widening itself is a build failure rather than a test
  failure: "it fits left of the eye" was prose in `ENTRY_MAX_SHOWN`'s doc and is
  a `const _: () = assert!` beside it now, because a row drawn under
  `PIN_EYE_RECT` makes the test red for the wrong reason. Driven: 11 and 12 stop
  compiling (`evaluation panicked: assertion failed: ENTRY_X0 + …`), and at 8 and
  9 — the direction still legal — the narrowed strip fails "stale '+' marker left
  after delete" where before it passed.

- **Three sweep tests spanned a batch that was a bare literal none of them could
  see.** `rsk_fido`'s reset sweep, `Fs::factory_wipe` and `rsk_piv`'s
  `wipe_piv` each collect fids in a fixed-size batch, and each has a test whose
  only job is to cross the wrap to a second pass — the bound that keeps `keys[n]`
  in range is untested otherwise, and what breaks it is an out-of-bounds index,
  not a wrong answer. All three sized their fixture off a **copy** of the number:
  80 against `[0u16; 64]`, 150 against `[0u16; 64]`, and PIV's guard against an
  `8 × 32` delete budget the sweep stopped having (progress is counted in deleted
  files against `RESET_MAX_DELETES` now). Measured: widen the FIDO batch to 128
  and the honest tree is green — *and so is the same tree with the bound deleted*;
  `[0u16; 256]` does it to `factory_wipe`, `[0u16; 320]` to PIV. The batch is a
  named constant in each of the three now (`SWEEP_BATCH`, `WIPE_BATCH`,
  `files::SWEEP_BATCH`) and the fixtures are derived from it, so a widening either
  carries the fill with it or turns the row red. Driven: at batch 128 / 256 the
  deleted bound now panics `index out of bounds: the len is 128 but the index is
  128` (and 256), and PIV at batch 320 fails "the fill no longer spans more than
  one sweep batch". Refactor plus test wiring, no behaviour change.

- **An adversarial review of the entry below found three more lines of the same
  four-applet sweep that no test could falsify, and one premise the new tests
  rest on that nothing asserted.**
  *The premise.* Each of the four valve tests kills `>` → `==` only while the
  batch does not DIVIDE the budget; the tests argue that in prose and nothing
  held them to it. Measured: add one fid to `is_fido_fid` and move the bound to
  `4 × 256 + 16` — which `reset_bound_is_exactly_the_fid_space` *forces*, since
  it asserts the bound equals the fid space — and the honest tree stays at
  `615 passed; 0 failed` **and so does the same tree with `==`**, because
  1040 = 5 × 208. A `const _: () = assert!(…)` beside each of the four fixtures
  makes it a compile error instead: driven through all six arms (each budget
  moved onto a multiple of five, and `UNDEAD` moved to 1, which divides
  everything — the exact blindness the two old runaways had).
  *The swallowed `?`.* `gone.value.map_err(…)?` → `let _ = gone.value;` left
  615 / 118 / 140 / 197 passing in all four sweeps. The refusing fixtures cannot
  see it, because the loop then spins on the fid the medium kept straight into
  the VALVE, which returns the *same* error. The removal COUNT is what separates
  a sweep that stopped from one the budget stopped, so
  `rsk_fs::storage::faults::RemoveMedium` counts them now and one test per applet
  bounds the spend at the five files it seeded. Driven: the swallow turns exactly
  one test red in each crate, reading "the sweep asked for 1039 removals over 5
  files" — the runaway, not its inverse.
  *The metadata half, in FIDO only.* `orphaned |= gone.record.is_err()` inside
  FIDO's `sweep` → `|= false;` also left 615 passing, and only there: OATH, PIV
  and OpenPGP own the same line. Every `reset()`-level fixture reaches the sweeps
  with the flag already set, because the seed loop above them sets it first — an
  asymmetry inside the very class the entry below says it read by class. Closed
  the way the new tests are, by calling `sweep` directly over a medium whose
  EF_META is unreadable and asserting both arms (`Ok(false)` clean, `Ok(true)`
  faulted, and an empty range either way).
  *The truncated walk.* `if complete` is what stops an empty batch from reading as
  "the range is clear" when the medium truncated the enumeration, and forcing it
  true left 615 / 118 / 197 passing — PIV alone owned it, because the only fixture
  in the tree that truncates a walk was PIV's own local `TruncatedWalk`. Promoted
  to `rsk_fs::storage::faults::TruncatedWalk` (PIV's copy deleted, its test
  re-pointed) with one test per applet. Driven: the forced arm turns exactly one
  test red in each of the four, reading `left: Ok(false) right: Err(Other)` —
  success over key material the sweep never looked at.
  `bcdDevice -> 0x098E`, then `0x098F` for the shared fixture, for the same reason
  as the entry below: nothing here can reach the image, and the row counts
  `crates/rsk-fs/src/storage.rs` wholesale.

- **The reset runaway valve was falsifiable in none of its four applets, and the
  reason was the batch, not the cardinality.** `deleted > RESET_MAX_DELETES` is
  each wipe's progress guard; mutating `>` to `==` lets `deleted` — which rises a
  whole batch at a time — step *past* the budget without ever equalling it, and the
  valve stops guarding. It had stood open since D2.4 as "not drivable at
  `4 × 256 + 15`", and that diagnosis was wrong: a medium that answers `Ok` to
  `remove` and keeps the record runs 1039 deletions out of **five** files, no
  shipped-cardinality array required. What actually made it undrivable is that the
  two runaways the tree already had re-yield exactly **one** fid — and 1 divides
  every budget, so the mutant merely trips one delete early and
  `reset_sweep_fails_when_storage_does_not_converge` (FIDO) and
  `reset_reports_failure_when_the_sweep_cannot_converge` (PIV) pass it by
  construction. OATH and OpenPGP reached the valve with nothing at all: their fault
  backends *error*, which stops the sweep at a `?` above it.
  One fixture for the class — `rsk_fs::storage::faults::Undead`, whose records die
  only after a stated ceiling so a valve that has stopped guarding *converges and
  answers success* instead of hanging the suite — and one test per applet over
  **five** undead records, 5 dividing none of 1039 · 257 · 768 · 512. Driven: `==`
  at each of the four valves turns exactly one test red, and the failure reads
  `left: Ok(..) right: Err(..)` — success reported over a range the sweep never
  cleared, which is the defect and not its inverse. The budget assertion beside it
  has its own isolating mutation (`> RESET_MAX_DELETES` → `> 2 * RESET_MAX_DELETES`:
  "the valve let the sweep spend 2075 deletions on a budget of 1039"). `>` → `>=`
  stays a **conformance** verdict, recorded separately and measured green in all
  four: it differs from `>` only where `deleted` lands exactly on the budget, which
  a non-dividing batch rules out.
  `bcdDevice -> 0x098D`: no behaviour change and no line of this can reach the
  image — `storage::faults` is `#[cfg(any(test, feature = "test-util"))]` — but the
  bcd row counts `crates/rsk-fs/src/storage.rs` wholesale, because the file is a
  plain module even where its contents are gated.

- **Eleven more citations in the same class, found by sweeping it instead of
  fixing the three that were reported.** The class is every `reset.rs` and
  `is_*_fid` citation the model carries: 59 read by hand against the code they
  land on, 11 wrong. Two were the `is_fido_fid`/`is_fido_gate_fid` confusion the
  previous round left behind — the `store` variable and `RSKeyAppletSeams`'s
  `FidoReset` both cited the *gate* predicate's `EF_BACKUP_SEALED` paragraph while
  their prose is about `is_fido_fid`, now `214-256` on both pages. Two were ranges
  that stop short of what they name: `authenticatorReset` cited as `31-74` when
  `reset` runs to `:90` (`formal/README.md` had it right), and the `Err` "at
  `:117-121`" that is on `:122`. One ended mid-sentence two lines before the
  `ctx.state.reset()` its invariant's third clause is about.
  Four more came out of the same paragraphs and are the reset's RAM half:
  `Ctx::load_keydev` cited three times as `lib.rs:91-95`, which is
  `require_presence`, and `state.keydev_dec` as `state.rs:360-362`, which is
  `channel`. The last two are in `scripts/security_trace.py`, which no gate reads:
  both name `reset.rs:187` for the reset-window predicate that is on `:211` — the
  same sentence `formal/README.md` already cited correctly, which is the tell that
  found them. Re-locked, each verified through the lock's own first/last line.
  No syntactic rule was added: "reject a citation whose first or last line is a
  comment" was measured last round at 190 false positives of 485. **The scope
  that sentence never gave**, since a measurement nobody can reproduce is a
  number and not evidence: every citation the gate reads whose span resolves to
  a real range in a real file, counting a line that starts with `//`, `/*` or
  `*`. Re-measured at that scope on this tree — 600 such spans — the rule fires
  on **227**, and its narrowest variant (first *and* last both comments) on
  **45**. The share has not moved (39% then, 38% now), which is the point: a
  rule that rejects two citations in five is not a rule.

- **Six `reset.rs` citations in `RSKeySecurityState.tla` pointed at code their
  prose was never about, three of them re-blessed by a mechanical +6 shift.** The
  shift moved sixteen line numbers without a content check, and the commit's own
  `citations.lock` recorded the proof: the citation *labelled*
  `is_fido_gate_fid (run-36)` was locked as ending on `pub fn is_fido_seed_fid`.
  It was inherited — the pre-shift `130-143` had the same target — and
  `citation_gate.py` cannot see it by design, since whether a resolved line still
  *means* what the model says is a review question its own header calls out. The
  shift was also partial: `Phase 1` was corrected to `:77` while `Phase 2` kept
  `:59` and `BugResetGatesFirst` kept `:58-59`, both of which are the
  `ctx.state.reset()` comment. All six are re-derived by content and re-locked:
  the two sweeps at `77-78`, the gate sweep at `78`, `is_fido_gate_fid` at
  `177-204`, and the `EF_BACKUP_SEALED` paragraph at `182-203` — which is what
  `formal/README.md` has said all along, so the two pages agree again.

- **The reset refinement could not express the mechanism its own safety argument
  rests on, so four Kani obligations were green over it vacuously.** 0x098B made
  the secret sweep the thing that stops a wipe whose seed the medium kept — its
  predicate is `is_fido_fid && !is_fido_gate_fid`, which covers the seed fids —
  but the projection in `reset_assurance.rs` guarded the *earlier* boundary
  instead: `advance()` refused to leave the seed phase with a live seed,
  `well_formed`'s `Secrets` arm required `!owner_seed`, and `delete` refused a
  seed fid there at all. "In the secret sweep with a live seed" was therefore
  unreachable, and every obligation about the gate phase over a live seed was
  discharged over an empty set. Measured: **merging the two sweeps into one — the
  audit run-36 defect the phase split exists to prevent — left all four harnesses
  SUCCESSFUL.** The 2→3 boundary is unguarded now and the seed holds 3→4 shut,
  which is what the code does. Both mutants are red on the widened domain and
  green on the old one: the merged sweep fails all four (each clause naming
  itself), and the real defect it models — dropping the seed fids from the secret
  sweep's predicate — fails the induction obligation. Verification-only source,
  cfg-excluded from every firmware flavour, so no `bcdDevice` bump.

- **A TERMINATE DF that failed with the private key still on the card wrote
  factory defaults over the owner's KDF, signature counter and cardholder data.**
  The re-seed became unconditional at 0x098A on the argument that "the gate
  records go last" — but `is_openpgp_gate_fid` named five of the ~ten records
  `scan_files` writes, and `EF_KDF`, `EF_SIG_COUNT` and `EF_SEX` were swept in
  phase 1, the only phase that can stop with secrets still on the medium.
  Measured on a wipe refused at `EF_PK_SIG`: `EF_KDF` `81 01 03 82 01 08` →
  `81 01 00` (KDF: none), `EF_SIG_COUNT` `00 12 34` → `00 00 00`, `EF_SEX` `31`
  → `39`. The KDF one locks the owner out of a key that is still there: PW1 and
  PW3 are verified over the KDF *output*, so a card advertising KDF-none makes
  `gpg` send the raw passphrase and spend both retry counters. All three are
  deferred to phase 2 now, which also covers the device-wide `Fs::factory_wipe`
  — a torn one there reaches the same end state at the next boot's `scan_files`.
  A clean wipe is unchanged: both phases still delete everything and the re-seed
  still restores every default, so no status word moves on any non-fault path.
  The measurement in the entry below was the same shape as the defect: its watch
  list held the seven gate records while the function under test wrote ten. It is
  derived from `scan_files` itself now — run over an empty medium, its live fids
  *are* the set — so a record added there without a phase decision fails the
  suite. **bcdDevice → 0x098C.**

- **`authenticatorReset`'s seed loop still reached the exact end state the
  metadata repair exists to remove, and still made no progress on a retry.** The
  reason a sweep must stop on a refused backend removal is that `for_each_key`
  re-yields the fid it could not remove — a property of the *enumerating* sweeps.
  `FIDO_SEED_FIDS` is a fixed two-element `for` with no enumeration and nothing to
  spin on, and `force_delete_halves` removes UNCONDITIONALLY, so a medium that
  refused one seed fid — including one that was never live — forfeited the whole
  wipe. Measured over three consecutive resets with the refusal standing:
  `live=[cred0, cred1, rp, pin, backup]` on rounds 1, 2 **and** 3, byte-identical
  to the row 0x0989 was written to remove. The value failure is accumulated there
  now, the way the record failure already was, and the answer is still `Err` — a
  removal that could not be proven is not a clean wipe. Safe because the secret
  sweep's predicate covers the seed fids too: a seed that is genuinely still live
  is re-yielded there and stops the wipe before the gate phase, which is what
  would drop `EF_BACKUP_SEALED` and re-open the one-time seed-export window over
  it (`ResetKeepsTheBackupSeal`, SEC-FIDO-006C) — pinned by a test that refuses
  the removal of a LIVE seed and asserts `EF_PIN` and `EF_BACKUP_SEALED` survive.
  Swept by class rather than by site, as the tree's own rule asks: the four other
  delete loops in the four applet sweeps all take their fids from `for_each_key`,
  so a refusal there really does re-yield and `?` stays right in every one.
  Correction, re-measured: the new test also goes red on the `BugSeedDoesNotLead`
  co-mutant, but on the ANSWER — `Ok(0)` where `Err` is owed, since that patch
  deletes the `refused` flag — and not on the seed ordering.
  `a_torn_reset_never_starts_while_the_seed_is_still_readable` is the one that
  kills it for the right reason, and the two of them are the whole failure list.
  **bcdDevice → 0x098B.**

- **A TERMINATE DF that erased the whole applet and then locked it out until the
  next reboot.** The sweep gained a THIRD outcome at 0x0989 — the range is clear,
  one metadata drop could not be *proven* — inside a two-valued return, and
  `terminate_df` collapsed it with the ABORTED case, so a completed wipe skipped
  `scan_files`. Nothing else runs it: boot and TERMINATE are its only two callers.
  The card was left with no `EF_PW_PRIV`, and every later TERMINATE answered
  `6A88` for the rest of the power cycle — the commit's own root-cause pattern,
  one layer up. Measured over ONE transient EF_META read fault with the medium
  healthy afterwards: `first=6581 reprovisioned=[] retry=6A88`, and a persistent
  fault gave the same row, so the status word named the wrong cause in both.
  `rsk_piv::files::reset_files` has answered `wiped.and(ensured)` since 0x0987
  with a comment naming this hazard verbatim; the OpenPGP sibling does now too,
  and the same fixture reads `first=6581 reprovisioned=[PW1, PW3, PW_PRIV,
  PW_RETRIES] retry=9000` transient and `retry=6581` persistent — usable again,
  and still honest about the medium. Re-seeding unconditionally is safe because
  the gate records go last, and that is measured rather than argued: over a wipe
  refused in phase 1 all seven gate records survive and `scan_files` changes
  **none** of them, so it cannot put a touch-OFF UIF flag back over a private key
  the surviving DEK still opens. Two corrections, both re-measured: that watch
  list was seven records against a function that writes ten, and the three it
  missed are the entry above; and driving `scan_files`' `UIF_DEFAULT` write
  unconditionally fails **three** tests rather than one — the safety test plus
  `boot_settles_a_sex_code_outside_the_value_list` and
  `a_refused_sex_repair_leaves_the_old_byte_and_retries`, which count writes and
  see three extra ones. All three fail in the same direction.
  **bcdDevice → 0x098A.**

- **The delete-caller row could be satisfied by a discard it could not see.**
  `scripts/deleter_gate.py` derived "reads the answer" from a `let _ =` at the
  statement's head, so three other spellings of the same discard read as `read`:
  `_ = …` (the `let`-less destructuring assignment), a trailing `.ok();`, and
  `drop(…)` around the call. Any of them turns a `must-read` site into a
  best-effort one with `cargo fmt --check` and `clippy -D warnings` clean and the
  row green — verbatim the property the guard's docstring claims. And the
  receiver test (`.delete(`) could not see the same call spelled UFCS, so
  `Fs::force_delete(fs, x)` and `<Fs<S>>::delete(fs, x)` were invisible: two new
  unaudited callers, one of them deleting the FIDO seed, left the roster at 43.
  Both ends of a statement are read now, the UFCS spelling is on the roster, and
  the mutation table carries all four arms — each driven through the row itself,
  green before and red after.

- **The fix for that faulted drop introduced a worse defect than the one it
  closed, and `authenticatorReset` is where it was measured.** `Fs::force_delete`
  names three outcomes and returned a type that carries two, so every caller had
  to collapse them — and the four applet reset sweeps collapsed them with `?`. A
  faulted read of EF_META, the ONE blob every applet shares, then aborted the wipe
  after a single file, at the same fid on every retry, so no retry made progress:
  measured side by side on the same fixture, three consecutive resets answered
  `Err` with `EF_KEY_DEV_ENC` — the soft lock's wrapped copy of the device seed —
  still in flash together with both credentials, the RP record and the PIN, where
  the previous build had erased all of them. That defeats the reset's own
  ordering rule, that what a cut leaves behind must at least be undecryptable, and
  it is the `?`-before-the-value repair measurement had already rejected, arriving
  through the callers instead of through the body.
  `Fs::force_delete_halves` hands the two answers back apart now, and the four
  sweeps read both: a refused backend removal still stops the sweep, because
  `for_each_key` keeps re-yielding a fid it could not remove, while a faulted
  metadata drop is carried to the end of the range and answered for there — so the
  wipe erases everything it can reach AND does not report success over what it
  could not. `force_delete` is the fold of the two and is unchanged at the five
  sites outside `rsk-fs` that delete one named record, `att_clear`'s ordered pair
  included — three distinct functions, and a count `scripts/deleter_gate.py`
  derives from the tree rather than one written here from memory (this line said
  *six*, and nothing in the tree is six).
  Pinned in all four applets, each driven red by the real regression with the whole
  crate suite watched: in every one the status word matched on both sides and the
  SURVIVOR list was the discriminator, which is why a test asserting only the
  answer passed the defect. **bcdDevice → 0x0989.**

- **The faulted-drop defect that `Fs::delete` was cured of was still standing at
  the third deleter, and every applet reset sweep goes through it.**
  `Fs::force_delete` spelled its metadata drop `let _ = self.meta_delete(fid)` and
  then answered `Ok(())` — `BugDeleteHidesFaultedDrop`, the mutant
  `NoSilentOrphan` (SEC-STORE-006) exists to kill, in the shipped tree on the
  P0-launch reset path. The docs had recorded PIV's MOVE with `to = 0xFF` as "the
  one caller in the tree that deletes a fid carrying a head"; the caller audit of
  the delete family found the second one, and it is `wipe_piv`, which sweeps the
  very same head-carrying fids through `force_delete`. So a PIV RESET whose EF_META
  drop could not land answered `9000` with a head standing over a key that was
  gone, and GET METADATA reads that head — its `is_key` arm dropped the `has_key`
  probe precisely because a delete "clears the meta record unconditionally".
  `force_delete` returns the metadata outcome now, exactly as `delete` does; the
  backend `remove` is still unconditional, so this is not the `?`-before-the-value
  repair measurement rejected — no secret outlives its erase, only the answer
  changed. All ten `force_delete` callers already read that answer, and all four
  sweeps already treat a flash read fault as "the range cannot be proven clear",
  so the fault now fails the wipe it could not prove instead of being reported
  complete. Held at both layers, each driven red before the fix:
  `a_faulted_metadata_drop_is_reported_by_force_delete_too` (`rsk-fs`) and
  `a_reset_answers_for_the_heads_it_could_not_drop` (`rsk-piv`, over a medium that
  refuses EF_META's own `remove`). **bcdDevice → 0x0987.**

- **Three removal commands answered `9000` over what they had not removed.** The
  caller half of the same audit: of the 23 `let _ = fs.delete…` sites outside
  `rsk-fs`, most are best-effort by design and stay that way — an index the store
  rebuilds, a sealed nickname the rpIdHash AAD already invalidates, a large blob
  its slot's next owner cannot open, an OTP slot whose *reply* is the status
  record recomputed from flash, a staging record every later `load_dek` retires
  anyway, journal entries the reset has already re-sealed under a seed it
  replaced. Four are not, because the command's whole effect **is** the removal
  and nothing else on the card repairs it: OATH `DELETE` (`0x02`) over a
  credential, OATH `SET CODE` (`0x03`) dropping the OTP-PIN that would otherwise
  survive as a second unlock path past the code being installed, `SET CODE`'s
  `73 00` removing the access code itself, and OpenPGP `PUT DATA 0xD3` with an
  empty body clearing the reset code — the RC verifier *and* the DEK sealed under
  it, so a refused removal left a `RESET RETRY P1=0` path live behind a card that
  had just reported it revoked (`init`'s repair pass reaches the FACTORY reset
  code alone). All four read the answer now and map it to `6581`, matching the
  sibling commands of the same shape: PIV's `DELETE DATA` and CTAP's
  `deleteCredential` both already did. Four tests over a medium that refuses to
  remove one nominated fid, each driven red against the unfixed code with the
  whole suite watched. **bcdDevice → 0x0988.**

- **A faulted `EF_RP` probe filed a SECOND resident-credential record for one
  relying party, and nothing merges the pair.** `bump_rp` located the rp's index
  entry with a collapsing `Fs::read`, whose `None` covers "a different rp" and
  "the flash could not serve this slot" alike — so a refused probe of the slot
  that *does* hold this rpIdHash fell through to the free-slot path and wrote a
  duplicate. `decrement_rp` breaks at its first match and touches one record per
  call, so the pair stands: `enumerateRPs` counts the rp twice, and when the
  first record drains to zero its deletion takes `EF_RPNICK` at that slot with it
  — the device-local nickname destroyed while the rp is still live under the
  duplicate. Driven on a medium that refuses one nominated fid: two records for
  one rpIdHash, then `rp0=None rp1=Some(1) nick0=None` after a single decrement.
  The probe is fallible now, and the refusal is narrowed to where it is earned:
  a slot belonging to some OTHER rp cannot hide this one, so the unread slot is
  carried and only refuses on reaching the free-slot path — the first shape of
  the fix denied every resident registration on the device, for every rp, until
  one unreadable record came back. `makeCredential` also stops reporting a flash
  fault as `KeyStoreFull`, which tells the platform to delete passkeys: that
  cannot help a refused read and destroys data to no end. **bcdDevice → 0x09AD.**

- **A faulted `EF_PIN` probe cleared the forced PIN change that `setMinPINLength`
  had just imposed, and persisted the cleared flag.** `set_min_pin_length` reads
  `EF_PIN` twice — `has_data` for "is a PIN set at all", then the record for its
  length — and a collapsed answer at either left `force` false. That value is
  written to `EF_MINPINLEN[1]` two statements later, so a PIN below the floor the
  command had just raised kept working with no change demanded,
  `force_change_pending` read the cleared flag from then on, and the
  `reset_pin_uv_auth_token` / `clear_ppuat` invalidation was skipped with a live
  token standing. Nothing short of another `setMinPINLength` repaired it and
  nothing told the owner. Both probes are fallible now and the command refuses:
  nothing is written at that point, so a refusal costs a retry. Driven on a medium
  that refuses one nominated fid, both arms separately — `stick_after(EF_PIN, 0)`
  and `(…, 1)` — each red against the unfixed code with `forceChangePin = 0` on
  the medium. Found while verifying the new read-fault threat-model clause against
  the code. **bcdDevice → 0x09AE.**

- **A boot that could not read `EF_PHY` opened every USB interface, including ones
  the owner had disabled.** `rsk_phy::load` folds "no record was ever written" into
  "the flash would not answer", so one refused probe handed the boot the build
  defaults — build VID/PID, build strings and `USB_ITF_ALL`. The identity fields
  cost a host tool a lookup; the interface mask is a gate. The boot takes a typed
  answer now: a record that reads is obeyed, a record that was never written still
  opens everything (a factory-fresh key with two interfaces looks broken), and a
  record the medium refuses opens the management-capable pair — CCID and HID — and
  nothing else. Not `ALL`, because that is the widening; not narrower, because one
  management-capable interface must survive or the record can never be rewritten,
  and which one the owner kept is exactly what could not be read. **The cost of the
  new state:** on such a boot the OTP keyboard is absent, so a slot configured to
  type does not, until the record reads again. Three re-probes come first — `Fs`
  does not memoise a failed read — so a transient fault costs the boot nothing.
  **bcdDevice → 0x09B0.**

- **OpenPGP charged a wrong password's retry *after* comparing it, so a decrement
  that never reached flash made the guess free.** The counter is this applet's only
  rate limit — unlike clientPIN there is no per-boot soft lock — and it was written
  after the card had already answered, with no read-back: a program that silently
  did not land answered `63Cx` to a wrong password with the counter frozen, i.e.
  unlimited guesses at one power cycle apiece. `check_pin` now charges the attempt
  before the comparison and reads the counter back, and the success path gives the
  charge back — the shape `rsk-piv`'s `check_ref`, `rsk-fido`'s
  `spend_and_verify_pin_hash` and `rsk-oath`'s `spend_and_match_otp_pin` have
  carried for four audits; OpenPGP was the applet the sweep never reached.
  **Ordering is what closes it, not the read-back:** on a full counter the success
  path rewrites the value it already holds, so a read-back placed after the
  comparison is satisfied by a store that stored nothing — which is why the
  regression test asserts that the *right* password also fails when the charge
  cannot be proved. A store that silently drops the write is the reproduction
  (`DeafStorage`, one fid and the `write` verb only, so the interleaving stays
  reachable). Two costs, both deliberate: an interrupted `VERIFY` now spends a try
  the holder did not use (the direction to fail in, and the guide says so), and a
  storage failure here answers `6581` instead of the `6983` the old code
  conflated it with. **bcdDevice → 0x0984.**

- **The rename keypad's space key read "SPACE" instead of `␣`.** The antialiasing
  change swapped the symbol for the word because U+2423 OPEN BOX is not in the
  generated atlas and would have rendered as `?` — a word on a key sized for a glyph.
  The atlas gains the character instead (98 entries now, +493 B: 409 B of coverage plus seven glyph records), and
  the key is a symbol again. The rule the old assertion stated, "T9 labels must be
  ASCII", was the right question with the wrong answer: the atlas is ASCII plus three,
  so the check now asks the atlas whether a label's characters resolve to their own
  glyph rather than to the `?` fallback. **bcdDevice → 0x0981.**

- **One colour the marquee could not place on its ramp blanked the whole PIN title.**
  The scrolling title composites into an off-screen four-bit band, and the band
  recovered each pixel's coverage by inverting the blend — so a colour that was
  neither the text nor the panel background had no coverage to return, the frame
  errored, and the error was answered by zeroing the buffer. The one-bit mask this
  replaced took the tolerant rule instead ("not the background means ink"), and that
  rule is back: an off-ramp colour is full coverage. The band target's error type is
  `Infallible` again, which deletes the branch rather than fixing it, and a
  compile-time assertion keeps it that way. **bcdDevice → 0x0980.**

- **Two overlapping glyphs took the later coverage instead of the greater, so the
  second one punched a near-background pixel into the first one's stroke.** The
  trusted display's text draws each pixel by walking the string, and a pixel both
  glyphs cover kept whichever it read last. Glyph boxes do overlap — 8 of the 97 in
  the atlas have a negative left bearing and 28 carry ink past their advance — and a
  sweep of all 97×97 pairs in every role found **53 that composite wrong**, worst
  `\j` and `(j` in the 19 px heading at 13 of 15 coverage steps: an all-but-solid
  stroke pixel replaced by an all-but-background one. Headings and the service name
  on the approve prompt render attacker-chosen text, so the pair is choosable.
  The regression asserts the property rather than a golden pixel — adding a glyph
  may never lighten what the prefix already drew. **bcdDevice → 0x097F.**

- **29 of the 42 `file.rs:line` citations in Rust source were repaired; 19 of
  them named code the claim was never about.** `scripts/citation_gate.py` reads
  the `formal/` pages and nothing else, so the same three token-gate call sites
  are cited twice in the tree — once on a gated page and once in a Kani proof
  header — and only the gated copy had followed the code:
  `formal/README.md` already said `getassertion.rs:384-387`, `config.rs:243-245`
  and `credmgmt.rs:278`, while `state_kani.rs` and `credmgmt_kani.rs` still said
  `376-379`, `222-224` and `277` — 8, 21 and 7 lines out, the last of them a
  doc-comment line reading `/// has been located.`. The worst was 79 lines:
  "the dispatch prologue every CBOR command runs first (`lib.rs:207`)" pointed at
  `out[0] = CTAP2_OK;`, the response *epilogue*. Nine more had drifted endpoints
  while still touching their subject, and one (`` `:392` `` in
  `clientpin_tests.rs`) was a bare line number with no filename, which no rule
  can resolve. Every one was re-pointed by reading the code, not by a guard —
  the guard that would have caught them lands in the next commit.

- **The pinpad's "Allow host PIN entry?" gate lost its Approved card when the
  presence seam moved.** `handle_secure_req` — the CCID `PC_to_RDR_Secure` path
  behind an OpenPGP/PIV pinpad VERIFY on a trusted-display build — asked for
  presence through `rsk_fido::UserPresence`, the only presence trait its scope
  imported. Splitting the merged trait into `request` (a per-signature smartcard
  touch policy) and `request_ceremony` (a host-raised ceremony) re-pointed that
  one call at the leaner ask, silently: it still compiled, because the FIDO name
  is now a re-export of the shared trait. The hold still approved the same thing
  and every CCID status byte was unchanged, but the ~0.43 s "Approved" card that
  told the holder their tap had landed stopped playing before the pad appeared.
  It asks `request_ceremony` now — the same ask its twin, clientPIN built-in UV,
  has always used — and names the seam `rsk_sdk::` so the resolution is a choice
  rather than whichever trait happened to be in scope.

  Nothing could have caught it: the path is `display`-gated firmware, which no
  host test executes and which the emulator has no counterpart for (its CCID
  answers `PC_to_RDR_Secure` with the no-pad default). So the thing that is
  checkable is checked instead — `ASK_CENSUS` lists every production presence
  ask in `crates/` and `firmware/src` with which of the two it is, and
  `every_presence_ask_is_the_one_its_caller_means` fails when a call changes
  column. Falsified four ways, one at a time: putting the defect back reports
  `worker.rs` as `(0 ceremony, 1 touch)` against a census of `(1, 0)`; the
  inverse — PIV's slot policy taking the ceremony ask — reports `auth.rs` the
  other way round; and blinding either half of the walk fails on the anchor
  (`the scan missed …`) rather than passing over an empty scan.

- **The accepted attestation-chain length depended on whether a PIN was set.**
  `MAX_RAW_SUBPARA` is scratch for the pinUvAuth MAC, so its length check sits on
  the PIN branch — a PIN-less `ATT_IMPORT` accepted chains a PIN-protected one
  refused `CTAP2_ERR_REQUEST_TOO_LARGE`. `ATT_CHAIN_MAX` had been tied to the
  store's per-value ceiling alone (audit run-32's fix), so when `MAX_VALUE_BYTES`
  later doubled for reasons internal to the store, the accepted chain doubled with
  it — past that MAC buffer and, once ML-DSA-87 widened the COSE key by 640 bytes,
  past the CTAPHID response ceiling too. It is now the tightest of its three real
  ceilings (store, MAC scratch, worst-case makeCredential response), applied in
  `att_chain_pack` where both paths pass, and held by a build-time assert. The cap
  falls 4069 → 2132 bytes. A device already holding a longer chain keeps
  registering: the chain now has to parse intact to be used, so a truncated read
  falls back to device attestation instead of failing the registration —
  re-import within the new cap, or `ATT_CLEAR`, to restore org attestation.

- **A getInfo test stopped being able to fail when the member count reached 24.**
  `dispatch_get_info_ok` pinned the response's map size by comparing one raw byte
  against `0xA0 + count`. That formula holds only to 23: from 24 upward CBOR writes
  `0xB8` followed by a separate length byte, so the first byte reads `0xB8` for
  every count from 24 to 255. The roster crossed 24 one commit earlier, and the
  assertion went green on the new number while no longer distinguishing it from any
  larger one. It now decodes the header instead of comparing a byte — verified by
  declaring 25 members while writing 24, which the byte comparison accepted and the
  decode rejects.

- **A doc comment in `rsk-fs` described the function below the one it sat on.**
  `mark_absent`'s one-line doc and its `#[inline]` had both landed on
  `record_unless_faulted` during an earlier edit, leaving `mark_absent`
  undocumented and its neighbour carrying someone else's description ahead of its
  own. Only what was displaced moved back: `record_unless_faulted` gains no
  `#[inline]`, because the evidence says the attribute belongs to `mark_absent` —
  the doc above it names `mark_absent` — while nothing says the other ever had
  one, and inventing it would be an optimizer hint smuggled into a comment fix.
  Found while reading the cache primitives for the store refinement pilot.
  `bcdDevice` 0x0960 → 0x0961: refactor, no behaviour change.

- **An RSA-3072 or RSA-4096 PIV key is usable again under Windows' own smart-card
  minidriver.** 0.4.10 began requiring GENERAL AUTHENTICATE's algorithm byte to
  equal the one the slot's key was stored under — the reference behaviour, and
  the fix for a slot whose key the request never named. But SP 800-73 has no id
  for RSA-3072 or RSA-4096: `0x05` and `0x16` are Yubico's, so a host holding
  only the standard table cannot name such a key with any byte the card would
  take. `msclmd.dll`, the PIV minidriver Windows uses when Yubico's is not
  installed, is exactly that host, and BitLocker unlock through it stopped
  working ([#79](https://github.com/TheMaxMur/RS-Key/issues/79)).

  Inside the RSA family the byte may now differ. It still chooses neither the key
  nor its size — both come from the slot — so the body is pinned to the *slot's*
  modulus, before the touch and before the load: a request naming the family
  reaches the key, one naming a different key is refused without prompting or
  spending the PIN freshness. Across families, and between the two EC curves
  (both of which the standard does name), the exact byte is still required.

  A deliberate divergence, measured on both sides rather than argued: a YubiKey
  5.7.4 insists on the exact byte — nine P1 values at a provisioned slot, only
  its own is `9000` — and is itself unusable for an RSA-4096 key under that
  minidriver, failing with the same `SCARD_E_INVALID_PARAMETER` on the same test.
  So this is RS-Key working where the reference does not. Found by bisecting six
  firmware builds against `certutil -scinfo` on real hardware.
  **bcdDevice → 0x095A.**

### Security

- **A wipe that could not re-arm the at-rest scrub says so now — out of band, and
  never in the wipe's own answer.** The wipe paths call `rsk_fs::request_rescrub`
  best-effort (`let _ = …`), deliberately: on a wipe "leave the record in force"
  means leave the secrets live, so a refused re-arm must not stop a factory reset.
  Most carry a head call and a retry, and the retry recovers a **single-shot**
  refusal. A **persistent** one it cannot — `EF_HARDENED` stays latched over an
  already-tombstoned, chip-serial-rooted verifier, no later boot ever laps, and the
  wipe still answers the host success. Nothing anywhere reported that.

  `Fs` now latches it in RAM (`Fs::rescrub_refused`), set on `request_rescrub`'s
  `Err` path — which is why **no call site changed** — and
  `authenticatorVendor 0x41 / 0x05` BACKUP_STATE carries it as key `5`
  (`docs/protocol.md` §9). `rsk status` prints a line only when it is set; older
  hosts ignore an unknown key and older builds omit it.

  **What it does NOT say**, because that is the whole trap: not "the marker lies",
  not "hardening failed". At the *gated* call sites a refusal already stops the
  write it guards, so nothing is superseded and the marker stays true — and the
  command either errors to the host or skips a lazy migration and leaves the older
  record in force. Key 5 is **medium health for this power cycle** — a re-arm was
  refused — and it is worded that way in the wire spec and at the field.

  **Why a latch and not a read.** A latched `EF_HARDENED` is the steady state of
  every OTP-provisioned device past its first lap (`RSKeyBootHardening`'s `Init` is
  `marker = TRUE`), so reading the marker on demand would report trouble on a
  healthy key; the condition is a fact about a *transition*, and after a healthy
  wipe the marker is absent. So something must remember, and RAM is the floor: a
  flash breadcrumb would be a write to the medium that is refusing, and its own
  failure would be unreportable by the same argument. It clears on the next power
  cycle whether or not the flash recovered.

  The **control was written first**, because it is the entire false-positive
  argument: a device that completed its lap, re-latched the marker and took an
  ordinary `factory_wipe` reports nothing. Beside it, the arm that decides the
  wording — a single-shot refusal the retry recovered reports anyway, since the flag
  says the medium refused rather than that the lap is lost, and clearing it on the
  retry would narrow it to "the LAST re-arm failed", which is exactly the shape a
  wipe has — and the arm the earlier tests had missed entirely: a removal that lands
  while the READ-BACK faults, which no case drove and which a latch set only on the
  marker-still-there arm would have reported as a healthy device.

  **No `tests/*.py` repro exists and none is claimed.** `rsk_fs::run_at_rest_lap`
  has exactly one caller, `firmware/src/main.rs:633`, gated on `mkek.is_some()`;
  `tools/emu` never calls it and builds its device with `otp_key: None`, so on the
  emulator `EF_HARDENED` is never latched and its RAM medium refuses nothing. A
  board would need a `FAKE_MKEK` build *and* a persistently refusing
  `remove(EF_HARDENED)`, and no hook in this tree injects a flash-remove fault on
  device. Falsified through the gate row instead: dropping the latch takes
  `test (host)` to rc 101. **bcdDevice → 0x09C5.**

- **PIV RESET and OATH RESET re-arm the at-rest scrub unskippably too — the
  four-member class is closed.** The two applets closed at 0x09C0 got the pair
  the other two did: `request_rescrub` at the head, ahead of every tombstone, and
  again after the sweeps. The retry stood BELOW the sweeps' `?`, so the one
  conjunction it exists for returned straight past it. **Driven, not read off the
  source** — the sibling entry left this pair claimed-but-undriven, and this
  programme finds such claims wrong about two thirds of the time. Both reproduced,
  each against two controls on one medium:

  | applet | head refusal | sweep fault | answer | secret | `EF_HARDENED` |
  |---|---|---|---|---|---|
  | PIV | single-shot | walk truncated after `EF_PIN`'s tombstone | `6581` | tombstoned | **LIVE** |
  | PIV control A | single-shot | none | `9000` | tombstoned | cleared |
  | PIV control B | none | truncated | `6581` | tombstoned | cleared |
  | OATH | single-shot | walk truncated after `EF_OTP_PIN`'s tombstone | `6581` | gone | **LIVE** |
  | OATH control A | single-shot | none | `9000` | gone | cleared |
  | OATH control B | none | truncated | `6581` | gone | cleared |

  `EF_PIN` / `EF_PUK` and `EF_OTP_PIN` are the records the fault is chosen at
  because they are the ones with no eager boot migration — they re-key on their
  own successful verify — so a reset before that verify leaves a verifier rooted
  in `HKDF("NO-OTP", serial_hash)`, which the public chip serial alone derives,
  under a marker no later boot laps.

  So the flash half of each wipe is its own function now — `sweep_phases`, in
  both — with the retry standing between it and the `?` that propagates its
  answer, the shape `reset`'s `wipe` and `wipe_openpgp`'s `sweep` already took.
  Control flow is otherwise byte-for-byte identical and **nothing host-visible
  moved**: every arm above answers after exactly what it answered before, and only
  the marker cell changes.

  Neither wipe's phase order moved with the extraction: PIV still sweeps
  `is_piv_secret_fid` then `is_piv_gate_fid`, OATH `is_oath_cred_fid` then
  `is_oath_lock_fid`, and the paragraph stating why each order carries the
  security property moved down onto the function that implements it rather than
  being rewritten. PIV's re-provisioning stays outside the wipe, in `reset_files`,
  where it already was.

  One new case per applet, three mutants each, every failure read for its
  DIRECTION and not its colour. The retry put back BELOW the `?`: "the head re-arm
  was refused and the sweep then faulted, so the only retry left is one the fault
  returns past" — and **only the new case falls**, 159/1 and 133/1 against
  unmutated 160/0 and 134/0, which is what makes that case load-bearing. The head
  re-arm dropped: `PIV RESET: 0xd181 was superseded BEFORE the lap was re-armed …`
  over `[…, Remove(0xd181), Remove(0xe010), Remove(0xd19b), Remove(0xd180), …,
  Remove(0xce14), …]`, and `OATH RESET: 0x10a0 was superseded BEFORE …` over
  `[Remove(0x10a0), Remove(0xce14)]`. The retry dropped: "the head re-arm was
  refused and nothing retried it". A deletion mutant is the wrong model for the
  first of those three — the property is an order and a placement, so it is the
  `?` that moves, not the call.

  PIV's case reads the tombstone off the truncating walk's own trigger rather
  than off the medium, because `reset_files` runs `scan_files` whatever the wipe
  answered and re-seeds a published default over `EF_PIN`; OATH re-provisions
  nothing after its wipe, so its case reads `EF_OTP_PIN` straight off the medium.
  Neither asserts an absolute position in the op log — `RamStorage` is a
  `HashMap`, so only the relative order of the two ops is stable.

  **What this does not close.** A medium that refuses `remove(EF_HARDENED)`
  PERSISTENTLY still leaves the marker standing over the verifier the wipe
  tombstoned, and the wipe still answers `9000`: control A of the pre-existing
  retry case asserts exactly that, because gating the re-arm would leave the
  secrets live, which is the one direction a reset must never fail in.

  **bcdDevice → 0x09C4.**

- **`Fs::factory_wipe` was the sixth `wipe-sweep` site all along, and its
  `compact()` was not the exemption two commits took it for.** `88bbcdc` and
  `14224cc` closed five reset paths against the at-rest scrub class — a tombstone
  appends like a re-seal, so a sweep that supersedes a pre-OTP-sealed verifier
  under a latched `EF_HARDENED` leaves it readable in a flash dump for the life of
  the key. Both commits recorded that the device-wide wipe needed nothing, because
  it ends with `self.storage.compact()`. That lap sits behind every `?` above it.

  Measured: on a `Cut` medium that dies after the first tombstone lands,
  `factory_wipe` returns `Err(MemoryFatal)` with the verifier gone and
  `EF_HARDENED` still standing, and **neither caller reboots** —
  `firmware/src/worker.rs` folds the wipe to `.is_ok()` and skips the reboot, and
  the trusted display's `pin.rs` paints "wipe failed" and returns. No later boot
  laps, because `run_at_rest_lap` gates on the marker and nothing else. The
  success path carries the same order defect on its own: `EF_HARDENED` is in
  neither the preserve set nor `first`/`last`, so the sweep drops it in phase 1 in
  flash-ring order, after an arbitrary prefix of tombstones.

  The fix is the head re-arm the five closed sites carry, ahead of the first
  append and **best-effort** — on a wipe, "leave the record in force" means leave
  the secrets live, so a refused re-arm must not stop the erase. No tail retry:
  phase 1 removes `EF_HARDENED` itself, so the marker is provably gone on the `Ok`
  path and the `?` returns before a retry could run on the `Err` one. Putting
  `EF_HARDENED` in `first` instead was measured and rejected — its removal there
  is `self.storage.remove(fid)?`, which propagates, so a single-shot refusal
  becomes the wipe's own answer; and it only moves the marker into the same phase
  as the FIDO device seed, whose order against it is still the flash ring's.

- **`scripts/deleter_gate.py` could not see the wipe that erases everything, twice
  over.** `factory_wipe` removes through `self.storage.remove` — not one of the
  four delete verbs — from inside `crates/rsk-fs`, which the roster's scope
  excludes. So "5 of 5 `wipe-sweep` rows closed" was a statement about 43 sites
  that never included the device-wide one. Measured before choosing: widening
  `VERBS` with `remove` alone still finds it zero times (43 -> 45 sites, none in
  `Fs`); narrowing `SKIP_DIRS` alone likewise (43 -> 48, and none of the 5 added
  is the wipe); doing both reaches 66 and drags in 21 `Storage`-impl forwardings
  whose answer has no metadata half to dispose of. So the removals `Fs` performs
  on its own behalf are derived separately, into a new `[[fs_removal]]` table in
  `assurance/deleters.toml` — enclosing method and call text held against the
  code, and whether the method re-arms the scrub **derived from its body**, so the
  fix above cannot be deleted with the row green.

  **bcdDevice → 0x09C3.**

- **The last three applet wipes re-arm the at-rest scrub too, and the re-arm now
  survives a wipe that faults on the way.** `wipe_oath` and `wipe_piv` were
  closed at 0x09C0; the three `wipe-sweep` rows of `assurance/deleters.toml` left
  un-re-armed there were FIDO `authenticatorReset` (two rows, one function) and
  OpenPGP TERMINATE DF. A tombstone appends like a re-seal — `rsk-fs`'s
  `EF_HARDENED` doc has always said "and from any that deletes one" — and neither
  `is_fido_fid` nor `is_openpgp_fid` covers `0xCE14`, so the marker outlived every
  one of these wipes. FIDO's `EF_PIN` and OpenPGP's PW1 / PW3 / RC have no eager
  boot migration: they re-key on their own successful verify
  (`clientpin.rs`'s `spend_and_verify_pin_hash` and `spend_and_verify_pin_at`,
  `pin.rs`'s `migrate_pin_kbase` — there is no `verify_pin` in `clientpin.rs`, as
  the first draft of this entry said), so a card reset before that verify left the
  pre-OTP verifier — rooted in `HKDF("NO-OTP", serial_hash)`, which the public
  chip serial alone derives — readable in a flash dump and brute-forceable
  offline, with no later boot ever lapping over it.

  Each site takes the pair the two closed ones carry: `request_rescrub` at the
  head, ahead of every tombstone, and again after the sweeps. **Best-effort, not
  gated, and that is the whole difference from the re-key sites**: "leave the
  record in force" means, on a wipe, leave the secrets LIVE, so a refused re-arm
  must not stop the reset — the shape `neutralize_default_reset_code` set. The
  second call recovers a single-shot refusal of the first and costs no append
  where the first landed, because `Fs::delete` skips a backend it already marked
  absent.

  **And it is unskippable, which a retry written after the sweeps was not.** The
  sweeps carry `?`, so the one conjunction the retry exists for — the head refused
  ONCE *and* a wipe that then faults — returned straight past it. Measured on both
  applets with a control beside the subject: head refused once and the walk
  truncated after the verifier's tombstone, FIDO answered `Err(Other)` with
  `EF_PIN` gone and `EF_HARDENED` **live**, OpenPGP `6581` with the private keys
  gone and the marker **live**; either fault on its own cleared it. So the flash
  half of each wipe is its own function now — `reset`'s `wipe`, `wipe_openpgp`'s
  `sweep` — with the retry standing between it and the `?` that propagates its
  answer. Nothing host-visible moved: every arm answers exactly what it answered
  before. Surfacing the refusal in the answer instead was measured and NOT taken —
  it is behaviourally safe (its four failures are all status-word, every wipe
  oracle stays green), but it changes what `authenticatorReset` and TERMINATE DF
  tell a host on a fault they report as success today, which is a protocol
  decision rather than a repair.

  FIDO's retry stands ahead of `ensure_seed` because `ensure_seed`'s OWN `?` would
  skip it. The two reasons the first draft of this entry gave are both withdrawn:
  the sweeps' `?` skips either position identically, so it cannot pick between
  them; and `ensure_seed` *does* supersede — its attestation-leaf rewrite is a
  measured `Write(0xce00, 490B)`, which `seed.rs` has recorded since `ec83f7a`,
  and the reason it owes the lap no re-arm is that `EF_EE_DEV` is a public X.509
  leaf rather than a chip-serial-sealed secret.

  `reset.rs`'s two registry rows are one function: `sweep` is called from `reset`
  and nowhere else in the crate but its own tests, so one re-arm at the head of
  `reset` covers both. `wipe_openpgp` likewise has exactly one production caller,
  `terminate_df`, so the pair sits inside the wipe and `scan_files`'
  re-provisioning stays outside it — the arrangement `reset_files`/`wipe_piv`
  already had.

  Three cases per applet, four mutants each, each read in the direction it fell —
  and three of the four are positional where the fourth is a semantics change, not
  four reorders. The head re-arm dropped, leaving only the end-of-wipe one:
  `FIDO RESET: 0x1080 was superseded BEFORE the lap was re-armed …`, and the
  OpenPGP twin at `0x1081`. The head re-arm made *gating* — the semantics one:
  "the refused re-arm stopped the wipe, which leaves the passkeys LIVE — the one
  direction a reset must never fail in", and the OpenPGP twin naming the private
  keys. The retry dropped: "the head re-arm was refused and nothing retried it".
  The retry put back BELOW the wipe's `?`: "the head re-arm was refused and the
  sweep then faulted, so the only retry left is one the fault returns past" — and
  only the new case falls on that one, which is what makes it the case that buys
  the placement. The order oracle prints an op LOG, and only the RELATIVE order in
  it is stable: `RamStorage` is a `HashMap`, so across five runs of the same mutant
  `Remove(0x1081)` stood 1, 6, 7, 8 and 10 places ahead of `Remove(0xce14)`. The
  gating oracle does stand FIRST in its arm, ahead of any status word, so a mutant
  falls on the wipe and not on a binding; the ORDER oracle does not —
  `assert_eq!(…, Ok(0))` precedes it.

  **What this does not close.** A medium that refuses `remove(EF_HARDENED)`
  PERSISTENTLY still leaves the marker standing over the verifier the wipe
  tombstoned, and the wipe still answers `Ok(0)` / `9000`: the cases assert exactly
  that, because gating the re-arm is the wrong direction on a wipe. `wipe_piv` and
  `wipe_oath` carry the same skippable-retry shape this entry fixes for FIDO and
  OpenPGP, read from their source and not yet driven. And `Fs::factory_wipe` is a
  wipe path of its own with no `request_rescrub` in it.

  **bcdDevice → 0x09C2.**

- **A refused re-arm at the head of an applet wipe left the marker latched over
  every tombstone the sweep then appended, and nothing retried it.** Best-effort
  (0x09C0) buys the ORDER and closes "nothing re-armed at all"; it does not buy
  the gate, and the residual was real rather than theoretical — on a medium
  refusing `remove(EF_HARDENED)`, OATH RESET tombstones a possibly
  chip-serial-rooted verifier under a standing marker and answers `9000`. Gating
  it is still the wrong direction (a refused wipe leaves the secrets LIVE), so
  `wipe_oath` and `wipe_piv` **retry the re-arm once the sweep is done**. Where
  the head landed it costs no append at all — `Fs::delete` skips a backend it
  already marked absent — and a single-shot refusal is the only kind either call
  recovers from, which is the same bound `rsk_otp`'s `BUMP_TRIES` states. Pinned
  by a case per applet on a medium refusing only the FIRST `remove(EF_HARDENED)`,
  each with the persistent refusal as its control so the assertion is about the
  retry landing and not about a marker the fixture never latched. Two mutants per
  applet, each read for direction: deleting the retry says `the head re-arm was
  refused and nothing retried it`, and deleting the HEAD one instead — a reorder,
  since the property is an order — says `0x10a0 was superseded BEFORE the lap was
  re-armed` over `[Remove(0x10a0), Remove(0xce14)]` (OATH) and `0xd181` over the
  full PIV log. **RESIDUAL, unchanged and now stated: a PERSISTENT refusal still
  latches.** `crates/rsk-oath` 130 → 133, `crates/rsk-piv` 159 → 160.
  **bcdDevice → 0x09C1** — the only line in this batch that reaches the image;
  every entry below it is a comment, a test or a host script.

- **The boot migrations' refused-re-arm arm ORPHANS the record at three of six
  sites, and 0x09BE's "does not create a new failure" was wrong about it.**
  Skipping the write leaves the pre-OTP copy unsuperseded, which is the safe
  direction at rest — but at `rsk-piv`, `rsk-oath` and `rsk-otp` the command
  paths open the CURRENT arm only, so the record is unreadable until a later boot
  migrates it. Measured end to end, each with the fault cleared as its control: a
  Yubico-OTP slot programmed before the burn **types nothing** (`button_ticket`
  answers `None`, the slot still on the medium); a PIV key slot answers `6581`;
  and OATH is the quiet one — `LIST` answers **`9000` over an empty body**, so
  the credential simply disappears. The other three degrade instead and are named
  so the next sweep starts from a list: the FIDO seed reads both arms through
  `open_any`, the rescue devcert key through `unseal_scalar`, and
  `migrate_rp_seal` displaces a CLEARTEXT rpId that stays readable either way.
  **A read-both fallback in those command paths was measured and REFUSED**, not
  argued: with one added to `rsk_otp::try_read_slot`, `power_up_bump` — which
  runs AFTER the lap — read the pre-OTP copy and re-sealed it under the current
  arm with `EF_HARDENED` still latched, on a healthy medium with no fault in it
  at all. That is the defect 0x09BD and 0x09BE closed at nineteen sites, rebuilt
  at one that has no re-arm and cannot cheaply get one, and it re-admits the
  chip-serial arm at every command rather than once at boot. So the code stands
  and **the cost is written at each of the three sites**: a transient fault costs
  one boot (the pass is unconditional and reruns), a persistent one costs the
  slot until the medium recovers. PIV and OATH take it at the migration arm;
  `rsk-otp` takes it in `try_read_slot`'s own doc instead, rewritten four lines
  for four, because `RSKeyAppletPolicies.tla` cites `power_up_bump` by line and
  any insertion above it moves that citation. No image change — comments and test
  messages, five of which said the copy "must stay in force" and now say what
  that actually leaves; the three that still say it are the arms where the record
  really does stay readable (the FIDO seed, the rescue devcert key, the cleartext
  rpId).

- **Two reasons `6754c81` gave were checked rather than inherited, and one was
  false.** `ensure_seed` does NOT "write only what it found absent": it reaches
  `rebuild_att_cert`, which rewrites `EF_EE_DEV` whenever the stored leaf fails
  `cert_matches_template` — measured on a `Cut` medium with a fully provisioned
  card and a stale template, the op log is `[Write(0xce00, 490B)]`, a superseding
  write with nothing absent anywhere in it. The EXCLUSION stands, for the reason
  now recorded at the site: `EF_EE_DEV` is a public X.509 leaf, not a
  chip-serial-sealed secret, so the copy it displaces discloses nothing. And the
  reason `migrate_slot`'s `weak` predicate drops `FORMAT_F1_OTP` (`0x11`) was
  never given at all: that copy is fixed-IV/no-MAC CBC — a second at-rest
  weakness the same re-seal repairs — but it is sealed under the OTP arm, so a
  flash dump alone cannot open it and the lap is owed nothing.

- **`f07a2dd`'s headline was refuted by its own sibling fault, and its sweep
  count was stale by two.** "A refused re-arm now writes nothing at all" is true;
  the entry's OPENING sentence is not, because the `EF_OTP_PIN` drop is a second
  append after the seal and a medium refusing only THAT reaches the same end
  state: `SET CODE` answers `6581`, `has_key(EF_OATH_CODE)` is true,
  `has_data(EF_OTP_PIN)` is true, and a fresh SELECT offers a challenge whose
  `LIST` answers `6982` while `VERIFY PIN` with the old PIN answers `9000` and
  opens the store. No ordering closes it — dropping the PIN first trades a false
  lock for a silent loss of protection — so it is **stated as the residual and
  pinned by a test** that also records what the arm does buy: the lock-down,
  which stands ahead of the drop. "`rsk-oath` has three `request_rescrub` sites"
  was the count at 0x09BD; at `f07a2dd`'s own tree there were FIVE, because
  0x09BE had added `reseal_if_plaintext`'s pair two commits earlier. Both read:
  the conclusion survives, each has its re-arm ahead of its write.

- **Moving that gate above the seal also stopped a refused re-arm from locking
  the session down, which nothing declared and no test pinned.** Same-session
  `LIST` after the refusal answers `9000` now and answered `6982` before; the
  status word is `6581` either way, so only a test can see it. **The new
  behaviour is the right one and is now pinned**: the command wrote nothing, so
  it must leave the card — the caller's earned unlock included — exactly as it
  found it, and the lock-down exists to revoke the second unlock path `SET CODE`
  creates, which a refused re-arm never created. Both mutants read for direction:
  the order reversion says `left: Sw(27010)` where `9000` is required, and moving
  `self.validated = false` below the drop says `left: Sw(36864)` where the
  installed-code arm must lock down. `crates/rsk-oath` gains both cases.

- **Two more tombstones were checked for this class and are OUT of it, by
  measurement rather than by shape.** OATH's `73 00` removal arm and `cmd_delete`
  both append over records that ARE eagerly boot-migrated, which 0x09BE made a
  skippable state. `cmd_delete` cannot reach a pre-OTP credential at all —
  `find_cred` reads the current arm only, so it answers `6984` and writes
  nothing. `73 00` can, but only behind `VERIFY PIN`: it needs `validated`, and
  over a code that cannot be read that is the sole route to it — and `VERIFY PIN`
  re-arms the lap itself, immediately before. Measured both ways: on a transient
  fault the marker is already clear by the time `73 00` runs; on a persistent one
  it is not, and a re-arm added here would be refused by that same medium. Inert
  in both directions, so neither site gains one.

- **The `bcdDevice` row could not tell an entry that records the bump from a file
  that merely moved, and three shipped builds went through the hole.**
  `bcd_gate.py` asked only `git diff --name-only <span> -- CHANGELOG.md`, so
  0x09BE, 0x09BF and 0x09C0 all landed with the row printing
  `bcd-gate: ok — 0x09C0, bumped by 88bbcdc5, nothing unbumped since` and no
  record anywhere of what those builds carry — one of the three entries still
  carrying a literal `«bumped by the manager»` placeholder. The row now also
  requires a line the CHANGELOG **ADDS** over that span to read
  `bcdDevice … 0x<value>`, and the three entries name theirs. Added lines only,
  because the file is append-only and a whole-file search is satisfied by
  history; bounded on the right, so `0x09C1` is not met by `0x09C10`;
  case-insensitive, because `0x010a` is the same build. **The word and the value
  must share one line, and that clause exists because the first cut of this rule
  had the same family of hole it was closing**: a bare hex anywhere in the added
  text counted, so an entry whose own bcd line said `the manager will fill this
  in` passed on the strength of a sentence *about the rule* that quoted the
  value. Found by driving the `bcd bump + CHANGELOG` row rather than the
  function — the row printed `ok`, exit 0, over the exact defect it was written
  for; it exits 1 now. Six table entries, each with the message that proved its
  direction: an entry naming nothing, one naming the WRONG value (what an
  `any 0x…` reading would pass), one where only an OLDER commit names it, that
  quoted-prose case, the lower-case control and the longer-hex bound. The
  fixture's own entry had to start naming its value too, which is what a real
  one does. Host-only.

- **No applet reset path in the tree re-armed the at-rest scrub — measured at
  five wipe-sweep sites across four applets, zero of them — and OATH RESET and
  PIV RESET do now.** A tombstone appends like a re-seal, which `rsk-fs`'s
  `EF_HARDENED` doc has always said ("and from any that deletes one"). `EF_OTP_PIN`
  and PIV's `EF_PIN` / `EF_PUK` have no eager boot migration — they migrate on
  their own verify — so a factory reset can tombstone a verifier still rooted in
  the public chip serial, brute-forceable offline from a flash dump, while
  `EF_HARDENED` stays latched and no later boot ever laps. Derived from
  `assurance/deleters.toml`'s 43 dispositions, not from memory: 5 `wipe-sweep`
  sites (`rsk-fido/src/reset.rs` ×2, `rsk-oath`, `rsk-openpgp/src/terminate.rs`,
  `rsk-piv/src/files.rs`), and no `request_rescrub` in any of their functions.
  None of the four applet predicates covers `0xCE14`, so the marker survives every
  one of them; `Fs::factory_wipe` is the exception and needs no re-arm, because it
  ends with `self.storage.compact()` and scrubs directly.

  `wipe_oath` and `wipe_piv` re-arm at the head of the sweep, ahead of every
  tombstone and of `scan_files`' re-provisioning. **Best-effort, and that is the
  whole difference from the gated sites**: "leave the record in force" means, on a
  wipe, leave the secrets live, so a refused re-arm must not stop the reset — the
  shape `neutralize_default_reset_code` already used. Both directions pinned by
  one case per applet: the re-arm moved to the end of the sweep says "superseded
  BEFORE the lap was re-armed" over `[Remove(0x10a0), Remove(0xce14)]` (OATH) and
  over the full PIV wipe log; the re-arm made *gating* instead says the refusal
  stopped the wipe and left the key material live. The remaining three sites —
  FIDO `authenticatorReset` ×2 and OpenPGP TERMINATE DF — are the same shape and
  are not closed here.

  **A claim about `rsk_piv::set_retries` was checked rather than inherited, and it
  holds.** Its `EF_RETRIES` write stands ahead of the re-arm gate; the reason it
  stays there is that four plaintext counter bytes supersede no chip-serial-rooted
  copy, so a refused re-arm leaves a *retriable command* — new totals, both
  references in force — and not a remnant. Measured on a medium refusing only
  `remove(EF_HARDENED)`: `6581`, `EF_RETRIES` `3,3,3,3` → `5,5,5,5`, `EF_PIN` and
  `EF_PUK` byte-identical, `EF_PUK` still chip-serial-rooted. The reason is
  recorded at the site, and the gate it never had is now a case that reddens when
  the answer is swallowed. `crates/rsk-piv` 157 → 159 tests.

  Not verified, and the same limit the class has carried since 0x09BD: no board
  was touched, and `RamStorage` overwrites in place, so no host test can read a
  recovered pre-OTP copy. The fixtures witness the ORDER of the appends and the
  marker.

  **bcdDevice → 0x09C0.**

- **OATH `SET CODE` installed the access code and then refused, leaving the
  OTP-PIN it exists to revoke alive underneath it.** Making every superseding
  write conditional on the at-rest re-arm (`3d016ef`, 0x09BD) put the
  `request_rescrub` gate between the two flash writes this command makes: the seal of
  `EF_OATH_CODE` landed first, and the gate's `6581` returned before the
  `EF_OTP_PIN` drop. Walked on a `RemoveStuck` medium refusing
  `remove(EF_HARDENED)` and nothing else, so no reset is in it: `SET CODE`
  answered `6581`, `has_key(EF_OATH_CODE)` was **true** and `has_data(EF_OTP_PIN)`
  **true**, and the surviving PIN is not merely a leftover — a *fresh* SELECT
  offered a challenge, `LIST` behind it answered `6982`, and `VERIFY PIN` with
  the old PIN answered `9000` and opened the store. A lock the owner was told had
  failed, with a second unlock path standing beside it.

  The site's own mitigation was already applied and does not close it. `SET
  CODE` hoists `self.validated = false` above the gate precisely so a refused
  re-arm locks down — but that flag is per-session, `select` recomputes it, and
  `VERIFY PIN` sets the same flag `VALIDATE` does. The measurement above is a new
  session. **The gate moved ahead of the seal instead**, which is the rule the
  command already states for its own grammar refusals: judged before a byte is
  written, so the standing state survives the refusal. A refused re-arm now
  writes nothing at all. `EF_OTP_PIN` is still the only OATH record with no eager
  boot migration, so the ordering the re-arm exists for is unchanged — the gate
  simply leads both appends now instead of one.

  Two oracles, both driven red before the fix and both killed by the ordering
  reversion alone, each failure read for its DIRECTION rather than its colour.
  The refusal end state (`a_set_code_whose_re_arm_the_medium_refuses_installs_no_code`)
  says *a write happened that must not have*, never the inverse; and the `Cut`
  medium's append log says `[Write(0xbaff, 49B), Remove(0xce14), Remove(0x10a0)]`
  — the seal ahead of the re-arm — where the fixed order puts `Remove(0xce14)`
  first. Tests 126 → 127.

  Swept by shape, not by name. `rsk-oath` has three `request_rescrub` sites and
  this was the only one with a write ahead of its gate: OTP-PIN `CHANGE` and
  `VERIFY` are preceded only by `spend_otp_retry`'s counter rewrite, which stores
  the same verifier bytes (the fixture's `still_weak` arm) and narrows the retry
  budget rather than granting anything, so their refusal paths leave no
  authorization live. One other site in the family has the ordering shape and is
  NOT this hazard, named here rather than changed: `rsk_piv`'s `SET RETRIES`
  writes `EF_RETRIES` before its gate, so a refused re-arm leaves the new totals
  with PIN and PUK un-reset — a partial application of a command that already
  required both the management key and the PIN, with the old references still in
  force.

  **bcdDevice → 0x09BF.**

- **The boot pass re-keys pre-OTP records too, and standing before the at-rest lap
  is not the same as standing before the lap that latched.** 0x09BD swept thirteen
  lazy re-keys onto "re-arm first, and write only if the re-arm landed"; the eight
  calls at `firmware/src/main.rs:610-617` were left out on the reading that the lap
  at the foot of their own block covers whatever they supersede. It covers only the
  boot they run on. `run_at_rest_lap` latches `EF_HARDENED` once per device and
  gates on it and nothing else, so a boot that silently skipped a record — every
  one of these migrations opens with a `read_key`/`seal_read` that spells a flash
  READ FAULT the same way it spells an absent slot, and closes with a `let _ = put`
  — latches the marker anyway, and the boot that finally migrates that record
  supersedes a copy still sealed under `HKDF("NO-OTP", serial_hash)` with the lap
  gated shut for the life of the key. No reset is needed anywhere in it.

  One member needs no fault at all, which is what settled that this is reachable
  rather than latent. `migrate_rp_seal` returns whole while `load_keydev` answers
  `None` — a PIN-wrapped `0x03`/`0x13` seed, or a soft-locked device — so on such
  a key the boot that boxes a legacy cleartext rpId is *routinely* not the boot
  that latched the marker, and the domain it displaces stays readable in a flash
  dump. That record's own comment already assumed "the one-shot `EF_HARDENED`
  compact lap that runs after this pass" would take it.

  **Six superseding arms across five crates**, each now calling
  `rsk_fs::request_rescrub` ahead of its write and skipping (or failing) the write
  when the medium refuses it: `migrate_slot` in `crates/rsk-fido/src/seed.rs` (the
  seed and the attestation key, tags `0x01`/`0x02`), `migrate_kbase` in
  `crates/rsk-rescue/src/keydev.rs` (a pre-OTP GCM blob or a bare 32-byte CBC
  record), `migrate_kbase` in `crates/rsk-piv/src/seal.rs`, both arms of
  `migrate_seal` in `crates/rsk-otp/src/lib.rs` — the pre-OTP one and the legacy
  plaintext one, whose superseded copy holds the slot's AES key in the clear — and
  `migrate_rp_seal` in `crates/rsk-fido/src/credential.rs`. Each is gated on
  `dev.otp_key`, the same gate the boot glue puts on the lap, so a pre-OTP board
  neither re-arms nor has its migration made conditional on one.

  It costs nothing where it fires: the re-arm clears a marker the lap at the foot
  of the same boot block re-latches, and on a steady-state boot no arm is reached,
  so no lap is forced. The narrowness matters — `migrate_keydev_pin`'s re-arm had
  to stay this narrow at 0x09BD, or every correct PIN verify would order a
  multi-second compaction on the next boot.

  Three boot calls were measured and are **not** in the class: `ensure_seed` writes
  only records it found absent; `scan_files` writes factory defaults, its one
  superseding path (`neutralize_default_reset_code`) having re-armed since 0x09BD;
  and `rsk_otp::power_up_bump`, which runs *after* the lap, reads through a
  `try_read_slot` that opens under the current arm only, with no pre-OTP fallback,
  so it can never supersede a chip-serial-rooted copy.

  Six host tests, one per arm, each in three parts: the append ORDER read off a
  `Cut` medium's log; the GATE driven on a `RemoveStuck` that refuses
  `remove(EF_HARDENED)` and serves everything else, which is the fault that reaches
  the losing end state with no reset in it; and a control on that same medium with
  the fault cleared, so the gate assertion is about a write that was refused and
  not about a pass that never fired. Fourteen mutation arms, each reverting one
  change alone and each read for its DIRECTION: every ordering reversion says
  `was superseded BEFORE the lap was re-armed` over a log reading
  `[Write(fid), Remove(0xce14)]`, and every gate reversion says the migration went
  ahead over a copy the re-arm had not cleared — never the inverse. A narrowing arm
  (dropping the legacy `0x01` tag from the seed's `weak` predicate) is killed too,
  and one arm was first written as a DELETION, reported `nothing re-armed the
  at-rest lap at all`, and was redone as a reversion — the same correction 0x09BD's
  entry records. rsk-fido 672 → 674, rsk-piv 155 → 156, rsk-otp 79 → 81,
  rsk-rescue 41 → 42.

  **Not closed, and named so the next sweep starts from a list.**
  `rsk_oath::migrate_seal`'s `reseal_if_plaintext` carries the same two arms — a
  pre-OTP re-seal and a legacy plaintext one — and is unfixed here. And the model
  would not have caught this: `RSKeyBootHardening`'s `Boot` is one atomic step with
  no state between the migrations and the lap, and `LazyRekey` / `RekeyBegin` are
  guarded on `phase = "serving"` — so a boot-phase re-key, and a migration that
  fails on one boot and succeeds on the next, are states that module cannot enter.
  The rule it asserts is the right one; what it cannot express is where this change
  applies it. **bcdDevice → 0x09BE.**

- **OATH's boot pass was the sixth member of the boot-migration class, and it
  carries the two arms the other five did.** `rsk_oath::migrate_seal` runs at
  `firmware/src/main.rs:613`, ahead of `run_at_rest_lap`, and standing ahead of
  the lap is not the same as standing ahead of every lap — `rsk-fs`'s own doc now
  says so. `reseal_if_plaintext` re-seals a credential (or the SET CODE key) that
  opens only under `dev.without_otp()`, i.e. under `HKDF("NO-OTP", serial_hash)`,
  which the public chip serial alone derives; and it seals a legacy record whose
  HMAC secret is in the clear on the medium. Neither write was conditional on
  anything. A boot whose `seal_put` was refused latched `EF_HARDENED` all the
  same, and the boot that finally migrates that record supersedes the weak copy
  under a marker `run_at_rest_lap` gates on and nothing clears.

  Both arms re-arm ahead of the write and are gated on it landing, in the shape
  the five sibling passes use — the plaintext arm on `dev.otp_key.is_none() ||
  …is_ok()`, because that is what `run_at_rest_lap`'s caller gates the lap on.

  Measured before it was fixed, and in both directions. The order half fails on
  the `Cut` medium's log with **one op in it** — `[Write(0xba00, 51B)]` for the
  pre-OTP arm, `[Write(0xba00, 58B)]` for the plaintext arm — "nothing re-armed
  the at-rest lap at all", which is the tree's actual defect and not its inverse.
  The gate half, read on a `RemoveStuck` medium refusing only
  `remove(EF_HARDENED)`, fails saying the pre-OTP copy was superseded anyway.
  Four mutants kill, each reddening only its own arm: each re-arm moved AFTER its
  write (a reorder, not a deletion — the property is an order) says "superseded
  BEFORE the lap was re-armed" with `[Write(0xba00, …), Remove(0xce14)]`, and
  each re-arm's answer swallowed says the copy was superseded with the marker
  still on the medium. Each case carries a control on the same medium with the
  fault cleared, so the refusal assertion is about the gate and not about a pass
  that never fires. `crates/rsk-oath` 127 → 130 tests. **bcdDevice → 0x09BE**, the same
  bump as the entry above — one commit carried both arms of this class.

- **Every lazy re-key re-arms the at-rest scrub before it writes, *and does not
  write when the re-arm did not land*.** The re-key and the
  `rsk_fs::request_rescrub` under it are two separate flash appends with no
  atomicity between them, and all thirteen call sites shipped them in the order
  that loses the wrong one: `fs.put` first, `fs.delete(EF_HARDENED)` second. A
  reset landing between the two left `EF_HARDENED` **set** over a copy the write
  had just superseded — still sealed under the pre-OTP root
  `HKDF("NO-OTP", serial_hash)`, which the public chip serial alone derives, with
  no secret and no stretching. `run_at_rest_lap` gates on `has_data(EF_HARDENED)`
  and nothing else, so that copy is not merely missed once: **no later boot ever
  runs the lap again**, and it stays in the ring for the life of the key.

  **Order is only half of it, and the half that covers a power cut.**
  `request_rescrub` swallowed its own medium's refusal (`let _ = fs.delete(…)`),
  so a backend that refuses `remove(EF_HARDENED)` and serves everything around it
  reached that same end state with **no reset in it at all** — measured: OATH
  CHANGE OTP PIN answered `9000`, re-keyed the verifier and left the marker
  latched over the superseded chip-serial copy. It answers now, `Ok` meaning "the
  lap WILL run": the marker is read back through `Fs::has_data`, the same gate
  `run_at_rest_lap` itself reads, because `Fs::delete`'s own result is neither
  necessary (it reports the EF_META drop, and `EF_HARDENED` keeps no metadata) nor
  sufficient (it skips the backend when the present bit is clear, which is exactly
  what a read-fault-truncated `Fs::scan` leaves over a live marker — and then
  answers `Ok`). Every superseding write is conditional on that answer. `Result` is
  `#[must_use]`, so the compiler, not a `git grep`, enumerated the callers.

  Two of the fourteen do not refuse the command when the re-arm fails, because at
  those two the write is already best-effort and skipping it is the safe half:
  OATH VERIFY's legacy-record upgrade (`let _ = fs.put`) and `load_dek`'s
  stale-stage retirement. The record stays in force and a later command retries.
  The refusal this repo already weighed for `Fs::delete` — "one flash fault would
  stop every delete on the device, including the wipe" — does not transfer to the
  other eleven: there the dangerous act is *proceeding*, refusing leaves the
  pre-existing record in force, and none of the thirteen is on a wipe path.

  Found by an adversarial review of `RSKeyBootHardening`'s marker rows, then
  measured in code. The sweep is the class, not the report: it named five sites,
  `git grep request_rescrub` has **thirteen** — the two FIDO PIN verifies, OATH
  SET CODE / CHANGE / VERIFY OTP PIN, OpenPGP `migrate_pin_kbase`, `load_dek`'s
  stale-stage retirement, `recover_staged_dek`, the stage/verifier/commit
  sequence and PUT DATA `0xD3`'s clear arm, and PIV's SET RETRIES, `check_ref`
  fallback and `unblock_pin_with_puk`.

  **A fourteenth calls it never**, and no grep finds it: `init.rs`'s
  `neutralize_default_reset_code` tombstones `EF_RC` and `EF_DEK_RC` — the same
  two records as PUT DATA `0xD3`'s clear arm — on a card from firmware <= 0x07F6
  still carrying the public admin default as its reset code. It runs from
  `scan_files`, which boot runs *before* the lap but TERMINATE DF re-runs
  mid-session, so a sweep that failed to clear `EF_RC` reaches it with the marker
  already latched. It is also **the one site whose write is not gated on the
  re-arm**: "leave the pre-existing record in force" means, here, leaving a live
  unauthenticated `RESET RETRY P1=0` path, and an online key-recovery route beats a
  superseded copy in the ring. Both directions are pinned by tests.

  **And one guard was narrower than the writes behind it.** Both FIDO re-arms sat
  under `if migrated` — EF_PIN's verifier matched pre-OTP — while
  `migrate_keydev_pin` re-keys `EF_KEY_DEV` off the pre-OTP arm on the success path
  regardless. The two records part company for real: `migrate_keydev_pin` opens
  with `fs.read_key(EF_KEY_DEV, …)`, and `read_key` collapses a flash READ FAULT
  into the same `None` an absent slot gives, so one faulted probe makes the seed
  migration a silent no-op for a verify that goes on to persist an OTP-rooted
  `EF_PIN`. Every later verify then re-keys a 0x03 seed with `migrated` false and
  nothing re-arming. The re-arm moved to `migrate_keydev_pin`, where the record's
  own format byte says whether the copy being superseded is chip-serial-rooted —
  it must stay that narrow, or every correct PIN verify would force a multi-second
  compaction lap at the next boot.

  **One of the thirteen could not be fixed by a swap.** `commit_staged_dek` held
  "the ONLY re-arm" for `change_pin`, both `reset_retry` arms and
  `put_reset_code`'s set arm — but it is the *last* of three appends
  (`stage_dek`, `put_verifier`, then the commit), so moving it to the head of its
  own function still left `put_verifier`'s re-key of a chip-serial-rooted `EF_PW1`
  in front of it. It moves to the head of `stage_dek`, the first append of all
  four sequences, which keeps the single chokepoint and puts it ahead of every
  write it covers. That claim rested on one of the four sequences; all four carry
  an ordering assertion now, and removing the chokepoint reddens five rows.

  The order is host-testable and now tested: `rsk_fs::storage::faults::Cut` is a
  medium that serves a budget of mutations and then refuses every one after,
  keeping the ordered log of those that landed — the shape of a reset between two
  appends. `CutMedium::assert_re_armed_before` is the oracle, with both halves
  required to appear in the log, because an order nothing performed is held
  vacuously and an absent marker is the store's default state. Each site was
  proved falsifiable by reverting its own swap alone; every failure reads
  "superseded BEFORE the lap was re-armed" — the marker SURVIVED — and never the
  inverse. The control that stays green hoists OATH CHANGE's re-arm one append
  *earlier* still, which changes the medium's order
  (`[W(0x10a0), R(0xce14), W(0x10a0)]` → `[R(0xce14), W(0x10a0), W(0x10a0)]`) and
  is not a no-op.

  `Cut` is **not** the only fault that tells the two orders apart, as this entry
  first claimed. Six of the thirteen return from a refused write *before* their
  trailing re-arm — both FIDO verifies, `migrate_pin_kbase`, `recover_staged_dek`,
  `commit_staged_dek` and PIV's `check_ref` — so a backend refusing one chosen
  `write` separates them there on `has_data(EF_HARDENED)` alone. Measured at
  `check_ref` with `write(EF_PUK)` refused: `6581` either way, marker cleared under
  the fix and latched reverted. `Cut` still earns its place for the other seven,
  whose re-arm runs whatever the write returned.

  **`spend_and_verify_pin_at`'s fallback — the trusted display's own PIN verify —
  was reached by no host test**, shadowed by the host path in every sweep;
  `a_local_pin_verify_re_arms_the_lap_before_it_re_keys` covers it now, and is the
  single row a `panic!` at that site reddens. The *function* was never unreached:
  a `panic!` at its first statement takes nine rows down (ten now). What a host
  fixture cannot reach is the real power cut between two flash appends: `Cut`
  models it, and only the flash ring keeps the superseded copy a dump would read.

  The cost of the safe order is one extra lap, and that lap is not nothing:
  `SeqStorage::compact` writes `(MAIN_LEN + SECTOR) / 1024` throwaway 1 KiB records
  unconditionally, forcing the ring head a full turn so every sector of the main KV
  partition is swept and erased — a multi-second stall at boot, before USB attach.
  It stays the right direction: it is bounded at one per boot, idempotent, and
  every trigger is an authenticated command.
  **bcdDevice → 0x09BD.** The write order, the swallowed refusal, the fourteenth
  site and the guard that was narrower than its writes ship as one change,
  because the last three are what an adversarial review of the first found.

- **Two commands revoke a pre-OTP credential by tombstoning it, and a tombstone
  is not an erase.** The run-35 class was written as "lazily *re-keys*", and both
  of these DELETE instead — but `EF_HARDENED`'s promise is the broader one
  (SEC-BOOT-001: "no superseded weak-sealed copy awaits the scrub"), and a
  log-structured store keeps a deleted record's bytes in the ring until a
  compaction lap reclaims the page, exactly as it keeps a superseded one's. Both
  re-arm the lap now, after the store call and in the shape the OATH and PIV
  sites already use.

  **OATH SET CODE (`0x03`)** drops `EF_OTP_PIN`. That is the one OATH record
  `migrate_seal` does not reach at boot — the credentials and the access code are
  re-sealed eagerly there, before `run_at_rest_lap`, so `EF_OTP_PIN` is the only
  OATH record that can still be chip-serial-rooted when a host command arrives.
  The PIN's *value* is what leaks, and the command's own comment expects the
  owner to re-mint it.

  **OpenPGP PUT DATA `0xD3` with an empty body** clears the reset code, dropping
  `EF_RC` *and* `EF_DEK_RC`. That one is worse, and the reason was read in the
  code rather than assumed: `EF_DEK_RC` is the card's DEK sealed under the RC
  session, the clear arm calls neither `rewrap_dek` nor `stage_dek`, and nothing
  else on the card rotates the DEK — so the tombstoned copy still opens the
  private keys. The new test proves it by measurement: it opens `EF_DEK_RC`
  under the pre-OTP arm before the clear, then `load_dek`s after it, and the two
  DEKs are byte-identical. `pin_derive_session` is HMAC-SHA256 + HKDF over the
  *public* serial with no stretching, and GCM authenticates, so the reset code
  falls to an offline, unthrottled, self-checking search — no verifier needed.

  Both cases fell before the fix on the marker assertion — the marker SURVIVED a
  supersession that should have cleared it, which is the missing-re-arm direction
  and not its inverse — and each asserts its record is chip-serial-rooted first,
  so it cannot pass by the record being strong. Four mutants kill, each reddening
  only its own case (the call deleted; the call swapped for a marker *read*), and
  two controls that are measurably not no-ops stay green: each re-arm moved ahead
  of its delete, which under a one-operation write budget flips both the status
  word and which record survives (OATH `9000`/marker-latched → `6581`/marker-
  cleared), and the suite cannot see it. **bcdDevice → 0x09BC.**

  **A third site was claimed and is REFUTED.** OpenPGP `reset_retry` verifies the
  RC or PW3 and re-keys `EF_PW1` — the PIV asymmetry exactly — and its only
  re-arm is the one inside `commit_staged_dek`. That coupling is real but it is
  not a hole: on a healthy medium `commit_staged_dek` cannot be skipped after the
  verifier write (its early exits need the stage it just wrote to be gone), and
  the only way to skip it is a medium that has stopped accepting writes — on
  which `request_rescrub` cannot clear the marker either, because clearing it is
  itself a write. Measured, not argued: an added unconditional re-arm on both
  arms left the outcome **byte-identical at every write budget from 0 to 11**. So
  no call was added; the coupling is recorded at `commit_staged_dek` instead, and
  `reset_retry_via_pw3_re_arms_the_at_rest_lap` is the case that goes red if a
  future edit makes it conditional.

- **PIV re-keys a reference on two paths that never verified the one they
  overwrite, and the run-35 class is four crates wide, not two.** `rsk-fs`'s
  `EF_HARDENED` doc defines the class as *any* applet that lazily re-keys a
  pre-OTP record after the lap has run; the sweep one commit ago read it as the
  two applet crates it had open. RESET RETRY COUNTER (`unblock_pin_with_puk`)
  verifies the **PUK** and then writes a fresh **PIN** verifier — and the PIN is
  blocked on that path by construction, so `check_ref`'s migrating fallback has
  never run on `EF_PIN`. SET RETRIES (`0xFA`) is gated on the PIN and the
  management key, never on the PUK, then rewrites **both** references to factory
  defaults, so `EF_PUK` can still be chip-serial-rooted when its record is
  superseded. Either way the displaced verifier is rooted in the public chip
  serial — brute-forceable offline from a flash dump — while `EF_HARDENED` stayed
  latched, so no boot ever swept it. Both re-arm the lap now, after the store
  write, in the shape the OATH site already used.

  Measured before it was fixed, and as someone else's claim rather than a given:
  each new case in `crates/rsk-piv/src/tests.rs` reads the record back to prove
  it is chip-serial-rooted, proves the *other* reference's own migrating verify
  does re-arm, latches the marker, and then falls on the marker assertion — the
  marker SURVIVES a re-key that should have cleared it, which is the missing-
  re-arm direction and not its inverse. Four mutants kill, each reddening only
  its own case (the call deleted; the call swapped for a marker *write*), and
  three controls that are not no-ops stay green: each re-arm moved ahead of its
  store write, and SET RETRIES' two writes swapped. All seven binaries differ
  from pristine by digest.

  The sweep is finished across all four applet crates this time, from
  `pin_derive_verifier`'s four writers outward, opening every caller rather than
  trusting a comment: FIDO's `set_pin` refuses when a PIN exists while
  `change_pin` and the display's `local_pin_gate` verify first and re-arm there;
  OpenPGP's writers funnel through `commit_staged_dek` or `migrate_pin_kbase`,
  and `init`'s rewrite arm runs only when neither verifier exists; OATH's
  `cmd_set_otp_pin` mints only into absence; PIV's `change_reference` and
  `scan_files` are covered by `check_ref` and by absence.

  The family that pins all of this was satisfiable by absence. Every case put
  `EF_HARDENED` and then asserted it gone, with nothing checking the latch took —
  and absence is the default. A shared-path defect that makes `Fs::put` answer
  `Ok(())` without storing for that FID left all ten cases GREEN while hiding the
  very re-arm they exist to pin. With the latch now asserted at all ten (the
  shape `crates/rsk-fs/src/fs_tests.rs:382` already used), the same defect
  reddens every one of them. Their messages also claimed a superseded copy was
  "readable in a flash dump", which no host test can witness: `RamStorage` is a
  map that overwrites in place, so these are call-presence oracles on the marker,
  and three of them now say so. **bcdDevice → 0x09BB.**

- **OATH's PIN CHANGE is a lazy pre-OTP re-key too, and run-35's sweep did not
  reach it.** That sweep re-armed the at-rest scrub in FIDO clientPIN, the
  display device PIN, PIV and OATH — but OATH's `0xB2` VERIFY only. `0xB3`
  CHANGE writes the same fresh v1 verifier over the same record, and
  `otp_pin_matches` explicitly accepts a v1 stored *before* the OTP burn, so a
  PIN set on a pre-OTP board and changed after it superseded a verifier rooted
  in the public chip serial — brute-forceable offline from a flash dump — while
  `EF_HARDENED` stayed latched and no boot ever swept the displaced copy. The
  legacy `[counter, double_hash_pin]` layout CHANGE upgrades is the same story.
  `cmd_change_otp_pin` re-arms the lap now, after the store write and in the
  sibling's shape.

  Measured, not argued: the new test in `crates/rsk-oath/src/otp_pin_tests.rs`
  reads the record back before the CHANGE to prove it is chip-serial-rooted,
  latches the marker, and fails on today's code at the marker assertion — the
  marker SURVIVES a re-key that should have cleared it, which is the missing-
  re-arm direction and not its inverse. Two mutants kill it (the call deleted;
  the call swapped for a marker *read*), and two controls that are not no-ops
  stay green: the re-arm moved ahead of the store write, and a refused store
  answering `6985` instead of `6581`.

  A class sweep of these two applet crates found no other site still missing it:
  the OpenPGP verifier writers all funnel through `commit_staged_dek` /
  `migrate_pin_kbase`, which re-arm, and `cmd_set_otp_pin` mints only where no
  record exists, superseding nothing. The boot-time migrations do not need it —
  they run before `run_at_rest_lap`, not after. Two crates was the wrong scope,
  and the entry above says what the class really is and what PIV was hiding in
  it. **bcdDevice → 0x09BA.**

- **The delete guard that shipped one commit ago raised `6581` over erases that
  had completed.** `Fs::delete` drops the shared `EF_META` record *first* and
  removes the value anyway, so its `Err` folds two states: the value gone with a
  record standing over it, and the medium refusing the removal. An OTP slot
  carries no `EF_META` head of its own, so on any device that has metadata at all
  — every provisioned one — a faulted read of *somebody else's* blob made
  `CONFIGURE`-with-an-all-zero-config answer `6581` for a slot that really was
  erased. Measured before the fix: `sw = 0x6581` with the record already gone from
  the medium, where the pre-guard build answered `0x9000` correctly.

  The three delete sites read the record back now (`slot_still_live`) and refuse
  only when it is still there. A probe that cannot answer counts as live, because
  once the value may be in flash the alarm is the safe direction — and that
  direction has its own test, since a read-back that collapsed a faulted probe to
  *gone* would answer `9000` over a record the medium still holds. Both arms and
  the false alarm are driven: three mutations, three kills, one saying `6581` over
  a completed erase, one `9000` over an unperformed delete, one `9000` over a
  record still in flash.

  Found by a re-review of the previous commit rather than by the gate — a guard
  that is too strict fails in the direction no `let _ =` sweep looks at.
  **bcdDevice → 0x09B8.**

- **A faulted flash read spelled *unprogrammed slot*, so an unauthenticated
  `SLOT_SWAP` destroyed both records.** `Storage::read` answers `None` for a
  value that is absent and for one it could not serve, and `rsk-otp` reads a
  slot's access code out of the record it just probed — so a refused probe
  presented a protected slot as a free one. Six sites acted on that collapse, and
  the swap is the one that loses data rather than a gate: `cmd_swap` read both
  slots, and a slot read as absent had its own `ct_eq` gate skipped, was DELETED
  by the other slot's `None` arm, and was written over by the other slot's
  record. Driven before the fix on the shipped command handlers, one faulted
  probe of slot 2 and one bare `0x06` frame carrying no code at all: slot 1
  empty, slot 2 holding slot 1's record, slot 2's own record gone.

  The four gates take a fallible probe now — `seal::try_seal_read` beside
  `seal_read`, the shape `Fs::try_read` already has — and answer `6581` where the
  medium could not decide: `CONFIGURE`, `UPDATE`, `SWAP`, and
  `code_clears_every_slot`, the gate on the device-global scan-map and NDEF
  writes, which cleared for an unreadable slot and let a host retarget what that
  slot TYPES. The three `let _ = fs.delete(…)` in those handlers read their answer
  too, because the reply is `status()` taken back off the same flash: a slot that
  did not go reported itself VALID under a `9000`.

  **Three of the six were losing data or opening a gate; three were reporting a
  mutation that never happened, and the entry does not blur them.** `SWAP`'s read,
  `CONFIGURE`'s read and `code_clears_every_slot` are the first kind.
  `CONFIGURE`'s delete, `UPDATE`'s read and `SWAP`'s *second* delete are the
  second: `Sw(36864)` where `Sw(25985)` belongs, nothing lost. That last one is
  worth saying plainly — its record write has already landed when the delete is
  refused, so the guard buys the report and not the state, and its own test says
  so.

  **The write half of the replay window, which the read half does not cover.**
  The Yubico position is a pair, and both halves reach flash. The press's write —
  the 15-bit advance, owed on a virgin slot's FIRST press (its stored tail is
  zero) and thereafter when the one-byte session counter wraps — was
  `let _ = put_slot(…)`: measured, the press after a refused one re-typed
  `(use 1, session 0)`, this power cycle's FIRST position, because the slot reads
  the old counter back and pairs it with a session it has already used. A press
  that cannot store its advance now types nothing and leaves the RAM half where
  the stored one is, so the press is retried rather than replayed. The boot bump's
  write is retried too (`BUMP_TRIES`, both sides) — one refused write no longer
  costs a whole power cycle.

  What is NOT claimed, and one of these is more reachable than anything above. A
  boot-bump write the store refuses **for good** still leaves the counter where it
  was, and the next cycle re-types the last one's positions — `Fs::put` answers
  `NoMemory` on a full store, so this needs no fault at all. **That is a choice
  and not a limit.** Two closures were built and measured — one carrying the boot
  pass's failure out to the applet, one keeping it in the crate by making the
  first press of a slot do the advance itself and deny the press if the store
  refuses — and what ships is the other arm of the same choice, because a store
  that cannot be written to would otherwise silence every slot on the key. It is
  **pinned by a test that asserts the repeat**, and that pin now binds the boot
  pass's `()` so wiring an outcome through it is a compile error rather than a
  green test. The same choice does not arise for a medium that keeps refusing a
  boot READ, or for the swap's torn half, which is older and unchanged. Twelve
  mutations, twelve kills, each read for direction — every failure says a mutation
  happened that should have been refused, a position was re-typed, or a `9000`
  stood over something that did not happen; none says something should have
  succeeded. Two of the twelve are killed by the same assertion, and one is a
  liveness kill (`left: 0`, `right: 1`) — correct here, and named because that is
  the shape an inverse-defect kill hides in. The collapsing-probe roster written
  at `read_slot_m` is 7 functions / 11 probes; the first cut of it said six and
  named a function that does not exist. **bcdDevice → 0x09B7.**

- **`SLOT_SWAP` moved a Yubico OTP record and left half of its replay position
  behind.** The position a validation server orders OTPs by is a PAIR: the
  15-bit use counter that lives in the slot RECORD, and the one-byte RAM session
  counter, which is indexed by SLOT NUMBER and written only by a button press.
  `cmd_swap` moved the record — public id, AES key, use counter — to the other
  index and left the session counter where it was, so the record was re-paired
  with whatever the destination slot had spent, and a slot pressed fewer times
  handed it a position it had already typed. Measured against the shipped
  command handlers: a slot 1 configured and pressed three times types
  `(use 1, session 0)`, `(1, 1)`, `(1, 2)`, and after one `0x06` frame slot 2
  types `(1, 1)` again — a pair already emitted in this power cycle, the
  position moving BACKWARDS, which is the replay these two counters exist to
  refuse. It needs no authentication: an unprotected slot's stored access code
  is all-zero, so the bare `ykman otp swap` frame satisfies the swap's `ct_eq`
  gate with the default.

  The volatile half travels with the record now, so a swapped record's pair is
  exactly the pair it would have had with no swap — which is why the repair is
  an exchange and not a reset of both counters, the tempting other reading:
  resetting them re-emits the FIRST position of the power cycle rather than the
  second. The three siblings that also write that record were swept and are
  clean, because none of them changes its index: `cmd_update` carries the tail
  forward in place, the boot seal migration re-seals at the same FID, and
  `cmd_configure`, which zeroes the persisted counter, deliberately leaves the
  session counter standing — a test pins that direction too. A host that
  programs the same secret into a second slot still clones its own credential,
  as on a YubiKey; that host holds the AES key and can mint any OTP it likes.
  **bcdDevice → 0x09B6.**

- **A device PIN the running build could not collect waived the vendor gate
  entirely.** `vendor::pin_gate` is the PIN factor on every host-driven operation
  that reveals or replaces device identity — `BACKUP_EXPORT`, `BACKUP_LOAD`,
  `BACKUP_FINALIZE`, `ATT_IMPORT`, `ATT_CLEAR`, the audit commands, `CONFIG_WRITE`.
  With no clientPIN it takes the device PIN on the panel, and that branch was
  guarded by `uv_available()`, which is **false on every presence backend but the
  trusted display**. `EF_DEVICE_PIN` is not a display-only record — `is_fido_fid`
  keeps it — so it survives a reflash from a display image to a screenless one,
  and the gate then fell through to `Ok(())`: the owner had set a PIN and the
  second factor silently became a touch. Driven before the fix on the shipped
  code path: `ATT_CLEAR` completed and the org attestation key was destroyed with
  a device PIN set and no way to ask for it. It answers `CTAP2_ERR_PUAT_REQUIRED`
  (`0x36`) now — recoverable by reflashing the display image and clearing the PIN,
  or by a factory reset, which is the restrictive side. `docs/threat-model.md`
  named only the clientPIN form of this factor and now names both.

- **A record written by an earlier build faulted the firmware on an UNGATED
  command.** `Fs::read` answers the record's FULL length — its own doc comment says
  so — and three sites sliced `buf[..n]` with no clamp. The reachable one is
  `ATT_STATE`, which takes no PIN, no touch and no channel: `cert::ATT_CHAIN_MAX` is
  a `min3` over a store cap, a MAC cap and a CTAPHID response cap, and `ab8bcfc`
  took it from **4069 to 2132** in this same unreleased series. A key provisioned
  with an attestation chain under the old cap therefore holds an `EF_ATT_CHAIN`
  record longer than the new build's 2141-byte buffer, and the first `ATT_STATE`
  after the upgrade panicked — measured, `range end index 2142 out of range for
  slice of length 2141`. `ATT_STATE` now reports the key present and OMITS the chain
  hash it cannot compute, rather than publishing one over a prefix.

  The other two are the same shape and not reachable on any build shipped so far,
  because their writers cap what their readers hold: `clear_force_change` on the
  changePIN path (a wider `MAX_MIN_PIN_RPIDS` record — the panic lands AFTER the new
  PIN is committed, so no status word reaches the host; the record is now left whole
  rather than written back shortened, which is what a clamp would have done), and
  the type-1 enterprise-attestation allowlist (a wider `MAX_EA_RPIDS` list — clamped,
  because a shorter allowlist only ever declines). `u2f.rs` already clamped this
  record and its comment names the class; three siblings were missed. Every
  `Fs::read`-then-slice site in the tree was re-swept: 15 sites, 12 already clamped.

- **One faulted probe replayed the credential-store tag, and a platform holding the
  replayed value kept a stale cache.** `encCredStoreState` (getInfo `0x1E`) is a
  128-bit tag a platform compares for equality to decide whether to re-enumerate
  its discoverable credentials. `cred_store_state` read `EF_CRED_STATE` with
  `Fs::read`, whose `None` covers "never written" and "the flash could not serve
  it" alike, and the absent arm is the ZERO tag.

  Zero is right for the first and a replay for the second, because it is not a
  neutral value: it is exactly what a fresh (or just-reset) device publishes, so a
  platform can be holding it. `bump_cred_store_state` reads that tag, adds one and
  writes the result — so one faulted probe wrote `1` over the live value and
  started the sequence again from a prefix already served. Measured with three
  credential-set changes on the record: tag `3`, one fault, tag `1`.

  Refused now, not clamped. The bump deliberately runs *before* the write it
  describes, so its `Err` aborts the store change too and the tag never falls
  behind what it describes — all four callers already carried the error arm. The
  publishing half is the same probe seen from the platform's side, and it takes the
  other available direction: `seed::enc_cred_store_state` omits the optional member
  rather than publishing a zero, because an absent member equals no tag any
  platform holds, so it re-enumerates. Over-reporting a change costs one walk;
  under-reporting costs correctness.

- **One faulted probe reported the PIN-readable management-key escrow revoked over
  the host's own new key.** PIV `SET MANAGEMENT KEY` revokes the escrow last —
  `mgm_clear_protected` clears the ADMIN-DATA `0x02` flag after the new key is
  sealed, so a torn write cannot strand a PRINTED-only owner. Both of its
  `EF_PIVMAN_DATA` probes read with `Fs::read`, whose `None` covers "no ADMIN DATA
  record" and "the flash could not serve it" alike, and the absent arm is `Ok(())`
  — nothing to revoke.

  The flag is what makes `GET DATA` PRINTED synthesize the management key from the
  sealed `0x9B` slot, and that slot now holds the key the *host* just chose. Both
  probes measured on a `ProbeStuck` medium: `9000`, the flag still `0x02`, and
  PRINTED handing the new key back to the PIN. A persistent fault stops at the
  first probe, so the second needs `stick_after(EF_PIVMAN_DATA, 1)` to be reached
  at all — it collapses the same way. The status word is the whole repair here:
  the key-then-flag ordering means a refused revocation legitimately leaves the
  flag standing, so what may not happen is reporting it as done. `MEMORY_FAILURE`
  now, from both probes.

  Same probe, second site: `PUT DATA` PRINTED refuses ordinary printed information
  while the escrow is live, because `GET DATA` answers with the synthesized key and
  the stored object could never be read back. That refusal is a match guard, so the
  collapsed answer made it a branch that never runs — the write fell through to the
  generic object arm, was persisted, and was acknowledged `9000`. Stored and
  hidden, the one outcome the arm exists to avoid.

  The collapsing `mgm_is_protected` stays at its third caller, `GET DATA` PRINTED,
  where an unreadable record costs the `6A82` an absent object already answers —
  and where the opposite direction is the one that must not happen: a `true` over
  no escrow would synthesize the *live* management key for the PIN.

- **One faulted probe waived a pending forced PIN change and issued the token it
  exists to withhold.** While `EF_MINPINLEN[1]` is set, a correct PIN buys no
  pinUvAuthToken until changePIN lifts the flag (CTAP 2.1 §6.5.5.7.1;
  ClientPin2-GetPinToken F-5 asserts it). `force_change_pending` read the flag with
  `Fs::read`, and all three of its callers spend `false` to let something *through*
  — a token issued, a changePIN allowed to reuse the old value.

  Control leg: the correct PIN answers `PIN_INVALID` while the flag stands and no
  token is minted. One faulted probe on the same command and the host gets a live
  `mc|ga` token. Reads as PENDING now, the same fail-closed direction and the same
  reasoning as `pin_is_set` five functions below it.

- **One faulted probe reset every OpenPGP slot's key-origin claim to imported.**
  `origin::mark` rewrites the whole `EF_KEY_ORIGIN` record to change one slot, so it
  reads the others first — and it read with `Fs::read` and *discarded* the result.
  For a short record from an older build that is right: `of` reads an uncovered slot
  as imported anyway. A failed read is not that. The buffer stays zeroed and is
  written straight back, so the other slots lose the on-card-generation claim
  §4.4.3.8 exists to make, which reaches the host through DO `0xDE`.

  Driven through the real IMPORT with two slots marked generated: one faulted probe
  and both read back **imported (2, 2 where 1, 1 was owed)**, permanently. It refuses
  now — `mark`'s two callers already weigh its `Result` opposite ways on purpose, so
  the IMPORT stores no key over a record it could not carry forward and the GENERATE
  keeps ignoring it, which only under-claims.

- **One faulted probe minted a new device-certificate key over the live one and
  persisted it, unauthenticated, retiring every certificate the old key issued.**
  `rsk-rescue`'s `load_or_generate` mints and persists a fresh secp256k1 key when
  `EF_DEVCERT_KEY` reads absent — the documented first use. It probed with
  `fs.read_key`, whose `None` covers both that and a read the flash could not serve.
  `KEYDEV_SIGN P1=0x02` (read the device public key) takes no user presence at all,
  so a USB host on its own reached it. This is the `ensure_seed` shape the original
  sweep converted, in a crate that diff never opened.

  Driven through the real APDU: the device's public key, a signature made under it
  that verifies (the control), then one faulted probe on the same command. All four
  assertions fall — the sealed record is replaced, the device advertises a different
  65-byte key, the old signature no longer verifies against it, and the command
  answers `9000`. The last leg is what makes it a loss rather than a hiccup: **after
  the medium recovers the device still answers the new key**, because the mint was
  persisted.

  Only a CONFIRMED absence mints now. Both reachable spellings of that absence are
  driven and still work — a boot walk that decided the FID space (so the probe never
  reaches the backend) and one a read fault cut short (so the absence goes to the
  backend and comes back as a real `Ok(None)`). That arm is proven non-vacuous by
  its own mutant: stopping the mint from persisting turns it red.

- **One faulted probe made OpenPGP GENERATE mint and seal RSA-2048 where the owner
  had configured Ed25519.** `read_advertised_algo` resolves the slot's algorithm
  attribute and GENERATE mints whatever it says. Its `_` arm covered three states at
  once: a slot with no attribute configured (which must resolve to `DEFAULT_ALGO` —
  the documented path for a slot the owner never set), an empty record, and a probe
  the flash could not answer.

  All three are asserted at the function, because only there can "absent" and
  "faulted" be told apart: absent → `DEFAULT_ALGO`, empty → `DEFAULT_ALGO`,
  configured → itself, faulted → `Ok([1, 8, 0, 0, 32, 0])`, which is RSA-2048.
  Driven through the real GENERATE afterwards: the control leg with Ed25519
  configured mints a 32-byte point, and one faulted probe stores a **270-byte
  `EF_PB_SIG` with inner tag `0x81`** — an RSA modulus — at `9000`.

  Fixed by splitting the arm three ways rather than by choosing a default: `Ok(_)`
  keeps the documented absent/empty path exactly as it was, and only `Err` is new,
  refusing with `Sw::MEMORY_FAILURE`. A GENERATE that cannot read the algorithm it
  must honour has to refuse, because what it would otherwise do is seal a weaker key
  the owner never asked for.

- **One faulted probe minted a fresh card-level AES key over the OpenPGP owner's,
  and the card then deciphered every old ciphertext to garbage at `9000`.**
  `keygen_tail` seeds `D5` when the DEC slot is generated and `EF_AES_KEY` is empty,
  and it asked with `fs.has_key` — the same `false` for an absent slot and for one
  the flash could not read. `D5` is card-level (§7.2.12 gives PSO:ENCIPHER no key
  reference at all), so the blast radius is everything ever enciphered under it.

  Driven end to end: a `PUT DATA D5` key, a plaintext enciphered under it, then a
  DEC GENERATE. Control leg first — a healthy medium leaves the standing key
  byte-identical, which is the documented "the seed never **replaces** a standing
  key". Then one faulted probe: the sealed record is replaced (60 bytes for 60,
  entirely different), the GENERATE answers `9000`, and PSO:DECIPHER of the old
  ciphertext answers `9000` with the wrong plaintext — a success status over
  corruption, not an error.

  Fixed by fail-closed skip, not refusal. The private key is already committed when
  this runs, so refusing would fail a GENERATE whose key is in the slot; the seed is
  documented non-fatal and the next DEC generate makes it again. Skipping costs a
  card with no `D5` until then; overwriting costs every message.

- **One faulted probe took the minPINLength floor down permanently, and a second
  copy of the same read stored a PIN underneath it.** CTAP 2.1 §6.11 makes
  minPINLength monotonic — setMinPINLength may only raise it, and nothing short of
  a factory reset puts a lowered floor back. Both readers of `EF_MINPINLEN[0]` used
  the collapsing `Fs::read`, whose `None` covers "no policy set" and "the flash
  could not serve it" alike, and the collapsed arm resolves to the build's
  `MIN_PIN_LENGTH` — below any floor an owner would have configured.

  `config::current_min_pin` is what the monotonic guard compares against. With an
  enterprise floor of 16 stored and the control leg confirming `setMinPINLength(8)`
  is refused on a healthy medium, one faulted probe and the record reads **8**.
  `clientpin::min_pin_length` is the enforcement twin, and it is reached by two
  different doors: with the same floor of 16 in place, one faulted probe and a
  **six-code-point PIN is stored** — by the panel's `store_local_pin` and by the
  host setPIN, both answering success.

  Both are fixed by refusing, because both write. `current_min_pin` is fallible and
  `set_min_pin_length` answers `CtapError::Other`; a new private
  `clientpin::try_min_pin_length` serves the two sites that ENFORCE the floor
  (`store_new_pin` → `CtapError::Other`, `store_local_pin` → `SetPinError::Storage`,
  not `TooShort`, since the floor is exactly what could not be read and naming a
  number would be an invention). The collapsing `min_pin_length` stays for the
  sites that only *show* the floor or size a pad buffer from it — `builtin_uv`'s
  entry length and the display's dot count — where a lowered value costs a wasted
  entry the store path then refuses, not a stored PIN. Each copy is falsified by
  its own test and by neither the other's.

- **One faulted probe turned a one-shot OpenPGP PIN entry into an unlimited
  signing session.** OpenPGP 3.4 §7.2.10: DO `C4`'s first byte at `0x00` is "PW1
  valid for ONE PSO:CDS", and `inc_sig_count` is the only place that spends it. It
  read the flag with `Fs::read`, whose `None` covers both "no PW status stored" and
  "the flash could not serve it" — and that arm leaves PW1 STANDING, so whoever is
  on the wire after the owner's one legitimate signature gets every further
  signature for free.

  Driven with the fault aimed at `EF_PW_PRIV` alone, because the statement
  immediately below reads `EF_SIG_COUNT` and already refuses — a whole-backend
  fault would be caught by that neighbour and prove nothing about this line.
  Control leg first: one PIN entry, one signature, `EF_SIG_COUNT` at 1 and the
  second PSO:CDS `6982`. Same card, same one PIN entry, one transient faulted probe
  as the first signature spends it: a **second 64-byte ECDSA signature** comes back
  `9000`, and the card's own counter reads **3 where it owed 2**.

  Fixed by failing closed — a probe that could not be completed spends PW1 —
  rather than by refusing. The signature this call has already produced was
  authorised; only the next one is in question, and refusing would discard a
  finished private-key operation (the post-crypto DoS this same function's
  `EF_SIG_COUNT` neighbour is commented for). The genuinely-absent arm is left
  exactly as it was: only `Err` is new.

- **One faulted probe let the trusted display overwrite a populated PIV retired
  slot — the sealed key and the certificate — with no management-key auth behind
  it.** `retired_slot_is_free` is the *whole* authorisation for the panel's
  Generate key: physical presence at the screen is the only other gate, and
  docs/guides/display.md states the action is "restricted to empty slots
  (add-only, never overwrite)". Both of its probes were the collapsing
  `has_key` / `has_data`, which answer the same `false` for an absent record and
  for one the flash could not read.

  Driven on a `ProbeStuck` medium, one row per probe aimed at its OWN fid (a fault
  on the key shadows the cert probe behind it). Slot 0x82 holding a key and no
  certificate — the state a host GENERATE leaves, and the state an on-device
  X25519 generate leaves, since X25519 cannot self-sign: one faulted `key_fid(0x82)`
  read and the stored 64-byte sealed key is replaced by a fresh 61-byte sealed
  P-256 key, `Ok(())` returned. Slot 0x83 holding a certificate and no key: one
  faulted cert read and the stored certificate goes **5 bytes → 476**, again
  `Ok(())`. Both destroy material that only a management-key-authenticated host
  command is supposed to be able to touch.

  It is two copies, not one. `rsk-piv`'s `info::next_free_retired` inlines the same
  predicate to pick the target slot, and it offered the occupied slot in both rows.
  The two are fixed differently because they answer different questions.
  `retired_slot_is_free` **refuses** — `Sw::MEMORY_FAILURE` — because a generate
  that cannot confirm the slot empty must not write; `next_free_retired`
  **fail-closed defaults to "not free"** and moves to the next slot, because a
  probe that failed is not a slot known free and skipping it costs one candidate
  out of twenty rather than a key. Falsified by reverting each guard alone: the
  keygen predicate's revert fails on the data assertion ("a faulted probe let the
  panel generate destroy the sealed key"), the picker's revert fails on the picker
  assertion with the data assertion still passing — so neither is held by the
  other.

- **One faulted probe erased the clone-detection evidence for every credential on
  the key, and signed an assertion with the fabricated value.** signCount is the
  only clone signal a relying party gets (WebAuthn L3 §6.1.1), and all three of its
  readers spelled a failed flash read as *not provisioned*: `get_sign_counter`
  answered **0**, `cred_sign_counter` answered *unmaterialized* — which the caller
  seeds from the global counter — and `set_cred_sign_counter` merged the new value
  into a **zero-filled** buffer truncated to the target slot.

  Measured end to end over two resident credentials, A at three assertions and B at
  one: one faulted `EF_CRED_CTR` read and the host receives `Ok` with signCount
  **0** for a credential that had just reported 3, the packed file goes **8 bytes →
  4** holding `[1,0,0,0]`, B's next assertion reports **0** where it owed 2 and A's
  reports 1 where it owed 5. Both credentials lost their counters and B was never
  named by the request. At the writer alone, three slots held at 11/22/33: one
  faulted read truncates **12 bytes → 8**, zeroes slot 0, drops slot 2 — and returns
  `Ok(())`. On the global counter `bump_sign_counter` writes **1** over a live 77,
  and U2F AUTHENTICATE signs and returns the fabricated 0.

  The class was re-derived mechanically rather than read off the diff, and the file
  says so itself: `ensure_seed`'s converted guard fifty lines above reads "a faulted
  probe here would roll the signature counter back to zero" — the code that actually
  rolls it back was left alone.

  Fixed by keeping the states apart instead of choosing a default.
  `cred_sign_counter` answers `Result<Option<u32>>` — `Err` a fault, `Ok(None)` an
  unmaterialized slot (absent, short, or a real 0 in a gap a higher write
  zero-extended over), `Ok(Some)` a live counter — and `report_sign_counter` owns
  the one place the per-credential and global reads combine. `get_sign_counter` is
  gone rather than kept as a collapsing sibling: all four of its callers sign or
  persist the value, so the sibling would have had no user but the tests, and unlike
  `backup_sealed` / `device_pin_is_set` there is no conservative `u32` to collapse
  to. getAssertion, getNextAssertion and U2F AUTHENTICATE now refuse
  (`CTAP2_ERR_OTHER` / `6F00`) rather than sign a number the medium never served.

  Two of the guards sat behind a neighbour: with the fault STUCK, the write-back
  three statements later refuses on the read guard's behalf, so both call-site
  `?`s could be reverted with the suite green. `stick_once` reaches them — the
  medium recovers before the write-back — and the reversion then rewrites the
  counter from the fabricated value: slot 0 `[2,0,0,0]` → `[1,0,0,0]`.

- **One faulted probe at an unauthenticated SELECT handed a host every OATH secret
  on the card.** `select` derives the session's lock state from a single probe —
  `validated = !fs.has_key(EF_OATH_CODE)` — and `validated` is the access-code gate
  on PUT, DELETE, SET CODE, RESET, RENAME, LIST, CALCULATE and CALCULATE ALL. SELECT
  takes no authentication and the host drives it, so a probe read as "no code set"
  unlocked the whole credential store for the session with nothing presented.
  Measured on a code-locked applet: control `LIST` → `6982`, one faulted
  `EF_OATH_CODE` probe → `9000` and the credential list on the wire. It resolves to
  CODE SET now, the direction `lock_engaged` and `pin_is_set` already take.

  Found by re-deriving the class mechanically rather than by reading the diff again
  — the file's OTP-PIN gate 180 lines above had been converted while the applet's
  primary gate had not.

  Its sibling at `cmd_validate` was left collapsing **on purpose**: `select` now
  reads an unprobeable code as set, so `validated` is already false in every state
  that arm can be reached in, and the fallible twin there is bit-identical. A guard
  nothing can falsify is a comment with a type; the reason is recorded at the site.

- **A card whose boot walk hit one transient fault reported every credential slot
  FULL for the rest of the power cycle — a factory reset included.** `Fs::scan`
  latches `scan_truncated`, and `present_slots` answers "occupied" over the whole
  range while it is set, which is the right trade for a walk that decided nothing.
  `factory_wipe` resets the caches that flag describes — `present`, `decided`, the
  dynamic set — but not the flag. Measured after one transient boot-walk fault and
  a successful wipe: `for_each_key` yields nothing (`seen = 0`, the store really is
  empty) while `present_slots` still answers `[true, true, true, true]`, so
  `credential_store` and OATH's `free_slot` refuse on a card that was just reset.
  The doc comment's own defence — "a fresh `Fs` that has not scanned still reports
  free — its store is empty" — is precisely the case it got wrong. The wipe clears
  it now, and it may: the wipe does not return at all without a COMPLETE walk of
  every phase, which is the same evidence `scan` requires.

- **A faulted probe waived the OpenPGP touch gate, and lowered a UIF the card
  documents as unchangeable.** `check_uif` is the touch gate itself — PSO:CDS,
  PSO:DEC and INTERNAL AUTHENTICATE all pass through it — and it decided on a
  `Fs::read` that answers the same `None` for "no UIF configured" and "I could not
  read it". Measured over a declined touch: control `6600`, one faulted
  `EF_UIF_SIG` probe `9000` — the signature made with no confirmation at all. It
  resolves to ON now.

  The second is the guard the reviewer named and did not drive; driven here.
  OpenPGP 3.4 §4.4.3.6: UIF `02` is "permanently enabled … not changeable with PUT
  DATA", clearable only by a factory reset, and its guard read the stored value the
  same collapsing way. Measured with PW3 verified: control
  `CONDITIONS_NOT_SATISFIED`, one faulted probe and the stored value goes `02` →
  `00`, irreversibly short of TERMINATE DF.

  Separately, `formal/README.md` cited `putdata.rs:192-194` twice for "PUT DATA
  `0xC4` is an administrative write gated on PW3". The locked text says that span
  is the **UIF** block; the PW3 gate is `put_pw_status`'s own `!sess.has_pw3` at
  `:244-247`. The citation named code the prose was never about, and only became
  visible because this change rewrote the line it ended on — `citation_gate.py`
  reports a locked line that MOVED, never one edited where it stood.

- **PIV `MOVE KEY` destroyed the certificate at BOTH slots on a faulted probe, and
  answered `9000`.** It reads the source certificate and, finding none, deletes the
  destination's; the source's goes at the end of the move. `Fs::read` answers the
  same `None` for "no certificate" and "I could not read it". Measured: `MOVE 9A ->
  82` with `0xD205` stuck → `sw = 0x9000`, source certificate `None`, destination
  certificate `None` (it was 40 bytes of a known fill). Three more probes in the
  same command took the fallible twin: the metadata head (a faulted `meta_find`
  stranded the moved key with no head, which `GET METADATA` and the PIN/touch gate
  both read), the tail read-back (`has_key`'s collapsed `false` let a failed
  `remove` answer OK over a key that is still live — the shape `Fs::delete` closed
  one layer up), and the source blob itself (`FILE_NOT_FOUND` over a slot the medium
  merely could not read tells the host the slot is EMPTY, and a host that believes
  it fills the slot). `Fs::try_read_key` is the `read_key` twin, keeping the
  `KeyFid` chokepoint.

  The fault medium grew the two capabilities these needed: `ProbeMedium::stick_after`
  lets N reads of a fid through before faulting — a guard standing BEHIND another
  probe of the same record is otherwise unfalsifiable, which is how 18 of the
  previous batch's guards ended up held by nothing — and `refuse_remove` drives a
  failed delete and a faulted read-back on one medium.

- **One faulted flash probe erased the tamper-evident audit trail and left it
  looking freshly initialised.** `journal::load_meta` read `EF_AUDIT_META` with the
  collapsing `Fs::read`, and its absent arm is *genesis* — the state of a journal
  that has never been written. `raw_append` then wrote at slot 0 and `put_meta`
  **persisted** it. Measured: `seq_next` 10 → 1, `start` 0, the head no longer over
  the window, ten entries out of the live window, all of it on flash. The chain's
  whole job is to make that undetectable-loss case impossible.

  The eviction fold was the second half: `raw_append` folded the entry it is about
  to overwrite into the epoch only `if read_slot(..).is_some()`, so a faulted slot
  read at eviction dropped an entry from the chain *without* folding it — and the
  head still verified over the shortened history. Three more readers spelled the
  same thing: `chain_head` (whose result gets SIGNED by `AUDIT_CHECKPOINT`),
  `vendor_read` (the export the host folds against that signature) and
  `fold_and_scrub` (which deletes the slots after committing the fold). All four
  refuse now; the two coalesce paths decline instead, which sends the caller to
  `append`, which refuses. `for_each_event` deliberately keeps the collapse — it
  writes nothing, signs nothing and opens no gate, and its one caller is a display
  screen with no error state to paint; a faulted `EF_AUDIT_META` still renders
  there as an empty log.

- **One faulted flash probe waived the vendor PIN gate and handed out the device
  master seed.** `vendor::pin_gate` is the *only* PIN half of the gate on
  `BACKUP_EXPORT`, `BACKUP_LOAD`, `BACKUP_FINALIZE`, `ATT_IMPORT`, `ATT_CLEAR`,
  `AUDIT_READ`, `AUDIT_CHECKPOINT`, `AUDIT_CONFIG` and `CONFIG_WRITE`, and it
  decided "is a PIN configured" on the collapsing `Fs::has_data`. `VENDOR_MSE` is
  ungated, so the residual barrier was one touch under "Export secret seed?" — and
  none at all on a `no-touch` build. Measured on a PIN-protected card with the MSE
  channel re-handshaked and no token: control `Err(PuatRequired)`, one faulted
  `EF_PIN` probe `Ok(64)` — the 64-byte encrypted seed blob. Both of the gate's
  records took the fallible probe, not just the one that was driven: a display
  build's owner often sets only the **device** PIN, and a faulted `EF_DEVICE_PIN`
  probe waived the gate identically (measured `Ok(64)` with both halves at their
  old spelling).

- **A faulted `EF_BACKUP_SEALED` probe re-opened the export window
  `BACKUP_FINALIZE` had sealed** — irreversible short of a reset that destroys the
  identity it protects. Measured: control after FINALIZE `Err(NotAllowed)`, one
  faulted probe `Ok(64)`. Its second reader is the trusted display, whose Backup
  screen offers the on-device recovery-phrase reveal on `!sealed`; `backup_sealed`
  / `backup_status` resolve to SEALED on a probe the medium could not answer, the
  same direction `lock_engaged` already took. `pin_is_set` and `device_pin_is_set`
  move with them: `local_pin_gate` returns `true` outright when no PIN of that
  scope exists, so the collapsed `false` waived every destructive on-device action
  rather than raising its gate.

- **The comment that scoped a threat-model clause was wrong about the physics,
  and three registry verdicts argued from it.** `crates/rsk-store/src/lib.rs`
  said the walk's early exit is a read fault *"which a NOR power cut never
  produces (a torn write yields deterministic bytes, not a read error)"*. All
  four legs re-derived, and the claim is refuted: `WRITE_SIZE` is **1** on this
  target (embassy-rp `flash.rs:35`, forwarded through `BlockingAsync` and
  `SharedFlash`, and `WORD_SIZE = max(WRITE_SIZE, READ_SIZE) = 1`); the item
  header is **8 bytes** written in **one** `flash.write` call
  (`third_party/sequential-storage/src/item.rs`, `LENGTH = 8`, fields `0..4` /
  `4..6` / `6..8`, and one call at `write`); a cut that leaves the length field
  programmed and the length-CRC erased at `0xFFFF` cannot match, because
  **0 of 65 536** two-byte lengths produce `0xFFFF` — measured exhaustively, and
  not by luck: **8 of them do** before `crc16`'s closing `match crc { 0xFFFF =>
  0xFFFE }`, a clamp whose own doc line is "A crc that never returns 0xFFFF", so
  the guard is load-bearing rather than decorative. `ItemHeader::read_new` then
  answers `Error::Corrupted` after one retry. A torn write is deterministic **and**
  a read error.

  What actually keeps the enumeration honest is that `ItemHeaderIter::traverse`
  advances one word past `Corrupted` on purpose instead of propagating it. The
  comment says that now, and so does its second copy in `crates/rsk-store/src/
  tests.rs` — which no list of consumers had, and which the same wording had been
  retyped into. `docs/threat-model.md`'s clause A keeps its scope and drops the
  false reason; the `rests_on` pin moves with the sentence in the same change, and
  reddens the gate from either side (measured both ways).

  The routing of `SEC-STORE-003/-004/-005` away from `TM-HOST-POWER-CUT` is
  unchanged, but its reason is replaced. It was "a cut cannot produce a read
  fault"; it is now the THREAT — the cut clause is about what a write leaves
  behind and in what order, those three are about a read the medium refused,
  whoever caused it. The open half is named rather than assumed: whether any
  cut-reachable page state makes a per-key `fetch_item` return `Corrupted` is
  unmeasured. Within one boot it cannot — the location cache a cut clears is the
  only path that propagates it — and no board has been asked the rest.

- **One faulted flash probe re-seeded the factory PIN, PUK and management key at
  an unauthenticated PIV `SELECT`.** `Storage::read`/`size` answer the same `None`
  for "no such record" and for "that read failed", and an absent record is how
  this firmware spells *not provisioned yet* and *no gate configured* — so the two
  collapse at the place it costs most. Measured over one faulted `EF_PIN` probe:
  `SELECT` → `9000`, the PIN record replaced byte-for-byte with the `DEFAULT_PIN`
  verifier, `VERIFY` of the owner's PIN → `63C2`, `VERIFY 123456` → `9000`. It is
  a class, not a site, and PIV was not the worst of it: FIDO's `ensure_seed` ran
  the same guard over `EF_KEY_DEV` at **boot**, so one faulted probe minted a new
  device seed over the live one and every credential derived from it — no host
  command involved. Also measured re-seeded: OpenPGP's `PW1` verifier (`123456`
  then verifies, and the owner's PW1 does not), the PIV management key, the FIDO
  signature counter and large-blob array. And the gates: OATH's OTP-PIN check
  handed the stored passwords to an unauthenticated host, `clientPin`'s `setPIN`
  let one install a PIN over the owner's, `alwaysUv` resolved to the compile
  default, and the makeCredential and largeBlobs UV gates both dropped to user
  presence.

  `Fs` published no way to tell an absence from a failed read — the distinction
  existed inside the crate (`Storage::last_error`, used to keep the present-cache
  honest) and stopped at its edge, so "check whether the read faulted" was not
  expressible at a call site. It is now: `Fs::try_read`, `try_has_data`,
  `try_has_key` and `try_meta_find` answer `Err` for a probe the backend could not
  complete and `Ok` only for one it answered, and the collapsing `read`/`has_data`
  /`meta_find` are defined in terms of them, so the collapse is one visible line
  per method instead of a property of the type. **50 guards in 25 functions across
  four crates** take the fallible probe — every one whose *absent* arm overwrites
  configured material or opens a gate. The recipe, because two of those three
  numbers shipped wrong the first time: a guard is a `try_*` call **site** (one per
  line, tests, Kani, assurance shims and `rsk-fs` itself excluded), minus the three
  module-local wrapper bodies (`piv::files::provisioned`,
  `openpgp::init::provisioned` and `read_file`), plus every call of those wrappers —
  32 − 3 + 21. A function counts once if it holds any guard, which is the reading
  that makes the sentence say what it looks like it says; the wrapper bodies are not
  among them. `17` matched no reading of the tree it described, and `five` counted
  `rsk-fs` — which publishes the probes and holds no guard. `docs/limitations.md`
  named four crates all along, so the two copies disagreed. Guards whose absent arm only reports a status field, repeats an
  idempotent repair, or already fails the command closed keep `has_data` — the
  `EF_MINPINLEN` floor among them, where the weaker reading costs the OWNER a
  shorter PIN of their own choosing and gives an attacker nothing. `try_read`'s
  documentation names the rule rather than the sites.

- **A boot scan a read fault cut short made every credential slot it never
  reached read FREE, and `makeCredential` writes a free slot without re-reading
  it.** `Fs::present_slots` answered from the raw present bit, which is clear both
  for a slot the walk proved empty and for one the walk never got to — measured,
  a truncated scan gave `[false, false, false, false]` over a range where
  `Fs::read` still returned the live record. The two are the same class as the
  faulted probe above, one call out: `for_each_key`'s completeness flag was
  already captured by `scan` and then used for nothing but the decided-bitmap
  fill. `scan` remembers it now, and a range it could not enumerate reports
  occupied — `credential_store` answers `KEY_STORE_FULL` instead of minting over a
  live passkey, and every other reader re-`read`s the slot it was told about and
  skips the empty ones. A scan that COMPLETED is bit-for-bit the old answer, and a
  fresh `Fs` that has not scanned still reports free.

- **The `rsa` crate is out of the tree, and with it RUSTSEC-2023-0071.** The
  Marvin timing side channel has **no fixed release** — OSV gives
  `introduced: 0.0.0-0` with no `fixed` event, so every version is affected —
  and the crate sat inside an authenticator's trust base behind a documented
  carve-out. The two paths that still reached it are `rsk-rsa`'s own now: PIV
  certificate signing at key generation, and PSO:DECIPHER for a legacy `P‖Q` key
  whose prime width is not a multiple of 32 (which the asm CRT core cannot take).
  Both run the same base-blinded, Bellcore-fault-checked private operation the
  rest of the tree already used, and both end in the same constant-time unpad.

  **The carve-out is deleted, not relocated.** `cargo audit` runs with no
  `--ignore` on either lockfile, `deny.toml`'s `[advisories].ignore` carries no
  vulnerability at all (only three "unmaintained" entries), and the `rsa`
  exemption is gone from `supply-chain/config.toml`.

  No wire byte moves: every status word is what it was, including PSO:DECIPHER's
  deliberate `EXEC_ERROR` on a malformed block and `pso.rs`'s `WRONG_LENGTH`
  fallback onto the legacy arm. The sealed `P‖Q‖dP‖dQ‖qInv` blob is byte-identical
  — `dP`, `dQ` and `qInv` do not depend on which totient `d` was derived from —
  so an already-provisioned key keeps signing and deciphering across the upgrade.

  **What this does not close is the padding oracle.** PSO:DECIPHER still tells a
  malformed block from a well-formed one by response code, because the command's
  specification requires it to either return a session key or report failure.
  Removing the dependency changes nothing about that; see
  [limitations](docs/limitations.md).

  The tests lost their oracle with the crate, so they gained a better one:
  `crates/rsk-rsa/src/vectors.rs` holds OpenSSL 3.6.2 known-answer vectors
  (regenerate with `scripts/rsa_vectors.py`), and every signature the card
  produces is now compared to OpenSSL's byte for byte rather than merely
  round-tripped against our own verifier.

- **PSO:DECIPHER no longer runs its private operation on the `rsa` crate.** It
  takes the same blinded, Bellcore-fault-checked asm CRT core as PSO:CDS
  (`rsk_rsa::sign_crt`) and unpads PKCS#1 v1.5 with the applet's own
  constant-time `pkcs1v15`, so RUSTSEC-2023-0071 — which has no fixed release —
  no longer sits under the one command that decrypts a ciphertext the host chose.
  The wire surface does not move with the implementation: a malformed block still
  answers `EXEC_ERROR`, and a test pins the new path's status word to the old
  one's. One arm still reaches the crate on purpose — a legacy `P‖Q` key whose
  prime width is not a 32-multiple, which no current firmware can store and which
  cannot sign either, would otherwise lose the ability to decrypt its own
  archived messages — and the entry above has since taken that arm too, so the
  crate is gone from the tree entirely.

  This does not close the padding oracle, and nothing can: DECIPHER must either
  return a session key or report failure, so the status word itself separates
  well-formed from malformed. What the constant-time unpad buys is that the
  *reason* for a refusal does not leak on top of the refusal.

- **The `rsa` crate's RUSTSEC-2023-0071 carve-out now describes the code that
  actually exists.** Its justification still claimed the crate was "the OpenPGP
  RSA backend" and that the `hazmat` feature was there because PIV GENERAL
  AUTHENTICATE needed the raw private op. Both stopped being true when signing
  moved onto `rsk_rsa`: three of the five private-RSA paths never enter the
  crate at all, and `rsa::hazmat` is referenced nowhere in the tree. The feature
  is dropped — a smaller API surface for a dependency inside an authenticator's
  trust base — and the two paths that do reach the crate (both since taken over
  by `rsk-rsa`, see above) are named in `deny.toml` and in
  [limitations](docs/limitations.md), together with the
  residual risk on PSO:DECIPHER. No behaviour change, measured: no loadable
  section moves or changes size and every symbol keeps its size — the only image
  delta is mangled-name hashes and a reordering of three anonymous constants,
  which is what feeding a different feature set to `-C metadata` looks like.

### Internal

- **The TLC runner no longer loses a row to the second the row before it
  started in.** TLC names its metadir after the current second, and a run refuted
  in its initial state exits without removing that directory, so the next
  configuration — started straight after a sub-second mutant — found the name
  taken and refused to run at all. A whole `safety` tier lost five `SeamSolo_Bug*`
  rows that way, each `RED:` with no reason and a `!!`, and its record took a
  second 2.5-hour run through a wrapper that cleared the leftover by hand.
  `run-tlc.sh` makes one fresh root under `formal/states/` per invocation, hands
  every row a `-metadir` of its own inside it, removes the root from an EXIT trap,
  and stops with exit 2 when it cannot make one; `TLC_STATES` moves that root the
  way `TLC_OUT` moves the logs, so the merge gate's cases no longer write into
  `formal/`. `scripts/test_run_tlc.py` reproduces the refusal — between two runs
  and between the rows of one tier — with a stand-in that treats the metadir the
  way the pinned jar (TLC 2.19) was measured to: named after the second inside
  whatever root it is handed, refused when taken, left behind by an initial-state
  refutation. Each of the four parts is cut out of the runner once to watch its
  own case fall. `formal/run-tlc.sh` is a model input, so the recorded tiers are
  stale until the next re-run.

- **The slack TLC floors are a third of what they bound again.** The grant record
  (`c92bfb3`) grew the shipped configuration from 77 563 872 to 108 618 956
  distinct states and left the large safety floors at about a quarter of what
  they bound — the drift `formal/floors.txt` names as the one failure nothing
  reports. Three more had drifted earlier and on their own: `Store` sat at 24.7%
  since its count grew from 272 to 364 and only its comment followed (`e7bf392`),
  and `Liveness` and `Fairness`, set at about a quarter of 7 903 336 and never at
  a third, were at 13.8%. Each is now a third of the count `formal/runs.toml`
  recorded at `70e104a`: `Shipped` and `Historical_E76` 25 854 624 -> 36 206 318,
  `AlwaysUv` 7 800 000 -> 10 483 724, `PermWide` 7 000 000 -> 9 728 632,
  `ForceChange` 4 000 000 -> 4 951 108, `Liveness` and `Fairness` 2 000 000 ->
  4 838 141, and `Store` 90 -> 121. `TokenRefinement` sits above a third (54%),
  and `Liveness_Full` is in no tier and has no recorded count, so both keep
  theirs. `floors.txt` is a model input as well, so this lands with the runner
  fix and one re-run records both.

- **Two gates in two checkouts no longer share one pytest base.** `check.sh`
  pinned its three pytest rows under `~/.cache/rs-key/pytest`, one base per user,
  and pytest removes a pinned base when a session starts. Two sessions ran the
  full gate in two checkouts of this repository at once, both gate rows pinned to
  `~/.cache/rs-key/pytest/gate`, where the later start removes the earlier run's
  `tmp_path` tree under it — a row that can go red for nothing in the code. The
  base is keyed by the checkout now, a short hash of `git rev-parse
  --show-toplevel` under the same cache root. A base still holds one run per row;
  what changes is that every checkout path gets its own, so a deleted worktree
  leaves its base (about a megabyte) with nothing to sweep it.
  `scripts/test_gate_scripts.py` evaluates `check.sh`'s own assignment, under its
  own `set` line, in a repository and a worktree of it; holds every gate pytest
  row to `$GATE_PYTEST_TMP/`; runs two concurrent pytest sessions pinned where
  each checkout's gate row would pin them, the first holding a file while the
  second starts; and requires a gate with no git to stop rather than fall back to
  the shared base. Eight mutations of `check.sh` — per user, by basename, by the
  common git dir, inside the checkout, ignoring `XDG_CACHE_HOME`, a row spelling
  its own path, a second assignment below the first, `pipefail` dropped — each
  redden one to four of those cases for their own reason, while the mutation table
  itself falls for none of them; the per-user line, driven through the `pytest
  (gate scripts)` row, fails the same three cases it fails alone.

- **A PIN-derived record stays on the pre-burn root until its own reference is
  presented**, and that is now written down instead of assumed away. Every record
  sealed under the key base alone moves to the fused root at a boot pass; re-keying
  a PIN-derived one needs the secret, so it happens at that reference's next
  VERIFY. Ordinary use presents PW1, PW3 gates the admin surface only, and an
  OpenPGP resetting code may never be presented at all — and until one is, a flash
  dump plus the public chip serial opens the DEK copy behind it, which is every
  OpenPGP private key and the AES key with them. A PW3 still on its published
  default needs no search at all, and PIV's PUK has the same shape without a DEK
  behind it. The card cannot retire what it cannot recognise: a verifier is an
  opaque hash, so a record written before the burn and one written after are
  indistinguishable. Registered as `PLAT-THREAT-002` with the three routes out —
  the operator presenting the references, an arm byte in the verifier record, or
  the DEK copies under an outer device-rooted seal a boot pass can move — named in
  `docs/limitations.md` and in the threat model's own OTP clause, with
  `docs/production.md` corrected: the burn migrates what it can reach, and the
  operator is told to verify PW3 and re-set the resetting code afterwards. A host
  test drives both halves: the code and its DEK copy are still chip-serial-rooted
  after the burn boot and a PW1 verify, and the RESET RETRY that presents the code
  is what moves it.

- **The roster that refuses an unowned writer of the grant record could not see
  one that goes through a free function.** `scripts/token_refinement_gate.py`
  recognised a write by its receiver — `fs.put_key(fid, ..)` — and reached one hop
  further, to a caller that hands a named fid to such a helper. The boot re-seal
  is three hops (`migrate_keydev_boot` → `migrate_slot` → `put_sealed32` →
  `fs.put_key`) and only the last one has a receiver, so `EF_PAUTHTOKEN` gained a
  production writer the registry owned nothing for and the row stayed green.
  Measured, not argued: a `[[persistent_writer]]` row for `migrate_slot` answered
  `stale owner` — the gate did not consider the site a writer at all. The
  hand-off clause now follows a fid parameter as far as the chain goes, in both
  directions: a helper that hands its own fid on becomes a writer, and a named key
  that reaches one reaches everything it hands the fid to. Which parameters count
  is derived from the sites that already write a handed fid (`KeyFid`, `u16`
  today) rather than named here. Both new owners are registered as `Noop`: the
  re-seal rewrites the record in place, so nothing tier A reads moves. The gate's
  own summary line moves with the roster, and eleven evidence bundles transcribe
  it, so `persistent=12/4` becomes `14/5` in each. Seven mutants of the new clause
  are each killed by a named case of `scripts/test_token_refinement_gate.py`,
  which is where this gate keeps its mutation table.

- **The trace replay CI runs against the emulator went red on the grant `0x09CB`
  mints at provisioning.** Since then `ensure_seed` has written the persistent
  grant record beside the seed, so a factory key holds `EF_PAUTHTOKEN` with no PIN
  behind it. `RSKeySecurityState` still began without one, and `TraceSecurity`
  failed `R4aRawRefinesB` on its initial state. Local `check.sh` replays only the
  committed recording, which predated the change, so it stayed green.
  The model now keeps the record apart from the grant a platform was handed.
  `gate.ppuatRec` is what the recording, the Rust alpha, γ and the reset sweep
  read. `gate.ppuat` is what the two invariants about a held grant read:
  `NoAccessibleSecretWithoutGate`'s structural clause and
  `NoTokenAfterInvalidation`. So `gate.ppuat => pin.set` and the
  `BugPpuatIsAGate` kill stand unchanged. A boot may mint the record or not,
  because `ensure_seed` skips the mint on a soft-locked key; the trace mapper pins
  the mint it predicts. Tier A gains `ProvisionGrant`, the record appearing with no
  PIN at a boot, a finished reset or a backup load, and the generated Rust table
  grows to 12 operations and 1 039 edges. A's `persistentGrant` is therefore the
  record and not a holder of it, which `docs/authorization-slice.md` now lists
  among what A does not say.
  The emulator had its own copy of the gap: its replug and warm reboot ran none of
  `main.rs`'s boot block, so a grant a setPIN revoked never came back there as it
  does on a board. Both now run it, and `every_boot_runs_the_boot_block` fails
  on the old device loop. `formal/traces/security-phase4.jsonl` is re-recorded:
  75 steps, the extra one being the reset sweeping that record. Every
  `TraceSecurity*`, `TokenGate*` and `TokenRefinement*` verdict held.

- **The seam mutants moved the model, and every published count was of a state
  space that had gone.** Five applet-seam mutants and a moved `gen-configs.sh`
  left ten configurations the safety tier lists in no recorded run at all, and 43
  of the tier's inputs changed since the commit the last run was recorded
  against — so `published run-counts`, a `check.sh` row, had been red on a state
  nothing could have merged through CI. Both tiers re-run on the machine the last
  record was taken on, at the same default `WORKERS=2`: safety **5994 s over 224
  configurations**, liveness **2116 s over 4**, **228 of 228 observed**, no row
  short of its floor. It reconciles against the last record rather than replacing
  it — 25 GREEN and 189 RED become 25 and 199 with the ten new mutants, all RED,
  and no other verdict moved. Where the model did not change the state space is
  byte-identical (`Shipped.cfg` at 986 836 197 / 77 563 872 / depth 58, and
  `AlwaysUv`, `PermWide`, `ForceChange`, `Fairness` likewise), while the seam
  mutants' spaces did move — `Historical_E77` 1 646 545 → 1 725 880 states. That
  difference is the point: the stale record was not merely old, it was wrong
  about the numbers it published.

- **A carve-out no code path can reach sent the card two commands the reference
  device never gets.** The vendored OpenPGP suite follows `PUT DATA F9` with
  `CHANGE REFERENCE DATA` unless the card moves the references itself, and picks
  `81 01 00` over an empty body on the same condition — `is_gnuk` and
  `is_yubikey`. Neither is ever assigned `True` anywhere in the vendored tree,
  so both carve-outs are unreachable and the suite fails against a real YubiKey
  exactly as it fails here. Measured on one: a YubiKey 5.7.4 answers `9000` to
  `PUT DATA F9` with the suite's own `KDF_FULL`, `6982` to the CHANGE carrying the
  raw old password — PW1 retries 3 → 2, so the try is spent — `9000` to `VERIFY
  81` with the DO's own hash, and `6A80` to an empty body. RS-Key answers the same
  on all three, so this is a harness defect and is fixed as one: a
  `kdf_moves_references` flag carries the one thing those two were saying about
  KDF, and `is_yubikey` is left alone because it also gates the Le on GET DATA,
  `skip_tag_if_any` and the private-key template. Driven both ways against a
  recording reader — flag off still emits the two CHANGEs, flag on emits none.

- **The recording apparatus had no finger.** `tests/*.py` reach the device over
  CTAPHID and nothing else, so no suite could answer a prompt the trusted display
  puts up — which is why the formal replay's recording carries `builtin_uv` false
  in every event, and §6.1.2 step 6.3's built-in-UV upgrade is a boundary
  `scripts/security_trace.py` refuses rather than checks. `--taps-port` gives the
  pad a socket: the `--taps` contact grammar one line at a time, plus a control's
  NAME (`key 7`, `onboard skip`, `allow,800`) resolved through the panel's own hit
  test, so a control that moves takes its name with it where a coordinate in a
  Python file would not. The channel is what synchronises — a bound of one, the
  same the crate's display tests use — so the `ok` answering a line means the pad
  has taken the contact before it, and a suite can keep the finger in step with
  the commands it sends. `--taps` stays fire-and-forget, and the two are refused
  together: one is a queue and the other a rendezvous, so a file's contacts would
  race the socket's. The consumer is the next change; this one is the mechanism,
  its vocabulary and their test.

- **The store model could not judge a delete the medium had refused.**
  `RSKeyStore!Delete` carried one disjunct — the power cut — so the faulted
  metadata drop was a transition nothing stated, and the sweep that walks it
  armed its injector for `MetaAdd` and `MetaDelete` alone. It has the second
  disjunct now, and a second enumeration clause to go with it: `NoSilentOrphan`
  (SEC-STORE-006). The split is the point. An orphaned record IS a state the
  shipped tree can be in — `Fs::delete` removes the value even when EF_META
  cannot be read — so `NoOrphanedMetadata` keeps every arm whose drop landed, and
  the new one forbids only answering `Ok` from the arm that could not.
  `BugDeleteHidesFaultedDrop` is its mutant, and its code co-mutant is the
  previous entry's fix inverted: RED at 61 distinct states in the model, killed in
  the tree by two tests rather than one, because the host sweep arms the fault for
  `Step::Delete` now and counts the times it met a record standing over a value it
  had removed. The clean arm stays the RAM sweeps' — an injector armed for every
  delete would leave it untested, which is the shape a review already paid for
  once. Safety tier: 186 rows, no mismatches.

- **`Fs::delete` answered `Ok(())` for a delete whose metadata drop had failed**,
  and the value went anyway — over a medium whose EF_META read faults once, that
  is a value gone with its record still standing, which is the 0x077C databug's
  end state reached with no power cut in it. Reachable on hardware:
  `rsk-store`'s `read`/`size` set `last_err` straight from `sequential-storage`'s
  `fetch_item`. The obvious repair — propagate before removing the value — is the
  wrong one and is not what shipped: EF_META is **one blob shared by every
  applet**, a failed read of it means "cannot tell" rather than "no record", and
  most callers spell this `let _ = fs.delete(…)`, so a single flash fault would
  have stopped every delete on the device, wipes included, while the callers that
  discard the result went on reporting success — an orphaned record traded for a
  secret outliving its erase. The removal stays unconditional and the error is
  **returned**: `Err` now names a state (value gone, record may stand) instead of
  hiding it, and the five callers that check a delete report failure where they
  used to claim success. The heads are minted by `rsk-piv` alone, so the one
  caller that deletes a fid carrying one is PIV's MOVE with `to = 0xFF` — the
  slot delete — and it reads the answer now: the head gets a retry, because one
  EF_META read can fault where the next lands, and the key is read back, because
  a `remove` that failed leaves the source holding a live key. Both directions
  answer `6581` instead of `9000`. bcdDevice 0x0985 → 0x0986. The model's half is
  **not** in this change and is recorded in `docs/store-refinement.md`:
  `RSKeyStore!Delete` still carries no faulted disjunct, so the sweep cannot yet
  judge the shape.

- **Two build flavours were gated by rows that ran four tests between them.**
  `check.sh`'s `test (fips: rsk-fido)`, `test (fips: rsk-piv)` and
  `test (strong-pin)` each passed a bare name to `cargo test`, so the only
  behavioural coverage the shipped `firmware-fips` and `firmware-strong-pin`
  images get was 4, 1 and 4 cases — measured, with 605, 134 and 611 reported as
  "filtered out" on the same line. They run the whole suite now, as
  `test (fido-conformance)` already did: the build for the permutation happens
  either way, so the filter bought seconds and cost each flavour its coverage.
  rsk-fido's fixtures had been swept already; rsk-piv was still red in the same
  shape — six cases provision an RSA-1024 key or a 3DES management key, both of
  which `fips-profile` refuses (SP 800-131A), so each asserted in its *setup* an
  error the build cannot produce. Where the size is a case's fixture the two RSA
  ids swap under that profile (`ALGO_RSA_FIXTURE` / `ALGO_RSA_OTHER` and their
  lengths), so the freshness ladder and the two family-relaxation cases run at
  2048 there and at 1024 everywhere else — a 2048 keygen costs 0.1–0.4 s here,
  where 4096 would put a minute into every run. Where the refused algorithm is
  the case's subject, the case is `cfg`'d out and
  `fips_refuses_3des_mgm_and_rsa1024` carries the profile's half; it gained the
  import arm, which is the second guard on the same rule and had nothing
  asserting it. The default profile does not move (136 rsk-piv cases before and
  after), and the three widened rows were each driven red through a mutation the
  filtered row stayed green on.

- **bcdDevice 0x0984 → 0x0985, no behaviour change.** The security-trace
  recorder's edit in `crates/rsk-device/src/ctap.rs` landed without one. It sits
  under `#[cfg(feature = "security-trace")]`, a feature no firmware flavour
  declares — only `tools/emu` turns it on — so no image differs. The counter
  counts builds rather than behaviour, and `bcd_gate.py` deliberately cannot tell
  a feature nothing ships from one that does, so the tax is paid here rather than
  the guard taught an exemption.

- **The GUI font tables record the stack that rasterised them, and pin the layout
  engine.** The generated header hashed the IBM Plex files, which is half the input:
  FreeType rasterises and Raqm lays out, and either moving rewrites the tables with
  nothing in the diff to say why the gate row went red. Both versions are in the
  header now. The layout engine is pinned rather than defaulted, because Pillow picks
  Raqm when libraqm is present and FreeType's own layout when it is not — measured,
  the two disagree about two advances in the 30 px face (`f` and the middle dot, 10 px
  against 11), so a Pillow built without libraqm would have silently produced
  different tables. It now refuses the run instead. The tables themselves are
  byte-identical: Raqm was already what the committed data was built with.

- **Three lockfiles pinned crate versions their own authors had withdrawn.**
  `cargo audit` reports a yanked version as a warning and exits 0 — the same
  shape that let two unsound advisories sit in `tools/tui` for weeks — so the
  gate was green over `bitcoin_hashes` 0.14.100 and `time` 0.3.48 (tui) and
  `spin` 0.9.8 (root **and** `fuzz/`). Swept as a class rather than by the three
  names that were reported: all **564** distinct (crate, version) pairs across
  the four lockfiles were checked against the crates.io index, and those three
  are the only yanked ones. Now 0.14.101, 0.3.55 and 0.9.9 — four lines per
  lockfile, nothing else moved. Refactor-grade: no behaviour change, and the
  counter moves only because `spin` genuinely reaches the image
  (`spin` → `lazy_static` → `num-bigint-dig` → `rsk-rsa` → `firmware`, confirmed
  with `cargo tree -i --target thumbv8m.main-none-eabihf`) and `bcdDevice`
  counts builds. Worth recording that nothing asked for that bump:
  `scripts/bcd_gate.py`'s `VISIBLE` is `("firmware/", "crates/")`, so a root
  `Cargo.lock` edit that re-pins a dependency compiled into the firmware is
  invisible to it — measured, the row stayed green with the lockfile already
  changed and the counter untouched. `cargo-vet` **did** notice, correctly:
  `spin:0.9.9 missing ["safe-to-deploy"]` stopped the gate at rc 255, because
  0.9.8 was covered by a local exemption rather than an audit, so there was no
  baseline to delta from. The exemption moves to 0.9.9 — the same "unreviewed,
  risk accepted" posture it already recorded, now on a version its author has
  not withdrawn. No new review is claimed.

- **CodeQL's first run would have reported 289 alerts, 229 of them test
  vectors.** `rust/hard-coded-cryptographic-value` cannot tell a KAT from a
  secret, and this tree is built out of KATs — `crates/rsk-oath/src/tests.rs`
  alone accounted for 37. An alert list that is 79% noise is one nobody reads.
  `.github/codeql/codeql-config.yml` keeps the test suites, the Kani siblings,
  `fuzz/`, `tests/` and `third_party/` out of extraction; measured against the
  pinned bundle, 289 alerts become 60, with nothing left in a test-shaped file.
  Two things decided the shape of it. `**/*_tests.rs` alone is not enough —
  AGENTS.md puts a crate root's tests in plain `tests.rs`, which is where the
  largest single source of alerts was, so both spellings are listed. And
  `paths-ignore` is applied at EXTRACTION, not at analysis: handed to
  `database analyze` it changed nothing at all (279 results before and after),
  and it works only because `codeql-action/init` passes it to `database create`.
  A config written on the other assumption would have sat in the tree doing
  nothing, with the check still green. This is not the workflow-level
  `paths-ignore` that `codeql.yml`'s header refuses — that one skips the run,
  which Scorecard counts against the SAST score; this one still runs and still
  counts, and Scorecard still reports `SAST tool detected: CodeQL`. The cost,
  stated in the config and in docs/testing.md: a defect in a test helper is now
  not found, rather than found and filtered.

- **Nothing in the tree parsed `.github/workflows`, and a workflow that does not
  parse breaks a check that is not about workflows at all.** OpenSSF Scorecard's
  SAST row runs actionlint over *every* file in that directory, so one malformed
  sibling returns score **-1** for the whole check rather than merely failing
  detection — a single tab in `codeql.yml` was enough. Eight workflow files
  rested on a tool nobody ran: no actionlint, yamllint, zizmor or
  action-validator anywhere in the tree, and no `check.sh` row that read the
  directory at all. `actionlint` joins the dev shell (`nix/devshells.nix` — a
  toolchain addition, so it is maintainer-visible), and `workflow lint` is now
  the **first** row of `check.sh`, ahead of `fmt`: it costs ~0.2 s, and a class
  that makes another check lie should fail in the first second rather than the
  fourteenth minute. It takes no file arguments on purpose — actionlint
  discovers the workflows from the git root, which covers `.yaml` as well as
  `.yml` (a `*.yml` glob does not) and which turns an empty or missing directory
  into an error (`no YAML file was found`, exit 3) rather than the silent pass
  over nothing this repo keeps rediscovering. `ci.yml`'s always-on `docs` job
  runs the same command for the reason it already runs gitleaks: `pages.yml`
  sits inside `ci-scope.sh`'s DOCS_ONLY set, so a change to that workflow alone
  skips `check` entirely. Falsified through the row rather than the binary, exit
  codes taken with no pipe: an unknown runner label, a bad `matrix.<prop>`, a tab
  in the indentation and an unquoted `$var` in a `run:` block each stop the gate
  at row 1 of 1 with rc 1 and its own message — and with the row deleted that
  same tab left all 95 rows green, which is what makes it load-bearing rather
  than decorative. Host tooling and CI only, so no `bcdDevice` bump.

- **Two hand-written curve rosters bounded a buffer size, and nothing said so.**
  `rsk-piv`'s `MAX_EC_POINT` is 97 — a P-384 point — while
  `rsk_ec::PrivKey::public_point` writes up to 133 for P-521 and writes with
  `copy_from_slice`, so a curve one byte too wide is a panic on the first key
  operation, not an error. 97 was safe only because `curve_for_algo` and
  `curve_from_id` each accept four curves and no wider one; no test tied either
  roster to the number. One now walks both over their whole `u8` domain and
  asserts the point fits. Falsified three ways: `5 => Curve::P521` fails on the
  width assertion naming P-521 at 133 against 97; dropping a curve and blinding
  the walk each fail on the roster count, so a loop that reads nothing cannot
  pass. `curve_from_id` is `pub(crate)` to be reachable, matching its sibling —
  refactor, no behaviour change, and the counter moves because bcdDevice counts
  builds.

- **The crate tiers were true and nothing could tell.** Applet-to-applet edges
  reached zero over the tier refactor — six manifest edges (`fido→mgmt`,
  `fido→rescue`, `openpgp→mgmt`, `piv→mgmt`, `piv→openpgp`, `otp→mgmt`) down to
  none — and the only thing holding them there was that everyone remembered.
  `deny.toml` now states the rule as a graph assertion on the existing
  `cargo-deny` row: each of the eight applet crates is reachable only from
  `firmware`, `rsk-device` and `rsk-display`; `sha2`, `sha1`, `rsk-sha512` and
  `rsk-mldsa` only from `rsk-crypto`; `rsk-ec` and `rsk-rsa` from a named
  allowlist rather than through the facade, because routing them behind it would
  put 11 and 12 third-party crates into the closure of the five that do neither.
  A sideways edge exits 2 there instead of waiting for a reviewer to notice it,
  and `-D unused-wrapper` fails the row the other way too — when an allowlisted
  edge is gone and its entry has quietly become decoration. Host-side only: no
  firmware file moved, so no `bcdDevice` bump.

- **The crate-layer drawing named 17 of 28 crates, under a footer reading
  "Source: workspace Cargo.toml manifests".** So 57 of the 100 manifest edges
  had an endpoint it could not draw at all. It also showed seven applets against
  a registered eight, still carried the already-deleted `rsk-piv → rsk-openpgp`,
  put `rsk-rsa` in the platform tier beside `rsk-sdk`, and claimed every applet
  builds on `rsk-crypto` when `rsk-mgmt` and `rsk-vendor` do not.
  `scripts/crate_graph.py` emits it now — every name, count and note off the
  manifests — and a new `crate graph` gate row fails when the committed SVG has
  drifted. The tier table is the one thing still written down, and the script
  holds the manifests to it: a workspace member it does not place is a hard
  failure, and so is any dependency that does not point into a later band.
  `docs/architecture.md`'s alt text has to be the drawing's own `<desc>`, which
  is how it came to say "seven applet crates" for a month.

- **The FIDO applet declared the hash backend the crypto facade exists to hide,
  and compiled not one line against it.** `crates/rsk-fido/Cargo.toml` carried
  `sha2` in `[dependencies]`, while every digest the applet takes goes through
  `rsk_crypto::{sha256, hmac_sha256, hkdf_sha256, hkdf_sha512}`: no `sha2::`
  path, no `use sha2`, no `Sha256`/`Sha384`/`Sha512`/`Digest`/`FixedOutput`
  anywhere under its `src/` — and the same grep, pointed at `rsk-crypto/src`,
  returns 17 lines, so it can see one when there is one to see. That edge is
  what the facade's own receipt is against:
  `5fbeeb3` swapped SHA-512 from `sha2` to `rsk-sha512` by editing
  `rsk-crypto/src/hash.rs` and `mac.rs` and no applet file at all. The
  `kani-soft` feature's `sha2/force-soft` came down with the dependency and was
  redundant next to `rsk-crypto/kani-soft`, which already sets it — which is
  what `rsk-openpgp`, `rsk-oath` and `rsk-otp` forward and nothing else, along
  with `rsk-bip39` and `rsk-slip39`. (`rsk-piv` still names its own beside that
  one. Different shape, and left alone: its `sha2` is a dev-dependency its
  `src/tests.rs` hashes with seven times.) Both are gone, and the dependency's
  five-line explanation with them — the three-line pointer at `rsk-crypto` that
  every other forwarder carries says it now. `cargo tree -p rsk-fido --features
  kani-soft` still resolves `sha2 v0.10.9|force-soft`, and the SLOW and LIGHT1
  tier selections still `cargo check` one package at a time, which is how
  `cargo kani` re-invokes them — worth doing by hand, because **no row in
  `check.sh` ever builds with `--features kani-soft`**; only the weekly Kani
  tiers do. Refactor, no behaviour change — but the image moves, so the counter
  does. Nothing grew: all 28 workspace members' normal-dependency closures
  (`cargo tree --edges normal`) are identical before and after, and the
  comparator was falsified first — pointed at an injected `rsk-oath → rsk-ec`
  it names the 12 crates that edge would add. `sha2 0.10.9` still reaches
  `rsk-fido` through `rsk-crypto` and `ed25519-dalek`. And the default shipping
  image — `cargo build --release -p firmware`, no features, taken before the
  16M/display/no-touch rebuilds overwrite the ELF — is the same program:
  `.text` 810 500 and `.bss` 337 556 bytes on both sides, 1343 function labels
  on both sides, 264 254 instructions on both sides, and **81 of those
  instructions differ**, every one of them a relocated immediate — 79 `movw`
  low halves of `movw`/`movt` address pairs, and 2 `d4d4` inter-function
  padding half-words objdump renders as `bmi.n`, each sitting after a diverging
  instruction and before the next function's symbol. Byte-identity is not
  reachable for a manifest edit at all — dropping a dependency changes the
  crate's `-C metadata` hash and with it the symbol and `.rodata` numbering — so
  the bar is instead: same instruction count, same mnemonic profile, and every
  difference enumerated and accounted for.

- **The shared EC public-key DO chose both of its length forms from the point
  width, and one of them measures something else.** `make_ec_pubkey_do` builds
  `7F49 { 86 <point> }`: the inner length counts the point, the outer one counts
  the whole `86` object around it, which is 2 or 3 bytes longer. Both took the
  long form on `point.len() >= 128`, so a 126- or 127-byte point left the outer
  length short-form while the value it had to carry was 128 or 129 — written out
  as `80`, the indefinite length DER forbids, or as `81`, a long form with no
  byte behind it. Either one mis-frames the key for every host that reads it.
  Not reachable today and no shipped byte changes: `PrivKey::public_point`
  returns 32, 65, 97 or 133 and nothing else, on all three call sites in both
  applets, and an attacker-chosen IMPORT picks the scalar, not the point width.
  But the encoder is `pub` in a tier-0 crate that exists to be called from more
  than one place, and its own signature accepts the two widths it cannot encode.
  Each length now takes the long form when the value *it* encodes reaches 128 —
  the rule `rsk_sdk::tlv::format_len` already states two tiers up, where an
  algorithm crate cannot reach it. The walk over reachable widths could not see
  this (all four sit clear of the boundary), so a second one covers every width
  the encoder is documented for, and its reader rejects a non-canonical length
  instead of accepting it: without that, moving the threshold anywhere in
  98..=133 re-parsed cleanly and was pinned by nothing. Falsified against the
  previous encoder (`plen 126: outer DO unreadable`) and against a threshold
  moved to 100 (`plen 100: inner DO unreadable`).

- **The PIV applet borrowed the OpenPGP applet's elliptic-curve key type, and
  that was the last applet reaching sideways.** `Curve`, `PrivKey` and
  `make_ec_pubkey_do` lived in `rsk-openpgp/src/keys.rs`, so `rsk-piv` — which
  shares none of OpenPGP's DO model, PW1/PW3 sessions or DEK seal — depended on
  the whole applet for a key type, an eight-value curve tag and a TLV wrapper.
  Six `use rsk_openpgp::keys::…` sites and one manifest dependency; both are
  now zero, and with them the last applet→applet edge in the tree. Measured
  over all 56 ordered applet pairs: **0 manifest edges, 0 `rsk_x::` uses in
  code**. Six `rsk_<applet>::` references survive, every one inside a comment
  where one applet explains its ordering by pointing at a sibling that does the
  same thing — prose, not a dependency. Both halves are a `git grep` anyone can
  re-run — `^rsk-<b> = ` in `crates/rsk-<a>/Cargo.toml`, and `rsk_<b>::` under
  `crates/rsk-<a>/src` — and the counter was falsified before it was believed:
  pointed at `rsk-sdk` the same two greps find the edge from all eight applets,
  2 to 48 uses each.

  The key type went to `rsk-ec`, beside the fixed-base comb it already signs
  through, and the crate's charter grew to match: it is the EC layer now, not
  just the comb. `Curve::id` — the persisted `[curve_id]` byte both applets tag
  a sealed key with — became public, which deleted PIV's byte-identical hand
  copy of the same eight-arm table. `MAX_EC_SIG` / `MAX_EC_POINT` followed the
  operations whose output they bound. What did **not** follow: `curve_from_attr`
  maps an OpenPGP *algorithm attribute* to a curve and stays with the DO model
  that defines those attributes, and `store_ec_key` / `load_ec_key` stay with
  the DEK seal they are I/O for. All 17 tests of the moved code went with it or
  stayed with what they test — 14 to `rsk-ec` (4 raw-signature, 3 X25519, 7
  brainpool KAT), 3 kept in `rsk-openpgp` (the attribute mapping, and the two
  DEK-seal tests, in a file that no longer calls itself `keys_x25519_tests`) —
  none rewritten, none lost, and 8 new ones on top.

  `make_ec_pubkey_do` is not curve vocabulary — it is the `7F49 { 86 <point> }`
  data object both applets answer GENERATE and IMPORT with. It went to
  `rsk-ec/src/pubdo.rs`, which is where `rsk_rsa::pubdo` already holds
  `7F49 { 81 <N> · 82 <E> }` for exactly the same reason; splitting the two
  halves of one DO family across two crates would have been the worse answer.
  `rsk-sdk::tlv` was the other candidate and is the wrong one: it holds generic
  BER primitives, not named objects. Its new `MAX_EC_PUBDO` replaces PIV's
  `[0u8; 110]` and OpenPGP's twice-written `8 + MAX_EC_POINT`.

  `rsk-ec` is tier 0 and gained **no** `rsk-*` dependency (`cargo tree -p rsk-ec
  -e normal --depth 1`: twelve third-party crates, not one of them `rsk-*`).
  Two things had to be cut for that, both along seams `rsk-rsa` had already
  cut. `Sw` became `EcError` — three variants, each naming the status word its
  callers answer with, reproduced at each applet's APDU edge by `ec_sw` and
  pinned arm by arm (`ec_sw_reproduces_every_status_word`, in both crates). The
  split between `Failed` and `BadPoint` is load-bearing: it is what keeps a
  refused signature at `6400` while a malformed ECDH peer point stays `6984`.
  And `PrivKey::generate` takes `rsk_ec::Rng`, bridged by an `EcRng` beside each
  applet's existing `RsaRng`. `PrivKey::sign` needed no bridge at all — its
  `_rng` parameter had been dead since every curve here became deterministic,
  and carrying it would have meant building an adapter for an argument nobody
  reads.

  **Nothing an already-provisioned key depends on moved**, and that is measured
  rather than intended. Undo the one mechanical substitution the tier boundary
  forced — `Sw::EXEC_ERROR`/`DATA_INVALID`/`FUNC_NOT_SUPPORTED` → the matching
  `EcError` variant, and `rsk_ec::` → `crate::` — and the three moved spans
  differ from their parent (`868653b`) **only** in the crate header, the module
  docs, the test hooks, two `pub`s and `sign`'s signature. No arithmetic, no
  control flow, no buffer width and no error direction moved. The
  sealed blob is still `[curve_id] ‖ scalar`, the eight tags are written out
  one by one in a test rather than round-tripped (a renumbering would move both
  sides of a round-trip together), and four real records sealed by the
  `868653b` build — P-256, P-384, Ed25519, X25519 — are checked into
  `rsk-piv`'s tests and must still load. Falsified: remapping PIV's
  `curve_from_id` fails that test with "P256 decoded as the wrong curve",
  flipping one fixture byte with "record from the old build refused". Remapping
  `rsk_ec::Curve::from_id` leaves it GREEN — PIV reads through its own,
  deliberately narrower table — and `curve_id_round_trips_and_rejects_unknown_tags`
  in `rsk-ec` catches it instead (its sibling `curve_id_tags_are_frozen` reads
  only `id()` and stays green, so it is one test, not two).
  `docs/protocol.md` describes neither of these: the curve tag is
  at-rest only, and the `7F49` DO is the public spec's, byte-unchanged.

  The image is **not** byte-identical this time, and should not be: a clean
  `cargo build --release -p firmware` goes from 811 500 to **810 580 bytes, 920
  smaller** (`arm-none-eabi-size`, `text + data`, the sum `check.sh`'s budget row
  takes; `bcdDevice` pinned, so the counter is not the difference). **None of the
  deletions is why**, which is measured and not guessed: put the dead `_rng`
  back at all six `sign` call sites and PIV's duplicate tag table back beside it,
  and the image rebuilds at 810 580 — the same byte count, so the two of them
  together are worth **zero**. PIV's `curve_id` never had a symbol of its own to
  delete; it was already inlined into `store_ec_key`, and `Curve::id` inlines
  into the same jump table. What actually moved is codegen: `PrivKey`'s four
  large methods crossing a crate boundary re-cut the cross-crate inlining, 1047
  symbols changed size, 80 512 bytes of gross movement, and −920 is the 1.2 %
  that did not cancel. Nothing left the image. Every symbol that disappears is
  one of the six that reappear under `rsk_ec::key::`, or a wrapper now inlined
  into a caller that grew to match (`p521`'s `FieldElement::mul` into
  `primeorder`, `sha2`'s `Sha512::finalize_into` into `hmac`), or two identical
  one-instruction `Rng::fill` shims the linker folded (`RsaRng`, `EcRng`) — and
  `.bss` is unchanged to the byte at 337 556.

- **Four applets reached into the management applet for a config record and a
  serial.** `EF_DEV_CONF` — the Yubico DeviceInfo record `ykman config usb`
  writes, and the READ CONFIG response built around it — lived inside
  `rsk-mgmt`, so `rsk-fido` and `rsk-otp` depended on the management applet to
  write it, while `rsk-openpgp` and `rsk-piv` depended on it for five lines that
  derive the 8-digit serial from the chip id. Those are two different things and
  they went to two different places. The record is its own crate now,
  `rsk-devconf`, in the shape `rsk-led` and `rsk-phy` already had — below the
  applets, depending only on `rsk-fs` and `rsk-sdk`. `serial4` is
  `rsk_sdk::serial4`, beside `FIRMWARE_VERSION`: the same device identity four
  applets report for four unrelated reasons, declared once where every applet
  already looks. `git grep -c rsk_mgmt` over `rsk-fido`, `rsk-otp`,
  `rsk-openpgp` and `rsk-piv` goes 3/7/5/3 → **0**, and all four drop the
  dependency.

  Crossing a crate boundary did **not** publish the record's vocabulary. Inside
  `rsk-mgmt` the FID was crate-private, which is what let the FIDO vendor
  `CONFIG_WRITE` say "ask the codec, you cannot reach the record"; a `pub const`
  would have demoted that to a convention on a record which survives
  `authenticatorReset` and which one unparseable byte hides the device behind
  for good (audit run-33). So the FID, the stored-size cap and the thirteen
  DeviceInfo tags stay private — as `rsk-phy` keeps its own twelve tags — and
  are re-exported as `rsk_devconf::raw` only under `test-util`, which just the
  applet tests and two fuzz targets turn on. Naming `rsk_devconf::EF_DEV_CONF`
  from an applet is `error[E0603]`, and `raw` does not exist in an image build.
  One constant is genuinely shared and genuinely public: `DEV_CONF_WRITE_MAX`,
  the request bound the CCID WRITE CONFIG applies before the codec strips.
  Visibility is compile-time only and `raw` is `cfg`-gated out, so the image
  does not move — measured, not assumed: `objcopy -O binary` over the release
  build before and after is the same `bc04bca3…`, and only the debug sections
  differ, because a new `[features]` table changes the crate's `-Cmetadata`
  fingerprint. The second `bcdDevice` step is a build counter, not a behaviour
  change.

  **No byte of the record moved**, and that is checked rather than intended:
  every moved span of the codec is byte-identical to its old self bar eight
  lines — that one `pub`, the import and the version tag naming
  `rsk_sdk::FIRMWARE_VERSION` directly, and two doc clauses that named the
  applet the codec no longer lives in. All 37 tests moved byte-identical, 21
  to the record and 16 to the applet, none rewritten and none lost.
  `EF_DEV_CONF = 0x1122` and every size constant keep their values, so a key
  provisioned by an older build reads the same record through the same parser
  and there is nothing to migrate. `docs/protocol.md` §6 describes the same
  TLV; only the "Source:" pointers follow the file.

- **FIDO reached across the applet tier for a config record, and only the crate
  graph said so.** `EF_PHY` — the PicoForge-compatible device-config TLV that
  carries USB identity, LED wiring and the interface mask — lived inside the
  rescue applet, so everything that reads it depended on `rsk-rescue`: 19
  references from `rsk-fido` alone, plus `rsk-device`, `rsk-display`,
  `firmware`, `tools/emu`, a fuzz target and the Miri harness. It is its own
  crate now, `rsk-phy`, in the shape `rsk-led` already had for `EF_LED_CONF` —
  below the applets, depending only on `rsk-fs` and `rsk-sdk`. `rsk-fido` and
  `rsk-display` no longer name `rsk-rescue` at all.

  **No byte of the record moved**, and that is checked rather than intended:
  the codec is line-for-line its old self — `diff` against the parent moves the
  crate header and the trailing `#[path]` module hooks and not one line between
  them — and its tests and Kani harnesses are byte-identical files, wire
  vectors included. A key provisioned by an older build reads the same
  `EF_PHY = 0xE020` through the same parser, so there is nothing to migrate.
  `docs/protocol.md` §7.1 and `rsk hw` describe the same tags; only the
  "Source:" pointers follow the file.

  The Kani `heavy` tier moves with the proofs — it was `rsk-rescue` because of
  this record's 11.1 GB round-trip, and is `rsk-phy` now; the harness and cover
  floors are unchanged because nothing was added or dropped.

- **Seven applets each declared the same presence seam, and the board answered
  all seven.** `Rng`, `UserPresence`, `Presence`, `PinEntry` and `AlwaysConfirm`
  were 29 declarations across the applet tier, byte-identical apart from FIDO's
  fourth `Presence::Cancelled`; `rsk-device` carried two supertrait blocks and
  their blanket impls purely to reconcile them, and `firmware`, `tools/emu` and
  `rsk-display` wrote the same impl five and seven times over. They are declared
  once now, in `rsk-sdk` — the crate every applet already depended on, so the
  move added no dependency edge — and the glue is gone: `firmware` and the
  emulator implement one `Rng` and one `UserPresence` each.

  The seven presence impls were **not** actually identical, which is the part a
  straight merge would have broken. The trusted display closes an approved
  WebAuthn ceremony with a ~0.4 s "Approved" card and runs a registration screen
  for `makeCredential`, and its own comment says paying that on OpenPGP/PIV —
  which ask for presence once *per signature* — would be a latency regression.
  A cancel differs too: only CTAP2 can be cancelled mid-wait, so only FIDO could
  answer `Presence::Cancelled`; the six card applets got `Timeout`. The shared
  trait keeps both apart by asking two questions rather than one — `request` for
  a smartcard touch policy, `request_ceremony` for a CTAP2 ceremony, the latter
  defaulting to the former — so every status word, every CTAP error and the pop's
  scope are what they were.

  The randomness seam stays split in two on purpose. `rsk-rsa` is an algorithm
  crate below `rsk-sdk` and may not reach up for it, so it keeps its own `Rng`
  and the two are bridged where they meet (`rsk_openpgp::keys::RsaRng`,
  `rsk_piv::RsaRng`, `firmware`'s `core1::SdkRng`, the emulator's `EmuRsaRng`).
  The alternative — `rsk-sdk` re-exporting `rsk_rsa::Rng` — was measured rather
  than argued: `rsk-sdk` has 14 direct dependents and `rsk-rsa` has 4, so that
  edge would pull `rsk-rsa` and `num-bigint-dig` into the closure of ten crates
  that do no RSA. Same reasoning that kept the `RsaError → Sw` table duplicated.

- **Two rows of that mutation table asserted the right outcome for the wrong
  reason.** Measured one mutant at a time: deleting the `s ≥ n` refusal
  (RFC 8017 §8.2.2 step 1) left the whole suite green, because the `s = n` case
  reduces to zero and fails the EM comparison anyway — and without that refusal
  the oracle accepts `sig + n`, a second representative of a signature it has
  already seen. The over-wide-data case had the same shape: it sat ten bytes
  short of the width where the check is what stops the EM construction indexing
  past its own buffer. Both mutants now die, each on the assertion that names it
  and in the direction that describes the defect.

  Three comments outlived the crate they described. `firmware/Cargo.toml` still
  blamed the 128 KiB heap on the `rsa` crate; two RSA tests still said they
  verified through it. And one citation did not follow the shift its neighbours
  did — `formal/comutants.toml` pointed `Session::set_pin` at the function after
  it. `docs/testing.md` now records how the differential against `rsa` 0.9.10 is
  rebuilt, since the crate cannot come back into the tree to hold it: including
  that a comparison gated behind `is_ok() || is_err()` compares nothing, and that
  upstream cannot be asked about an unbalanced key because its CRT recombination
  does not terminate for `q ≫ p`.

- **The new RSA test oracle could not be made to say "no".** `verify_pkcs1v15`
  arrived with five call sites and not one negative case, so a version hard-wired
  to `true` left the suite green — and the generated-key half of both applets'
  RSA tests had nothing else checking them. It now has its own mutation table
  (`crates/rsk-rsa/src/verify_tests.rs`): a flipped signature bit, a flipped
  digest bit, another message's signature, the wrong modulus, the wrong exponent,
  three wrong lengths, `s = n`, and over-wide data. Falsified by stubbing the
  function to `true` and reading which assertions fell.

  Three more from the same review. The EMSA-PKCS1-v1_5 block builder had been
  copied into both signers rather than shared, so the PKCS#1 padding rule lived
  in two places; it is one `emsa_block` now. `rsa_sign`'s DigestInfo arm maps
  every failure back to `Failed`, which is the single status word the `rsa`
  crate's `sign_with_rng` could answer there — the new width errors were
  unreachable through `rsk-piv`'s certificate path, but "unreachable" is not
  "identical". And three `mod_inverse` results — the private exponent, `qInv`,
  and each blinding factor's inverse — were signed intermediates dropped without
  scrubbing, where the crate they replaced wiped its own; they ride in
  `Zeroizing` now.

  Two comments were narrower than the truth they defend. The Garner
  recombination is underflow-safe for *any* `p` and `q` — `m1 < p` is a `modpow`
  postcondition — not only for the unbalanced pair the comment named; and
  PSO:DECIPHER's legacy arm collapses every failure to `EXEC_ERROR` where the asm
  arm answers the four-variant table first, which the comment read as identical.
  A safety argument stated narrower than it is invites the next reader to weaken
  it.

- **`rsk-rsa` owns the RSA key type, so nothing above tier 0 names a foreign
  one.** `rsa::RsaPrivateKey` used to cross from an algorithm crate into both
  card applets, `rsk-device` and `firmware` — five manifests and eleven source
  files spelling a dependency's type in their own signatures. `rsk_rsa::RsaKey`
  replaces it, and its public surface is bytes: `size()`, `n_be()`, `e_be()`, and
  a `from_p_q` reached through the byte-taking `rsa_from_pqe`. `rsk-piv` and
  `rsk-openpgp` no longer name a bignum at all; `rsk-rsa` still has no `rsk-*`
  dependency. Three PKCS#1 v1.5 helpers moved with it — the software private
  operation, `rsa_sign` and a new `rsa_decrypt` — each a port of what the `rsa`
  crate ran, arm for arm, including which of `check_public` and `validate`
  refuses an imported key, because an applet's status word follows that.

- **The citation gate said `ok` over 75 rotted citations, and one whole page was
  outside it.** `formal/citations.lock` now records what each of the 423
  `file.rs:line` citations pointed at, and a locked line found ELSEWHERE in its
  file is reported with the line it moved to. A line edited *in place* still
  passes: that false alarm is what the row was deliberately built without, and
  both halves are pinned. `formal/comutants.toml` joins the guarded pages — 13
  of its 16 citations named a file nothing could resolve, and two landed on
  unrelated code, one of them wrong the day it was written. Pages that reason
  about several applets at once must now write a repo path, because `lib.rs:1020`
  decides nothing for this gate or for a reader. Four more citations were wrong
  and are re-pointed, including `Ctx::load_keydev`, which named `require_presence`.
  Host-side only: no firmware behaviour, so no bcdDevice bump.

- **Why the RSA status-word table is allowed to exist twice.** `rsa_sw` maps
  `RsaError` to a status word in both card applets, and the comment defending
  that named the orphan rule — which in fact permits the shared
  `impl From<RsaError> for Sw`, because `Sw` is `rsk-sdk`'s own type and the
  `rsk-sdk` → `rsk-rsa` edge it needs points downward. What rules it out is the
  cost: `rsk-sdk` is the seam every applet depends on, so that impl puts
  `rsk-rsa` in FIDO's, OATH's, OTP's, mgmt's, rescue's, fs's and usb's
  dependency closures, none of which do RSA. Both halves measured; both copies
  stay, each pinned arm by arm. Comments only — refactor, no behaviour change,
  and the counter moves because a bump counts builds.

- **The RSA layer moved out of the OpenPGP applet and into `rsk-rsa`.** The CRT
  parameter layout and its blinded, Bellcore-fault-checked private operation,
  PKCS#1 v1.5 (the DigestInfo encoding, both signers, the constant-time decrypt
  unpad), the key type, keygen, and the `7F49` public-key DO now live in the
  crate that already held the assembly under them. PIV was reaching across a
  tier for all of it — `rsk_openpgp::rsa_crt`, `keys::rsa_sign`,
  `keys::RsaKeygen`, `keys::MAX_RSA_BYTES` and four more — and reaches down for
  it now instead; the applets keep only what is theirs, the APDU framing and the
  seal I/O. Behaviour-preserving: the `rsa` crate rode along with the code that
  used it (the entry above has since dropped it), and no wire byte moves.

  The status words could not ride along, because a tier-0 crate must not name
  `rsk_sdk::Sw`. `rsk-rsa` returns its own four-variant `RsaError` and each
  applet maps it at its APDU edge, reproducing every status word the old code
  answered — including PSO:DECIPHER's deliberate `EXEC_ERROR` on a malformed
  block. Both mappings are pinned arm by arm, and both pins were checked by
  breaking an arm and reading which assertion fell.

  Two constants that were written out twice collapsed on the way:
  `MAX_RSA_BYTES` (`512` in `keys.rs`, `2 * MAX_MOD` in `rsa_crt.rs`) and the
  maximum sealed plaintext (`5 * MAX_MOD` in `rsa_crt.rs` and again in
  `rsk-piv/src/seal.rs`). Both survivors derive from `rsk_rsa::MAX_MOD`, so
  neither can drift from the width the assembly actually accepts, and every
  remaining user of both was read. `num-bigint-dig` left the OpenPGP and PIV
  manifests, where nothing referenced it any more.

- **`rsk-rsa-asm` is now `rsk-rsa`.** The crate held the vendored UMAAL assembly
  and nothing else, while the RSA layer above it — CRT parameters, PKCS#1 v1.5,
  the key type, keygen — lived inside the OpenPGP *applet*, which is why PIV
  reaches across a tier to sign. RSA was the only algorithm family in the tree
  without a crate of its own. The rename comes first and alone: a crate called
  `-asm` cannot honestly hold pure Rust, and the moves land on top of it. Pure
  rename, no code moved yet.

## [0.4.10] - 2026-08-14

The conformance release: every applet swept against a real YubiKey 5.7.4, three
runs per cell, with each difference measured before it was called a bug — which
retired several of the findings that had started the sweep. Four of what survived
could damage a key, and two defaults change in ways you will notice. The rest is
status words, at-rest ordering, and the instruments that were supposed to catch
this class already: proofs that ran against nothing, fuzz targets that never
reached their applet, and gate rows nobody had watched go red.

### TL;DR

A conformance release, measured rather than argued: where an entry below names a
reference, it is a YubiKey 5.7.4, three runs per cell. If you read nothing else:

- **Four ways to damage a key are closed.** A PIV `VERIFY` whose body was not the
  8-byte wire form spent a PIN retry, so three malformed commands blocked the PIN.
  A short unpadded new reference was stored verbatim, and with the PUK shortened
  too the only exit was `INS FB` RESET — which destroys every PIV key. A signature
  at a PIN-always slot locked the card. And generating an OpenPGP keypair
  destroyed an AES key the host had installed.
- **Two defaults changed and you will see it.** PIV slot `9e` defaults to PIN
  `NEVER`, which is what SP 800-73-4 makes the card-authentication key for, and a
  key generated without `--touch-policy` no longer demands a touch on every
  operation — that one used to hang scripted use with no diagnostic.
- **One thing to know when upgrading.** The OpenPGP sex DO `5F35` narrows to the
  codes the reference accepts; a device provisioned before this release is
  migrated on its next boot, once, and needs nothing from you.
- **The debug counter read is gone from shipping images.** Vendor `INS 12`
  reported the prime-search statistics on every build; it is behind a feature now,
  like its two neighbours.

Everything else is status words, at-rest ordering, and the instruments — grouped
below in the usual four sections, security last.

### Added

- **A Kani proof over the APDU dispatcher's *sequences*, the first one in the
  tree that applies more than a single call to a stateful object.**
  `Dispatcher::process` carries three audit findings in its own comments —
  run-34 #26 (a stranded `CLA 0x10` APDU prefixed the next command, so the
  victim's own GENERAL AUTHENTICATE signed the injector's data under the
  victim's touch), run-35 (fixing that for SELECT alone left every other
  instruction absorbing it), run-37 (a mismatch-only test let a stranded segment
  swallow the next client's SELECT, leaving the previous applet selected and
  still PIN-verified) — each reachable in two or three APDUs, and every existing
  harness was single-call, so the surface with three demonstrated bugs had no
  proof at all. The new one drives the real dispatcher with a recording stub
  applet over a selected card and **every pair of raw APDUs up to six bytes**,
  and shows: it never panics; the chain buffer stays in bounds and a *dropped*
  chain leaves no bytes behind, not merely a cleared flag; **the applet is never
  handed a body from a command it did not itself terminate** — the `Nc` it sees
  is the second command's own unless the pair is a legitimate ISO 7816-4 chain,
  in which case it is exactly the sum, with no third possibility; a
  secure-messaging class reaches no applet, SELECT included; and a well-formed
  SELECT for a registered AID always reaches the applet, whatever chain state it
  walks into. Reintroducing any of the three historical bugs makes it fail, and
  the solver hands back the two-APDU witness. Proof-only (`cfg(kani)`): the
  firmware image is byte-identical, so no `bcdDevice` is owed.

- **Three Kani harnesses that prove things about *sequences* of security
  states, not single calls.** The 53 harnesses this tree already had are all
  single-call: a parser, a codec, one arithmetic step. RS-Key's dangerous
  defects have not lived there — they have lived in orderings (a token
  surviving a PIN change, one channel continuing another's enumerate walk, a
  gate deleted before the key it guards). `rsk-fido` now carries a symbolic
  four- to five-operation sequence over the **real** `FidoState`, checked after
  every step: `NoTokenAfterInvalidation` (a pinUvAuthToken retired by
  `stopUsingPinUvAuthToken`, a reroll, an `authenticatorReset`, a power cycle or
  its own usage timer never authorizes again, and only a fresh issuance brings
  one back) and `NoAuthorizationBypass` (a credentialManagement enumerate walk
  is servable only to the channel whose *Begin* opened it — CTAP 2.1 §6.8
  exempts the *Next* legs from carrying authorization of their own, so the
  `(channel, counter)` pair **is** the check).

  The third drives the real `verify_cm_token` with a `pinUvAuthParam` minted
  while the grant was live and replayed after it died, and asserts two things:
  the gate refuses, **and the replayed MAC still verifies**. `stop_using_token`
  deliberately leaves the token bytes in place, and `config.rs` and
  `credmgmt.rs` test the MAC and the permission bits and nothing else — so at
  those two sites zeroing `permissions` is not defence in depth, it is the only
  defence. That asymmetry is now pinned by a proof instead of by a comment.

  **All eight clauses have been shown to be able to fail**, one isolated
  mutation each, every one rebuilding a real defect or removing a defence the
  tree relies on: `stop_using_token` keeping permissions or wiping the token
  bytes, `may_walk_rps` ignoring the channel or losing its counter half,
  `user_verified()` dropping the UV flag, and `consume_after_user_presence`
  keeping permissions (GHSA-wqjm-653g-hgw3). Each turns exactly the clause that
  names it red, and nothing else. Costs, on an 18-core Apple Silicon under load:
  138 s, 43 s and 393 s. The invariant names are shared with the TLA+ model in
  `formal/`, so one property reads model → code → harness. **cfg-gated code
  never reaches the image, so no `bcdDevice` bump.**

- **A TLA+ model of the security state, `formal/RSKeySecurityState.tla`.** 41
  actions over PIN retries, the pinUvAuthToken and its permissions, the touch
  and channel owners, the reset window, the persistent gate records and the
  position at which power is lost inside a multi-write flash sequence. TLC
  checks six named invariants — the same six the `rsk-fido` Kani harnesses use —
  exhaustively over 13 232 120 distinct states at small constants. Fourteen
  mutation switches rebuild real RS-Key defects and **all fourteen are caught by
  the invariant that names them**, each proved solo so a mutant caught by a
  sibling cannot pass for one that names its own; `-coverage` shows no dead
  action. It has produced **two counterexamples on the shipped tree** (a torn
  reset phase can strand an unmanageable credential, or a persistent
  credentialManagement grant on a key whose PIN record is gone) — both LOW, both
  awaiting a ruling, neither fixed.

  It is a **design artefact, not an assurance layer**, and `docs/testing.md` →
  "Formal claims" is the paragraph to quote: a green TLC run is a result about
  the model, whose fidelity to the code is maintained by hand. An adversarial
  review of the first revision proved why that wording matters — the green run
  rested on an abstraction that made the model *narrower* than the firmware (a
  power cut left the device permanently seedless, where every boot regenerates
  the seed), and repairing it turned the run red until a device-lifetime ghost
  in one invariant was retired at the right moment. Both are fixed, and the
  measurement that the repaired invariant still catches its mutant is in
  `formal/README.md`. Not in `flake.nix`, not in the gate, not in CI: the
  2.2 MB `tla2tools.jar` plus a host JRE, run on demand.

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

- **The Kani proofs run on pull requests now, split into tiers by measured
  cost.** They used to run only in the daily `deep-checks` row, because one
  harness in `rsk-rescue` costs ~80 minutes — so every proof sat a day away from
  the change that broke it. Measured, they are not one population: 38 harnesses
  over 12 crates discharge in 209 s of solving all told, and four crates hold
  everything slow. `ci.yml` has a `proofs` job running the fast tier on any change
  under `crates/`, plus the `rsk-fido` + `rsk-fs` sequence proofs (~13 min) when
  the diff reaches `rsk-fido`, `rsk-fs`, `rsk-store` or `rsk-wipe` — the state
  those proofs are about. The daily row still runs **all** of them; nothing was
  dropped from it.

  `scripts/kani.sh` owns tier → crates and is the only place a roster is written;
  it also floors the number of harnesses each tier must prove, because a roster
  that selects nothing prints a summary and exits 0 — the shape this repo has
  now shipped three times. `kani_gate.py` reads that table back with `--tiers`
  and holds it to the same contract as before (every crate carrying a proof on
  the full tier, every tier run by a row CI actually executes, every tier on the
  page a reader copies), and it finally has its own mutation table —
  `scripts/test_kani_gate.py`, 27 cases, both directions.

  ⚠️ `proofs` is a new job name. If `main`'s ruleset should require it, it has to
  be added there; nothing in the repository can do that for itself.

- The gate asserts a **stack floor** (`FIRMWARE_STACK_FLOOR_KIB`, alongside the
  flash budget). Static RAM had grown 28.5 KiB since `0x082B`, taking the same
  amount off the stack ceiling with nothing measuring it.

- The gate seals a throwaway-keyed image and asserts its first metadata block is
  `ignored`, so the sealing order above cannot silently regress. The real signing
  key stays out of it.

### Changed

- **The presence-scope arbitration moved into `crates/rsk-device`.** Which
  transport owns the one physical button, whose cancel may end its touch wait,
  and the `spent` latch that stops one hold satisfying two ceremonies all lived
  in `firmware/src/presence.rs` — a `no_std` embassy-rp binary for thumbv8m that
  neither `cargo test` nor `cargo kani -p` can build, so the rule an unprivileged
  FIDO-HID process must not be able to cancel an OpenPGP signature had no test
  and no proof. It has both now: the arbitration is `rsk_device::presence`, with
  the button, the clock and the blocking delay behind a `Board` trait, and
  `firmware/src/presence.rs` keeps the board half and the seven `UserPresence`
  impls. `NoCrossTransportTouchConsumption` — the fourth of the six TLA+
  invariants, and the one `formal/README.md` said could not be proved where it
  lived — now reaches a Kani harness, taking the traceability table from two of
  six to three. Behaviour and wire surface unchanged; no `bcdDevice` bump.

- **Slot `9e`, the PIV Card Authentication Key, defaults to PIN `NEVER`.** It
  defaulted to `ONCE`, so a key generated there needed a `VERIFY` before every
  session — which is the one thing that slot is defined *not* to need.
  SP 800-73-4 makes `9e` the key usable without a PIN, for physical-access and
  contactless readers, and a YubiKey 5.7.4 defaults it accordingly: measured three
  runs, a default-policy `9e` key signs with nothing verified at all, and its
  signature spends none of the freshness a `pin-policy ALWAYS` slot reads, where
  a `9a` signature in the same state answers `6982` and does spend. Ours matched
  neither. An explicit `--pin-policy ONCE` or `ALWAYS` at `9e` is stored and
  enforced exactly as before — identical on both cards, measured — so this costs
  nobody a gate they asked for, and keys already on a card keep the policy they
  were generated with. The use-time resolution of a legacy unresolved policy byte
  now goes through the same resolver as the store-time one, so a record an older
  build wrote and one this build writes mean the same thing at the same slot.
  **bcdDevice → 0x08D5.**

- **A PIV key generated without `--touch-policy` no longer demands a touch.** The
  card resolved an absent touch tag to `ALWAYS`, so a plain
  `ykman piv keys generate 9a pub.pem` minted a key that wanted a physical press
  before every sign, decrypt and ECDH — and every unattended consumer (`pkcs11`,
  `age-plugin`, SSH with a PIV key) then hung on a prompt nobody was there to
  answer, with no diagnostic beyond a timeout. The one flag that would have
  avoided it is the one the user did not pass. A YubiKey 5.7.4 resolves the same
  absent tag to `NEVER`, measured three runs across all four primary slots, both
  through `ykman` and through a raw `GENERATE` carrying no `AC` policy tags at
  all. Ours does now, on every slot including the retired ones and the
  trusted-display's own retired-slot generation. **Nothing is silently
  downgraded**: an explicit `--touch-policy ALWAYS` or `CACHED` is stored and
  enforced exactly as before, and keys already on a card keep the policy they were
  generated with — this is the default for *new* keys only. If you want the press,
  ask for it, which is also how you ask a YubiKey. **bcdDevice → 0x08D4.**

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

- **Four dead AES algorithm IDs dropped from the OpenPGP constants.**
  `ALGO_AES`, `ALGO_AES_128`, `ALGO_AES_192` and `ALGO_AES_256` sat under a
  comment calling them the first byte of an algorithm-attributes DO — a field
  OpenPGP gives only to the three asymmetric keys (`C1`/`C2`/`C3`). **The card's
  AES PSO is untouched and stays implemented**; it names its algorithm by key
  width rather than by an ID byte, which is what `AES_KEY_LENS` next door
  already says — 16 bytes is AES-128, 32 is AES-256, and §7.2.11 has nothing
  between, so `ALGO_AES_192` named a mode the spec does not define. Nothing read
  any of the four, anywhere in `crates/`, `tools/`, `firmware/`, `fuzz/` or
  `tests/`, and the four that remain are now exactly the four the comment
  describes. Measured, not assumed: the flashed image keeps the same SHA-256
  over `objcopy -O binary`, with a verbatim rebuild and a live edit to the same
  file as the two controls, so only non-loadable sections move. The bump is what
  `scripts/bcd_gate.py` charges a `pub const` in a shipped crate, which cannot
  tell a dead one from a live one; paying it beats teaching the guard a hole.
  **bcdDevice → 0x0953.**

- **PIV `GENERAL AUTHENTICATE` dispatches on a typed operation, not on a raw
  tag.** Which operation a dynamic-auth template asks for was decided by one
  hand-kept list of accepted tags and then carried out by a separate `match` on
  the tag byte, whose catch-all answered `6A80`. Nothing tied the two together,
  and the compiler could not object: the `match` was over a `u8`, so its
  catch-all made it exhaustive whatever the arms said. A tag added to the filter
  and forgotten in the dispatch would therefore be *selected* as the operation
  and then refused — a silent no-op wearing a status word. Both lists are now
  the variants of one private `Op`, the dispatch is exhaustive over the enum,
  and the drift is a build error; verified by adding a fifth variant and
  watching `E0004` name the missing arm. Behaviour is unchanged — the PIV suite
  passes untouched, and the tag comparison stays `u16`-wide, since matching on a
  truncated low byte would let `0x0181` pass for `0x81`. The image is 16 bytes
  smaller.
  **bcdDevice → 0x0954.**

- **One name for `0x6A80` across the tree: `Sw::WRONG_DATA`.** The SDK called it
  `INCORRECT_PARAMS`, one letter from its neighbour `INCORRECT_P1P2` (`0x6A86`)
  — a different status word — so the name argued for the reading that belongs to
  the other constant. Three crates had each worked around it on their own: PIV
  and OpenPGP with a private `WRONG_DATA` alias, U2F by glossing its call sites
  with `// 0x6A80 WRONG_DATA`. The tree had already voted 219 uses to 122; this
  makes it official, and both aliases go, so the status word has one name and no
  translation layer between crates. `docs/protocol.md`'s row moves with it, where
  `6A80 | INCORRECT_PARAMS | bad data field` had been arguing with itself.

  Proven a pure rename rather than assumed. Normalising every spelling of the
  name to one token leaves 32 of the 39 files byte-identical to their old selves,
  and the 7 that are not are exactly the two deleted aliases, the three imports
  that pulled them in, and two comments that existed only to gloss the old name.
  In the built image `.text` and `.data` are byte-identical and 47 bytes of
  `.rodata` move — the line and column numbers in `core::panic::Location`
  records, which shift because the aliases took their lines with them and `Sw::`
  widens a call site by four characters.
  **bcdDevice → 0x0955.**

### Fixed

- **…and then the proof runner could not start at all.** The fix below landed as
  `--features rsk-crypto/kani-soft`, which survives the pass where `cargo kani`
  compiles the whole selection and dies on the one where it re-invokes cargo once
  per selected package: there, a feature the package does not have is a hard
  error, whatever a sibling in the same run declares. The fast tier failed at
  `rsk-fs` having proved nothing, and it could not be reproduced with a plain
  `cargo check`, which has no second pass. Every crate a tier selects now declares
  `kani-soft` — forwarding to the dependency that hashes, empty where there is
  none — and `scripts/kani.sh` asserts that roster rather than assuming it, so a
  crate added to a tier is told what it is missing. `rsk-piv` pulls `sha2`
  directly and had been missed. Verified on real x86_64: the fast tier proves 50
  of 50, the security-state tier 8 of 8. The image is byte-identical with the new
  manifests and without them, measured, so this is again the guard charging for a
  Cargo table it cannot see through. **bcdDevice → 0x0959.**

- **The proof runner can hash again on x86_64.** Kani has no model for inline
  assembly, and `cpufeatures` writes its runtime CPU probe in it, so on an
  x86_64 host any harness that hashes reached `core::arch::x86_64::__cpuid_count`
  and was failed as an unsupported construct — a tool limit wearing the shape of
  a property violation. It never showed on aarch64, where that call does not
  exist, so the harness that hit it was green on the author's machine and red the
  first time CI ran it. `poly1305` and `sha1` take a `--cfg` to drop the probe;
  `sha2` 0.10 takes a Cargo feature, so `rsk-crypto` and `rsk-fido` gained an
  opt-in `kani-soft` that only `scripts/kani.sh` turns on. It must stay opt-in:
  forcing the soft backend swaps sha2's XIP-cache-sized compressor for its ~28 KB
  unrolled one and moves the image, measured. With the feature off the image is
  byte-identical, also measured, so this bump is the guard's charge on a Cargo
  table it cannot see through rather than a change to what ships.
  **bcdDevice → 0x0958.**

- **The private-use DO access rules are unchanged — and this entry exists so the
  next reading does not undo them.** `0101`/`0103` take PW1 no. 82, `0102`/`0104`
  take PW3, and PW3 is not a master key over the cardholder's pair. A measurement
  taken on 2026-08-14 appeared to show a YubiKey 5.7.4 serving `GET 0103` and
  `PUT 0101` under PW3 alone, and the rule was briefly loosened to match. It was
  an artefact of the probe: the cells were driven down one connection in rising
  order of privilege, so PW1.82 from an earlier cell was **still standing** when
  the PW3 cell ran. Re-measured with each state reached from its own reset, PW3
  alone answers `6982` to both. The card does not clear PW state on a re-SELECT
  of the same AID, which is what makes a rising-privilege probe lie — and the
  same trap is already recorded in `getdata.rs` from a previous time. Any probe
  of this table must power-cycle between cells.
  **bcdDevice → 0x0957.**

- **A one-byte body is one refusal on every PIV command, and the management key
  outranks the request below it.** `MOVE KEY` answered `6700` to any body at all —
  before looking at the management key — and `GENERATE ASYMMETRIC KEY PAIR` judged
  its whole template before it, so a caller with no credential could tell a
  well-formed request from a malformed one on two management-gated commands.
  `GENERAL AUTHENTICATE` spelled an empty body `6700` where every other framing
  refusal on that command is `6A80`. Measured on a YubiKey 5.7.4, `Lc` walked over
  0-40 on eleven instructions: **`Lc = 1` is `6A80` on all of them, and every other
  length behaves exactly as `Lc = 0`** — the same for data bytes `41`, `00` and
  `5C`, with and without a trailing `Le`, and in the short and extended encodings.
  It outranks even "this instruction does not exist": an undefined `INS` answers
  `6A80` at `Lc = 1` and `6D00` at every other length, on both cards. That rule is
  one check at the top of the applet now; `MOVE KEY` ignores its body as the
  reference does, and `GENERATE`, `MOVE KEY` and `IMPORT` all ask for the
  management key before judging `P1`/`P2` — the reference answers `6982` there
  too, and our stricter `P1`/`P2` validation is unchanged, just one gate lower.
  `docs/protocol.md` §5.1 documents the rule for third-party hosts, including that
  it is PIV-only. `bcdDevice` → `0x0935`.

- **An OpenPGP `PUT DATA` to a tag the card cannot write is `6B00` at every body
  length.** Past `MAX_DO_BYTES` it was `6A80`: the cap that DO `C0` announces sits
  above the routing split on purpose — the cardholder-certificate arm writes flash
  without passing through the generic writer — but that put it above the *tag* as
  well, so a DO no arm below could write was answered for by its body's length. A
  YubiKey 5.7.4 answers `6B00` to `7A`, `FFFF` and `0042` at 10, 2036, 2037, 2038
  and 3000 bytes with PW3 verified, 3 runs byte-identical. The order is password →
  tag → length now, and "is there anywhere to put this" has one owner that a
  whole-tag-space test holds to what the command actually answers. The
  unauthorised column is unchanged — a flat `6982` at every tag and every length —
  and so is the deliberate divergence above the cap for a writable DO, where the
  reference answers `9000` and keeps `n mod 256` bytes. `bcdDevice` → `0x0934`.

- **PIV `GET METADATA` for the PIN and PUK carries the algorithm tag.** The two
  records the command serves for a secret had a different shape from the ones it
  serves for a key: `05` and `06` and no `01`. A YubiKey 5.7.4 answers both
  `00 F7 00 80 00` and `00 F7 00 81 00` with `01 01 FF 05 01 01 06 02 03 03` —
  algorithm `FF`, SP 800-78 having no identifier for a secret that is not a key —
  measured 3 runs byte-identical, and it was the last cell in the whole PIV
  `P1P2` sweep where our record differed from the reference's in shape rather
  than in content. Nothing in tree read the tag and `yubikit`'s `PinMetadata`
  does not require it, so this is parity rather than a repair. `bcdDevice` →
  `0x0933`.

- **PIV `GET METADATA 9B` tag `05` answers for the slot's touch policy as well as
  its key.** It compared the stored management key against the factory one and
  stopped there, so a card carrying the factory key behind a touch gate the owner
  had raised reported itself as being in its factory configuration — while tag
  `02`, two fields earlier in the same response, published the touch byte that
  said otherwise. A YubiKey 5.7.4 clears the flag in exactly that case (measured
  2 runs: factory key + `P2=0xFE` → `01 01 0A 02 02 00 02 05 01 00`), and the
  `0x08F9` fix that reconciled this record's touch byte already argued from that
  reading. **`ykman piv info` follows the flag** — on a fresh card it prints
  "WARNING: Using default Management key!" and with the gate raised it does not,
  measured on the reference, which is the behaviour being matched. The pin-policy
  byte is deliberately *not* folded in: `0x0875` shipped `PINPOLICY_ALWAYS`
  there, `0x08D7` changed the mint without repairing what was already written,
  and `SET MGM KEY` forwards the byte — so a card upgraded from a release would
  have lost that warning while still holding the published default key.
  `bcdDevice` → `0x0932`.

- **A command chain that outgrows the reassembly buffer is a length error, not a
  class error.** The intermediate segment that reached the ceiling answered
  `6E00` — "CLA not supported" — telling the host its class byte was wrong when
  the only thing wrong was the length; fifty lines down, the *final* segment's
  overflow already answered `6700`. One condition, two answers. A YubiKey 5.7.4
  answers `6700` on the intermediate segment too (measured on a chained OpenPGP
  `PUT DATA`, authenticated and not, past its own ~3060-byte ceiling), so the
  two ends now agree with each other and with the card. `docs/protocol.md` says
  what the ceiling is. `bcdDevice` → `0x0931`.

- **OpenPGP `GET DATA` and in-application `SELECT` stop telling an internal file
  from an absent one.** `GET DATA` spoke three answers for "I do not serve this":
  `6A88` for a tag it did not know, `6982` for one of the 28 internal storage
  FIDs that the applet's `P1P2` space happens to address, and `9000` with an
  empty body for the write-only reset-code DO `D3`, which no writer ever fills.
  `SELECT` by fid had the same split. Either one named the applet's whole file
  map to a caller holding no credential, and the `D3` cell made a reset code read
  as "set to nothing". `GET DATA` answers `6B00` throughout now and `SELECT`
  answers `6A88`, each matching what it already said for a tag that does not
  exist. A YubiKey 5.7.4 answers `6B00` to 65513 of the 65536 `GET DATA` cells,
  swept end to end; its only two `6982`s are `0103` and `0104`, the private DOs
  it does serve, which is exactly the meaning `6982` keeps here. The two private
  DOs are unchanged and match the card password for password: unauthenticated
  both are `6982`, PW1-82 alone opens `0103`, PW3 alone opens `0104`.
  `bcdDevice` → `0x0930`.

- **An on-device menu now yields to an OTP command too, not only to
  CTAPHID/CCID.** On a trusted-display build the worker runs on one thread, so a
  browse modal (Passkeys / Settings) hands it back the moment host work is queued
  — but the predicate that decides it read only the transports' signal, and a
  keyboard-interface OTP frame is the worker's *separate* one. A `ykman otp
  calculate` behind an open menu therefore waited out the 60 s privacy backstop or
  a tap — a host-visible failure, not just a delay, since the OTP transport has no
  keepalive and gives up first — and an OTP command that needs a touch had no
  screen to paint its prompt on until the modal went. Both queued sources now
  count, and the floor-applying variant delegates to the same predicate rather than
  keeping a second copy of the list — the copy 23 of the 26 display call sites
  actually use. The `UI_YIELD_FLOOR_MS` floor (audit run-35) applies unchanged, and
  the OTP signal is raised only by a complete 10-report frame with a matching CRC,
  never by a host's status poll, so nothing fires on idle enumeration. Button
  builds are unaffected — the whole path is display-only. What this does **not**
  change: a yield still ends whatever modal is open, and a few of them lose work
  when it does (a half-typed passkey nickname, a seed being copied to paper). That
  was already true for a CTAPHID command and is a separate finding.
  **bcdDevice → 0x0951.**

- **A replayed vendor `SET LED` no longer writes flash.** `INS 10` on the vendor
  AID persisted `EF_LED_CONF` on every call, including one that changed nothing —
  the guard audit run-27 gave its FIDO twin (`CONFIG_WRITE`/`CONFIG_TARGET_LED`) in
  `cad140e` and never swept to the CCID sibling, and the shape `persist_dev_conf`
  already folds into the writer for the DeviceInfo record. It is ungated on the
  default build and reachable over both CCID and CTAPHID, and `EF_LED_CONF` is
  **not** a counter FID, so the churn landed in the main partition, where the
  credentials live. Measured over the device's own store (`rsk_store::SeqStorage`
  on the board's 352-page main ring), driving byte-identical APDUs: 28.1 B appended
  per replay on an empty key, and 117.0 B / 203.8 B once the ring was 74.8% / 85.2%
  live and reclaim had to migrate credential records past it — one main-page erase
  per 35 and per 20 writes respectively. A replay now costs nothing at all. The LED
  is still applied live before the comparison, so a host sees no difference; a
  record written by an older firmware (13/9/3/2-byte layout) is not a match and is
  still upgraded. **This bounds only the replay**: a host that varies the block on
  every call still churns the same pages, on this command and on its ungated
  siblings. Closing that means re-taking the ungated-by-default decision across
  **both** writers of the record — `docs/protocol.md` §8 and
  `docs/threat-model.md` §1 record it as deliberate ykman parity — so it is left
  to the maintainer rather than half-applied here. **bcdDevice → 0x0950.**

- **A U2F command on a new CTAPHID channel no longer inherits another channel's
  applet selection under `rsk-emu`.** The MSG applet selection is one global for
  every channel and U2F has no SELECT of its own, so a board drops it when the
  channel changes as well as on a `CTAPHID_INIT` (audit run-34 #27, run-35). The
  emulator had only the INIT half — the one
  `tests/15_u2f_vendor_msg_isolation.py` drives — so another process's vendor-AID
  SELECT still sent a second channel's U2F REGISTER to `INS_INCREMENT`. It keeps
  the board's `last_msg_cid` now. Its two CTAPHID transports still share one
  channel-id space, so a socket channel and a USB/IP one with the same id are not
  told apart; that is recorded, not fixed.

- **A PIV object id resolves by its whole value, not its low sixteen bits.**
  `object_fid` matched `id & 0xFFFF` for the two Yubico objects, so the 2-byte id
  `FF01` — and `00FF01`, `7FFF01`, `ABFF01` — all read the **attestation
  certificate**, and `FF00` the ADMIN-DATA object. Same class as the `7F61` alias
  fixed one entry below, two lines from the line that fixed it, and found by the
  review of that fix. A YubiKey 5.7.4 resolves the exact three bytes and answers
  `6A82` to every masked spelling, measured 3 runs byte-identical. Read-only and
  both objects are ungated-read, so nothing was disclosed that a host could not
  already ask for by its proper name — but two ids sharing a file is the defect,
  not the consequence. The `5FC1xx` arm's mask was already exact and is now
  pinned too, because `read_needs_pin` matches an id **exactly**: a masked
  spelling that still resolved would have read a Table 3 object with no PIN.
  `data_object_fid`'s `0xF0` reservation — what keeps `5FC1F1` from being a
  second, management-key-only door to the attestation certificate
  ([limitations](docs/limitations.md) says there is none) — had no test at all and
  has one now. `bcdDevice` → `0x0925`.

- **The panel's "Protect mgmt key" keeps a touch gate the owner raised.**
  `protect_mgm_key` wrote `TOUCHPOLICY_NEVER` over whatever stood there, so a card
  whose owner had raised the `0x9B` gate with `SET MGM KEY P2=0xFE` came back
  touch-free after an on-screen protect — a second setting changed by an action
  asked for something else, and the one writer left over after `0x08F9`
  reconciled the others. It re-keys the slot, but the gate is a property of the
  slot rather than of the key bytes, so it now carries forward. Only a stored
  `ALWAYS` does: an absent head or a byte no writer emits still resolves to the
  published default, so a torn or spurious record cannot invent a gate through
  this path either. Panel-only, and no host path reaches it. `bcdDevice` →
  `0x0924`.

- **PIV `GET DATA 7F61` no longer returns whatever was written to `5FC1B6`.** The
  BIT group template and the data object `5FC1B6` shared one file: `object_fid`
  mapped `7F61` to `0xD2B6`, which is `5FC1B6`'s own fid. A management-key write
  to `5FC1B6` — an ordinary, ungated-read data object — therefore came back out of
  `GET DATA 7F61`, refuting the comment beside the mapping, which said a valid id
  with no data answers `6A82`. A YubiKey 5.7.4 answers `6A82` to `7F61` before and
  after that write, measured on both cards; `7F61` is never populated and is not
  writable on either card, so it now owns no file and answers `6A82` the way an
  unknown id already does. No security impact — both ends are ungated-read and
  management-gated-write — but two objects sharing a fid is a latent one.
  `bcdDevice` → `0x0923`.

- **An unauthenticated OpenPGP `PUT DATA` with an over-long body answers `6982`,
  not `6A80`.** The `MAX_DO_BYTES` gate — the cap DO `C0` announces — was checked
  above every ACL, so a body one byte past it was the last thing in this command
  that outranked the password; `0x08F3` had moved the tag below the ACL and left
  the length above it. A YubiKey 5.7.4 answers `6982` at 10, 2036, 2037 and 3000
  bytes on `5E`, `7A`, `D5`, `D3`, `C4`, `7F21`, `C1`, `0101`, `0103` and an
  unknown tag alike, 3 runs byte-identical. **The authorised half deliberately
  does not follow the card**: measured, it answers `9000` to an over-long chained
  write and silently keeps only `n mod 256` bytes (`n = 256` stores nothing at
  all), which is the one behaviour this project never copies — so an over-long
  write past the cap stays `6A80` with the DO untouched, and everything up to the
  cap still stores byte-for-byte. `bcdDevice` → `0x0922`.

- **PIV `CHANGE REFERENCE DATA` / `RESET RETRY COUNTER` answer `6A88` for a key
  reference they do not have.** Both answered `6A86`; a YubiKey 5.7.4 answers
  `6A88` — *reference not found* — on the P2 axis (`00`, `01`, `04`, `82`, `9B`,
  `FF`, plus `81` on `2C`) and on the P1 axis (`01`, `FF`) alike, at every body
  length, measured 3 runs byte-identical. Note the card is **not** consistent
  across its own PIN commands: `VERIFY`'s undefined reference is `6A80` on the
  same card in the same session, which is why this cell had to be measured rather
  than derived from its neighbour. No refusal on either command costs a retry,
  there or here. `bcdDevice` → `0x0921`.

- **A refused PIV `VERIFY` P1 answers `6A80`, the way the reference spells it.**
  `00 20 <P1> 80` with a P1 the command does not define answered `6A86`, and
  `00 20 FF 80` carrying a body — the status-reset form, which takes none —
  answered `6700`; a YubiKey 5.7.4 answers `6A80` to both (measured over P1
  `01`/`02`/`7F`/`FE` and over `FF` with 1- and 8-byte bodies, 3 runs
  byte-identical). It was the last `6700` in the PIN handlers. Neither refusal
  moves the standing PIN status on either card, and the one VERIFY refusal that
  *does* drop it — a malformed body at P1 `00` — is unchanged. `bcdDevice` →
  `0x0920`.

- **One touch ceremony can no longer hold the key for twice the touch timeout.**
  After a confirm, the wait for the finger to lift took a *fresh* copy of the
  configured window instead of what was left of the ceremony's own, so a press
  landing on the iteration the deadline would have fired on ran the request to 2×
  the timeout — 60 s on the default, and 8.5 minutes at the 255 s a host can write
  into `EF_PHY`'s `PresenceTimeout`. The worker is single-threaded, so every other
  request queues behind it, and the key keeps reporting `UPNEEDED` the whole
  time. The debounce now runs inside the remainder of the ceremony's budget,
  which is what `rsk-display`'s touch-panel ceremonies already did. A debounce
  that gives up early loses nothing the `spent` latch does not already carry —
  it is set from the button sample either way — and the release edge it leaves
  behind is the click counter's to discount, which is the fix above.
  **bcdDevice → 0x0903.**

- **A touch you were asked for no longer types a one-time password.** The idle
  click counter turns N presses into "type slot N", and a consent ceremony uses
  the same button. The worker cleared the accumulated click state when a dispatch
  ended — but a touch wait can return with the finger still down, and clearing
  counters cannot suppress an edge that has not happened yet, so the release of
  the press you had just made for a signature or a PIN was counted as one click
  and, a second later, typed slot 1's Yubico-OTP into whatever had focus. A
  ceremony now hands the counter the button's live level, and the release it
  produces is discounted once. The gesture itself is unchanged: a press made
  while the key is idle still counts. The logic moved to `rsk_device::click`,
  where it is host-tested. **bcdDevice → 0x0902.**

- **A PIV card whose `0x9B` metadata was lost no longer comes back demanding a
  touch.** `scan_files`' repair arm — the one that runs when the management key
  survived but its metadata head did not — wrote `TOUCHPOLICY_ALWAYS`, while all
  three other writers (the mint arm, `protect_mgm_key`, and `SET MGM KEY` at
  P2=`0xFF`) wrote `NEVER`. A repaired card therefore invented a touch gate its
  owner never set, and the only way back down (`SET MGM KEY`) needs a management
  auth that must first pass that same touch — so where the button cannot be
  reached, the only escape was blocking the PIN and PUK and running a RESET that
  wipes every PIV key. It was not even reachable only by a torn wipe: a transient
  `EF_META` read fault at the first SELECT of a power cycle enters the same arm on
  a perfectly healthy card. The repair is a re-provisioning, and every other record
  `scan_files` restores comes back at its published default, so the touch byte now
  does too — the value a YubiKey 5.7.4 reports on a fresh card, measured 3/3, and
  the one `docs/guides/piv.md` already documented. A card that raised the gate
  itself with `SET MGM KEY` P2=`0xFE` keeps it. `bcdDevice` → `0x08F9`.

- **Generating an OpenPGP keypair no longer destroys the AES key a host installed
  at DO `D5`.** The DEC arm of GENERATE minted a fresh AES-256 key over whatever
  stood there. That was harmless while the card was the only thing that could
  write `D5`; `PUT DATA D5` landed this week, and the same line became an
  unrelated operation quietly shredding host key material — everything encrypted
  under that key unrecoverable, with no error, and no way to read the DO back to
  notice. OpenPGP 3.4.1 makes `D5` card-level, not the DEC slot's: §7.2.12's
  PSO:ENCIPHER carries **no key reference at all**, so the card's one `D5` is the
  whole key material of a command that never touches the DEC slot, and §7.2.14
  lets GENERATE reset the signature counter and "other related DO (e. g.
  certificates)" — a DO with no per-slot instance is related to none of the three
  key pairs. GENERATE still seeds `D5` when it is **empty**, so the AES capability
  Extended Capabilities b2 announces works on a fresh card as before.
  `bcdDevice` → `0x08F8`.

- **The pre-commit hook's impact report is readable again.** `scripts/impact.py`
  read Rust's anonymous constant — `const _: () = assert!(…)`, an idiom this tree
  uses about eighty times — as a constant *named* `_`, and then answered
  `git grep -w _` with 2381 "unread use sites". It fired once for real, on the
  presence lift, printing beside the one report that mattered. A guard nobody can
  read is not a guard — the same failure as a proof nobody runs, one layer up.
  `_` is a hole and not a name now, in both the Rust and the Python paths, and
  the script has the mutation table it never had.

- **A const generic parameter is no longer read as a constant.** A
  `const N: usize,` alone on a line inside a multi-line `<…>` is spelled exactly
  like an item, and `scripts/impact.py` reported it — answering `git grep -w N`
  with 323 lines, the same unreadable shape the anonymous constant made. Only a
  parameter list carries on past the type with `,` or `>`; an item ends in `;`,
  or opens a bracket its value continues inside. No such parameter is in the tree
  today, so nothing changes about what the hook prints — it is closed before the
  first one lands, because the report it would ruin is the one nobody then reads.

- **A name too generic to grep no longer buries the finding beside it.** Some
  redefined constants really are called `N`, `HEADER` or `UNION`, and the site
  count under them is a whole-word `git grep` and nothing narrower — it crosses
  languages and prose, which is the entire reason the tool catches a Rust
  constant's Python and documentation copies. So the count cannot be made
  precise, and scoping the search by language would break the founding case. What
  can be fixed is the burial: the report is ordered narrowest-first instead of
  alphabetically, so the six sites worth reading are no longer printed under
  three hundred that are not, and the list says what the number is where it cuts
  off at twenty.

- **`bcdDevice` skips twice, past numbers parallel branches had already spent —
  to `0x08F7` and then to `0x0952`.** Conformance work ran in separate worktrees
  on reserved ranges so that no branch computed its next value from a base
  another was moving, which is what produced three collisions the day before.
  The reservations held both times; the assumption about *landing order* did
  not, and the lower-numbered branch landed second on each occasion, leaving the
  tip reporting a lower counter than commits behind it. No released image ever
  carried the skipped values. The risk is a bench one: a board flashed from an
  intermediate commit and one flashed later could answer `ioreg` with the same
  number and not be the same firmware, and reading that number is how a flash is
  verified here. Each skip starts above every value the history has used, which
  ends it without renumbering landed commits off a moving base — the operation
  that caused the original collisions. Behaviour is unchanged by either.

- **PIV `GENERAL AUTHENTICATE` dispatches on the first operation tag the body
  carries, and an empty `81` at a key slot is a private-key operation.** Three
  faults in one dispatcher, all measured against a YubiKey 5.7.4 three runs each.
  `7C 02 81 00` at a provisioned key slot returned sixteen random bytes under tag
  `81` — a host that does not check the tag reads them as a signature — where the
  card should sign; the oracle answers `7C 49 82 47 3045…`, a real ECDSA
  signature, and spends the PIN freshness for it. Tag precedence was a fixed
  table rather than body order, so an ordinary ECDH request that happened to
  carry an empty `81` got those random bytes instead of the shared secret: the
  oracle signs for `7C .. 82 00 81 00 85 <point>` and agrees for the same body
  with `85` first, and now so do we. And a body carrying no operation the card
  recognises — an unknown tag, a truncated TLV inside the template, a lone empty
  response placeholder, or mutual auth asked at a key slot — answered `9000`
  having done nothing, where the oracle answers `6A80`. An empty or unusable `85`
  point now reaches the key before it is refused, which is both the oracle's
  answer (`6A80`) and its accounting (the freshness is spent, because the request
  got as far as the key). At `9B` an empty `81` is still the single-auth
  challenge the arm exists for.

  Swept with it, because the dispatcher stated the principle and then broke it:
  every "this key is not that algorithm, or this operation is not for this slot"
  refusal now answers `6A80` and spends nothing. Measured across nine cells, two
  runs — a P-256 slot addressed as ECCP384, RSA-2048 or Ed25519; an ECDH asked at
  `9B` or at an RSA/AES slot; an empty `81` at a key slot under any symmetric
  algorithm; a mutual-auth step 2 whose tags arrive reversed — where ours answered
  `6A86`, and `6581` on the RSA arm, whose seal read ran first. The check has one
  owner now, ahead of the touch prompt and the key load, which also closes a hole
  the RSA arm carried on its own: it had **no** algorithm check at all, so an
  RSA-2048 request at an RSA-3072 slot loaded the 3072 key and spent the PIN
  freshness before refusing on length. **bcdDevice → 0x08D9.**

- **A key in a retired PIV slot is no longer a one-way trip, and
  `GET METADATA f9` answers.** Two narrow gates, both measured against a YubiKey
  5.7.4 three runs each. `MOVE KEY` refused retired → active with `6A86`, so a
  key parked in `82`–`95` could never come back to `9a`/`9c`/`9d`/`9e`; the
  oracle allows both directions (`82 → 9a`, `9a → 82`, `82 → 9c` all `9000`) and
  Yubico documents no direction restriction. The refusal carried no reason, and
  a self-move — the case that would destroy a key — is refused separately and
  still is. `GET METADATA` at the attestation slot answered `6A88`, "referenced
  data not found", on a card that mints that key and its self-signed certificate
  at first boot: the slot simply keeps no metadata record, because `is_key(0xf9)`
  is false and nothing had needed one. The head is now synthesized rather than
  stored — every field is fixed by construction, an on-card ECCP384 key that is
  always generated — so a card provisioned by an older build answers exactly as a
  fresh one does, with no flash migration. A slot whose key is gone still reports
  it gone. **bcdDevice → 0x08D8.**

- **`GET METADATA 9B` reports one PIN policy instead of two.** Slot `9B` is the
  management key, not a key slot: `is_key(0x9B)` is false in both the PIN gate
  and the freshness spend, so its stored pin-policy byte gates nothing. Two
  writers filled the field in anyway and disagreed — first provisioning wrote
  `ALWAYS`, the trusted display's *Protect mgmt key* wrote `NEVER` — so which one
  a card reported depended on its history, and nothing in the tree tied them
  together (`scripts/impact.py` cannot see this class: no constant's value moved).
  A YubiKey 5.7.4 reports `0x00` there in every state — fresh, escrowed, after a
  host rotation — measured two runs, which is also the honest value for a slot
  with no policy to report. One named constant now, and a test that drives all
  three paths into the record. **bcdDevice → 0x08D7.**

- **A PIV key import takes a private scalar of exactly the field length.** The
  length was bounded from above only, so `IMPORT` accepted a one-byte P-256
  scalar, stored it, and then signed with it — `d = 1`, a key anyone can forge
  against — and it accepted 32 bytes declared as P-384 as a P-384 key. A YubiKey
  5.7.4 answers `6A80` to every length but the curve's field: measured 1, 2, 31
  and 33 bytes on P-256 and 32 and 47 on P-384, three runs each. Left-padding a
  short value is the host's job, because a host that got the length wrong got the
  key wrong. Ed25519 and X25519 imports take the same rule at 32 bytes. It needs
  the management key and the host chose the bytes, so this is conformance and
  fail-fast rather than a hole — but a slot quietly holding a key nobody meant to
  import is worth refusing. **bcdDevice → 0x08D6.**

- **`PUT DATA 5FC109` (PRINTED INFORMATION) stored nothing and said `9000`.**
  `ykman piv objects import 5fc109 …` followed by `export` did not round-trip, and
  any host that put real printed information there lost it silently — the read
  answered `6A82` even with the PIN. A YubiKey round-trips it, measured. It is an
  ordinary data object now, PIN-gated for reading like its three Table 3 siblings.
  One shape is still acknowledged and deliberately **not** stored: a body that is
  exactly a PivmanProtectedData escrow record (`88 L { 89 L <key> }`, what
  `ykman piv access change-management-key --protect` writes there). The key it
  carries is already sealed in the `0x9B` slot that `GET DATA` synthesizes the
  reply from, and persisting the host's copy would leave a management key in
  plaintext at rest, which is the whole reason this card synthesizes rather than
  stores. The match is on that exact shape — length-consistent, no trailer, a real
  management-key length — so printed information that merely carries those tags is
  stored like anything else. While the escrow is live, PRINTED *is* the escrow:
  the read answers with the key, and a write of other content is refused with
  `6985` rather than accepted and hidden under it. That is also how this avoids
  the YubiKey's behaviour in the same spot, which takes the write and destroys the
  only copy of a management key its owner may never have seen. An escrowed card
  therefore reads back exactly what it did before. **bcdDevice → 0x08D3.**

- **A PIV `PUT DATA` that deletes no longer answers `9000` when the delete
  failed.** The store half already mapped a refusing flash write to `6581`; the
  delete half dropped the result on the floor, so a host wiping fingerprints, an
  iris image or printed information off a card got the word that says they are
  gone while they were still there. Same class as the entry above, and after it
  those objects hold real data.

- **The OpenPGP sex DO `5F35` now holds a code the card will take back.** We
  seeded `'0'` (ISO 5218 "not known") at first boot and accepted it on
  `PUT DATA`; a YubiKey 5.7.4 answers `6A80` to `'0'` and holds `'9'` ("not
  applicable") itself — six readings across two independent resets — so its
  default is a member of its own accepted set and a host can read `5F35` out of
  DO `65` and write the same byte straight back. Ours could not, once the set was
  narrowed, which is a read-modify-write `gpg --edit-card` actually performs. The
  accepted set is now `{'1','2','9'}` and the first-boot default is `'9'`.
  **Upgrade path**: a card provisioned by an older build holds `'0'`, so boot
  settles it to `'9'` — a one-time repair in the same family as the PW-status
  maxima below, guarded by a read of the DO, so the boot after it writes nothing
  and a store that refuses the write leaves the old byte for the next boot to
  retry. It runs **after** the other boot repairs rather than beside the first-boot
  seeds, because it is the only write an already-settled card makes and a failure
  must not skip the resetting-code repair that precedes it. The write coerces *any*
  byte outside the set, not just `'0'`: the cost is identical and it also settles a
  record some other build left.
  **The honest cost**: ISO 5218 distinguishes `0` (not known) from `9` (not
  applicable), so the repair does change a stated meaning, and the card cannot
  tell a `'0'` it wrote by default from one a cardholder deliberately chose — the
  old firmware accepted `'0'` from a host. Both codes are non-answers rather than
  data, `'0'` was our own invention, and the alternative is a byte the card reads
  out and refuses back. **bcdDevice → 0x08F2.**

- **`PUT DATA D5` installs the AES key, so the capability the card announces can
  be completed.** Extended Capabilities byte 1 bit 2 says this card does PSO:DEC
  and PSO:ENC with AES, and OpenPGP 3.4 §7.2.11 makes DO `D5` the way a host
  supplies that key. We announced the bit, implemented both operations, and had no
  `D5` handler at all — the tag fell through to `6B00` — so the only AES key those
  operations could ever use was the one `GENERATE` mints internally on the DEC
  slot, which no host can supply or replace. `D5` now takes PW3 and exactly the two
  widths §7.2.11 gives that key, 16 (AES-128) or 32 (AES-256); every other length,
  the empty write included, is `6A80` with the standing key left in place. A
  YubiKey is no help here and is not being followed: it answers `6B00` to
  `PUT DATA D5` in every state, has no AES PSO at all, and leaves the capability
  bit clear — self-consistently. Ours was the inconsistent card, and the spec is
  the reference where our functionality is wider.

  Three consequences worth reading before relying on it, none of them silent any
  more. §7.2.11 gives `D5` no deletion, so **an installed key cannot be removed** —
  only overwritten, replaced by a DEC keygen, or cleared by `TERMINATE DF`; an
  empty write that disarmed an announced capability would be the worse silence.
  **Regenerating the encryption keypair replaces the key**, because that is how a
  holder retires the slot's secrets; `keytocard` (IMPORT) does not, and the two are
  pinned apart by a test now. And `GET DATA D5` answers `6982`, not `6A88`: the DO
  is READ = *Never* per §4.4.1 and is an internal EF like every other sealed slot —
  before this it reported "no such object" for an object the card would now accept.

  The key is checked byte-for-byte, not by round-trip: the host suite compares the
  cryptogram against an independent AES-CBC implementation, and the gate's own test
  carries the FIPS-197 §C.1/C.3 vectors (a zero-IV CBC of one block is that block
  under ECB), which is what catches a silent AES-256 → AES-128 truncation that two
  round-trips cannot see. **bcdDevice → 0x08F6.**

- **IMPORT judges the password before the key slot, finishing the `PUT DATA`
  sweep.** `0x08F3` moved that judgement ahead of the tag on `PUT DATA` (`0xDA`)
  and stopped one instruction short. IMPORT (`0xDB`) carries its target — the
  control-reference template naming the key slot — inside the body, and the body
  was parsed first: an **unauthenticated** caller got `6A80` for a template the
  card does not know and `6982` for one it does, which enumerates the accepted
  slot set `{B6, B8, A4}` and the header framing exactly as the `6B00`-vs-`6982`
  split enumerated the writable DOs. It answers a flat `6982` now, whatever the
  body says. Unmeasured on a YubiKey — the reference was measured on `0xDA` — so
  this cell follows by class rather than by measurement, and the test says so.
  Two comments recording that measurement are corrected in the same breath: both
  read as if `6B00` were the card's answer everywhere, when it was taken with PW3
  verified, and one of them is the twin the `0x08F3` commit qualified while
  leaving its sibling alone. **bcdDevice → 0x08F5.**

- **OATH `SET CODE` with no body at all is `6A80`, not "remove the access code".**
  A YubiKey 5.7.4 refuses a body-less `SET CODE` and removes a code only for the
  `73 00` spelling — the one ykman actually sends, and the one RS-Key already
  implements. The earlier entry above kept the body-less form because YKOATH's own
  document says "if length 0 is sent, authentication is removed"; measured against
  the card, that sentence describes the `73` value's length and not the APDU's.
  Reversing it costs no functionality and loses nothing: the removal a host
  actually performs still works, and the refusal leaves the standing code opening
  the applet rather than dropping it — checked both ways, including that an
  unvalidated session still meets `6982` first and cannot use the refusal as a way
  past the gate. **bcdDevice → 0x08F4.**

- **PUT DATA judges the password before the tag.** The command carries its target
  in P1P2, and ours resolved that target first: an **unauthenticated** caller got
  `6B00` for a tag the card cannot write, `6985` for the signature counter and
  `6982` only for a tag it can — so the writable-DO set could be enumerated
  without a PIN by the codes alone. A YubiKey 5.7.4 answers a flat `6982` to every
  tag until PW3 is verified, and only then tells `6B00` (not a writable target)
  from `9000` — measured over `D5`, `C5`, `CD`, `7A`, `5E`, and two tags it does
  not know at all, 3 auth states x 3 runs. The judgement moves ahead of the
  resolution, so the pre-PW3 column is now flat here too, including the signature
  counter the measurement never covered. Low impact — the writable set is public
  in the card spec — but it is a wire divergence on unauthenticated input, and the
  in-tree comment that recorded the `6B00` measurement said nothing about the
  state it was taken in; it does now. **bcdDevice → 0x08F3.**

- **An explicit `0` PIN- or touch-policy byte in a PIV key template is refused.**
  On the wire, "default" is expressed by *omitting* the `AA` / `AB` tag. Sending
  the tag with value `0x00` is a different thing, and a YubiKey 5.7.4 treats it as
  an undefined value: `6A80`, indistinguishable from `0xFF` — measured 3/3 on `9E`
  and `9A`, with and without the sibling tag, against controls (`0x01`, `0x05`,
  `0xFF`) that behave identically on both cards. Ours mapped `0x00` onto "default"
  and resolved it, so a template the reference rejects produced a key. It now
  answers `6A80`. Nothing a host sends changes: `ykman` and `yubico-piv-tool`
  express "default" by leaving the tag out, which is why the no-tag row is
  byte-identical to the old `--pin-policy default` row. IMPORT reads the same two
  tags through the same resolver and follows by class — no YubiKey reading exists
  for an imported `AA 01 00`, and one byte must not mean two things on two commands
  of one card.

  Two orderings move with it, both audit run-36's rule that a refusable request is
  judged before it is acted on. **IMPORT resolved the policies after storing the
  key**, so a refused template — `0x05` or `0xFF` before this change, and now the
  `0x00` a naive host is most likely to send — left the slot's previous key
  overwritten, its metadata record deleted and never re-added, and every later
  GENERAL AUTHENTICATE, GET METADATA and attestation on that slot answering `6A88`.
  The resolution is hoisted above the first write, as GENERATE already did, so a
  refusal now leaves key, certificate and metadata exactly as they were. And the
  blocking RSA GENERATE resolved after the prime search, buying a full RSA-4096
  keygen before answering `6A80`; it judges first now.
  Unchanged and deliberate: a literal `0` an **older build already stored** in a
  slot's metadata still resolves at use time, which is a different owner of the
  same byte. **bcdDevice → 0x08F1.**

- **A makeCredential or getAssertion that named an unsupported PIN/UV-auth
  protocol was told about something else.** The protocol was judged inside the
  PIN gate, which runs after the algorithm check, the option checks and the
  extension checks — so a request that got two things wrong learned about the
  second one and could keep resending the protocol the key had already refused. A
  YubiKey 5.7.4 puts that judgement earlier: measured against a bad algorithm, an
  empty `pubKeyCredParams`, `options.rk` and an hmac-secret missing its salts, it
  answers `CTAP1_ERR_INVALID_PARAMETER` to every one of them, on both commands.
  Ours does now too, judged once at the top and passed down rather than
  re-derived. This finishes the sweep started in `0x089D`, which moved the same
  judgement ahead of the selection gesture on these two commands and ahead of
  everything on the other five. Only a request naming a protocol other than 1 or
  2 changes: those were errors before and are errors now, with the code that
  names the actual cause. Two things still outrank it, both because that card
  puts them there: the request map's own shape — an absent mandatory key is
  `MISSING_PARAMETER` before any value is looked at — and the option *values* of
  §6.1.2/§6.2.2 step 4, so `up:false` and a bare `uv:true` stay
  `CTAP2_ERR_INVALID_OPTION` whatever the protocol says (eight readings each,
  with and without a `pinUvAuthParam`). **bcdDevice → 0x08BD.**

- **A credential asked for under a curve-explicit COSE id came back stamped with
  a different one.** `pubKeyCredParams` offering only ESP256 (`-9`), ESP384
  (`-51`), ESP512 (`-52`) or Ed25519 (`-19`) registered a credential attesting
  `-7`, `-35`, `-36` or `-8` instead — the id the site asked for was quietly
  folded onto its classic spelling. That is the one answer nothing supports:
  WebAuthn L3 §7.1 has the relying party check the returned key's `alg` against
  the list it sent, so such a site had to fail its own registration, and with
  `rk` set it had already burnt a discoverable-credential slot doing so. The
  attested key now carries the id the request selected. A YubiKey 5.7.4 answers
  `CTAP2_ERR_UNSUPPORTED_ALGORITHM` to all four — measured across two
  authentication states and re-measured from a second instrument — because its
  supported set is exactly its advertised set; ours is deliberately wider, as it
  already is for `-36`, `-47` and ML-DSA `-48`/`-49`, so §6.1.2 step 3 governs and
  the chosen id is the one the element specified. The four stay **unadvertised**
  in getInfo, on the same terms as `-8` and `-47`. A site offering both spellings
  gets whichever it lists first. Credentials already created keep working
  untouched: assertions select the key by curve, not by `alg`. One record change,
  compatible both directions — a curve-explicit id on P-256 is now stored (key 9),
  where before only a non-default curve was; an absent key 9 still reads as
  ES256/P-256, so a box an older build wrote is unchanged and one this build
  writes for `-7` is byte-identical to before. **bcdDevice → 0x08BC.**

- **OATH `CALCULATE`, `VALIDATE` and `SET CODE` accepted bodies the host did not
  mean.** All three found each tag anywhere in the data field and ignored
  whatever else was there, so a duplicate tag (which of the two is the key?), a
  reordering and trailing junk all came back `9000`. A YubiKey 5.7.4 reads them
  by position — exactly the documented TLVs, in the documented order, nothing
  before, between or after — and answers `6A80` to every one of those. The
  orders are `71 74` for `CALCULATE`, **`75 74`** for `VALIDATE` (the response
  really does come first) and `73 74 75` for `SET CODE`, with a lone `73 00`
  still removing the access code; `CALCULATE ALL` keeps the card's one
  exception, where the `74` must be first and the rest is ignored. Same class as
  the `PUT` grammar that shipped earlier. Checked before tightening: ykman 5.9.2
  (`yubikit/oath.py`) and the vendored pico-fido suite send exactly these
  orders, `tools/rsk` and the TUI have no OATH path, and the in-tree suites
  built two of them the other way round — those were ours, and are corrected.
  The password-safe commands (`B1`..`B5`) are left as they were: no YubiKey
  implements them, so there is nothing to match. **bcdDevice → 0x08BB.**

- **The OATH applet read `P1` in no command and `P2` in two.** A YubiKey 5.7.4
  judges both for every command and answers **`6B00`** — not the `6A86` we sent.
  We accepted `P1 = 01` outright (`9000`), so a host's typo in the parameter
  bytes came back as a completed command; `RESET` was the one place `P1` was
  looked at at all. The rule now lives in one place the whole table passes
  through, ahead of each command's body and its access-code gate, so a refused
  pair writes nothing: `00 00` everywhere, `00 01` on `CALCULATE` and `CALCULATE
  ALL` alone (the card refuses that byte on `PUT`, `DELETE`, `SET CODE`,
  `RENAME` and `LIST`, where it used to complete the command here), `DE AD` for
  `RESET`, and `VALIDATE` as the card's own exception — it refuses only when
  both bytes are non-zero. Anything else is `6B00`, and an instruction the
  applet does not implement still answers `6D00` first, per ISO 7816-4 §5.3.4.
  ykman 5.9.2 and the vendored YKOATH suite send exactly the accepted pairs,
  the password-safe commands (`B1`..`B5`) included. **bcdDevice → 0x08BA.**

- **OATH `SET CODE` took a proof carried over a challenge of any length.** The
  host proves it knows the code it is installing by HMACing a challenge of its
  own choosing, and we HMACed whatever it sent — one byte included, which is
  one byte of margin for a proof whose whole job is to stop a code being
  installed by something that cannot compute with it. A YubiKey 5.7.4 accepts
  **exactly 8 bytes**, the width of the challenge it hands out itself, and
  answers `6A80` to every other length with the installed code untouched.
  `ykman` 5.9.2 and Yubico Authenticator send `os.urandom(8)`, the vendored
  YKOATH suite's three `SET CODE` calls are already listed as divergences on an
  earlier rule, and *removing* a code is judged before the challenge is read — so
  nothing that works today starts being refused. (This entry said "both ways of
  removing"; the body-less spelling is refused now, see below.)
  **bcdDevice → 0x08B9.**

- **A wrong OATH access code answered the word for "there is no access
  code".** `VALIDATE` (`0xA3`) refused a proof that did not match with `6984`,
  which is the same status the applet returns when nothing is installed to match
  against. A YubiKey 5.7.4 keeps the two apart: `6A80` for a proof that does not
  match — right length or truncated — and `6984` only for "no such object",
  measured twice at every challenge width. A host that got `6984` could not tell
  whether it had the wrong password or the card had none, and the two want
  opposite next steps. `SET CODE`'s own proof check is unchanged: `6984` there
  is the card's answer too. **bcdDevice → 0x08B8.**

- **A truncated OATH `CALCULATE` carried the raw 31-bit truncation, not the
  code.** RFC 4226 §5.3 makes an OTP the dynamic truncation *reduced to the
  account's digit count*, and a YubiKey 5.7.4 sends the reduced value: same
  secret, same challenge, same 6-digit credential, the card answers
  `76 05 06 00 0A 46 83` (673411) where we answered `76 05 06 00 28 CB 03`
  (2673411, the truncation itself), measured twice at 6 and at 8 digits. `ykman`
  and Yubico Authenticator reduce host-side, so they showed the right code
  either way; a strict YKOATH client saw ten digits where a YubiKey shows six.
  Our own applet did not agree with itself either — `VERIFY CODE` (`0xB1`)
  compares the *reduced* code, so feeding `CALCULATE`'s four bytes straight back
  into it was refused. Both read paths (`0xA2` and `0xA4`) build their response
  through one function, and the modulus is the one `VERIFY CODE` already used. A
  credential stored by a build from before `PUT` bounded digits to 6/7/8 has no
  modulus and keeps answering with the bare truncation rather than becoming
  unreadable. **bcdDevice → 0x08B7.**

- **OATH `CALCULATE ALL` computed a different code from `CALCULATE` for the same
  credential and the same challenge.** The bulk read clamped the challenge to its
  first 8 bytes, on a comment asserting the spec said 8; the individual read
  hashed all of it. A YubiKey 5.7.4 does neither: it takes the challenge as an
  opaque **0..=64-byte** string, HMACs exactly what it was sent on both paths, and
  answers `6A80` from 65 — measured at 0, 1, 7, 8, 9, 15, 16, 20, 32, 62, 63, 64,
  65, 66, 80, 100, 127, 128 and 200 bytes, three readings each. So a host reading
  one account two ways got two answers for every challenge over 8 bytes, and a
  challenge no card would accept got a code out of us instead of a refusal. The
  bound now sits in one place both commands pass through, before the credential
  lookup (a name that does not exist and a 65-byte challenge is `6A80`, not
  `6984`) and after `P1`/`P2`, and the paging stash carries the whole challenge so
  a `SEND REMAINING` page cannot answer a different code from the first frame.
  This also settles the `only increasing` mark: it has always been compared
  against the challenge the host sent, so a clamped code meant the mark recorded
  bytes no code was ever computed from — the two are now the same bytes. The
  stored mark stays a fixed 64 bytes, so a mark an older build wrote is still
  readable; a compile-time assertion holds the challenge bound at or below it.
  **bcdDevice → 0x08B2.**

- **The resetting-code write keeps its own refusal word.** The judgement that a
  new password is out of range has one owner, and moving it from `6700` to
  `6985` moved all three of its callers — but only CHANGE REFERENCE DATA had
  been measured. A YubiKey 5.7.4 answers `6985` for CHANGE REFERENCE DATA and
  for RESET RETRY COUNTER under either P1, and `6A80` for `PUT DATA D3`: the
  resetting code is not offered to a VERIFY-shaped command, it arrives in PUT
  DATA's data field. Only that one call site is named differently; the range
  itself still has a single owner. The same measurement confirms the resetting
  code's minimum length is 8, which is what the card already enforced.
  **bcdDevice → 0x08B1.**

- **The on-card RSA keygen no longer escapes the class-byte rule.** Both RSA
  GENERATE fast paths — the ones the firmware runs off the dispatcher so the
  prime search can use both cores while the transport streams time extensions —
  are entered before `Dispatcher::process`, so the class byte it judges was not
  judged for them. On a build with the accelerator that made GENERATE the one
  command a secure-messaging class still executed: `04 47 …` generated a key and
  answered `9000` where every other command answers `6E00`, and `10 47 …` was
  executed outright instead of being accumulated as a chain segment. Measured on
  a YubiKey 5.7.4: `04 47 00 9A …` is `6E00` where `00 47 …` is `6982`, and
  `10 47 …` answers `9000` with the next command reporting `6883`. Both fast
  paths now fall through to normal dispatch for those classes, which is what
  answers them. A host build has no accelerator, so nothing changes there.
  **bcdDevice → 0x08B0.**

- **A power cut during OpenPGP's first boot is no longer permanent.**
  Provisioning writes the data-encryption key twice — sealed under the default
  user PIN, then under the default admin PIN — under a single "none of the copies
  exist" guard. A cut between those two writes made the guard false on the next
  boot, so the admin copy was never created, while the admin verifier further down
  still went in: PW3 then verified for ever over a key copy that did not exist,
  every operation needing it answered `6A88`, and TERMINATE DF was the only way
  out. The pair is judged together now, and only while neither verifier exists —
  past that point the card has been provisioned and a missing copy is a lost
  record rather than an interrupted first boot, where regenerating the key would
  throw the keys away. Nothing can be lost inside the window this does cover: no
  key can exist before the first boot finishes. Same two-record class as the PIN
  update fixed earlier, with a far narrower trigger and a worse outcome. The test
  drives the real provisioning with the flash dying at every write it makes, then
  boots again on the same flash and requires both PINs to open the same key.
  **bcdDevice → 0x08AF.**

- **The cardholder DOs are held to the shapes the spec gives them.** PUT DATA of
  the name (`5B`), the language preference (`5F2D`) and the sex (`5F35`) took any
  length and any content: a 255-byte name and a `5F35` of `'A'` both stored with
  `9000`. §4.4.1 caps the first two at 39 and 8 bytes and §4.4.3.4 gives the third
  the ISO 5218 code set, and a YubiKey 5.7.4 enforces all three — one byte over
  either cap is `6A80` with the DO untouched, and `'A'` is `6A80` on length 1, a
  content refusal rather than a length one. This is the same class as the
  fingerprint and timestamp gate that shipped earlier, on the DOs it did not
  sweep. Clearing a DO still works: these are caps, not fixed widths. It also
  closes a quiet display bug — the cardholder reader that feeds the trusted panel
  carries an 8-byte language field, so a longer one was already being shown cut.
  **bcdDevice → 0x08AE.**

- **A new password of an out-of-range length is refused with `6985`, not
  `6700`.** The APDU carrying it is perfectly well formed; it is the value inside
  that the card will not take, and `6700` "wrong length" sends a host looking at
  its own framing. Measured on a YubiKey 5.7.4, 3/3 on both references and at
  every boundary — `6985` for 0, 1 and 5 on PW1, for 0 through 7 on PW3, and for
  128 and 200 on both, with no retry spent. One owner: `CHANGE REFERENCE DATA`,
  `RESET RETRY COUNTER` and the reset-code write all judge a new value through
  the same check, so all three now say the same thing.
  **bcdDevice → 0x08AD.**

- **PIV VERIFY of an undefined key reference answers `6A80`, not `6A88`.** SP
  800-73-4's VERIFY response table lists `6982`, `6983`, `6A80`, `6A81`, `6A86`,
  `63 00` and `63 CX` — `6A88` appears nowhere in it — and a YubiKey 5.7.4
  answers `6A80` to every P2 but `80`, in both the case-1 and the `Le` form. Ours
  said "referenced data not found". The oracle and the spec agree against us, so
  this one is a straight correction. (The neighbouring cell that *looked* like the
  same class is not one: the empty-`Lc` status query answers `6983` when the
  counter is exhausted, which is what a YubiKey does on PIV and the opposite of
  what it does on OpenPGP — measured in both latch states, and our four cells are
  already right.)
  **bcdDevice → 0x08AC.**

- **A P1P2 that names something a command cannot address now answers `6B00`.**
  PUT DATA of `C5`, `C6`, `CD` or `7A` — the computed aggregates a host reads out
  of `6E`/`73` and only *looks* able to write — answered `6A88` "referenced data
  not found", as did an unknown tag, and SELECT DATA of occurrence 3 or 4 did the
  same. But the tag is this command's P1P2, and so is the occurrence, so the
  wrong-parameter code is the accurate one: a YubiKey 5.7.4 answers `6B00` to
  every one of those (measured 3/3, with occurrences 0-2 still `9000`). An
  unknown *tag* in SELECT DATA's data field keeps `6A88`, which is where it
  belongs. Two exceptions stay as they were and are noted rather than swept: the
  signature counter refuses its write with `6985` because that DO exists here and
  is write-never (a YubiKey does not serve it standalone at all), and GET DATA of
  the aggregates keeps working — a wider surface than the oracle's, which the
  spec permits and no host is hurt by.
  **bcdDevice → 0x08AB.**

- **DO `0xFA` no longer advertises two algorithms nothing can use.** X448 and
  Ed448 were listed among the supported per-slot attributes while GENERATE and
  IMPORT refused them outright — and because the write gate accepts exactly what
  that list advertises, `PUT DATA C1` of Ed448 *succeeded*: the attribute stuck,
  `gpg --card-status` reported Ed448 for the slot, and every operation on it
  failed until a good attribute was written back. §4.4.3.9 makes DO `0xFA` the
  machine-readable contract a terminal is told to use for key import, so an entry
  in it is a promise; no host reads the guide that documented the exception.
  Dropping the two costs nothing — nothing could use them — and closes the trap in
  the same move, because the writer and the advertisement have been one list since
  audit run-33. Measured on a YubiKey 5.7.4: it refuses every unadvertised
  attribute with `6A80` and leaves the DO unchanged, so the state ours could reach
  cannot exist there.
  **bcdDevice → 0x08AA.**

- **A password of a length no password could have no longer costs a retry.**
  VERIFY compared whatever it was handed: a one-byte or 200-byte value against a
  6-to-127-character reference was treated as a wrong guess, so it spent a try and
  dropped an already-entered PIN. Three of those block the reference. Measured on
  a YubiKey 5.7.4, 3/3 at every boundary: PW1 and the reset code below 6 or above
  127, and PW3 below 8 or above 127, answer `6A80`, spend nothing, and leave the
  standing access status up — and the length is judged before the blocked check,
  not after. Ours now does the same, in the one place all three of VERIFY, CHANGE
  REFERENCE DATA and RESET RETRY COUNTER compare a reference. **The gate applies
  only where the stored reference is itself inside the policy:** `PIN_MAX_LEN`
  arrived in a build that *added* the length check, so an older one stored
  whatever it was given, and this guide promises a shorter legacy value keeps
  working — refusing it would lock an owner out of their own key, which is never
  the parity answer. What is refused is the published policy and never the stored
  length itself; refusing exactly the lengths that cannot match would tell anyone
  holding the card how long the password is.
  **bcdDevice → 0x08A9.**

- **OpenPGP key IMPORT is now held to the slot's algorithm attribute.** The RSA
  arm read that attribute only to decide "RSA or EC" and never compared a length,
  so a 1024-bit key imported cleanly into a slot announcing RSA-2048 — and the
  card then gave two different answers about the same key: `C1` kept saying 2048
  while the public-key DO published the real modulus, with `gpg --card-status`
  printing the attribute. §4.4.3.12 makes the match a `shall`, and a YubiKey
  5.7.4 enforces it: 1024, 3072 and 4096 against a `C1` of 2048 are each `6A80`
  with nothing stored. IMPORT also reads the attribute through the same owner
  GENERATE uses, so an attribute this build does not advertise — one a
  pre-gate build could have stored, since `EF_ALGO_PRIV*` has no default and no
  migration — refuses both doors into the slot, not just one. The guide promised
  this refusal already and was wrong about the size, which was the case a user is
  most likely to hit; it is corrected, and it now also records that **RSA-1024 is
  advertised and works here** (a YubiKey offers no such thing) and should not be
  chosen for a new key.
  **bcdDevice → 0x08A8.**

- **Re-selecting the application you are already on no longer throws away the
  PIN.** Both OpenPGP and PIV reset their whole security status on every SELECT,
  including a SELECT of their own AID — so a host that re-selects before each
  command (several do) was made to ask for the PIN again and again, and the
  symptom reads as "the card keeps asking", which nobody files as a conformance
  bug. Both specs say the opposite in as many words. SP 800-73-4 Part 2 §3.1.1
  makes it a `shall`: with PIV current and the requested AID the PIV AID "or the
  right-truncated version thereof", "the setting of all security status
  indicators in the PIV Card Application shall be unchanged". OpenPGP 3.4.1 §4.2
  gives the access status "up to a RESET of the card, a SELECT to a **different**
  DF or an internal resetting", and §7.2.2 repeats it for PW1 82 —
  `rsk-openpgp` even quoted that sentence and then did the opposite. Measured on
  a YubiKey 5.7.4, 3/3 on both applets, including the right-truncated AID: a
  re-SELECT keeps everything and an unsupported AID never reaches an applet at
  all. **This holds authentication longer than before** and is a deliberate
  relaxation, so the two SELECTs that must still clear are pinned by the same
  tests: a different valid AID, and an ICC power cycle.
  **bcdDevice → 0x08A6.**

- **DO 7F66 now announces the APDU the transport can actually carry.** OpenPGP's
  extended-length information said 2047 command / 2048 response bytes while one
  CCID frame carries 2038, and §7.7 tells a host it may send exactly what that DO
  says — so the nine byte-lengths in between were licensed by the card and
  refused by its own reader, with no applet ever seeing them. §4.1.3.1 defines
  the pair as "the total amount of bytes sent to or received from the card in any
  command", header and lengths included, so the number to announce is the frame:
  2038, in both directions. It is now derived from one named constant instead of
  written out twice, and `rsk-device` — the only crate that sees both `rsk-openpgp`
  and `rsk-usb` — carries the compile-time assertion tying it to
  `MAX_CCID_MSG - HEADER`, so the two cannot drift again. Measured against a
  YubiKey 5.7.4: it announces 3070 and carries 3062, so the exact-fit property is
  not something the oracle demonstrates — the spec and the arithmetic are what
  decide it. Also measured, and *not* changed here: past its limit the YubiKey
  answers `6700` and the card lives; ours answers `6F00` and resynchronises, and
  the software emulator hangs up instead — recorded rather than fixed, because
  the transport's accumulator has no host-testable seam.
  **bcdDevice → 0x08A5.**

- **A command asking for secure messaging is refused instead of executed in the
  clear.** The class byte was nobody's business: OpenPGP and PIV never looked at
  it at all, so `04`, `0C`, `84` and `8C` — the ISO 7816-4 encodings that say
  "this exchange is secured" — ran as if they had been `00`, returning the real
  answer with `9000`. A client that believes it negotiated secure messaging got
  an unprotected exchange and had nothing in the response to tell it apart, and
  this card announces secure messaging **unsupported** (OpenPGP Extended
  Capabilities, bit 8 of byte 1 clear). The class is now judged once, in the
  dispatcher, before any applet or SELECT sees the command: chaining (bit `0x10`)
  is examined first and wins outright, then `CLA & 0x0C` answers `6E00`.
  Measured against a YubiKey 5.7.4 on PIV, OpenPGP and OATH: it answers `6E00` to
  `04` and `84`, serves `00`, `80`, `40` and `C0`, and takes `1C`, `90` and `FF`
  as plain chaining segments — so refusing `1C` would have *created* a
  divergence. (The two remaining ISO secure-messaging classes cannot be asked of
  a YubiKey at all: macOS PC/SC refuses to transmit 124 of the 256 class values,
  `0C` among them, so the spec decides those and it says the same thing.)
  **bcdDevice → 0x08A4.**

- **One old OATH record no longer fails `CALCULATE ALL` for the whole key.**
  Enforcing `only increasing` gave every opted-in credential a high-water mark
  in its stored blob, and a build before that one kept unrecognised tags
  verbatim — so a body already sitting on a provisioned key can have no room for
  a mark, or carry a private-tag value of the wrong width. Either one made the
  bulk read answer `6A80` with an **empty body**, for every account on the key,
  on every call, with nothing in the response to say which credential was at
  fault and no way back short of finding and deleting it. Such a record is now
  skipped by the mark pass and reported with the protocol's own "no response"
  tag, exactly as an uncomputable algorithm already was — it still has no code
  on either read path, because its mark cannot be kept and serving it in bulk
  would be the one place the property does not hold, but it no longer takes the
  rest of the store with it. Nothing a current build can store is affected: the
  `PUT` rule bounds a credential body well under the room a mark needs, and the
  two are now tied by an assertion rather than by arithmetic in two places.
  **bcdDevice → 0x08A3.**

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

- **The emulator stopped lying about the board.** `tools/emu` is what 48 of the
  52 on-device suites run against, so a divergence there is a wrong answer given
  confidently. Sixteen closed. An open menu starved a queued host command for
  **60 s where a board yields in 16 ms**, and a queued OTP frame — which carries
  no keepalive, so the host saw a failure rather than a delay — for as long. The
  panel's presence flags reached neither transport, so `CTAPHID_CANCEL` was
  ignored for the full ceremony and no `UPNEEDED` was ever sent. A U2F ceremony
  could not be cancelled at all, and a cancelled REGISTER still minted the
  credential the host had withdrawn. On-panel RSA generation was impossible where
  a board manages it, and the window froze for the whole search. The reported
  `bcdDevice` was a hand-copied constant **172 releases stale**, and is now read
  out of `firmware/src/main.rs`. `--taps <file>` drives the keypad from a script,
  which is how the trusted display's PIN rule came to be exercised for the first
  time since it shipped; `--auto-touch-ms` makes delayed presence deterministic.

### Security

- **The vendor applet's test counter no longer writes flash unauthenticated.**
  `INS 01` (INCREMENT) on AID `F0 00 00 00 01` appended to flash with no PIN, no
  touch and no rate limit, and the applet answers on **both** CCID and CTAPHID —
  the transport an unprivileged process reaches without any smartcard service.
  Measured on `tools/emu`, which runs the device's own `sequential-storage` over
  the device's geometry: 391 increments/s sustained over the CCID socket and
  411/s over CTAPHID_MSG, 16.0 bytes of the counter partition per increment, and
  once that 128 KiB partition fills (~8 100 increments) the ring reclaims — 44
  page erases counted over the next ~11 900 increments, a lower bound because a
  page erased and refilled between two samples is not seen. The churn stays inside
  the counter partition — the main partition did not move by a byte over 2 000
  increments — so what a wear attack reaches is the signature counters, not the
  credentials, and the erases spread across all 32 pages. A slow primitive, then;
  what decides it is that this is a test hook with no product function, and it
  should not be the thing that offers one. It takes a touch now, exactly like the
  AID's reboot-to-BOOTSEL arm and for the same stated reason; `GET 02` reads and
  stays ungated, and a no-touch build (what the on-device suites run against)
  confirms on its own. Not a pure gain: an ungated command that raises a consent
  ceremony lets a host hold the key in "awaiting touch", which is the shape the
  reboot and Management-reset verbs already have — visible, and far slower than
  the writes it replaces. The config-surface writes beside it (`SET LED`, the FIDO
  `CONFIG_WRITE` twin) stay ungated by default; that is the deliberate ykman
  admin-surface parity and a separate question. **bcdDevice → 0x0901.**

- **A torn wipe can no longer leave a credential-management grant standing over
  a deleted PIN.** The persistent `pcmr` token (`EF_PAUTHTOKEN`) was swept in the
  same phase as `EF_PIN` by both wipes — `authenticatorReset` and the device-wide
  factory wipe behind Management RESET and the on-screen "erase everything" — and
  that phase deletes in flash-ring order, which on a freshly provisioned key puts
  the PIN first. A cut between the two left the grant live with no PIN behind it,
  and its holder could go on reading the credential directory of everything
  registered afterwards. The grant is a *permission*, so unlike every other record
  in that phase its absence is the restrictive state; it goes with the secrets now,
  where no prefix of a wipe can do worse than revoke it early — and the ordering
  stops depending on which record the ring happens to hold first. The refusal added
  in `0x08C0` stays, for a record an older build already wrote to flash. The counter
  skips to a fresh decade because parallel branches held `0x08F8`–`0x08FF`.
  **bcdDevice → 0x0900.**

- **The PIV data objects whose read condition is the PIN are no longer
  world-readable.** SP 800-73-4 pt1 Table 3 gives four objects a contact read
  condition of PIN — Cardholder Fingerprints (`5FC103`), Cardholder Facial Image
  (`5FC108`), Printed Information (`5FC109`) and Cardholder Iris Images
  (`5FC121`) — and a YubiKey 5.7.4 gates exactly those four and nothing else.
  `GET DATA` applied a PIN check to `5FC109` alone, and then only once the
  management key had been PIN-protected, so a card provisioned as a real PIV
  credential handed its fingerprint templates, facial image and iris images to
  any process that could open the reader. Measured three runs per card: the gate
  is judged *before* the object is looked up, so an absent one answers `6982` and
  not `6A82` and cannot be used to probe what a card holds, and the management
  key does not stand in for the PIN. Writing them stays management-gated —
  reading and writing are separate conditions. **bcdDevice → 0x08D2.**

- **A PIV `CHANGE REFERENCE DATA` / `RESET RETRY COUNTER` body is two wire forms
  or nothing.** The handlers split the body at the *stored* reference length and
  handed the whole remainder over as the new value, and `put_pin_verifier` writes
  the raw slice's length as the record's own — so `00 24 00 80` with an `8 ‖ 6`
  body answered `9000` and stored a six-byte PIN. After that the padded `VERIFY`
  every host sends burned retries while only the raw six-byte body passed, the
  conformant `8 ‖ 8` change back was refused (the split had moved to six), and
  with the PUK shortened the same way the only exit was `INS FB` RESET — which
  destroys every PIV key and certificate. A YubiKey 5.7.4 answers `6A80` to every
  body but sixteen bytes on all three commands (`00 24 00 80`, `00 24 00 81`,
  `00 2C 00 80`), and judges the length *before* the old reference, so a wrong old
  value inside a malformed body costs no retry either; measured three runs per
  cell per card. `check_new_reference` is now the single owner of the value rule
  — an exact eight bytes, not a bound — so the panel path and any future caller
  are covered too, and the body is split at the wire form rather than at whatever
  the card has stored. That split matters on a card an older build already
  poisoned: sizing the gate off the stored length instead looks like it preserves
  more, and in fact takes the last exit away, because the sixteen-byte unblock
  every host sends would stop spending the PUK counter and `INS FB` RESET is gated
  on both counters reaching zero. As shipped, all three configurations keep the
  exits they had — a poisoned PIN is repaired by the PUK unblock and a poisoned
  PUK by `SET RETRIES`, both with the keys intact, and a card poisoned on both
  still reaches its reset. **bcdDevice → 0x08D1.**

- **A PIV `VERIFY` whose body is not the 8-byte wire form no longer burns a PIN
  retry.** SP 800-73-4 pt2 §2.4.3 fixes the PIN block at 8 bytes, `0xFF`-padded;
  the handler tested only for the empty status query and then handed a body of
  *any* length to the comparison, which missed and decremented. Three malformed
  `VERIFY`s — a middleware that forgets to pad, a host that sends the six digits
  raw, a fuzzer — blocked the PIV PIN, and recovery then needed the PUK. A
  YubiKey 5.7.4 answers `6A80` with the counter untouched to every body length
  taken in 1-16, 24 and 32 except 8; the 8-byte all-pad control burns on both
  cards, which is what makes this a wire-form gate rather than a refusal to
  compare. Measured three runs per length per card. The refusal still drops the
  card's standing PIN status, as the YubiKey does for every length but one — an
  `Lc = 1` body keeps it there, a quirk we do not copy, since revoking is the
  stricter half. A wrong `P1` or `P2` is refused *without* revoking on both cards,
  so this is a rule about the wire form and not about refusals in general. The
  gate is judged ahead of the blocked floor, again as the oracle does: on a
  blocked PIN a malformed body answers `6A80` where a well-formed one answers
  `6983`. Note the *write* side of the same wire form is only closed by the entry
  above it in this list; until that one, a card could still be given a short
  reference by a non-conformant host, and this gate then refused the short
  `VERIFY` that used to reach it — recoverable with `CHANGE REFERENCE DATA` or a
  PUK unblock, but a state worth naming. **bcdDevice → 0x08D0.**

- **The OpenPGP admin PIN no longer reaches the cardholder's private-use DOs.**
  OpenPGP Card 3.4.1 §4.4.1 hands `0101` and `0103` to PW1 no. 82 — the
  cardholder — and `0102`/`0104` to PW3, with no admin override on the first
  pair. Ours let PW3 stand in for PW2 on three of those cells: reading `0103`,
  writing `0103`, and writing `0101`. Whoever holds the admin PIN could therefore
  read and overwrite the two objects the card sets aside for the owner, which is
  the one pair of DOs whose whole purpose is that the admin credential is not
  enough. A YubiKey 5.7.4 answers `6982` to `00CA010300`, `00DA0103…` and
  `00DA0101…` with only PW3 verified — measured 3/3 across the full 4-DO × 4-state
  matrix, with a fully-authenticated baseline write proving each DO writable
  first, so a `6982` there means "this password may not" and not "this DO is
  read-only". Nothing is lost: the values stay readable and writable to PW2, and a
  tightening only turns some `9000`s into `6982`s. `gpg` never used the admin PIN
  for these — it prompts for the cardholder PIN when it touches a private DO — so
  no host flow changes. One thing the admin credential can still do to the
  cardholder's pair is destroy it: `TERMINATE DF` wipes the whole applet, which is
  §7.2.16's own model and not an exception to this rule. The Gnuk-derived
  conformance suite expects the permissive behaviour and is listed as a deliberate
  divergence (three tests, both KDF host modules). **bcdDevice → 0x08F0.**

- **A persistent credential-management grant no longer outlives the PIN that
  granted it.** CTAP 2.2 §6.8.2's `pcmr` token is a bearer secret in flash
  (`EF_PAUTHTOKEN`): its holder drives getCredsMetadata, enumerateRPsBegin and
  enumerateCredsBegin with no PIN check, because the record's presence *is* the
  permission. That reasoning holds for every way the record can legitimately come
  to exist — both issuance paths refuse without a PIN — and stops holding after a
  torn `authenticatorReset`, whose gate phase can take `EF_PIN` and lose power
  before `EF_PAUTHTOKEN`. The existing defence clears the leftover when a PIN is
  next established; an owner who carries on with a touch-only key never does that,
  and the old holder went on reading the credential directory — relying-party ids,
  credential ids, user names — of everything registered afterwards. Not keys, not
  assertions: deleteCredential and updateUserInformation never consulted the grant.
  The three reads now refuse it when no PIN is set, which is the same
  `PIN_AUTH_INVALID` a completed reset already answers, so a platform cannot tell
  the torn case from the clean one. Found by a TLA+ model of the wipe
  (`NoAccessibleSecretWithoutGate`, 102523 distinct states, depth 14). Nothing
  changes for a device with a PIN. **bcdDevice → 0x08C0.**

- **A wipe deletes the device seed first, so a power cut can no longer leave a
  *usable* passkey behind.** `authenticatorReset`'s own comment promised "the seed
  leads, so a surviving credential record is cryptographically dead" and nothing
  implemented it: the sweep batches every non-gate FIDO file, and `for_each_key`
  yields in flash-ring order rather than FID order, so `EF_RP` could go before
  `EF_CRED`. Cut power in between and the key comes back with a live discoverable
  credential whose relying-party entry is gone — `enumerateRPs` and the trusted
  display's Passkeys view both walk `EF_RP`, so neither lists it;
  `enumerateCredentials` is per relying party, so nothing can reach it to delete
  it; and `getAssertion` scans `EF_CRED` and signs with it happily. A TLA+ model of
  the wipe found it (`NoUnmanageableCredential`, 72128 distinct states, depth 13).
  The seed now goes in its own flash write ahead of the batch — both of its shapes,
  `EF_KEY_DEV` and the soft lock's `EF_KEY_DEV_ENC` — and the device-wide
  `Fs::factory_wipe` behind the Management RESET and the on-screen factory reset
  takes the same lead phase, since it bypasses the applet sweep entirely. **The
  strand itself is not prevented**: a torn wipe can still leave an `EF_CRED` record
  with no `EF_RP` entry, holding its credential slot until the next reset. What
  changes is that the record no longer decrypts under the regenerated seed, so
  nothing can authenticate with it — which is what the comment always claimed. A
  wipe that completes behaves exactly as before; the cost is one extra flash-ring
  walk per reset for whichever seed shape is absent. **bcdDevice → 0x08BF.**

- **The vendor applet's core1 counter read (`INS 12`) is gone from the shipping
  image.** `docs/protocol.md` has said all along that it "exist[s] only in
  debug/bench builds"; the firmware implemented it unconditionally, so every key
  answered it. What it hands out is the second core's prime-search telemetry —
  candidates tried and primes found, per core — which is a timing oracle over RSA
  key generation, read over an ungated CCID APDU with no touch and no PIN. Its two
  neighbours on the same AID were already gated for exactly that reason
  (`keygen-bench` for `INS 13`, `bench` for `INS 14`); this one is now behind
  `core1-stats`, and a default build answers `6D00` from the `Platform` trait's own
  default. Nothing host-side ever called it — not `tools/rsk`, not `tools/tui`, not
  a `tests/*.py` — so no tool loses a command. The gate now reads the built image
  and refuses any of the three debug commands in it, with a sibling method as the
  positive control so a nameless artifact fails instead of passing.
  **bcdDevice → 0x08BE.**

- **The PIV PIN and PUK are spent before they are compared, and the counter is
  read back.** `check_ref` compared first and wrote the retry counter after, and
  it trusted the write. A flash write that *refuses* is caught — the card answers
  `6581` to the right secret and a wrong one alike, so nothing leaks. One that
  silently keeps nothing is not, and that is the failure the rest of this tree
  already defends against (the FIDO clientPIN reads its counter back, citing a
  glitch or a partial program; so do the OTP fuse writes). In that state a wrong
  PIN answered `63Cx` and the right one `9000`, at full speed, with the counter
  pinned at its starting value: the retry budget had stopped being a budget, on
  VERIFY, CHANGE REFERENCE DATA and RESET RETRY COUNTER alike. The attempt is now
  spent and confirmed *before* any comparison, so a store that is not storing
  refuses ahead of learning anything. Reading the counter back is not enough on
  its own and was not the fix: on a full counter the success path rewrites the
  value already there, which a lying store satisfies — the ordering is what
  closes it. **On a working device nothing changes**: the same status words, the
  same counter, in the same order on the wire. The one cost is that a power cut
  between the write and the answer spends a retry the holder did not use, which
  is how the FIDO and OATH PINs have always behaved. OpenPGP's `check_pin` has
  the same compare-then-spend shape and is deliberately untouched here.
  **bcdDevice → 0x08B6.**

- **A wrong FIDO PIN no longer leaves an outstanding `pinUvAuthToken`
  working.** A platform that held a token — minted with the right PIN — kept it
  usable across any number of failed PIN attempts by anything else plugged into
  the same session, so the retry counter was the only thing an attacker's wrong
  guesses cost them; the credential the *previous* holder was still using was
  untouched. A YubiKey 5.7.4 invalidates the token on a failed PIN check, through
  every door — `getPinUvAuthTokenUsingPinWithPermissions` (`0x09`), the legacy
  `getPinToken` (`0x05`) and `changePIN`'s old-PIN check — measured four times
  per door on both PIN/UV-auth protocols, with idle, `getKeyAgreement` and
  `getPINRetries` as controls that leave it alive on both devices. CTAP 2.0
  §5.6.6 and 2.1 name only the key-agreement regeneration in that branch, so we
  were within the letter of the spec and the card does strictly more; parity
  decides, and it is the safe direction — a token minted before someone started
  guessing stops working, and a platform can always mint another. The reset sits
  in the one function every *host* PIN check passes through — the on-screen PIN
  pad is a second one and did not inherit it; see the entry below, which closes
  that. Untouched, deliberately: the persistent `pcmr` token is a separate
  flash-backed grant that survives replugs until a PIN change or a reset, and a
  failed attempt is neither. **bcdDevice → 0x08B4.**

- **A wrong FIDO PIN typed on the trusted display's own pad now ends the host's
  outstanding `pinUvAuthToken` too.** The entry above landed the rule in
  `spend_and_verify_pin_hash` and said the pad inherited it. It does not: the pad
  verifies the same `EF_PIN` record through a second function, which by design
  omits the CTAP-session side effects because the display task holds no CTAP
  context. The panel's only clientPIN prompt is the current-PIN step of the
  on-device *Change FIDO PIN* flow — `changePIN`'s old-PIN check, performed at the
  pad — so on a display build the same wrong PIN killed a platform's token when it
  arrived over USB and left it working when it was typed on the screen. The pad
  now signals the worker, which drops the token before the next CBOR command, the
  same path an on-device PIN *change* already used. It signals only for the
  clientPIN — the device PIN gates the panel's own UI and is no CTAP credential —
  and only when there was a retry budget to spend, because an entry that meets an
  already-blocked PIN is turned away before any comparison and the host path
  leaves a standing token alone there as well. No YubiKey has a pad, so this one
  is class consistency with the wire rule rather than a measured cell.
  **bcdDevice → 0x08B5.**

- **OATH `SET CODE` installed an access code with no key material.** `73 01 01`
  — an algorithm byte and nothing after it — answered `9000` and locked the
  applet behind a key that is the empty string, so the VALIDATE response every
  session wants is `HMAC("", challenge)`: a lock anyone can open, standing
  between the owner and their accounts, and indistinguishable from a real one
  from the outside. Anything up to 127 bytes was taken as well. A YubiKey 5.7.4
  accepts an algorithm byte plus **14..=64 bytes** of key and answers `6A80`
  outside that, which is the same range it enforces on a credential's secret —
  one rule, two commands, and it is now one constant here too. Measured across
  0, 1, 2, 3, 13, 14, 15, 16, 20, 32, 63, 64, 65 and up: on that card the
  "protected but unopenable" state cannot be reached at all, because every
  accepted `SET CODE` is one whose key the host proved it can HMAC with and
  every refused one leaves the previous state untouched. Ours now refuses before
  the proof is checked and before a byte is written, so a rejected `SET CODE`
  from a validated session leaves the standing code opening the applet — checked
  both ways. The bound is on what `SET CODE` takes, never on what `VALIDATE` can
  read: a longer code stored by an older build still opens the applet, or the
  upgrade would lock its owner out. Unchanged and deliberate: an empty `73` value
  still removes the code. (This entry also kept a **body-less** `SET CODE` doing
  the same, citing YKOATH's own text. That cell was reconsidered against the card
  and is refused now — see below. It predates this entry, so relative to released
  0.4.9 it is a live behaviour change for a host that followed the document
  rather than the card.) **bcdDevice → 0x08B3.**

- **An outstanding PIV management-key challenge no longer survives arbitrary
  traffic.** GENERAL AUTHENTICATE at 9B hands the host a challenge (or a witness)
  to answer; ours stayed answerable across *every* intervening command — GET
  DATA, PUT DATA, VERIFY, GET METADATA of any slot, an unimplemented
  instruction — until the applet was deselected. That is the widest possible
  window for a host sharing the card to finish someone else's handshake. It still
  takes the management key, so this is a longer race and not a bypass, but the
  race had no end. SP 800-73-4 Part 2 §3.2.4 does not give the lifetime, so the
  oracle decides: measured on a YubiKey 5.7.4, 3/3 over ten slots and both
  handshake flows, a challenge survives only another GENERAL AUTHENTICATE — even
  one that fails, even at another slot — and a GET METADATA of 9B itself; every
  other command drops it, and a SELECT that leaves PIV selected keeps it. Ours now
  implements exactly that, in one place every command passes through (plus the
  RSA-keygen fast path, which is the one command that reaches the applet without
  it). The neighbouring cells are pinned alongside: a challenge is single-use, and
  "none outstanding" stays a different status word from "wrong answer".
  **bcdDevice → 0x08A7.**

- **A failed OATH PIN *change* now drops the standing authentication, as a
  failed verify already did.** The two siblings disagreed about one rule. `0xB2`
  VERIFY PIN with a wrong PIN answered `6982` and closed the password safe;
  `0xB3` CHANGE PIN with a wrong *old* PIN answered `6982` and left it **open**.
  Measured with the control firing in the same run. The sharp end is that the
  anti-bruteforce machinery then protected nothing that was already open: after
  burning every retry — the card refusing even the correct PIN — `0xB5` GET
  CREDENTIAL went on serving the stored password. This is the class shipped for
  OpenPGP and PIV: a failed authentication drops the standing one. A CHANGE now
  clears both the OTP-PIN status and the access-code one, because `validated` is
  reachable *through* the PIN (VERIFY sets it too, doubling as VALIDATE for the
  nitropy flow), so leaving it would leave a status obtainable by proving the
  very PIN that just failed — the trade VERIFY already makes. The clear sits
  where the sibling's does, after the record and TLV checks, so a malformed
  request stays a syntax error rather than a spent attempt. No YubiKey behaviour
  exists to copy here and that is measured, not assumed: a 5.7.4 answers `6D00`
  to all of `0xB0`–`0xB6` and does not distinguish this family from any other
  unimplemented instruction, so the applet's own siblings decide. Unchanged, and
  measured on the card rather than swept along with it: a failed OATH *access
  code* VALIDATE keeps the standing unlock on a YubiKey, and keeps it here too.
  **bcdDevice → 0x08A2.**

- **The OATH `only increasing` property is enforced instead of stored and
  ignored.** YKOATH's PROPERTIES bit 0 promises that a credential's challenge
  never goes backwards. RS-Key accepted the byte at `PUT`, persisted it, and then
  consulted only bit 1 (touch) — `PROP_INCREASING` did not exist in the applet.
  Measured: a credential stored with `78 01` served challenge 100, then 101,
  then **50**, then **101 again with the same code**, and a control stored
  without the property answered identically in every row. So the card kept a
  security flag it did not implement, and gave the host no way to find out. What
  the property buys is exactly what was missing: a thief with brief physical
  access cannot harvest past TOTP windows, and their use of a *future* window
  makes the owner's next legitimate `CALCULATE` fail — the detection half. A
  YubiKey 5.7.4 really does enforce it, so parity decides, and refusing the `PUT`
  instead (the other option) is contrary to the card, which answers `9000`.
  Each opted-in credential now carries a persisted high-water mark: `CALCULATE`
  serves a code only for a challenge strictly greater than it, then raises it —
  and raises it *before* the code is computed, because the CCID layer puts the
  response buffer on the wire whatever the status word says. A refused
  `CALCULATE` leaves the mark alone, the initial mark is zero (so nothing is
  refused until the first code), the mark follows a `RENAME` and a re-`PUT`
  clears it, and the comparison is the card's own: zero-extend both sides on the
  right and compare unsigned, which is plain numeric `>` at TOTP's 8-byte
  challenge and reproduces all ten mixed-width rows measured on the card.
  `CALCULATE ALL` matches the card's harder rule — one credential at or below its
  mark fails the **whole** command with an empty body, with the marks before it
  in store order already raised — which needs the comparison pass to finish
  before the first response byte, since pages go out as they are built. The
  property stays inert for HOTP (which ignores the challenge) and bits 2–7 stay
  ignored, both as measured. Credentials the bulk read does not compute — HOTP,
  and touch-gated ones it only advertises — are not marked by it, so the
  `CALCULATE ALL` → touch → `CALCULATE` flow still works at the same challenge.
  Upgrading is safe: a credential an older build stored with `78 01` starts
  enforcing from a zero mark, and no data moves.
  **bcdDevice → 0x08A1.**

- **OATH `PUT` now accepts exactly the credential bodies a YubiKey accepts, and
  a refused one no longer destroys the credential it would have overwritten.**
  The body was barely parsed: any algorithm nibble, any type nibble, any digit
  count, any name length, any secret length and any extra tag were stored and
  served back under `9000`. Three of those bite. A **2-byte KEY TLV is an empty
  HMAC secret** — every RS-Key would then answer the same code for the same
  challenge, computable offline by anyone. An **algorithm nibble outside 1/2/3**
  stores a credential that `LIST` shows and `CALCULATE` can never compute
  (`6400` forever), which `CALCULATE ALL` framed as a `0x76` response TLV one
  byte long where the protocol says five — a malformed frame under a success
  status. And **unrecognised tags were kept verbatim**, roughly 1 KiB per slot
  across 255 slots: a caller-chosen write primitive on the CCID interface.
  Sharpest of all, because PUT overwrites by name, one malformed PUT **replaced
  a working credential with a permanently dead one and answered `9000`**, secret
  unrecoverable; a YubiKey refuses the PUT and the original keeps computing.
  Measured across the whole boundary on a 5.7.4 and now matched cell for cell:
  KEY TLV 16..=66 bytes, digits 6/7/8, type `0x10` or `0x20`, algorithm 1/2/3,
  name 1..=64 bytes, the initial moving factor on HOTP only and exactly 4 bytes,
  the property as the bare `78 vv` pair ykman sends, and no unknown tag, repeat,
  wrong order or trailing byte — everything else is `6A80` with **nothing
  stored**, decided before the store is touched. RENAME takes the same name
  bound, or PUT's would be one rename away from a bypass. Two follow-ons in the
  same class: `VERIFY CODE` reduced every code that was not 6 digits to 8, so a
  legal 7-digit credential rejected its own correct code (`6700`) and accepted
  the 8-digit reduction; and `CALCULATE ALL` now reports a credential it cannot
  compute with the protocol's own "no response" tag instead of that truncated
  frame. RS-Key's password-safe fields are its own extension, not a YubiKey tag,
  and stay accepted. Stored credentials are untouched — the rule is on the write
  path only, and an out-of-range one an older build wrote still lists, renames
  and deletes.
  **bcdDevice → 0x08A0.**

- **The advertised `maxMsgSize` is now tied to the transport that has to carry
  it.** getInfo advertised a literal `7609` in `rsk-fido`; the frame that is
  actually refused is sized by a *computed* constant in `rsk-usb`, and `rsk-fido`
  does not depend on `rsk-usb`, so nothing linked them — the two tests that name
  the constant only check getInfo echoes it back, which holds for any value. The
  declared number is a conforming platform's only licence to send a larger
  message: over-declare it and the platform sends one the transport drops before
  any CBOR is read, with no way to have predicted it. A YubiKey 5.7.4 demonstrates
  the invariant — it advertises 1536 and its largest accepted CTAPHID payload is
  exactly 1536, with 1537 killed by an `ERR_INVALID_LEN` frame; `maxMsgSize` and
  the enforced ceiling are one number. `rsk-device` sees both crates and now
  carries a compile-time assertion between them, so the *firmware build* fails
  rather than a test — and the largeBlobs fragment ceiling, derived from the same
  literal, rides on it. The sibling assertion that was already there compared the
  response buffer with the constant it is *defined as* and so could not fail; it is
  replaced by one that drives getInfo and checks the number on the wire. No wire
  change and no `bcdDevice` bump: both values are 7609 today, and this is the
  ratchet that keeps them equal.

- **A CTAP2 request body must now be exactly one CBOR item.** Bytes after the
  top-level map were read as the end of the message and ignored, so two readers of
  the same wire bytes could disagree about what was asked — the request-smuggling
  shape. §8 makes this a decoder SHOULD, and a YubiKey 5.7.4 refuses it with
  `CTAP2_ERR_INVALID_CBOR`, measured on clientPIN, getAssertion and makeCredential
  alike; the gate therefore lives in the dispatcher, once, for every command that
  parses a body. getInfo is exempt because it never looks at its body, which is
  also what the oracle does. A map header that under-counts its entries sweeps
  along with it — the entries it disowns are now trailing bytes rather than
  parameters we silently never read (`0x12`, not `0x14`). Measured and
  deliberately left alone, with the readings on record: non-minimal integer
  encodings (keys, values and major-2..4 length headers) and nesting past four
  levels are accepted by the oracle too — §8's nesting clause is a floor for
  authenticators, not a cap. CBOR **tags** are the second half of the same rule:
  refused already where a parser *reads* the value, walked straight through where
  it *skips* one, which is most of the key space — `{1:2, 2:2, 99: tag(0,1)}`
  answered `SUCCESS` here and `0x12` on the oracle. All 26 skip arms refuse a tag
  now. Duplicate
  and descending map keys are the one cell where we are stricter than the oracle
  and §8 endorses it ("decoders SHOULD reject"); left for the maintainer to rule on
  rather than loosened.
  **bcdDevice → 0x089F.**

- **hmac-secret now answers the three codes §12.5 names.** A `saltAuth` that fails
  to verify was `CTAP2_ERR_EXTENSION_FIRST` — a code about extension *ordering*,
  which tells the platform to resend the request that just failed its MAC — where
  §12.5 says `CTAP2_ERR_PIN_AUTH_INVALID` verbatim. A `saltAuth` of the wrong
  *length* was folded into that same MAC compare and so answered the MAC's code;
  a YubiKey 5.7.4 refuses anything but 16 or 32 bytes, under either protocol,
  *before* the MAC. And the `saltEnc` wire gate was per-protocol, so a 48-byte
  `saltEnc` under protocol one — which the oracle accepts — was refused with
  `CTAP1_ERR_INVALID_LENGTH`; the gate is now the oracle's protocol-agnostic union
  {32, 48, 64, 80}, with §12.5's own rule ("the result is not 32 or 64 bytes long
  → `CTAP1_ERR_INVALID_PARAMETER`") applied after the MAC, where the spec puts it.
  Everything the oracle rejects is still rejected with the same `0x03` it uses, and
  the order is unchanged: lengths before crypto, so unauthenticated input is thrown
  out cheaply and nothing leaks that the wire length did not already show — the
  measurement confirms the reference device does the same. A zero-length `saltEnc`
  or `saltAuth` is now a length error rather than a missing parameter; an *absent*
  one is still `CTAP2_ERR_MISSING_PARAMETER`, judged where it was so it stays ahead
  of the `up:false` refusal. `CTAP2_ERR_EXTENSION_FIRST` is no longer reachable and
  its variant is gone. Not changed: hmac-secret on an `up:false` assertion stays
  `CTAP2_ERR_UNSUPPORTED_OPTION`, which is §12.5 verbatim and what FIDO conformance
  checks — the YubiKey answers `CTAP2_ERR_UP_REQUIRED` there and is the one that
  diverges.
  **bcdDevice → 0x089E.**

- **A numeric `0` is a value the platform sent, not a parameter it omitted.** Four
  request fields carried no present-flag, so `0` was indistinguishable from absence
  and each of them answered the wrong thing. `pinUvAuthProtocol: 0` on
  makeCredential and getAssertion answered `CTAP2_ERR_MISSING_PARAMETER` — telling
  a platform to add the parameter it had just sent, a loop it cannot leave —
  where §6.1.2 / §6.2.2 step 2.1 and a YubiKey 5.7.4 both say
  `CTAP1_ERR_INVALID_PARAMETER`; measured, the oracle refuses `0` with a
  `pinUvAuthParam`, without one, and even ahead of step 1's zero-length selection
  gesture, so the gate now sits there too. `enterpriseAttestation: 0` registered an
  ordinary credential, where §6.1.2 step 9 keys on the field being *present* and
  the oracle refuses every present value while EA is disabled. `credProtect: 0`
  registered a credential with no protection and no extension output at all —
  §12.1 names no error for an out-of-range level, so the oracle decides, and it
  answers `CTAP1_ERR_INVALID_PARAMETER` to `0`, `4` and `255` alike: levels 4 and
  255 therefore move off `CTAP2_ERR_INVALID_OPTION`, and the test that asserted the
  old code was itself encoding the defect. clientPIN's own two sentinels go with
  them: protocol `0` is `CTAP1_ERR_INVALID_PARAMETER` on every subcommand and is
  judged before the missing-input check (the oracle refuses it on a request that
  carries nothing else), and a keyAgreement whose `alg` is `0` or simply absent is
  now accepted — the oracle reads `kty`, `crv` and `alg` not at all. Swept across
  the whole class: `authenticatorConfig`, `authenticatorLargeBlobs`,
  `authenticatorCredentialManagement` and the vendor `0x41` channel had the same
  collapse and now separate absent (`0x14`) from unsupported (`0x02`). The
  **order** moved with the codes: all five judged the protocol *after* the token
  or subcommand it travels with, so a request that got both wrong was told about
  the wrong one. `authenticatorClientPIN` now judges it once, above the
  dispatch — `getPINRetries`, the one subcommand every host calls
  unauthenticated, used to answer `SUCCESS` under a protocol this build does not
  support. **bcdDevice → 0x089D.**

- **A COSE key-agreement coordinate must now be exactly 32 bytes.** The platform's
  `keyAgreement` is a P-256 COSE key, and a coordinate that is not 32 bytes wide is
  not one — but a short one used to be right-aligned into the buffer, so a platform
  whose bignum strips a leading zero still set a PIN, still got a `pinUvAuthToken`
  and still had its hmac-secret salts evaluated. Measured on a YubiKey 5.7.4: 31
  bytes and 33 bytes both answer `CTAP1_ERR_INVALID_PARAMETER`, on protocol 1 and 2
  alike, at clientPIN's COSE parse *and* at hmac-secret's own. Nothing legitimate
  relied on the lenience: every host in this tree emits fixed-width coordinates,
  and the padding it rescued is a bug on the platform's side that no other
  authenticator hides. Swept across all three COSE-parse sites — clientPIN,
  hmac-secret and the vendor MSE channel, which had the same right-align and no
  oracle to check it against. The measurement takes a platform key whose `x`
  genuinely begins with a zero byte: strip a byte off any other coordinate and the
  point leaves the curve, so the request is refused for the wrong reason and the
  test cannot tell the rule from the failed key agreement.
  **bcdDevice → 0x089C.**

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

[Unreleased]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.11...HEAD
[0.4.11]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.10...v0.4.11
[0.4.10]: https://github.com/TheMaxMur/RS-Key/compare/v0.4.9...v0.4.10
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
