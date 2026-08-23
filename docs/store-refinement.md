<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Store refinement pilot

The third C→B pilot, and the smallest. It connects `RSKeyStore`'s **cache** half
to the code that maintains it: the model's `present` and `decided` variables, and
the `Fs` primitives that write them.

## Why only half

`RSKeyStore` has seven variables. Five of them — `val`, `meta`, `dead`,
`metaAbsent` and the FID map they range over — are the *persistent* side, and
that side already has evidence: `crates/rsk-fs/src/powercut.rs`'s four `*_landed`
predicates are what the module was lifted from, `powercut_kani.rs` proves them,
and the `power_cut` fuzz target replays a real medium through them.

`present` and `decided` had none. They are in-RAM, so no power-cut oracle sees
them; they are private to `fs.rs`, so no other crate's test reaches them; and
the model's clauses about them are the ones a reader would call obvious. One of
them — a faulted read cached as a decided absence — is audit run-36, and it
shipped.

## What the harnesses claim

Six, in `crates/rsk-fs/src/store_refinement_kani.rs`, each naming its model
action. The projection they run against is `store_assurance.rs`: it reads the
**real** bitmaps and calls the **real** primitives, hooked as a `#[path]` child
of `fs.rs` so the private methods are reachable without widening them.

| Model action | Concrete step | The clause |
|---|---|---|
| `Put(f, v)` | `mark_present` | `f` is decided live; no other FID moves |
| `Delete(f)` | `mark_absent` | `f` is decided absent; a live neighbour stays live |
| `Confirm(f)`, `fault = FALSE` | `record_unless_faulted` | the backend's answer is cached as decided |
| `Confirm(f)`, `fault = TRUE` | `record_unless_faulted` | **nothing** is cached — audit run-36 |
| `Init` / `Reboot` | `Fs::new` | nothing cached, nothing decided |
| — | `known_absent` | a clear present bit is trusted only once decided confirms it |

Every harness carries a **second** symbolic FID. That is the content: the model's
clauses are `[present EXCEPT ![f] = …]` — one element moves, every other stands —
while the code reaches its bit through `fid >> 3` and `1 << (fid & 7)`. A shift
that disagreed would alias two files onto one bit, and a `mark_absent` on one
would then read as a decided absence for the other. That is `NoFalseAbsent`'s
disaster reached through arithmetic rather than through a fault, and no
single-FID harness can see it.

## The scope, and what it cost

`FID_PRESENT_BYTES` is 3 under `cfg(kani)`, against a shipped width of one bit
per FID over the whole `0x0000..=0xFFFF` space — 8 KiB. Measured at that full width, the writing harnesses cost 149 s, 273 s,
302 s, 520 s and 794 s — two of them over `scripts/kani.sh`'s 5-minute FAST cap,
whose own rule is to move the crate to SLOW rather than raise the cap, and that
would have taxed the four 0.5-second `powercut` rules for this pilot's
arithmetic. At three bytes every one of the six runs in 0.04–0.08 s and the whole
`rsk-fs` set is under ten seconds.

Three bytes is not a round number: it is the smallest width at which both a
within-byte neighbour and a cross-byte neighbour exist, which is what the
aliasing clause needs. The harnesses take their domain from the constant
(`store_assurance::FID_LIMIT`), so it follows the shrink instead of restating it.

What the shrink stops proving is that **no FID can index past the map** — at full
width that fell out of the harnesses as a discharged bounds check. It is a
compile-time assertion now:

```rust
#[cfg(not(kani))]
const _: () = assert!(((u16::MAX >> 3) as usize) < FID_PRESENT_BYTES);
```

which is the stronger form: it is about the shipped width, and a proof would only
ever have covered the FIDs a harness enumerated.

## What this is not

- **Not a Kani result for the persistent half — and the first version of this
  bullet was wrong about why.** `NoOrphanedMetadata`, `NoRecordLostToMetaWrite`
  and `NoFalseMetaAbsent` have a bridge now — `store_steps_tests.rs`, below — but
  it is a host sweep, so the three stay `MODELLED-ONLY`: `assurance_gate` reads
  `BOUNDED` off a Kani harness name.

  A harness that does nothing but `meta_add` does fail, and the message is the
  present map:

  ```console
  ** 1 of 164 failed (34 unreachable)
  Failed Checks: index out of bounds: the length is less than or equal to the given index
   File: "crates/rsk-fs/src/fs.rs", line 118, in fs::Fs::<…>::decided_bit
  Verification Time: 0.109 s
  ```

  From which this page concluded "no metadata path can run under `cfg(kani)` at
  all" and "there cannot be one". **Both are false, and the review measured it.**
  The blocker is `EF_META`'s VALUE (`0xE010`, index 7170), not the map's WIDTH,
  and the value takes the same one-line alias `FID_PRESENT_BYTES` already has:
  with `#[cfg(kani)] EF_META = 0x0017` and nothing else changed, the same harness
  is `0 of 164 failed`, `SUCCESSFUL`, **0.244 s** — and two real obligations at
  the fault sites the model states verify over the existing `FaultBackend` in
  **0.107 s each**. Widening the map, which is what the old bullet argued about,
  was answering a question nobody asked.

  What genuinely is out of reach is the clauses over a MEDIUM. With the alias, a
  single-blob backend and `META_MAX` shrunk 1024 → 32, both blob obligations
  **time out at 420 s**. That is the blob rebuild, not the bitmap.

  So the honest position: the two fault-site obligations are a cheap win this
  page has not taken, and taking them means a `cfg(kani)` redefinition of a
  PUBLIC constant plus a status change for two registry rows — its own change,
  with its own mutation table, not a footnote to this one. The medium-backed
  clauses stay the host sweep's.

- **Not `Scan`.** The model's truncated-walk clause needs a backend that can
  truncate, which is a medium, not a bitmap. `fs_tests.rs` carries it; Kani does
  not.

- **Not a whole-behaviour result.** The Kani harnesses are one-step obligations at
  every FID, which is why `SEC-STORE-002` is `BOUNDED` and not more; the host
  sweep below is bounded by sequence LENGTH, which is the same kind of claim.

- **And it cannot be a per-FID state projection either.** The tempting move is to
  write the model's per-FID steps as Rust predicates and hold them against
  `powercut.rs`; it was tried and measured, and each predicate comes out as the
  *same boolean function* as its `*_landed` twin — 0 disagreements over a
  five-valued domain, which is a copy compared to itself. Two of the three are
  STEP recorders (a meta-only file legally has metadata and no value, so the
  violation is a record outliving a delete rather than a state) and the third is
  CROSS-FID (a `meta_add` dropping ANOTHER FID's record). `formal/README.md`'s
  phase 7 has the numbers.

## The persistent half, exhaustively on the host

`store_steps_tests.rs` drives the REAL `Fs` over a REAL medium at three FIDs and
reads one of three step recorders after every step. Three FIDs because
`NoRecordLostToMetaWrite` is about the records a rewrite *drops*: with a subject
and one neighbour, "the write kept everything else" cannot be told from "the
write kept the one file we looked at".

| Sweep | What it covers | Size |
|---|---|---|
| every three-step sequence | the clauses over a fresh store | 12³ = 1728 orderings, 5184 steps |
| the same, then a reboot with no `scan` | EF_META UNKNOWN rather than confirmed — the 0x077C door | 1728 × 12 more steps |
| every two-step sequence over a failing medium | the FAULT path both meta recorders are about | 144 orderings |
| each recorder against the state its invariant forbids | that a recorder can answer TRUE at all | 6 assertions |
| a live-read counter per recorder | that the sweeps are not a loop over nothing | 4 counters, all `> 0` |

Two measurements decide whether this is worth anything.

**It has teeth.** `comutants.toml`'s `BugDeleteMetaOnlyUnderPresent` — the 0x077C
databug verbatim — applied to `fs.rs` gives, in 0.00 s:

```console
NoOrphanedMetadata: [MetaAdd(0)] then Delete(0) left a record over a gone value
```

which is the shortest witness there is: a meta-only file deleted. All three
recorders have one now — `BugMetaAddDropsOnFault` gives `NoRecordLostToMetaWrite:
[] then MetaAdd(0) dropped a bystander's record` and `BugMetaDeleteDropsOnFault`
gives `NoFalseMetaAbsent: [] then MetaDelete(0) cached absence over a live
record`. The first of those **survived the first version of this sweep**, because
the faulting medium failed writes as well as reads and
`NoRecordLostToMetaWrite`'s loss needs the read to fail while the rewrite LANDS.
The counters are the reason that cannot happen twice: with `put` and `meta_add`
made inert the sweeps used to pass ~26 000 dead steps in silence, and they now
say `NoOrphanedMetadata was never read from a state it could refuse`.

**And it does not have all of them.** `BugDeleteValueBeforeMeta` — the two backend
writes reversed — **survives**, and correctly. The tempting reason is that the
completed end state is identical either way; measured, that is false — with a
bystander's record and a medium whose `remove` fails, `Put(0), MetaAdd(0),
MetaAdd(1), Delete(0)` ends at `meta=[false,true,false]` shipped and
`meta=[true,true,false]` reversed, no power cut involved. The narrow reason is
the right one: **`NoOrphanedMetadata` cannot separate them, because `val[0]`
survives in both** and an orphan is a record over a *gone* value.
`powercut.rs`'s `delete_landed` is what owns the ordering, which is why both
exist — and `cargo test -p rsk-fs` does kill this mutant, through
`powercut::tests::a_cut_never_leaves_metadata_behind_a_file_that_is_gone`.

### The one shape the sweep will not judge, and the defect behind it

**A faulted `Delete`.** `MetaAdd` and `MetaDelete` each carry a faulted disjunct
in the model; `Delete` carries none — `dead` there is a power *cut*, not a medium
error. Reading `NoOrphanedMetadata` at a faulted delete would be judging a step
nothing states, so the fault is armed only for the two actions that have one.

That is a modelling decision, and it is standing in front of something real. The
first version of this paragraph described it as a meta-only-file curiosity. **It
is not.** `Fs::delete` used to swallow `meta_delete`'s error (a `let _ =` in
`fs.rs`, deliberately quoted without a line — the fix moved it) and then remove
the value; over a medium whose EF_META read failed ONCE and then worked, a delete
of a file that **has data** returned `Ok(())` with the value gone and the record
standing:

```console
delete returned : Ok(())
after: meta=[true, false, false]  val=[false, false, false]
```

That is the 0x077C databug's end state, on the shipped tree, with no power cut
and no meta-only file. It is reachable on hardware — `rsk-store`'s `read` and
`size` set `last_err` straight from `sequential-storage`'s `fetch_item`, so
`last_error()` is a flash read error and not a modelling device. And the tree
already treats the consequence as a defect **in one place**: `rsk-piv`'s
`files.rs:302-310` reaches for `force_delete` precisely because "a stale AES-256
head left over a re-minted 24-byte DEFAULT_MGM wedges the slot on the length
compare". PIV's other `meta_add_slot` sites have no such repair.

**Closed in the code half, and not the way the first draft of this paragraph
proposed.** Propagating with `self.meta_delete(fid)?` *before* the value goes was
the obvious repair and it is the wrong one: EF_META is one blob shared by every
applet, a failed read of it means "cannot tell" rather than "no record", and most
callers spell the delete `let _ = fs.delete(...)`. So a single flash-read fault
would have stopped every delete on the device — a wipe included — while the
callers that discard the result reported success, trading an orphaned record for
a secret that outlives its erase.

What `delete` does now is remove the value regardless and **return** the metadata
error, so `Err` names a state (the value is gone, a record may stand) instead of
hiding it. The one caller in the tree that deletes a fid carrying a head is PIV's
MOVE with `to = 0xFF`, the slot delete — heads are minted by `rsk-piv` alone — and
it reads the answer: the head gets a retry, because one read can fault where the
next lands, and the key is read back, because a `remove` that failed leaves the
source holding a live key. Both directions answer `6581`.

The model's half is the other item, and it is still open: `RSKeyStore!Delete`
carries no faulted disjunct, so the sweep still cannot judge the shape, and
`NoOrphanedMetadata` still reads as unconditional where the code now permits an
orphan on an error it reports. Until that lands the invariant is stated more
strongly than the code holds it, which is the direction that at least fails
loudly.

The PR gate carries the same clauses at concrete FIDs
(`a_cache_write_moves_one_fid_and_no_other_across_three_bytes` and
`a_faulted_confirm_caches_nothing_and_a_clean_one_caches_the_answer`), because a
proof that only runs weekly is a proof a rename can take away on a Monday. That
test walks a **window** of 24 consecutive FIDs rather than checking a pair: `>> 3`
mistyped as `>> 2` and `& 7` as `& 3` alias *different* pairs, so a test naming
two FIDs catches whichever of them its two happen to meet.
