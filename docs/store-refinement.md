<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Store refinement pilot

The third C→B pilot, and the smallest. It connects `RSKeyStore`'s **cache** half
to the code that maintains it: the model's `present` and `decided` variables, and
the `Fs` primitives that write them. **RS-Key is not formally verified**: this is
one half of one model bridged to the code that maintains it, and the statuses
below are what that buys and no more.

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

Two more, in `store_meta_kani.rs`, are the EF_META **fault sites** rather than the
cache clauses. They are described in the first bullet of "What this is not",
because they are what that bullet used to say could not exist.

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

`EF_META` is aliased for the same reason and costs something different. At
`0x0017` it is **bit** 23 of the 24 the shrunk map has — the last bit of the last
byte — so the metadata blob sits *inside* the symbolic FID domain rather than
outside it, which is a different store topology and not the same one faster.
Three things stop being proved:

- that EF_META indexes within the shipped map. Shipped, `fid >> 3` puts `0xE010`
  at **byte** 7170 of 8192, and the compile-time assert above owns that;
- that EF_META is disjoint from every FID an applet writes. At `0xE010` it is
  outside every applet range; at `0x0017` it is inside the file space. That is an
  over-approximation the shrink INVENTS rather than one it hides — a `meta_add`
  whose subject is EF_META itself is a state the shipped store cannot reach — so
  `store_meta_kani.rs` assumes the collision away and says so;
- that `scan` registers every file it is handed. Its `fid == EF_META` skip
  (`fs.rs:286`) is compiled under `cfg(kani)` too, so under the alias it refuses
  FID 23 — a FID the harnesses' own domain draws from. Inert today, because no
  harness in the tree reaches `scan`; it is what the `Scan` bullet below would
  have to deal with.

`VIEW_FIDS` is untouched by all of it: at `0x0301` and up it does not land in the
24-bit map, it is read under `cfg(test)` only, and the seven-alternative
measurement that chose it — including the triple "around `EF_META`" — was taken at
`0xE010` and still stands.

## What this is not

- **Not a Kani result for the persistent half — and the first version of this
  bullet was wrong about why.** `NoOrphanedMetadata`, `NoRecordLostToMetaWrite`,
  `NoFalseMetaAbsent` and `NoSilentOrphan` have a bridge now —
  `store_steps_tests.rs`, below — but it is a host sweep, so the four stay
  `MODELLED-ONLY`: `assurance_gate` reads `BOUNDED` off a Kani harness name.

  A harness that does nothing but `meta_add` failed, before the alias below, and
  the message was the present map:

  ```console
  ** 1 of 164 failed (34 unreachable)
  Failed Checks: index out of bounds: the length is less than or equal to the given index
   File: "crates/rsk-fs/src/fs.rs", line 140, in fs::Fs::<…>::decided_bit
  Verification Time: 0.110 s
  ```

  From which this page concluded "no metadata path can run under `cfg(kani)` at
  all" and "there cannot be one". **Both are false, and the review measured it.**
  The blocker is `EF_META`'s VALUE (`0xE010`, index 7170), not the map's WIDTH,
  and the value takes the same one-line alias `FID_PRESENT_BYTES` already has:
  with `#[cfg(kani)] EF_META = 0x0017` and nothing else changed, the same harness
  is `0 of 164 failed`, `SUCCESSFUL`, **0.223 s**. Widening the map, which is what
  the old bullet argued about, was answering a question nobody asked.

  **The alias and the two fault-site obligations are taken now**, in
  `store_meta_kani.rs`, over the `FaultBackend` this page's cache harnesses
  already use: `meta_add` refusing a FAILED EF_META read rather than rebuilding
  from an empty blob (0.317 s), and `meta_delete` never caching that same read as
  a decided absence (0.156 s), both measured by the `pr` tier that runs them. Each asserts BOTH directions as separate clauses,
  because a refusal alone is satisfied by a `meta_add` that refuses everything —
  and because Kani 0.67 reports every `assert!` message in this crate as "a
  placeholder message", so the failing LINE is the only thing that tells a kill
  from its inverse. Driven: `BugMetaAddDropsOnFault` fails the first on the
  faulted arm, `BugMetaDeleteDropsOnFault` fails the second on the faulted arm.

  **What did not move is the two statuses.** `SEC-STORE-003` and `SEC-STORE-004`
  stay `MODELLED-ONLY`, and the two harnesses are named so that they stay there:
  `assurance_gate` FORCES `BOUNDED` from a harness function name containing the
  property's, without looking at domain, bound or `cfg`, so a name is all it
  would have taken. A `FaultBackend` holds no blob, so
  `meta[f]` is not represented and what verifies is the GUARD at the fault site,
  not "no record was lost"; and the domain is the shrunk one. `BOUNDED` there
  would be a scalar going up while the domain went quietly down. The thing that
  would earn it is a theorem carrying the `present`/`decided` arithmetic to the
  whole shipped `u16` domain, and that has no owner.

  What genuinely is out of reach is still the clauses over a MEDIUM. With the
  alias, a single-blob backend and `META_MAX` shrunk 1024 → 32, both blob
  obligations **time out at 420 s** — re-measured, `CBMC timed out`, at 419.9 s
  of solving for the record a `meta_add` may not drop and 420.7 s for the blob
  that may not read absent while one stands. That is the blob rebuild, not the
  bitmap, and it is the boundary of what the alias buys. The medium-backed
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
reads, after every step, the recorders that step can violate — five of them over
four properties. Three FIDs because
`NoRecordLostToMetaWrite` is about the records a rewrite *drops*: with a subject
and one neighbour, "the write kept everything else" cannot be told from "the
write kept the one file we looked at".

| Sweep | What it covers | Size |
|---|---|---|
| every three-step sequence | the clauses over a fresh store | 12³ = 1728 orderings, 5184 steps |
| the same, then a reboot with no `scan` | EF_META UNKNOWN rather than confirmed — the 0x077C door | 1728 × 12 more steps |
| every two-step sequence over a failing medium | the FAULT path three of the recorders are about | 144 orderings |
| each of the three helper predicates against the state its invariant forbids | that a recorder can answer TRUE at all, and one state over that it does not | 3 × 2 assertions |
| the fifth recorder | pairs a predicate with what `Fs::delete` ANSWERED, which no `StoreView` carries — so the sweeps above are where it is read | — |
| a live-read counter per recorder | that the sweeps are not a loop over nothing | 5 counters, each `> 0` in the sweeps that reach it |

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

### The one shape the sweep could not judge, and the defect behind it

**A faulted `Delete`.** `MetaAdd` and `MetaDelete` each carried a faulted disjunct
in the model and `Delete` carried none — `dead` there is a power *cut*, not a
medium error — so reading `NoOrphanedMetadata` at a faulted delete would have been
judging a step nothing stated, and the fault was armed only for the two actions
that had one. Both halves are closed now; the code's is below, the model's at the
end of this section.

That was a modelling decision, and it was standing in front of something real. The
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
`files.rs:310-319` rewrites the management key's head unconditionally, because
after a `force_delete` "a stale AES-256 head left over a re-minted 24-byte
DEFAULT_MGM wedges the slot on the length compare". PIV's other `meta_add_slot`
sites have no such repair.

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
hiding it. The `delete` caller that reaches a fid carrying a head is PIV's MOVE
with `to = 0xFF`, the slot delete — heads are minted by `rsk-piv` alone — and it
reads the answer: the head gets a retry, because one read can fault where the next
lands, and the key is read back, because a `remove` that failed leaves the source
holding a live key. Both directions answer `6581`.

**That was written as "the one caller in the tree", and the audit of the delete
family refuted it.** There is a second, and it is the one all four applet reset
sweeps go through: `Fs::force_delete`, whose metadata drop was a `let _ =`. PIV's
`wipe_piv` runs it over the same head-carrying fids, so RESET could answer `9000`
over a head it could not drop — `BugDeleteHidesFaultedDrop` still standing at the
third deleter, on the P0-launch reset path, after the `delete` half was closed.
`force_delete` returns the metadata outcome now, and its contract names the three
outcomes separately from `delete`'s because its callers need the distinction:
value gone and record gone, value gone with a record possibly standing, or the
medium refused and the value may be live. Held by
`a_faulted_metadata_drop_is_reported_by_force_delete_too` at the `Fs` layer and
`a_reset_answers_for_the_heads_it_could_not_drop` at the APDU layer.

**What the card then shows over an orphan is measured, not assumed.** PIV's GET
METADATA gates existence on the head alone — its `has_key` probe was dropped as a
per-slot flash fetch on every call — so a slot whose head outlived its key answers
`9000` with the head and the cached public point on an EC slot (the point rides in
the head), `6400` on an RSA one (the modulus is loaded from the key), and never
`6A88`. The probe stays out: the state is rare, both producers report it at the
moment they create it, and the cost is paid on every `ykman piv info`.

**And the first shape of that repair was itself the wrong one, measured.** Naming
three outcomes in the prose while returning a type that carries two left every
caller to collapse them, and the four sweeps collapsed them with `?`: a faulted
read of the shared EF_META blob then ended `authenticatorReset` after ONE file,
at the same fid on every retry, so no retry made progress and `EF_KEY_DEV_ENC` —
the soft lock's wrapped copy of the seed — survived with every credential. That
is the `?`-before-the-value failure arriving through the callers instead of
through the body. So the sweeps take
[`Fs::force_delete_halves`](https://github.com/TheMaxMur/RS-Key/blob/main/crates/rsk-fs/src/fs.rs)
now, which hands the two answers back apart: a refused backend removal still
stops the sweep, because `for_each_key` re-yields the fid it could not remove,
while a faulted metadata drop is carried to the end of the range and answered for
there. Both halves are the test, in all four applets — the range is empty AND the
command answers the fault — because a test that read only the status word passed
the aborting tree too.

**Every caller now carries a written decision**, in
[`assurance/deleters.toml`](https://github.com/TheMaxMur/RS-Key/blob/main/assurance/deleters.toml):
43 sites — 24 `delete`, 9 `delete_key`, 5 `force_delete`, 5
`force_delete_halves` — each classed, each
saying whether its fid can carry a head, and each saying whether discarding the
answer is an allowed best-effort wipe there or a device reporting success over
something still in flash. The roster under those decisions is **derived**, not
stored: `scripts/deleter_gate.py` reads the tree for the sites, the verbs and
whether each statement reads or discards the `Result`, and holds the file to that
in both directions, so a new caller arriving unaudited or a `must-read` site
quietly becoming a `let _ =` reddens the `delete-caller dispositions` row. It
derives the head-minting crates too, because every `drops-head` decision rests on
that being `rsk-piv` alone.

**And the model's half landed with it**, in `41c3b70`. `RSKeyStore!Delete`
carries a second disjunct now — the medium error, one backend write and no cut
point — and it took two clauses rather than one weakened one: an orphaned record
IS a state the shipped tree reaches, so `NoOrphanedMetadata` keeps every arm whose
drop landed while `NoSilentOrphan` (SEC-STORE-006) forbids the one thing the code
may not do, which is answer `Ok` from the arm that could not.
`StoreSolo_BugDeleteHidesFaultedDrop.cfg` is what says the new arm is reachable
rather than inert — RED on `NoSilentOrphan` in 43 distinct states at one worker,
61 at two and 74–76 at four. A counterexample search halts at the first violation,
so the verdict and the invariant are the result and the count is only where this
search happened to trip (`formal/README.md`'s rule for the column). The sweep's
fifth recorder asks the same question of the real `Fs`.

The PR gate carries the same clauses at concrete FIDs
(`a_cache_write_moves_one_fid_and_no_other_across_three_bytes` and
`a_faulted_confirm_caches_nothing_and_a_clean_one_caches_the_answer`), because a
proof that only runs weekly is a proof a rename can take away on a Monday. That
test walks a **window** of 24 consecutive FIDs rather than checking a pair: `>> 3`
mistyped as `>> 2` and `& 7` as `& 3` alias *different* pairs, so a test naming
two FIDs catches whichever of them its two happen to meet.
