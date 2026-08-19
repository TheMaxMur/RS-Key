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

- **Not the persistent half.** `NoOrphanedMetadata`, `NoRecordLostToMetaWrite`
  and `NoFalseMetaAbsent` stay `MODELLED-ONLY`; their evidence is the power-cut
  oracle's, and connecting it to the model the way this pilot connects the cache
  is the next increment.
- **Not `Scan`.** The model's truncated-walk clause needs a backend that can
  truncate, which is a medium, not a bitmap. `fs_tests.rs` carries it; Kani does
  not.
- **Not a whole-behaviour result.** These are one-step obligations at every FID,
  which is why `SEC-STORE-002` is `BOUNDED` and not more.

The PR gate carries the same clauses at concrete FIDs
(`a_cache_write_moves_one_fid_and_no_other_across_three_bytes` and
`a_faulted_confirm_caches_nothing_and_a_clean_one_caches_the_answer`), because a
proof that only runs weekly is a proof a rename can take away on a Monday. That
test walks a **window** of 24 consecutive FIDs rather than checking a pair: `>> 3`
mistyped as `>> 2` and `& 7` as `& 3` alias *different* pairs, so a test naming
two FIDs catches whichever of them its two happen to meet.
