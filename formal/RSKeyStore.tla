----------------------------- MODULE RSKeyStore -----------------------------
(*****************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                    *)
(* Copyright (C) 2026 RS-Key contributors                                    *)
(*                                                                           *)
(* The FLASH LAYER, and only it: `rsk-fs`'s `Fs` over a `Storage` backend    *)
(* (crates/rsk-fs/src/fs.rs), lifted from the Rust abstract model that       *)
(* already lives beside it -- powercut.rs's four `*_landed` predicates and   *)
(* powercut_model.rs's reboot loop. It models what a power cut may leave and  *)
(* what the in-RAM present-cache may believe. It models NONE of: the applets, *)
(* CTAP, the seal, the two-partition ring of rsk-store, wear or reclaim, or   *)
(* the value BYTES beyond "which of two distinct values". A green TLC run is  *)
(* a result about THIS model at these sizes, not about the firmware image --  *)
(* the same sentence formal/README.md opens with.                            *)
(*                                                                           *)
(* WHY A THIRD MODULE. The security model (RSKeySecurityState) already has a  *)
(* PowerCut, but it abstracts the store to per-record present/absent flags   *)
(* and asserts its flash invariants over quiescent states. The questions here *)
(* are one layer beneath that abstraction and it cannot ask them: does a torn *)
(* delete leave metadata naming a file that is gone, and can the present-     *)
(* cache read a committed key as absent? Both are `Fs` contracts, both have   *)
(* shipped as defects (0x077C, audit run-36), and both are what the roadmap's *)
(* refinement pilot inducts its persistent envelope (R0p) over -- so the      *)
(* store needs its own model before that pilot can stand on one.             *)
(*                                                                           *)
(* THE METHOD is the two siblings': each protected step carries a Guard (what *)
(* the Rust tests, mutable by a Bug* switch) against a Policy (the            *)
(* requirement, never mutated); a step the Policy forbids records the         *)
(* violated invariant in `viol`. Every Bug* rebuilds a defect this repo has   *)
(* actually shipped and fixed, and each must make TLC produce a               *)
(* counterexample -- an invariant no mutant can break is a test that cannot   *)
(* fail.                                                                      *)
(*                                                                           *)
(* THE THREE ORACLE PROPERTIES, mapped. powercut.rs names Atomicity,          *)
(* Durability and Enumeration. Atomicity -- a torn write lands the old value  *)
(* or the new one, never a third -- is a property of the log-structured       *)
(* append, so it is a MODELLING ASSUMPTION here (Put/MetaAdd land atomically) *)
(* rather than a falsifiable invariant; the Rust oracle's `Tear::Garbage`     *)
(* control is what checks it at the code level. Durability is                 *)
(* NoFalseAbsent (a spurious absent read IS the "committed key lost"          *)
(* disaster) together with NoRecordLostToMetaWrite. Enumeration is            *)
(* NoOrphanedMetadata (a deleted file's record must not linger in the walk).  *)
(*****************************************************************************)
EXTENDS Naturals

\* Supports `RSKeySecurityState!NoAccessibleSecretWithoutGate` — SEC-FIDO-004.
\* Supports `RSKeySecurityState!NoUnmanageableCredential` — SEC-FIDO-005.

(* Mutation switches, and the one scope constant. All FALSE is the shipped
   tree. *)
CONSTANTS
    \* The FID domain. Two is the MEASURED minimum, not an argument:
    \* `BugMetaAddDropsOnFault` is GREEN over one FID and RED from two, and
    \* no mutant in this roster needs a third (formal/scopes.txt).
    Fids,
    \* crates/rsk-fs/src/fs.rs:425-434 -- `Fs::delete` drops the metadata FIRST,
    \* then the value, so no cut inside it can leave value-gone-meta-alive
    \* (powercut.rs:43-51 `delete_landed`). The switch reverses the two writes.
    BugDeleteValueBeforeMeta,
    \* The 0x077C databug: `delete` dropped EF_META only under `if present_bit`,
    \* so a file given metadata but never `put` (present_bit = FALSE) kept its
    \* record after deletion and read back alive -- the metadata cleanup is
    \* unconditional now (fs.rs:426). The switch gates it on the value again.
    BugDeleteMetaOnlyUnderPresent,
    \* audit run-36: `record_unless_faulted` (fs.rs:144-148) refuses to cache a
    \* read that FAILED, because `Storage::read` returns None for both "absent"
    \* and "the read faulted" and caching the second as a decided absence turns
    \* one transient fault into a permanent false-absent. The switch caches it.
    BugCacheFaultAsAbsent,
    \* fs.rs:201-203 -- `scan` fills the decided bitmap for the WHOLE FID space
    \* only when `for_each_key` ran to completion; a walk a flash read fault
    \* truncated leaves the un-yielded FIDs UNDECIDED, to be re-probed. The
    \* switch decides the whole space regardless, so a missed live key reads
    \* absent.
    BugTruncatedScanDecidesAll,
    \* The 0x077C databug's meta half: `meta_add_reserve` (fs.rs:538-540) treats
    \* a FAILED EF_META read as fatal, because rebuilding the blob from an empty
    \* scratch would drop every other applet's record. The switch treats the
    \* faulted read as an empty blob, wiping them.
    BugMetaAddDropsOnFault,
    \* fs.rs:565 -- `meta_delete` refuses a FAILED EF_META read (MemoryFatal)
    \* rather than caching it as absence. The switch caches it, and the damage is
    \* the write AFTER: `meta_add` trusts `known_absent` and rebuilds from empty.
    BugMetaDeleteDropsOnFault

\* Two VALUES so an overwrite is observable. `NoVal` is the absent sentinel --
\* distinct from both stored values, so "reads back absent" and "reads back v1"
\* never collide.
Vals  == {"v1", "v2"}
NoVal == "none"

InvNames == { "NoOrphanedMetadata", "NoFalseAbsent", "NoRecordLostToMetaWrite",
              "NoFalseMetaAbsent" }

VARIABLES
    val,      \* [Fids -> Vals \cup {NoVal}]: the value committed to flash
    meta,     \* [Fids -> BOOLEAN]: whether a metadata record is committed
    present,  \* [Fids -> BOOLEAN]: the in-RAM present-cache bit (fs.rs:42)
    \* [Fids -> BOOLEAN]: the authority bit paired with `present` (fs.rs:51). A
    \* clear `present` is trusted as absent ONLY once `decided` confirms it
    \* (`known_absent`, fs.rs:113-115); an undecided FID falls through to the
    \* reliable backend, which is the whole tri-state defence.
    decided,
    \* Whether the power is gone: a torn multi-write leaves the device dead until
    \* the next boot, so nothing further may be written. `dev.dead()` in
    \* powercut_model.rs:47. Only `Delete` can set it (it is the only op with a
    \* cut point between two backend writes); a clean `Reboot` clears it.
    dead,
    \* `known_absent(EF_META)`: EF_META's own presence cache, which the record
    \* map above does not carry -- EF_META is the blob, not one of its records.
    \* A `meta_add` trusts this bit and rebuilds from empty when it is set.
    metaAbsent,
    viol      \* ghost: the set of invariant names some step has violated

vars == << val, meta, present, decided, dead, metaAbsent, viol >>

TypeOK ==
    /\ val     \in [Fids -> Vals \cup {NoVal}]
    /\ meta    \in [Fids -> BOOLEAN]
    /\ present \in [Fids -> BOOLEAN]
    /\ decided \in [Fids -> BOOLEAN]
    /\ dead    \in BOOLEAN
    /\ metaAbsent \in BOOLEAN
    /\ viol    \in SUBSET InvNames

Live(f)  == val[f] # NoVal
LiveKeys == { f \in Fids : Live(f) }

\* `Fs::new`: an empty store, caches all clear and nothing decided yet -- every
\* read falls through to the backend until `scan` or a confirm-on-miss seeds it.
Init ==
    /\ val     = [f \in Fids |-> NoVal]
    /\ meta    = [f \in Fids |-> FALSE]
    /\ present = [f \in Fids |-> FALSE]
    /\ decided = [f \in Fids |-> FALSE]
    /\ dead    = FALSE
    \* An empty store really has no EF_META, so the cache is honestly absent.
    /\ metaAbsent = TRUE
    /\ viol    = {}

(***************************************************************************)
(* The writes. Put and MetaAdd land ATOMICALLY -- the log-structured        *)
(* backend's append is old-or-new by construction, which is the Atomicity   *)
(* assumption stated in the header. So neither carries a cut point; only     *)
(* Delete does.                                                             *)
(***************************************************************************)

\* `Fs::put` (fs.rs:376-396): write the value, then `mark_present` -- which
\* sets BOTH the present and the decided bit (fs.rs:129-133).
Put(f, v) ==
    /\ val'     = [val     EXCEPT ![f] = v]
    /\ present' = [present EXCEPT ![f] = TRUE]
    /\ decided' = [decided EXCEPT ![f] = TRUE]
    /\ UNCHANGED << meta, dead, metaAbsent, viol >>

\* `Fs::meta_add_reserve` (fs.rs:525-551): rewrite EF_META with `fid`'s record
\* added, EVERY OTHER record preserved. The one shape that must not happen is a
\* rewrite that drops another FID's record -- which is exactly what treating a
\* faulted EF_META read as an empty blob does. Modelled as the success write,
\* plus the buggy faulted-rewrite as its own disjunct so the shipped tree never
\* offers it (a faulted `meta_add` on the shipped tree returns an error and
\* changes nothing, so it is not a transition).
MetaAdd(f) ==
    \* The SHIPPED read: a cache that says EF_META is absent is trusted, and the
    \* blob is rebuilt from empty (fs.rs:531-533). Correct while the cache is
    \* honest -- which is what NoFalseMetaAbsent is for.
    \/ /\ meta' = IF metaAbsent THEN [g \in Fids |-> g = f]
                                 ELSE [meta EXCEPT ![f] = TRUE]
       /\ metaAbsent' = FALSE
       /\ viol' = viol \cup
            (IF metaAbsent /\ \E g \in Fids : (g # f) /\ meta[g]
               THEN {"NoRecordLostToMetaWrite"} ELSE {})
       /\ UNCHANGED << val, present, decided, dead >>
    \/ /\ BugMetaAddDropsOnFault
       /\ meta' = [g \in Fids |-> g = f]
       /\ metaAbsent' = FALSE
       /\ viol' = viol \cup
            (IF \E g \in Fids : (g # f) /\ meta[g]
               THEN {"NoRecordLostToMetaWrite"} ELSE {})
       /\ UNCHANGED << val, present, decided, dead >>

\* `Fs::meta_delete` (fs.rs:556-586): drop `fid`'s record, and clear EF_META
\* once the last one goes. A FAILED read of EF_META must refuse (fs.rs:565) --
\* the switch caches it as absence instead, which is the door `meta_add`'s twin
\* mutant does not reach: the loss happens on the NEXT write, not this one.
MetaDelete(f) ==
    \/ /\ meta' = [meta EXCEPT ![f] = FALSE]
       /\ metaAbsent' = \A g \in Fids : ~meta'[g]
       /\ UNCHANGED << val, present, decided, dead, viol >>
    \/ /\ BugMetaDeleteDropsOnFault
       /\ metaAbsent' = TRUE
       /\ viol' = viol \cup
            (IF \E g \in Fids : meta[g] THEN {"NoFalseMetaAbsent"} ELSE {})
       /\ UNCHANGED << val, meta, present, decided, dead >>

(***************************************************************************)
(* Delete -- the only op with a cut point, because it is two backend        *)
(* writes: metadata FIRST, then the value (fs.rs:426-433). `k` is how many   *)
(* of the two landed before the power went: k=2 is the clean delete, k=1 is  *)
(* the torn one that leaves the device dead. The switch decides the ORDER    *)
(* of the two writes, and the second switch whether the metadata write runs  *)
(* at all on a value-less file.                                             *)
(***************************************************************************)
Delete(f) ==
    \E k \in 1..2 :
        \* Bug 1: the metadata drop is gated on the value being present, so a
        \* meta-only file keeps its record. `metaKept` is that skip -- it reads
        \* the value at drop time (unprimed), which is `present_bit` in the code.
        LET metaKept == BugDeleteMetaOnlyUnderPresent /\ ~Live(f)
        IN \* Reverse order writes the value FIRST (gone for any k >= 1) and the
           \* metadata SECOND (gone only once k reaches 2). Shipped order is the
           \* mirror: metadata first (dropped unless Bug 1 skips it), value second.
           /\ meta' = [meta EXCEPT ![f] =
                 IF BugDeleteValueBeforeMeta
                   THEN (IF k = 2 THEN FALSE ELSE meta[f])
                   ELSE (IF metaKept THEN meta[f] ELSE FALSE)]
           /\ val' = [val EXCEPT ![f] =
                 IF BugDeleteValueBeforeMeta
                   THEN NoVal
                   ELSE (IF k = 2 THEN NoVal ELSE val[f])]
           \* `mark_absent` rides the value remove; model `present` as tracking
           \* the value it can see, so no delete ever leaves a decided-absent
           \* over a live value (that direction is NoFalseAbsent's, and Delete
           \* is not one of its writers). `decided` is left as it was: a delete
           \* does not newly DECIDE a key absent in a way a later read relies on.
           /\ present' = [present EXCEPT ![f] = (val'[f] # NoVal)]
           \* THE ORDER'S ONE OBLIGATION: once a delete has begun (k >= 1), no
           \* reader may find metadata for a file whose value it has removed.
           \* Correct order drops meta first, so meta' is already FALSE whenever
           \* val' is gone; the reverse order and the Bug-1 skip are the two ways
           \* to reach meta'-set-with-val'-gone, and both are real defects.
           /\ viol' = viol \cup
                (IF (meta'[f] = TRUE) /\ (val'[f] = NoVal)
                   THEN {"NoOrphanedMetadata"} ELSE {})
           /\ dead' = (k = 1)
           /\ UNCHANGED << decided, metaAbsent >>

(***************************************************************************)
(* The reader's cache maintenance, and the boot that rebuilds it. These are  *)
(* where a committed key can be lost to a false ABSENT.                      *)
(***************************************************************************)

\* A confirm-on-miss: `read`/`size`/`has_data` consult the backend and cache the
\* answer through `record_unless_faulted` (fs.rs:207-236). `fault` is whether
\* that backend read FAILED rather than found the key absent. The shipped code
\* refuses to cache a fault; the bug caches it as a decided absence.
Confirm(f) ==
    \E fault \in BOOLEAN :
        /\ IF fault
             THEN IF BugCacheFaultAsAbsent
                    \* `record(f, false)` on a fault: mark_absent sets decided,
                    \* clears present -- a false-absent if `f` is actually live.
                    THEN /\ present' = [present EXCEPT ![f] = FALSE]
                         /\ decided' = [decided EXCEPT ![f] = TRUE]
                    \* `record_unless_faulted`: a faulted read caches nothing.
                    ELSE UNCHANGED << present, decided >>
             \* a clean read caches the backend's real answer for `f`
             ELSE /\ present' = [present EXCEPT ![f] = Live(f)]
                  /\ decided' = [decided EXCEPT ![f] = TRUE]
        /\ UNCHANGED << val, meta, dead, metaAbsent, viol >>

\* `Fs::scan` (fs.rs:161-204): clear the caches, then walk the backend. `seen`
\* is the set the walk yielded; `complete` is `for_each_key`'s completeness flag
\* (FALSE means a flash read fault truncated it). A complete walk yields every
\* live key and lets `scan` decide the WHOLE space (un-yielded => truly absent);
\* a truncated one may miss a live key, so only the yielded keys are decided and
\* the rest stay undecided -- unless the bug decides them all anyway.
Scan ==
    \E complete \in BOOLEAN, seen \in SUBSET Fids :
        /\ seen \subseteq LiveKeys
        /\ (complete  => (seen = LiveKeys))
        /\ (~complete => (\E g \in LiveKeys : g \notin seen))
        /\ present' = [f \in Fids |-> f \in seen]
        /\ decided' = [f \in Fids |->
              IF (complete \/ BugTruncatedScanDecidesAll)
                THEN TRUE
                ELSE f \in seen]
        /\ UNCHANGED << val, meta, dead, metaAbsent, viol >>

\* A power cycle: the medium survives, the RAM caches do not, the device is
\* alive again. Durability is structural here -- Reboot never touches `val` or
\* `meta`, so a committed value can only be LOST through a reader that reports it
\* absent, which is what NoFalseAbsent forbids.
Reboot ==
    /\ present' = [f \in Fids |-> FALSE]
    /\ decided' = [f \in Fids |-> FALSE]
    /\ dead'    = FALSE
    \* `Fs::new` decides nothing, so `known_absent(EF_META)` is FALSE until a
    \* read answers -- the fallback direction, never a carried-over absence.
    /\ metaAbsent' = FALSE
    /\ UNCHANGED << val, meta, viol >>

Next ==
    \/ \E f \in Fids, v \in Vals : ~dead /\ Put(f, v)
    \/ \E f \in Fids : ~dead /\ MetaAdd(f)
    \/ \E f \in Fids : ~dead /\ MetaDelete(f)
    \/ \E f \in Fids : ~dead /\ Delete(f)
    \/ \E f \in Fids : ~dead /\ Confirm(f)
    \/ ~dead /\ Scan
    \/ Reboot

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* THE INVARIANTS.                                                          *)
(***************************************************************************)

\* ENUMERATION. No delete leaves a metadata record for the file it removed --
\* the state the write order (metadata first) exists to forbid: a reader that
\* walks the store would find metadata describing a value that is not there
\* (`delete_landed`, powercut.rs:43-51, and the 0x077C databug for the
\* value-less file). Ghost, one writer: Delete. A meta-only file (a `meta_add`
\* with no `put`) legally has metadata and no value, so this cannot be a plain
\* state predicate -- the violation is a metadata record OUTLIVING a delete,
\* which is a step, not a state.
NoOrphanedMetadata == "NoOrphanedMetadata" \notin viol

\* DURABILITY, the reader half. A committed key is never read as absent: the
\* present-cache's confirmed-absent bit is set only over a genuinely absent FID.
\* A false-absent is the on-device "seed lost, regenerate" disaster and it opens
\* every gate that reads `has_data` (audit run-36). Structural -- it reads
\* straight out of the cache and the store, needing no cooperation from any
\* action, which is the strong form.
NoFalseAbsent ==
    \A f \in Fids : (decided[f] /\ ~present[f]) => ~Live(f)

\* DURABILITY, the writer half. A `meta_add` of one FID never drops another's
\* committed record -- the "torn meta_add wiped every existing record" crash,
\* where a faulted EF_META read was rebuilt from empty. Ghost, one writer:
\* MetaAdd. (MetaDelete of `f` legitimately touches only `f`, so it is not a
\* writer here.)
NoRecordLostToMetaWrite == "NoRecordLostToMetaWrite" \notin viol

\* SEC-STORE-004. EF_META's presence cache may say "absent" only when it really
\* is: `meta_add` TRUSTS this bit and rebuilds the blob from empty (fs.rs:531),
\* so a false absent here loses every record on the next write rather than this
\* one. A step recorder, because the losing write is legitimate once the cache
\* has lied -- no state predicate over `meta` can tell the two apart.
NoFalseMetaAbsent == "NoFalseMetaAbsent" \notin viol

=============================================================================
