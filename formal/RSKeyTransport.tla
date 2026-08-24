----------------------------- MODULE RSKeyTransport -----------------------------
(*****************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                    *)
(* Copyright (C) 2026 RS-Key contributors                                    *)
(*                                                                           *)
(* THE CTAPHID FRAME REASSEMBLER as a state machine: the channel, sequence   *)
(* and length checks a multi-frame message must pass before its payload is   *)
(* dispatched (crates/rsk-usb/src/ctaphid.rs:386-456, `Reassembler::feed`).  *)
(* Not the USB endpoints, not the async transport loop, not the applets the  *)
(* message reaches -- only the pure RX core that decides which 64-byte frames *)
(* belong to which in-flight transaction (the `in_tx` field,                 *)
(* crates/rsk-usb/src/ctaphid.rs:333).                                       *)
(*                                                                           *)
(* WHY MODEL IT, given the reassembler is already unit-tested and fuzzed.    *)
(* Every one of those exercises a SINGLE `feed` call, or a fuzzer's random    *)
(* frame stream checked for "no panic". The security properties are not      *)
(* about one frame: they are about what an INTERLEAVING of channels can       *)
(* assemble -- can channel B's bytes reach channel A's message, can a frame   *)
(* out of order complete a message, can a declared length overrun the buffer *)
(* across the frames that fill it. Those are invariants over the reachable    *)
(* space of a multi-frame transaction, which is what TLC checks exhaustively  *)
(* and a per-frame test or a sampling fuzzer does not assert.                *)
(*                                                                           *)
(* WHY AN EIGHTH MODULE. `rsk-usb` is the last workspace member no module     *)
(* covered, and the reassembler shares no variable with the other seven: a   *)
(* channel/seq/length triple is neither a FIDO security state, an applet     *)
(* status, a retry counter, a flash record, the capability mask, a display   *)
(* ceremony nor a boot marker.                                               *)
(*                                                                           *)
(* THE METHOD is the siblings': a Guard the Rust computes (mutable by a Bug*  *)
(* switch) against a Policy the requirement fixes. Two properties are ghosts  *)
(* (a splice and a desync are STEPS -- a completed message does not remember  *)
(* which frame each byte came from); the overrun is structural (an           *)
(* over-length transaction is a STATE the buffer index sits in). Each Bug*    *)
(* removes a real defence at a cited line, and each must make TLC produce a   *)
(* counterexample.                                                           *)
(*                                                                           *)
(* WHAT IS ABSTRACTED. A frame carries a CHUNK, not 57/59 payload bytes: the  *)
(* three properties do not look at byte contents, only at which channel a     *)
(* chunk came from, whether it arrived in order, and how many the buffer      *)
(* holds. `CTAPHID_INIT` always resyncs (crates/rsk-usb/src/ctaphid.rs:405,   *)
(* an init-type frame that IS CTAPHID_INIT falls through to start fresh), so  *)
(* `Init` is enabled in every state and a mid-transaction takeover is a       *)
(* takeover, not a splice -- B's fresh buffer holds B's chunks. The bounded   *)
(* IN-endpoint write that fixed the runtime interface wedge (0x075D,          *)
(* TX_TIMEOUT_MS) is a LIVENESS property of the async `run` loop, guarded by  *)
(* the FrameSink seam's own mutation-tested regression over the async `run`   *)
(* loop (crates/rsk-usb/src/ctaphid.rs:565), and is not this pure core's --   *)
(* stated, not smuggled.                                                      *)
(*****************************************************************************)
EXTENDS Naturals

CONSTANTS
    \* The channel domain. Two is the MEASURED minimum:
    \* `BugContIgnoresChannel` is GREEN over one channel and RED from two,
    \* and no mutant needs a third (formal/scopes.txt).
    Channels,
    Cap,   \* the message buffer's capacity in chunks (>= 2); CTAP_MAX_MESSAGE
    \* crates/rsk-usb/src/ctaphid.rs:433-435 -- a continuation whose channel is
    \* not the in-progress transaction's is CHANNEL_BUSY, and the owning
    \* channel's transaction is left intact. Removing the check appends the
    \* stranger's chunk to the owner's message: one host application's bytes
    \* spliced into another's.
    BugContIgnoresChannel,
    \* crates/rsk-usb/src/ctaphid.rs:437-440 -- a continuation whose seq is not
    \* the expected next aborts the transaction (INVALID_SEQ). Removing the
    \* check appends an out-of-order frame, assembling a message the host never
    \* sent in that order and dispatching it as authentic.
    BugContIgnoresSeq,
    \* crates/rsk-usb/src/ctaphid.rs:417-419 -- an INIT declaring more than
    \* CTAP_MAX_MESSAGE (the buffer's size, crates/rsk-usb/src/ctaphid.rs:209)
    \* is INVALID_LEN and starts nothing. Removing the check lets the declared
    \* length exceed the buffer, and the chunks that fill it index past `msg` --
    \* memory corruption in a no_std image.
    BugInitLenUnchecked

\* `NoChan` is `in_tx = false` -- no transaction open.
NoChan   == "none"

InvNames == { "NoCrossChannelSplice", "NoSequenceGap" }

VARIABLES
    owner,  \* the channel whose transaction is in progress, or NoChan
    seq,    \* the seq byte the next continuation must carry
    got,    \* chunks assembled into the buffer so far (self.cur, in chunks)
    need,   \* chunks the INIT declared (self.bcnt, in chunks)
    viol    \* ghost: the set of invariant names some step has violated

vars == << owner, seq, got, need, viol >>

\* got and need may reach Cap+1 ONLY under the length switch; that extra value is
\* precisely what NoBufferOverrun catches.
TypeOK ==
    /\ owner \in Channels \cup {NoChan}
    /\ seq \in 0..Cap
    /\ got \in 0..(Cap + 1)
    /\ need \in 0..(Cap + 1)
    /\ viol \in SUBSET InvNames

Init ==
    /\ owner = NoChan
    /\ seq = 0
    /\ got = 0
    /\ need = 0
    /\ viol = {}

(***************************************************************************)
(* INIT frame. CTAPHID_INIT always resyncs, so it is enabled in every state  *)
(* and starts a fresh transaction on its channel; the length check refuses    *)
(* a declared size past the buffer unless the switch removes it. A one-chunk  *)
(* message completes here.                                                    *)
(***************************************************************************)
StartInit(c, k) ==
    /\ (k <= Cap) \/ BugInitLenUnchecked
    /\ need' = k
    /\ got' = 1
    /\ seq' = 0
    /\ owner' = IF 1 >= k THEN NoChan ELSE c
    /\ UNCHANGED viol

(***************************************************************************)
(* CONT frame, only meaningful while a transaction is open (a stray          *)
(* continuation with no INIT provably changes nothing -- Outcome::None -- so  *)
(* it is not modelled). The three arms are the wrong channel, the wrong seq,  *)
(* and the in-order append; each Bug* turns a refusal into an append.        *)
(***************************************************************************)

\* The append shared by the in-order arm and the two buggy arms: one more chunk,
\* the expected seq advances, the transaction closes when the buffer fills. `tag`
\* is the ghost this particular append earns (empty on the honest arm).
Append(tag) ==
    /\ got' = IF got < Cap + 1 THEN got + 1 ELSE got
    /\ seq' = seq + 1
    /\ need' = need
    /\ owner' = IF got + 1 >= need THEN NoChan ELSE owner
    /\ viol' = viol \cup tag

Cont(c, s) ==
    /\ owner # NoChan
    /\ CASE c # owner ->
              \* a stranger's continuation: BUSY and intact, unless the switch
              \* splices its chunk into the owner's message
              IF BugContIgnoresChannel
                THEN Append({"NoCrossChannelSplice"})
                ELSE UNCHANGED vars
         [] s # seq ->
              \* same channel, out of order: abort, unless the switch appends
              \* it and assembles a message the host never sent in that order
              IF BugContIgnoresSeq
                THEN Append({"NoSequenceGap"})
                ELSE /\ owner' = NoChan
                     /\ UNCHANGED << seq, got, need, viol >>
         [] OTHER ->
              \* same channel, in order: the honest append
              Append({})

Next ==
    \/ \E c \in Channels, k \in 1..(Cap + 1) : StartInit(c, k)
    \/ \E c \in Channels, s \in 0..Cap : Cont(c, s)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* THE INVARIANTS.                                                          *)
(***************************************************************************)

\* No host application's chunk is ever assembled into another's message: a
\* continuation only appends on the channel that owns the transaction. Ghost --
\* a completed message carries no record of which frame each chunk came from, so
\* the splice is a step, not a state. One writer: Cont.
NoCrossChannelSplice == "NoCrossChannelSplice" \notin viol

\* No message completes out of the order the host sent it: an out-of-sequence
\* continuation aborts the transaction rather than filling the gap. Ghost, one
\* writer: Cont.
NoSequenceGap == "NoSequenceGap" \notin viol

\* The assembled length never exceeds the buffer: the declared size is refused
\* past the ceiling, and the chunk count never passes it. Structural -- an
\* over-length transaction is a state the buffer index sits in, and in a no_std
\* image passing the ceiling is an out-of-bounds write, not merely a bad value.
NoBufferOverrun == (need <= Cap) /\ (got <= Cap)

=============================================================================
