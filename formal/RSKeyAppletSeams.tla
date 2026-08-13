--------------------------- MODULE RSKeyAppletSeams ---------------------------
(*****************************************************************************)
(* SPDX-License-Identifier: AGPL-3.0-only                                    *)
(* Copyright (C) 2026 RS-Key contributors                                    *)
(*                                                                           *)
(* The CROSS-APPLET SEAMS, and only the seams. Not PIV, not OpenPGP, not     *)
(* OATH: none of their command sets is here, none of their crypto, none of   *)
(* their file layouts. What is here is the question those command sets keep  *)
(* getting wrong -- WHO HOLDS WHICH SECURITY STATUS, and WHAT ENDS IT.       *)
(*                                                                           *)
(* WHY THIS IS A SECOND MODULE rather than more of                           *)
(* RSKeySecurityState.tla. Those two state machines share no variable, and   *)
(* that is a measured claim rather than a convenience: the CCID side owns a  *)
(* Dispatcher and the only instances of openpgp / oath / piv / otp /         *)
(* management / rescue / vendor (crates/rsk-device/src/ccid.rs:86-102),      *)
(* while the CTAPHID side owns a SEPARATE Dispatcher whose applet array is   *)
(* literally one element, its own VendorApplet                               *)
(* (crates/rsk-device/src/ctap.rs:160-164). PIV, OpenPGP and OATH are not    *)
(* reachable over CTAPHID at all, so no status can be established on one     *)
(* transport and honoured on the other. A product of the two models would    *)
(* therefore multiply 17 million states by this module's own and buy exactly *)
(* zero new interleavings. What they DO share -- one flash, one button -- is *)
(* represented here as events (FactoryWipe, PowerCycle) rather than as       *)
(* shared state, and that is stated as the abstraction it is.                *)
(*                                                                           *)
(* THE METHOD is the sibling module's: each protected step carries a *Guard  *)
(* (what the Rust tests, mutable by a Bug* switch) and a *Policy (what the   *)
(* requirement is, never mutated); a step its Policy forbids records the     *)
(* violated invariant's name. Every Bug* rebuilds a defect this repo has     *)
(* actually shipped and fixed, and each must make TLC produce a              *)
(* counterexample.                                                           *)
(*****************************************************************************)
EXTENDS Naturals

(* Mutation switches. All FALSE is the shipped tree. *)
CONSTANTS
    \* crates/rsk-sdk/src/applet.rs:379-387 -- a SELECT of a DIFFERENT AID deselects the
    \* applet that was current, and the deselect is what resets its session.
    BugSelectKeepsOtherApplet,
    \* 637ed98 taken back out: PIV and OpenPGP used to reset on EVERY select,
    \* ignoring the `reselect` flag the trait hands them.
    BugReselectResetsStatus,
    \* crates/rsk-device/src/ccid.rs:327-342 -- the ICC power transition.
    BugCardResetKeepsStatus,
    \* e5da38b taken back out: PW3, the admin PIN, standing in for PW1/PW2 on
    \* PSO:CDS, PSO:DECIPHER and INTERNAL AUTHENTICATE.
    BugAdminOpensKeyOps,
    \* aa47867 taken back out: a failed OTP-PIN CHANGE that leaves the standing
    \* authentication open, so the budget can be burned through the door that
    \* does not close.
    BugFailedChangeKeepsStatus,
    \* crates/rsk-piv/src/auth.rs:114-118 -- the PIN-policy-ALWAYS slot spends
    \* its freshness, so one VERIFY authorises one key operation.
    BugPinFreshNotSpent

\* The three CCID applets that carry an in-RAM security status. `NoApplet` is
\* `Dispatcher::current = None` (crates/rsk-sdk/src/applet.rs:145): nothing
\* selected, which is where a card reset leaves the dispatcher.
Piv      == "piv"
Pgp      == "pgp"
Oath     == "oath"
NoApplet == "none"
Applets  == {Piv, Pgp, Oath}

\* The authentication references, per applet. PIV's PIN and its 9B management
\* key; OpenPGP's three (PW1 no. 81 signs, PW1 no. 82 deciphers, PW3 administers
\* -- crates/rsk-openpgp/src/pin.rs:19-38); OATH's access-code unlock and its
\* separate OTP PIN (crates/rsk-oath/src/lib.rs:212-220).
Refs == {"pivPin", "pivMgm", "pw1", "pw2", "pw3", "oathCode", "oathOtpPin"}

RefOwner(r) ==
    IF r \in {"pivPin", "pivMgm"} THEN Piv
    ELSE IF r \in {"pw1", "pw2", "pw3"} THEN Pgp
    ELSE Oath

InvNames == { "NoKeyOpOnTheAdminStatus",
              "ReselectPreservesAccessStatus" }

VARIABLES
    sel,    \* Dispatcher::current            (crates/rsk-sdk/src/applet.rs:145)
    held,   \* [Refs -> BOOLEAN]: the in-RAM security statuses
    \* PIV's `pin_fresh` -- the UNSPENT half of `has_pin`, which a PIN-policy
    \* ALWAYS key operation consumes (crates/rsk-piv/src/lib.rs:119-133). The
    \* only status here that is a two-part thing.
    fresh,
    \* Whether OATH has an access code provisioned. It decides what a SELECT
    \* means: `validated = !code_set` (crates/rsk-oath/src/lib.rs:1230-1234), so
    \* a code-less applet is unlocked by design and only a provisioned one has a
    \* status a SELECT can take away.
    oathCodeSet,
    \* Ghost: the freshness the REQUIREMENT leaves behind, always spent by a key
    \* operation. `fresh` is what the Rust holds and a Bug* switch may stop
    \* spending; this is what it should have been, and the two are equal in every
    \* state of the shipped tree. Without it BugPinFreshNotSpent was a mutant
    \* nothing caught: leaving `fresh` standing also leaves the Policy that reads
    \* `fresh` satisfied, so a second key operation on one VERIFY looked legal.
    pfresh,
    \* Ghost: the reference whose authentication was most recently REFUSED and
    \* not since re-authenticated. Its writers are enumerated at
    \* NoStatusAfterARefusedAuth; nothing else may write it.
    refused,
    viol    \* ghost: the set of invariant names some step has violated

vars == << sel, held, fresh, pfresh, oathCodeSet, refused, viol >>

NoRef == "noref"

TypeOK ==
    /\ sel   \in Applets \cup {NoApplet}
    /\ held  \in [Refs -> BOOLEAN]
    /\ fresh \in BOOLEAN
    /\ pfresh \in BOOLEAN
    /\ oathCodeSet \in BOOLEAN
    /\ refused \in Refs \cup {NoRef}
    /\ viol  \in SUBSET InvNames

\* `oathCode` starts TRUE and stays TRUE while no code is provisioned: OATH is
\* default-OPEN, unlike the other two (crates/rsk-oath/src/lib.rs:243-244).
Init ==
    /\ sel   = NoApplet
    /\ held  = [r \in Refs |-> r = "oathCode"]
    /\ fresh = FALSE
    /\ pfresh = FALSE
    /\ oathCodeSet = FALSE
    /\ refused = NoRef
    /\ viol  = {}

\* Every status an applet owns, gone. This is `Session::reset`
\* (crates/rsk-piv/src/lib.rs:153-157), `pin::Session::reset`
\* (crates/rsk-openpgp/src/pin.rs:67-80) and OATH's `deselect`
\* (crates/rsk-oath/src/lib.rs:1200-1204) -- three functions, one meaning.
ClearedFor(h, a) ==
    [r \in Refs |-> IF RefOwner(r) = a
                      THEN (r = "oathCode" /\ ~oathCodeSet) ELSE h[r]]

AllCleared == [r \in Refs |-> r = "oathCode" /\ ~oathCodeSet]

(***************************************************************************)
(* SELECT. crates/rsk-sdk/src/applet.rs:374-390 -- the ONE place that       *)
(* decides what a selection does to the applet that was current.           *)
(***************************************************************************)

\* `reselect` is `self.current == Some(i)`, so a SELECT of the SAME AID runs no
\* deselect at all. PIV and OpenPGP therefore keep everything (637ed98: SP
\* 800-73-4 pt2 3.1.1 makes it a `shall`, OpenPGP 3.4.1 4.2 says access status
\* holds until a select to a DIFFERENT DF, and a YubiKey 5.7.4 was measured
\* keeping all of it). OATH does not: it ignores the flag and re-locks
\* (crates/rsk-oath/src/lib.rs:1208), which is a recorded, deliberate asymmetry
\* rather than an oversight -- it has no oracle reading behind it.
Reselect(a) ==
    /\ sel = a
    /\ held' = IF BugReselectResetsStatus \/ a = Oath
                 THEN ClearedFor(held, a) ELSE held
    \* Parenthesised: `=` binds TIGHTER than `/\` in TLA+, so without them
    \* this reads `(fresh' = held'["pivPin"]) /\ fresh` -- an extra guard
    \* requiring `fresh`, which disabled both SELECT actions outright.
    /\ fresh' = (held'["pivPin"] /\ fresh)
    /\ pfresh' = (held'["pivPin"] /\ pfresh)
    \* The conformance recorder. PIV and OpenPGP must come through a re-SELECT
    \* with everything standing; OATH is the recorded exception.
    /\ viol' = IF a = Oath \/ held' = held
                 THEN viol ELSE viol \cup {"ReselectPreservesAccessStatus"}
    /\ UNCHANGED << sel, oathCodeSet, refused >>

\* A SELECT of a different AID: `applets[c].deselect(ctx)` runs on the applet
\* that was current, THEN `current` moves. The new applet's own select clears
\* nothing of its own for PIV/OpenPGP -- it has nothing, because its own
\* deselect ran when it lost the selection.
SelectOther(a) ==
    /\ sel # a
    \* Two resets, not one: the applet losing the selection runs `deselect`, and
    \* the one gaining it runs its own `select` with reselect = FALSE. The bug
    \* removes only the first -- the new applet still clears itself, which is why
    \* the defect is invisible from the newly selected applet's own side.
    /\ held' = IF BugSelectKeepsOtherApplet
                 THEN ClearedFor(held, a)
                 ELSE ClearedFor(IF sel = NoApplet THEN held
                                                   ELSE ClearedFor(held, sel),
                                 a)
    \* `pin_fresh` is the unspent half of `has_pin` and never outlives it.
    \* Parenthesised: `=` binds TIGHTER than `/\` in TLA+, so without them
    \* this reads `(fresh' = held'["pivPin"]) /\ fresh` -- an extra guard
    \* requiring `fresh`, which disabled both SELECT actions outright.
    /\ fresh' = (held'["pivPin"] /\ fresh)
    /\ pfresh' = (held'["pivPin"] /\ pfresh)
    /\ sel' = a
    /\ UNCHANGED << oathCodeSet, refused, viol >>

(***************************************************************************)
(* Authentication. One shape per applet, because the applets genuinely      *)
(* disagree about what a refusal costs -- see the invariant's comment.      *)
(***************************************************************************)

\* PIV VERIFY (crates/rsk-piv/src/lib.rs:475-489): success sets has_pin AND
\* pin_fresh, refusal clears both, through `Session::set_pin`
\* (crates/rsk-piv/src/lib.rs:140-143) which is the only writer of either.
PivVerify(ok) ==
    /\ sel = Piv
    /\ held' = [held EXCEPT !["pivPin"] = ok]
    /\ fresh' = ok
    /\ pfresh' = ok
    /\ refused' = IF ok THEN (IF refused = "pivPin" THEN NoRef ELSE refused)
                        ELSE "pivPin"
    /\ UNCHANGED << sel, oathCodeSet, viol >>

\* PIV CHANGE REFERENCE DATA / RESET RETRY COUNTER take no `&mut Session` at all
\* (crates/rsk-piv/src/lib.rs:494-518), so a refused change costs the standing
\* status NOTHING. Deliberate, and settled by measurement rather than taste:
\* SP 800-73-4 pt2 3.2.2/3.2.3 say the security status is unchanged and a real
\* YubiKey keeps it. It is here so the invariant below cannot be written as a
\* cross-applet rule by accident.
PivChangeRefused ==
    /\ sel = Piv
    /\ UNCHANGED vars

\* OpenPGP clears EXACTLY the addressed reference, and it keys the clear on the
\* FID it compared rather than on P2 (crates/rsk-openpgp/src/pin.rs:158-170):
\* RESET RETRY COUNTER compares EF_RC while passing p2 = 0x81, so a wrong
\* resetting code must leave PW1.81 standing.
PgpVerify(r, ok) ==
    /\ sel = Pgp
    /\ r \in {"pw1", "pw2", "pw3"}
    /\ held' = [held EXCEPT ![r] = ok]
    /\ refused' = IF ok THEN (IF refused = r THEN NoRef ELSE refused) ELSE r
    /\ UNCHANGED << sel, fresh, pfresh, oathCodeSet, viol >>

\* A refused CHANGE clears the addressed reference too -- the same writer
\* (crates/rsk-openpgp/src/pin.rs:229-231), which is where OpenPGP and PIV part
\* company.
PgpChangeRefused(r) ==
    /\ sel = Pgp
    /\ r \in {"pw1", "pw2", "pw3"}
    /\ held' = [held EXCEPT ![r] = FALSE]
    /\ refused' = r
    /\ UNCHANGED << sel, fresh, pfresh, oathCodeSet, viol >>

\* OATH VERIFY PIN (crates/rsk-oath/src/lib.rs:1172-1187) clears BOTH flags at
\* entry and re-sets them only on success: `validated` is reachable THROUGH the
\* OTP PIN as well as through the access code, so one bool carries two
\* provenances and both have to fall.
OathVerifyOtpPin(ok) ==
    /\ sel = Oath
    /\ held' = [held EXCEPT !["oathOtpPin"] = ok,
                            !["oathCode"] = ok \/ ~oathCodeSet]
    /\ refused' = IF ok THEN (IF refused = "oathOtpPin" THEN NoRef ELSE refused)
                        ELSE "oathOtpPin"
    /\ UNCHANGED << sel, fresh, pfresh, oathCodeSet, viol >>

\* aa47867: a refused CHANGE of the OTP PIN drops the standing authentication,
\* both halves (crates/rsk-oath/src/lib.rs:1148-1149). Before it, `0xB2` VERIFY
\* closed the safe on a wrong PIN and `0xB3` CHANGE did not -- so the whole retry
\* budget could be burned through CHANGE while GET CREDENTIAL went on serving
\* the stored password.
OathChangeRefused ==
    /\ sel = Oath
    /\ held' = IF BugFailedChangeKeepsStatus
                 THEN held
                 ELSE [held EXCEPT !["oathOtpPin"] = FALSE,
                                   !["oathCode"] = ~oathCodeSet]
    /\ refused' = "oathOtpPin"
    /\ UNCHANGED << sel, fresh, pfresh, oathCodeSet, viol >>

\* The access code is a MAC challenge-response with NO retry counter, so a wrong
\* answer costs nothing and keeps the standing unlock
\* (crates/rsk-oath/src/lib.rs:539-541) -- measured on a YubiKey 5.7.4 from a
\* genuinely locked applet. Two failed-auth rules inside one applet, and this is
\* the second: it must NOT write `refused`, because nothing was refused that had
\* a budget to protect.
OathValidateRefused ==
    /\ sel = Oath
    /\ UNCHANGED vars

\* SET CODE provisions the access code and re-locks
\* (crates/rsk-oath/src/lib.rs:405-410).
OathSetCode ==
    /\ sel = Oath
    /\ ~oathCodeSet
    /\ oathCodeSet' = TRUE
    /\ held' = [held EXCEPT !["oathCode"] = FALSE, !["oathOtpPin"] = FALSE]
    /\ UNCHANGED << sel, fresh, pfresh, refused, viol >>

OathValidateOk ==
    /\ sel = Oath
    /\ held' = [held EXCEPT !["oathCode"] = TRUE]
    /\ UNCHANGED << sel, fresh, pfresh, oathCodeSet, refused, viol >>

\* PIV's 9B mutual authenticate. Its own status, and it authorises the admin
\* surface only -- never a key operation, which is what `pin_satisfied`
\* (crates/rsk-piv/src/auth.rs:58-66) tests instead.
PivMgmAuth(ok) ==
    /\ sel = Piv
    /\ held' = [held EXCEPT !["pivMgm"] = ok]
    /\ refused' = IF ok THEN (IF refused = "pivMgm" THEN NoRef ELSE refused)
                        ELSE "pivMgm"
    /\ UNCHANGED << sel, fresh, pfresh, oathCodeSet, viol >>

(***************************************************************************)
(* The key operations -- the only steps whose AUTHORIZATION is at stake.    *)
(***************************************************************************)

\* e5da38b. PSO:CDS is PW1 no. 81 (3.4.1 7.2.10), PSO:DECIPHER and INTERNAL
\* AUTHENTICATE are PW1 no. 82 (7.2.11, 7.2.13), and NONE of the three names
\* PW3. The pre-fix guards were `!has_pw3 && !has_pw2` shaped, so the admin PIN
\* opened all three; a YubiKey 5.7.4 answers 6982 to PW3 alone on every one.
PgpKeyOpGuard(r) ==
    IF BugAdminOpensKeyOps THEN held[r] \/ held["pw3"] ELSE held[r]
PgpKeyOpPolicy(r) == held[r]

PgpKeyOp(r) ==
    /\ sel = Pgp
    /\ r \in {"pw1", "pw2"}
    /\ PgpKeyOpGuard(r)
    /\ viol' = IF PgpKeyOpPolicy(r) THEN viol
                                    ELSE viol \cup {"NoKeyOpOnTheAdminStatus"}
    /\ UNCHANGED << sel, held, fresh, pfresh, oathCodeSet, refused >>

\* A private-key GENERAL AUTHENTICATE at a PIN-policy-ALWAYS slot: `pin_satisfied`
\* is `has_pin && pin_fresh` there, and the operation SPENDS the freshness
\* (crates/rsk-piv/src/auth.rs:114-118) so one VERIFY buys one signature. The
\* management-key status opens nothing here -- it is the admin surface's.
PivKeyOpGuard  == IF BugPinFreshNotSpent THEN held["pivPin"]
                                         ELSE held["pivPin"] /\ fresh
PivKeyOpPolicy == held["pivPin"] /\ pfresh

PivKeyOp ==
    /\ sel = Piv
    /\ PivKeyOpGuard
    /\ viol' = IF PivKeyOpPolicy THEN viol
                                 ELSE viol \cup {"NoKeyOpOnTheAdminStatus"}
    /\ fresh' = IF BugPinFreshNotSpent THEN fresh ELSE FALSE
    /\ pfresh' = FALSE
    /\ UNCHANGED << sel, held, oathCodeSet, refused >>

(***************************************************************************)
(* The events that end a session from OUTSIDE any applet.                   *)
(***************************************************************************)

\* SCardDisconnect(SCARD_RESET_CARD) / CCID_POWER_OFF / CCID_POWER_ON:
\* `Dispatcher::reset_card` deselects, which drops the selected applet's
\* security status (crates/rsk-device/src/ccid.rs:327-342,
\* crates/rsk-sdk/src/applet.rs:222-230). This is the one the `cross_applet`
\* fuzz target already watches, one layer down.
CardReset ==
    /\ IF BugCardResetKeepsStatus
         THEN /\ UNCHANGED << held, fresh >>
         ELSE /\ held' = AllCleared
              /\ fresh' = FALSE
    /\ pfresh' = IF BugCardResetKeepsStatus THEN pfresh ELSE FALSE
    /\ sel' = NoApplet
    /\ UNCHANGED << oathCodeSet, refused, viol >>

\* A power cycle or a host-requested warm reset rebuilds every struct from
\* `new()`, so nothing in this module survives either. FIDO's clientPIN soft
\* lock is the only thing that rides a warm reset, and it belongs to the other
\* module (firmware/src/pin_lock.rs:12-21).
PowerCycle ==
    /\ sel' = NoApplet
    /\ held' = AllCleared
    /\ fresh' = FALSE
    /\ pfresh' = FALSE
    /\ refused' = NoRef
    /\ UNCHANGED << oathCodeSet, viol >>

\* `authenticatorReset` is FIDO's and reaches none of these: `is_fido_fid` is an
\* explicit enumeration plus four credential ranges precisely because the applets
\* interleave in the 0x10xx band, and 0x10A0 inside it is OATH's EF_OTP_PIN
\* rather than OpenPGP's (crates/rsk-fido/src/reset.rs:156-190). Modelled as a
\* step that changes nothing, so a mutant that made it reach would be visible.
FidoReset == UNCHANGED vars

\* `Fs::factory_wipe` (crates/rsk-fs/src/fs.rs:321-368) is FLASH-only: it never
\* sees an applet, so every in-RAM status here stands over freshly-defaulted
\* verifiers until the reboot both callers queue immediately after
\* (crates/rsk-device/src/ccid.rs:284-293, crates/rsk-display/src/pin.rs:663-671).
\* Modelled as the wipe AND its reboot in one step, which is what makes the
\* window unobservable -- and that is exactly the assumption to attack if anyone
\* ever separates them.
FactoryWipe ==
    /\ sel' = NoApplet
    /\ held' = [r \in Refs |-> r = "oathCode"]
    /\ fresh' = FALSE
    /\ pfresh' = FALSE
    /\ oathCodeSet' = FALSE
    /\ refused' = NoRef
    /\ UNCHANGED viol

Next ==
    \/ \E a \in Applets : Reselect(a)
    \/ \E a \in Applets : SelectOther(a)
    \/ \E ok \in BOOLEAN : PivVerify(ok)
    \/ \E ok \in BOOLEAN : PivMgmAuth(ok)
    \/ PivChangeRefused \/ PivKeyOp
    \/ \E r \in {"pw1", "pw2", "pw3"}, ok \in BOOLEAN : PgpVerify(r, ok)
    \/ \E r \in {"pw1", "pw2", "pw3"} : PgpChangeRefused(r)
    \/ \E r \in {"pw1", "pw2"} : PgpKeyOp(r)
    \/ \E ok \in BOOLEAN : OathVerifyOtpPin(ok)
    \/ OathChangeRefused \/ OathValidateRefused \/ OathValidateOk \/ OathSetCode
    \/ CardReset \/ PowerCycle \/ FidoReset \/ FactoryWipe

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* THE INVARIANTS.                                                          *)
(***************************************************************************)

\* THE SEAM ITSELF, and it reads straight out of the state: an applet holds a
\* security status only while it is the SELECTED applet. Selecting another AID
\* runs the previous applet's `deselect`, and a card reset selects nothing at
\* all, so no status may outlive the selection that bought it.
\*
\* `oathCode` is exempt while no access code is provisioned, because OATH is
\* default-OPEN there (crates/rsk-oath/src/lib.rs:243-244) -- an unlocked
\* code-less applet is not a status anybody authenticated for.
NoStatusOutsideItsSelection ==
    \A r \in Refs :
        (held[r] /\ ~(r = "oathCode" /\ ~oathCodeSet)) => sel = RefOwner(r)

\* A reference whose authentication was just REFUSED is not authenticated.
\*
\* This is a ghost (`refused`) and it has to be: "an attempt was refused" is a
\* step, not a state. Its writers are exactly the six authentication actions --
\* PivVerify, PivMgmAuth, PgpVerify, PgpChangeRefused, OathVerifyOtpPin,
\* OathChangeRefused -- plus PowerCycle and FactoryWipe, which retire it. Two
\* actions deliberately do NOT write it and that is the whole content of this
\* invariant: PivChangeRefused, because SP 800-73-4 and a measured YubiKey both
\* keep the status through a refused CHANGE REFERENCE DATA, and
\* OathValidateRefused, because the access code has no retry counter for a
\* refusal to protect. So there is NO single cross-applet rule here -- three
\* applets, three rules, each settled by a different authority -- and writing one
\* would have made the shipped tree red for two deliberate reasons.
NoStatusAfterARefusedAuth == (refused # NoRef) => ~held[refused]

\* No key operation runs on a status its own specification does not name. The
\* admin references -- OpenPGP's PW3 and PIV's 9B management key -- gate the
\* administrative surface and nothing else; PIV's PIN-policy-ALWAYS slots need
\* the UNSPENT half of the PIN status, so one VERIFY buys one operation.
\*
\* Ghost half, writers enumerated: PgpKeyOp and PivKeyOp. No other action is
\* gated by an authorization in this module.
NoKeyOpOnTheAdminStatus == "NoKeyOpOnTheAdminStatus" \notin viol

\* A CONFORMANCE claim, not a security one, and it is labelled as such because
\* it points the other way from the three above: 637ed98 WIDENED the
\* authentication window, so no safety invariant here can see it. SP 800-73-4
\* pt2 3.1.1 makes it a `shall` ("the PIV AID or the right-truncated version
\* thereof" leaves all security status indicators unchanged), OpenPGP 3.4.1 4.2
\* says access status holds until a select to a DIFFERENT DF, and a YubiKey
\* 5.7.4 was measured keeping all of it on both applets. Without this the
\* switch that rebuilds the pre-637ed98 tree would be a mutant nothing catches.
\*
\* Ghost, one writer: Reselect. OATH is exempt in the writer rather than here,
\* because its exemption is a property of that applet and not of the rule.
ReselectPreservesAccessStatus == "ReselectPreservesAccessStatus" \notin viol

=============================================================================
