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
    BugPinFreshNotSpent,
    \* The same shape one applet over: crates/rsk-openpgp/src/keys.rs:977-981,
    \* `inc_sig_count` clearing has_pw1 under the one-shot PW status.
    BugSigPinNotSpent,
    \* A user status opening the ADMIN surface -- the reverse of
    \* BugAdminOpensKeyOps, and unfalsifiable until the surface existed.
    BugUserStatusOpensAdmin,
    \* A refused OATH access-code VALIDATE that GRANTS the unlock. The refusal
    \* rule exempts that action entirely, so nothing could tell the two apart.
    BugRefusedValidateGrants,
    \* A USER status writing the PW status byte -- PUT DATA C4 is PW3's
    \* (crates/rsk-openpgp/src/putdata.rs:59-65). Its own switch rather than a
    \* share of BugUserStatusOpensAdmin, for the reason BugUnscopedOtpCancel has
    \* its own: a second gate on the same requirement, in a different function.
    BugPwStatusIgnoresAdmin,
    \* The two EXEMPT refusals, each taken back out. PIV's CHANGE REFERENCE DATA
    \* clearing the standing status -- SP 800-73-4 pt2 3.2.2/3.2.3 say it does
    \* not, and a YubiKey 5.7.4 was measured keeping it -- and a refused OATH
    \* access-code VALIDATE dropping the standing unlock, where a MAC
    \* challenge-response has no retry counter for a refusal to protect.
    BugPivChangeResetsStatus,
    BugRefusedValidateDropsUnlock

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

InvNames == { "NoKeyOpOnTheAdminStatus", "NoStatusAfterARefusedAuth",
              "ReselectPreservesAccessStatus",
              "ExemptRefusalPreservesStatus" }

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
    \* Whether PW1 is the one-shot kind: EF_PW_PRIV[0] = 0 makes PW1.81 valid for
    \* exactly one PSO:CDS (crates/rsk-openpgp/src/keys.rs:977-981), which is
    \* `pin_fresh` on the other applet. Host-writable through PUT DATA C4.
    oneShotSig,
    \* Ghost: the PW1.81 freshness the requirement leaves behind, spent by every
    \* signature while the one-shot status is set. Its `held` twin may be left
    \* standing by a Bug* switch; this may not.
    psig,
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

vars == << sel, held, fresh, pfresh, oneShotSig, psig, oathCodeSet,
           refused, viol >>

NoRef == "noref"

TypeOK ==
    /\ sel   \in Applets \cup {NoApplet}
    /\ held  \in [Refs -> BOOLEAN]
    /\ fresh \in BOOLEAN
    /\ pfresh \in BOOLEAN
    /\ oneShotSig \in BOOLEAN
    /\ psig \in BOOLEAN
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
    /\ oneShotSig = FALSE
    /\ psig = FALSE
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
    /\ UNCHANGED << sel, oneShotSig, psig, oathCodeSet, refused >>

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
    /\ UNCHANGED << oneShotSig, psig, oathCodeSet, refused, viol >>

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
    /\ UNCHANGED << sel, oneShotSig, psig, oathCodeSet, viol >>

\* PIV CHANGE REFERENCE DATA / RESET RETRY COUNTER take no `&mut Session` at all
\* (crates/rsk-piv/src/lib.rs:497-531), so a refused change costs the standing
\* status NOTHING. Deliberate, and settled by measurement rather than taste:
\* SP 800-73-4 pt2 3.2.2/3.2.3 say the security status is unchanged and a real
\* YubiKey keeps it.
\*
\* It was `UNCHANGED vars` -- a stutter step, which `[][Next]_vars` admits
\* anyway, so the action was indistinguishable from not existing and the
\* exemption it stands for was a comment. The KEEP is a requirement in its own
\* right and it now has the pair every other requirement here carries.
PivChangeRefused ==
    /\ sel = Piv
    /\ held'   = IF BugPivChangeResetsStatus
                   THEN [held EXCEPT !["pivPin"] = FALSE] ELSE held
    /\ fresh'  = IF BugPivChangeResetsStatus THEN FALSE ELSE fresh
    /\ pfresh' = IF BugPivChangeResetsStatus THEN FALSE ELSE pfresh
    /\ viol'   = IF held' = held /\ fresh' = fresh
                   THEN viol ELSE viol \cup {"ExemptRefusalPreservesStatus"}
    \* NOT a writer of `refused`, and that is the whole content of the rule.
    /\ UNCHANGED << sel, oneShotSig, psig, oathCodeSet, refused >>

\* OpenPGP clears EXACTLY the addressed reference, and it keys the clear on the
\* FID it compared rather than on P2 (crates/rsk-openpgp/src/pin.rs:158-170):
\* RESET RETRY COUNTER compares EF_RC while passing p2 = 0x81, so a wrong
\* resetting code must leave PW1.81 standing.
PgpVerify(r, ok) ==
    /\ sel = Pgp
    /\ r \in {"pw1", "pw2", "pw3"}
    /\ held' = [held EXCEPT ![r] = ok]
    /\ psig' = IF r = "pw1" THEN ok ELSE psig
    /\ refused' = IF ok THEN (IF refused = r THEN NoRef ELSE refused) ELSE r
    /\ UNCHANGED << sel, fresh, pfresh, oneShotSig, oathCodeSet, viol >>

\* A refused CHANGE clears the addressed reference too -- the same writer
\* (crates/rsk-openpgp/src/pin.rs:229-231), which is where OpenPGP and PIV part
\* company.
PgpChangeRefused(r) ==
    /\ sel = Pgp
    /\ r \in {"pw1", "pw2", "pw3"}
    /\ held' = [held EXCEPT ![r] = FALSE]
    /\ psig' = IF r = "pw1" THEN FALSE ELSE psig
    /\ refused' = r
    /\ UNCHANGED << sel, fresh, pfresh, oneShotSig, oathCodeSet, viol >>

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
    /\ UNCHANGED << sel, fresh, pfresh, oneShotSig, psig, oathCodeSet, viol >>

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
    /\ UNCHANGED << sel, fresh, pfresh, oneShotSig, psig, oathCodeSet, viol >>

\* The access code is a MAC challenge-response with NO retry counter, so a wrong
\* answer costs nothing and keeps the standing unlock
\* (crates/rsk-oath/src/lib.rs:539-541) -- measured on a YubiKey 5.7.4 from a
\* genuinely locked applet. Two failed-auth rules inside one applet, and this is
\* the second: it must NOT write `refused`, because nothing was refused that had
\* a budget to protect.
\* It must not GRANT, either, and that needed saying: exempting the action from
\* the refusal rule exempted it from everything, so a mutant that turned a
\* refused VALIDATE into a successful one was invisible -- `refused` provably
\* never takes the value "oathCode", so the ghost clause cannot reach that
\* reference at all. This is the Guard/Policy pair that can.
\* The two directions are DIFFERENT rules and each needs its own name: granting
\* on a refusal is the safety defect, dropping the standing unlock is the
\* conformance one (a YubiKey 5.7.4 keeps it, and there is no retry counter for
\* a refusal to protect). One recorder for both would have made the verdict
\* ambiguous the way four sibling call sites once made NoAuthorizationBypass's.
OathValidateRefused ==
    /\ sel = Oath
    /\ held' = IF BugRefusedValidateGrants
                 THEN [held EXCEPT !["oathCode"] = TRUE]
                 ELSE IF BugRefusedValidateDropsUnlock
                        THEN [held EXCEPT !["oathCode"] = FALSE] ELSE held
    /\ viol' = viol
         \cup (IF held'["oathCode"] /\ ~held["oathCode"]
                 THEN {"NoStatusAfterARefusedAuth"} ELSE {})
         \cup (IF held["oathCode"] /\ ~held'["oathCode"]
                 THEN {"ExemptRefusalPreservesStatus"} ELSE {})
    /\ UNCHANGED << sel, fresh, pfresh, oneShotSig, psig, oathCodeSet,
                    refused >>

\* SET CODE provisions the access code and re-locks
\* (crates/rsk-oath/src/lib.rs:405-410).
OathSetCode ==
    /\ sel = Oath
    /\ ~oathCodeSet
    /\ oathCodeSet' = TRUE
    /\ held' = [held EXCEPT !["oathCode"] = FALSE, !["oathOtpPin"] = FALSE]
    /\ UNCHANGED << sel, fresh, pfresh, oneShotSig, psig, refused, viol >>

OathValidateOk ==
    /\ sel = Oath
    /\ held' = [held EXCEPT !["oathCode"] = TRUE]
    /\ UNCHANGED << sel, fresh, pfresh, oneShotSig, psig, oathCodeSet, refused, viol >>

\* PIV's 9B mutual authenticate. Its own status, and it authorises the admin
\* surface only -- never a key operation, which is what `pin_satisfied`
\* (crates/rsk-piv/src/auth.rs:58-66) tests instead.
PivMgmAuth(ok) ==
    /\ sel = Piv
    /\ held' = [held EXCEPT !["pivMgm"] = ok]
    /\ refused' = IF ok THEN (IF refused = "pivMgm" THEN NoRef ELSE refused)
                        ELSE "pivMgm"
    /\ UNCHANGED << sel, fresh, pfresh, oneShotSig, psig, oathCodeSet, viol >>

(***************************************************************************)
(* The key operations -- the only steps whose AUTHORIZATION is at stake.    *)
(***************************************************************************)

\* e5da38b. PSO:CDS is PW1 no. 81 (3.4.1 7.2.10), PSO:DECIPHER and INTERNAL
\* AUTHENTICATE are PW1 no. 82 (7.2.11, 7.2.13), and NONE of the three names
\* PW3. The pre-fix guards were `!has_pw3 && !has_pw2` shaped, so the admin PIN
\* opened all three; a YubiKey 5.7.4 answers 6982 to PW3 alone on every one.
PgpKeyOpGuard(r) ==
    IF BugAdminOpensKeyOps THEN held[r] \/ held["pw3"] ELSE held[r]
\* PSO:CDS additionally needs PW1.81 UNSPENT while the one-shot status is set --
\* OpenPGP 3.4.1's "PW1 valid for one PSO:CDS", which `inc_sig_count` implements
\* by clearing has_pw1 after the signature (crates/rsk-openpgp/src/keys.rs:977-981).
\* `psig` is the requirement's copy, so a switch that stops spending the real one
\* cannot also satisfy the Policy that reads it -- the BugPinFreshNotSpent lesson,
\* applied before the mutant rather than after.
PgpKeyOpPolicy(r) == held[r] /\ (r = "pw1" /\ oneShotSig => psig)

PgpKeyOp(r) ==
    /\ sel = Pgp
    /\ r \in {"pw1", "pw2"}
    /\ PgpKeyOpGuard(r)
    /\ viol' = IF PgpKeyOpPolicy(r) THEN viol
                                    ELSE viol \cup {"NoKeyOpOnTheAdminStatus"}
    /\ held' = IF r = "pw1" /\ oneShotSig /\ ~BugSigPinNotSpent
                 THEN [held EXCEPT !["pw1"] = FALSE] ELSE held
    /\ psig'  = IF r = "pw1" /\ oneShotSig THEN FALSE ELSE psig
    /\ UNCHANGED << sel, fresh, pfresh, oneShotSig, oathCodeSet, refused >>

\* PUT DATA C4 -- the PW status byte that makes PW1.81 one-shot -- is an
\* ADMINISTRATIVE write, gated on PW3 by `write_authorized`
\* (crates/rsk-openpgp/src/putdata.rs:59-65, called at
\* crates/rsk-openpgp/src/lib.rs:286-288), and it is the only writer of that
\* status. The gate was `held["pw3"]` and nothing else: an enabling conjunct with
\* no Policy, in the family this module's sibling README spends four sections on.
\* Removing it left the reachable space BIT-IDENTICAL at 666 distinct states,
\* while anyone who could select the applet could clear the one-shot flag and
\* then sign for ever on a single PW1 VERIFY -- the requirement
\* BugSigPinNotSpent exists to protect, taken from underneath rather than
\* through the door it watches.
PwStatusGuard  == IF BugPwStatusIgnoresAdmin
                    THEN held["pw3"] \/ held["pw1"] \/ held["pw2"]
                    ELSE held["pw3"]
PwStatusPolicy == held["pw3"]

PgpSetPwStatus(v) ==
    /\ sel = Pgp
    /\ PwStatusGuard
    /\ viol' = IF PwStatusPolicy THEN viol
                                 ELSE viol \cup {"NoKeyOpOnTheAdminStatus"}
    /\ oneShotSig' = v
    \* Parenthesised. `=` binds tighter than `/\`: without them this reads
    \* `(psig' = psig) /\ held["pw1"]`, an extra guard that disabled the action
    \* whenever PW1 was unverified -- and BugSigPinNotSpent went green over it.
    /\ psig' = (psig /\ held["pw1"])
    /\ UNCHANGED << sel, held, fresh, pfresh, oathCodeSet, refused >>

\* THE ADMIN SURFACE, which the invariant named and the module did not have.
\* PUT DATA of an administrative DO needs PW3 on OpenPGP and the 9B management
\* key on PIV -- never a user status. Without a step that reads `pivMgm` and
\* `pw3` as GATES, "no key operation runs on the admin status" had no converse
\* and a user status opening the admin surface was unfalsifiable.
AdminOpGuard(a) ==
    IF BugUserStatusOpensAdmin
      THEN (IF a = Piv THEN held["pivMgm"] \/ held["pivPin"]
                       ELSE held["pw3"] \/ held["pw1"] \/ held["pw2"])
      ELSE (IF a = Piv THEN held["pivMgm"] ELSE held["pw3"])
AdminOpPolicy(a) == IF a = Piv THEN held["pivMgm"] ELSE held["pw3"]

AdminOp(a) ==
    /\ sel = a
    /\ a \in {Piv, Pgp}
    /\ AdminOpGuard(a)
    /\ viol' = IF AdminOpPolicy(a) THEN viol
                                   ELSE viol \cup {"NoKeyOpOnTheAdminStatus"}
    /\ UNCHANGED << sel, held, fresh, pfresh, oneShotSig, psig, oathCodeSet,
                    refused >>

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
    /\ UNCHANGED << sel, held, oneShotSig, psig, oathCodeSet, refused >>

(***************************************************************************)
(* The events that end a session from OUTSIDE any applet.                   *)
(***************************************************************************)

\* SCardDisconnect(SCARD_RESET_CARD) / CCID_POWER_OFF / CCID_POWER_ON:
\* `Dispatcher::reset_card` deselects, which drops the selected applet's
\* security status (crates/rsk-device/src/ccid.rs:327-342,
\* crates/rsk-sdk/src/applet.rs:222-230). This is the one the `cross_applet`
\* fuzz target already watches, one layer down.
\* Its own trailing UNCHANGED named `psig` while the ELSE branch assigned it, so
\* `psig' = FALSE /\ psig' = psig` pinned the whole action to a no-op wherever
\* PW1 stood verified under the one-shot status: a card reset taken from that
\* state was not modelled at all, and the MUTANT was enabled where the shipped
\* tree was not. 336 firings, no new distinct states -- the same shape as the
\* precedence trap, and `tla-lint.py` is what now finds both.
CardReset ==
    /\ IF BugCardResetKeepsStatus
         THEN /\ UNCHANGED << held, fresh, psig >>
         ELSE /\ held' = AllCleared
              /\ fresh' = FALSE
              /\ psig' = FALSE
    /\ pfresh' = IF BugCardResetKeepsStatus THEN pfresh ELSE FALSE
    /\ sel' = NoApplet
    /\ UNCHANGED << oneShotSig, oathCodeSet, refused, viol >>  \* a flash DO

\* A power cycle or a host-requested warm reset rebuilds every struct from
\* `new()`, so nothing in this module survives either. FIDO's clientPIN soft
\* lock is the only thing that rides a warm reset, and it belongs to the other
\* module (firmware/src/pin_lock.rs:12-21).
\* `psig` goes with `held["pw1"]`, here and in FactoryWipe. A ghost left standing
\* over a cleared status can only make the Policy that reads it EASIER to
\* satisfy, which is the direction that hides a violation rather than inventing
\* one -- masked today because every writer of `held["pw1"] = TRUE` writes `psig`
\* too, and that is an argument rather than a guarantee.
PowerCycle ==
    /\ sel' = NoApplet
    /\ held' = AllCleared
    /\ fresh' = FALSE
    /\ pfresh' = FALSE
    /\ psig' = FALSE
    /\ refused' = NoRef
    /\ UNCHANGED << oneShotSig, oathCodeSet, viol >>

\* `authenticatorReset` is FIDO's and reaches none of these: `is_fido_fid` is an
\* explicit enumeration plus four credential ranges precisely because the applets
\* interleave in the 0x10xx band, and 0x10A0 inside it is OATH's EF_OTP_PIN
\* rather than OpenPGP's (crates/rsk-fido/src/reset.rs:156-190). Modelled as a
\* step that changes nothing, so a mutant that made it reach would be visible.
FidoReset == UNCHANGED vars

\* `Fs::factory_wipe` (crates/rsk-fs/src/fs.rs:321-368) is FLASH-only: it never
\* sees an applet, so every in-RAM status here stands over freshly-defaulted
\* verifiers until the reboot both callers queue immediately after
\* (crates/rsk-device/src/ccid.rs:284-293, crates/rsk-display/src/pin.rs:697-722).
\* Modelled as the wipe AND its reboot in one step, which is what makes the
\* window unobservable -- and that is exactly the assumption to attack if anyone
\* ever separates them.
FactoryWipe ==
    /\ sel' = NoApplet
    /\ held' = [r \in Refs |-> r = "oathCode"]
    /\ fresh' = FALSE
    /\ pfresh' = FALSE
    /\ psig' = FALSE
    /\ oathCodeSet' = FALSE
    /\ refused' = NoRef
    /\ UNCHANGED << oneShotSig, viol >>

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
    \/ \E a \in {Piv, Pgp} : AdminOp(a)
    \/ \E v \in BOOLEAN : PgpSetPwStatus(v)
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
\* The ghost half exists because "a refusal granted access" is a step, and its
\* writers are exactly OathValidateRefused -- the one action the `refused` ghost
\* cannot cover, since nothing ever names "oathCode" as refused.
NoStatusAfterARefusedAuth ==
    /\ "NoStatusAfterARefusedAuth" \notin viol
    /\ (refused # NoRef) => ~held[refused]

\* No key operation runs on a status its own specification does not name. The
\* admin references -- OpenPGP's PW3 and PIV's 9B management key -- gate the
\* administrative surface and nothing else; PIV's PIN-policy-ALWAYS slots need
\* the UNSPENT half of the PIN status, so one VERIFY buys one operation.
\*
\* Ghost half, writers enumerated: PgpKeyOp and PivKeyOp. No other action is
\* gated by an authorization in this module.
NoKeyOpOnTheAdminStatus == "NoKeyOpOnTheAdminStatus" \notin viol

\* THE OTHER HALF OF THE REFUSAL RULE, and it points the opposite way: two
\* refusals must cost NOTHING, and each is settled by its own authority rather
\* than by a cross-applet principle. PIV's CHANGE REFERENCE DATA takes no
\* `&mut Session` at all (crates/rsk-piv/src/lib.rs:497-531) -- SP 800-73-4 pt2
\* 3.2.2/3.2.3, plus a measured YubiKey 5.7.4. OATH's access-code VALIDATE keeps
\* the standing unlock (crates/rsk-oath/src/lib.rs:539-541), because a MAC
\* challenge-response has no retry counter for a refusal to protect.
\*
\* So THREE APPLETS KEEP THREE RULES and no single one can be written: OpenPGP's
\* refused CHANGE clears the addressed reference, OATH's OTP-PIN CHANGE drops
\* both flags, and these two keep everything. That is the honest answer, and
\* what makes it a property rather than a paragraph is that both exemptions are
\* now falsifiable in the direction they actually go.
\*
\* Ghost, two writers: PivChangeRefused and OathValidateRefused.
ExemptRefusalPreservesStatus == "ExemptRefusalPreservesStatus" \notin viol

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
