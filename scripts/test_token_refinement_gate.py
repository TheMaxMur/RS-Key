# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Mutation table for the phase-5 concrete-event completeness gate."""

from pathlib import Path

import pytest

import token_refinement_gate


EXPORT = """TOKEN|OP|IssueToken
TOKEN|OP|SetPin
TOKEN|OP|UseMc
"""

MANIFEST = """[[volatile_writer]]
file = "crates/rsk-fido/src/state.rs"
function = "issue"
op = "IssueToken"

[[persistent_writer]]
file = "crates/rsk-fido/src/state.rs"
function = "persist"
op = "SetPin"

[[outcome_producer]]
file = "crates/rsk-fido/src/state.rs"
function = "authorize"
op = "UseMc"

[[walk_owner]]
file = "crates/rsk-fido/src/state.rs"
function = "may_walk_rps"
disposition = "out-of-scope"
why = "fixture: a guard maps to no A operation"

[[softlock_owner]]
file = "crates/rsk-fido/src/state.rs"
function = "pin_lock"
disposition = "out-of-scope"
why = "fixture: a guard maps to no A operation"

[[softlock_owner]]
file = "crates/rsk-fido/src/state.rs"
function = "restore_pin_lock"
disposition = "out-of-scope"
why = "fixture: a guard maps to no A operation"

[[reset_window_owner]]
file = "crates/rsk-fido/src/reset.rs"
function = "in_reset_window"
disposition = "out-of-scope"
why = "fixture: a guard maps to no A operation"
"""

STATE = """pub const PERM_MC: u8 = 0x01;
pub const PERM_LBW: u8 = 0x10;
pub const PERM_ACFG: u8 = 0x20;

pub struct PinUvAuthToken {
    pub token: [u8; 32],
    pub in_use: bool,
    pub permissions: u8,
    pub rp_id_hash: [u8; 32],
    pub has_rp_id: bool,
    pub last_used_ms: u64,
}

fn issue() {
    state.paut.in_use = true;
}

fn persist() {
    fs.put(EF_PIN, &[]);
}

fn authorize() {
    let authorized = state.paut.permissions & PERM_MC != 0;
}

// The struct the whole-token clause reads its type name off, and the MAC anchor
// the outcome axis reads its method AND its primitive off. Both used to be
// spelled in the gate — `*self` and `verify_token` — and both moved out of it
// once a write one crate over proved `self` was a spelling and not the state.
pub struct FidoState {
    ephemeral: [u8; 32],
    pub paut: PinUvAuthToken,
}

impl FidoState {
    pub fn new() -> Self {
        Self { ephemeral: [0; 32], paut: PinUvAuthToken::new() }
    }
}

pub fn verify_token(&self, proto: PinProto, data: &[u8], param: &[u8]) -> bool {
    pinproto::verify(proto, &self.paut.token, data, param)
}

pub struct PinLock {
    pub engaged: bool,
    pub mismatches: u8,
}

pub fn may_walk_rps(&self, channel: u32) -> bool {
    self.channel == channel && self.rp_counter <= self.rp_total
}

pub fn pin_lock(&self) -> PinLock {
    PinLock {
        engaged: self.needs_power_cycle,
        mismatches: self.new_pin_mismatches,
    }
}

pub fn restore_pin_lock(&mut self, lock: PinLock) {
    self.needs_power_cycle = lock.engaged;
}
"""

# The reset window's guard, in the file the derivation reads it out of.
RESET = """fn in_reset_window(ctx: &Ctx) -> bool {
    !ctx.state.warm_boot && ctx.now_ms <= RESET_WINDOW_MS
}
"""

PROJECTION = """pub const TOKEN_PERSISTENT_FIDS: [u16; 2] =
    [crate::consts::EF_PIN, crate::consts::EF_PAUTHTOKEN.get()];

impl FidoState {
    pub fn abstract_token(&self, persistent: TokenPersistentView) -> AState {
        AState {
            live: self.paut.in_use,
            permission_mc: self.paut.permissions & PERM_MC != 0,
            permission_acfg: self.paut.permissions & PERM_ACFG != 0,
            rp_bound: self.paut.has_rp_id,
        }
    }
}
"""

CONSTS = """pub const EF_PIN: u16 = 0x1080;
pub const EF_PAUTHTOKEN: KeyFid = KeyFid::new(0x1091);
"""

LIB = """pub mod state;
pub mod consts;
pub mod state_assurance;

#[cfg(test)]
mod harness;
"""

# Only the shape the gate reads: which public methods reach a storage mutation.
STORE = """impl<S: Storage> Fs<S> {
    pub fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.storage.read(fid, buf)
    }

    pub fn put(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.storage.write(fid, data)
    }

    pub fn delete(&mut self, fid: u16) -> Result<()> {
        self.storage.remove(fid)
    }

    pub fn delete_key(&mut self, fid: KeyFid) -> Result<()> {
        self.delete(fid.get())
    }
}
"""

MATRIX = """| # | Configuration | Kind | Published |
|---|---|---|---|
| 01 | `firmware` | package | yes |
| 16 | `firmware-display` | package | yes |
| 25 | `largeblob-ext` | feature | n/a |
"""


#: One family member per axis is what this fixture carries, so the shipped floors
#: are the wrong ruler for it. Not a global anything reassigns — the gate takes
#: them as an argument.
SCALED = dict.fromkeys(token_refinement_gate.AXES, 1)


class Tree:
    def __init__(self, root: Path):
        self.root = root
        self.write("formal/generated/token_relation.txt", EXPORT)
        self.write("assurance/token_refinement.toml", MANIFEST)
        self.write("crates/rsk-fido/src/lib.rs", LIB)
        self.write("crates/rsk-fido/src/state.rs", STATE)
        self.write("crates/rsk-fido/src/reset.rs", RESET)
        self.write("crates/rsk-fido/src/consts.rs", CONSTS)
        self.write("crates/rsk-fido/src/state_assurance.rs", PROJECTION)
        self.write("crates/rsk-fido/src/harness.rs", "")
        self.write("crates/rsk-fs/src/fs.rs", STORE)
        self.write("docs/assurance-matrix.md", MATRIX)

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def append(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.write_text(path.read_text() + text)

    def replace(self, relative: str, old: str, new: str) -> None:
        path = self.root / relative
        text = path.read_text()
        assert text.count(old) == 1
        path.write_text(text.replace(old, new))

    def own(self, category: str, function: str, extra: str = "", file: str = None) -> None:
        self.append(
            "assurance/token_refinement.toml",
            f'\n[[{category}]]\nfile = "{file or "crates/rsk-fido/src/state.rs"}"\n'
            f'function = "{function}"\n{extra}',
        )

    def findings(self) -> list[str]:
        """The gate over this fixture, with the floors scaled to it.

        The floors are calibrated on the real tree — 4 walk sites, 12 soft-lock,
        2 window — and this tree carries one family member each on purpose: the
        arms below are about the RULES, and a floor written for the checkout
        would make every one of them red for the fixture's size. The floors
        themselves are falsified against the real numbers in
        `test_a_derivation_that_finds_nothing_trips_its_own_floor`.

        Handed IN, never assigned over the module's own: a case that reassigns
        `FLOORS` leaves it reassigned for whatever runs next in the process, and
        the two arms that falsify the SHIPPED numbers would then be falsifying a
        fixture-sized stand-in with the real one nowhere in the run.
        """
        return token_refinement_gate.audit(self.root, SCALED)[0]


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    return Tree(tmp_path)


def contains(findings: list[str], text: str) -> bool:
    return any(text in finding for finding in findings)


def only(findings: list[str], text: str) -> bool:
    """The finding is there AND it is the only one — a direction check.

    Half the arms below add a site and assert one message; without this the arm
    passes on a fixture that went red for an unrelated reason, which is the
    failure mode this repo has measured twice.
    """
    return len(findings) == 1 and text in findings[0]


def test_green_fixture_passes(tree: Tree):
    assert tree.findings() == []


def test_this_checkout_passes():
    assert token_refinement_gate.audit(token_refinement_gate.ROOT)[0] == []


def test_an_owner_cannot_name_an_operation_outside_tla(tree: Tree):
    tree.replace("assurance/token_refinement.toml", 'op = "IssueToken"', 'op = "Unknown"')
    assert only(tree.findings(), "Unknown is outside the generated TLA+ Ops domain")


def test_the_persistent_domain_is_derived_from_the_projection(tree: Tree):
    tree.replace("crates/rsk-fido/src/state_assurance.rs", "EF_PAUTHTOKEN", "EF_ALWAYS_UV")
    assert contains(tree.findings(), "TokenPersistentView key derivation yielded")


@pytest.mark.parametrize(
    ("body", "finding"),
    [
        ("fn stray() { state.paut.permissions = 0; }\n", "volatile: unowned concrete site"),
        # `|=` and the in-place array writes: the first regex knew `=` and `&=`,
        # and knew three of the nine fields.
        ("fn stray() { state.paut.permissions |= 1; }\n", "volatile: unowned concrete site"),
        (
            "fn stray() { state.paut.rp_id_hash.copy_from_slice(&h); }\n",
            "volatile: unowned concrete site",
        ),
        ("fn stray() { fs.delete(EF_PIN); }\n", "persistent: unowned concrete site"),
        # `delete_key` is a token-record write the hand-written four could not see:
        # the alternation `put|put_key|delete|force_delete` matched `delete` and
        # then demanded `(`.
        ("fn stray() { fs.delete_key(EF_PAUTHTOKEN); }\n", "persistent: unowned concrete site"),
        (
            "fn stray() { let ok = state.paut.permissions & PERM_ACFG != 0; }\n",
            "outcome: unowned concrete site",
        ),
        # A permission outside the four the abstraction reads is still a gate.
        (
            "fn stray() { let ok = state.paut.permissions & PERM_LBW != 0; }\n",
            "outcome: unowned concrete site",
        ),
        # The MAC without the mask — the bypass shape the permission query alone
        # cannot see.
        ("fn stray() { if !state.verify_token(p, d, m) { fail(); } }\n", "outcome: unowned"),
        # Every shape below was written by an adversarial review of this gate and
        # was NOT flagged when it ran. A receiver is an expression, not one word.
        ("fn stray() { let _ = Fs::put(&mut ctx.fs, EF_PIN, &[]); }\n", "persistent: unowned"),
        ("fn stray() { let _ = Fs::delete(c.fs, EF_PIN); }\n", "persistent: unowned"),
        # The fid as the number the constant is defined as.
        ("fn stray() { let _ = fs.delete(0x1080); }\n", "persistent: unowned"),
        ("fn stray() { let _ = fs.delete_key(0x1091); }\n", "persistent: unowned"),
        # Replacing the whole token, which touches no `.paut.<field>` at all.
        ("fn stray(s: &mut S) { let _ = mem::take(&mut s.paut); }\n", "volatile: unowned"),
        ("fn stray(s: &mut S) { mem::swap(&mut s.paut, o); }\n", "volatile: unowned"),
        ("fn stray(s: &mut S) { let t = &mut s.paut; t.in_use = true; }\n", "volatile: unowned"),
        # A parenthesised permission set, and the primitive called as a path.
        ("fn stray(s: &S) -> bool { s.paut.permissions & (PERM_ACFG | PERM_MC) != 0 }\n", "outcome: unowned"),
        ("fn stray(s: &S) -> bool { PERM_ACFG & s.paut.permissions != 0 }\n", "outcome: unowned"),
        ("fn stray(s: &S) -> bool { FidoState::verify_token(s, p, d, m) }\n", "outcome: unowned"),
        # The six in-place mutators beside `copy_from_slice`.
        ("fn stray(s: &mut S) { s.paut.rp_id_hash.fill(0); }\n", "volatile: unowned"),
        # --- the four shapes a 2026-08-31 probe measured MISSED ------------------
        # The fid one `let` away from the write. Named in the gate's own docstring
        # as undiscovered for as long as the docstring existed.
        ("fn stray() { let fid = EF_PIN; let _ = fs.put(fid, &[]); }\n", "persistent: unowned"),
        # The same, ARITHMETIC — and this one was named nowhere at all: it spells
        # neither `EF_PIN` nor `0x1080`, so both discoverable forms are absent and
        # only folding the expression finds it.
        (
            "fn stray() { let f = 0x1000u16 + 0x80; let _ = fs.put(f, &[]); }\n",
            "persistent: unowned",
        ),
        # Two hops, because a one-hop rule is a rule about how the author spaced it.
        (
            "fn stray() { let a = EF_PAUTHTOKEN; let b = a; let _ = fs.delete_key(b); }\n",
            "persistent: unowned",
        ),
        # A `;` inside the type annotation used to make the whole binding invisible
        # to a `[^;]*` reader, which is the write after it going unowned in silence.
        (
            "fn stray() { let mut pad: [u8; 4] = [0; 4]; let fid = EF_PIN;"
            " let _ = fs.put(fid, &pad); }\n",
            "persistent: unowned",
        ),
        # The permission mask one `let` away from the live byte.
        (
            "fn stray(s: &S) -> bool { let p = s.paut.permissions; p & PERM_MC != 0 }\n",
            "outcome: unowned",
        ),
        # The whole token replaced under a name that is not `self`, which is what
        # `crates/rsk-device/src/ctap.rs:122` does at every power-up.
        (
            "fn stray(c: &C) { let mut st = c.state.borrow_mut(); *st = FidoState::new(); }\n",
            "volatile: unowned",
        ),
        # --- five more a §7.7 adversarial review drove through and watched slip ---
        # The MIRROR of the permission-local clause: the byte can be in the local,
        # or the PERMISSION can. One was taught and the other was not.
        (
            "fn stray(s: &S) -> bool { let need = PERM_MC; s.paut.permissions & need != 0 }\n",
            "outcome: unowned",
        ),
        # A `const` ITEM is a fid spelling no `let` reader sees — it lives outside
        # every `fn`, so the binding walk goes straight past it.
        (
            "const ALIAS_FID: u16 = 0x1080;\n\nfn stray() { let _ = fs.put(ALIAS_FID, &[]); }\n",
            "persistent: unowned",
        ),
        # The whole token replaced by a value that names NO type: answered from the
        # left-hand side, whose name is the token's owner by its parameter type.
        (
            "fn stray(fido_state: &RefCell<FidoState>) {\n"
            "    let mut st = fido_state.borrow_mut();\n    *st = Default::default();\n}\n",
            "volatile: unowned",
        ),
        (
            "fn stray(c: &C) { let mut st = c.borrow_mut();"
            " core::mem::replace(&mut *st, FidoState::new()); }\n",
            "volatile: unowned",
        ),
        # `let f = EF_PIN; fs.put(f, ..); let f = EF_RP;` — the write is governed by
        # the binding BEFORE it, and a last-binding-wins repair that ignored
        # position would lose this real writer to cure a cosmetic false one.
        (
            "fn stray() { let f = EF_PIN; let _ = fs.put(f, &[]); let f = EF_RP; use_it(f); }\n",
            "persistent: unowned",
        ),
    ],
)
def test_an_unowned_concrete_site_fails(tree: Tree, body: str, finding: str):
    tree.append("crates/rsk-fido/src/state.rs", body)
    assert only(tree.findings(), finding)


@pytest.mark.parametrize(
    "body",
    [
        # CONTROL. A fid that folds to a REAL number that is not a token record:
        # 0x1081 is OpenPGP PW1, one above EF_PIN. If the folder measured spelling
        # rather than value this would be red, and the case above would prove
        # nothing about which write it found.
        "fn stray() { let f = 0x1000u16 + 0x81; let _ = fs.put(f, &[]); }\n",
        # CONTROL. A local bound from a fid this projection does not own.
        "fn stray() { let fid = EF_ALWAYS_UV; let _ = fs.put(fid, &[]); }\n",
        # CONTROL. A fid built from a RUNTIME value folds to nothing —
        # `credential.rs:919` really is `let fid = EF_RP + i`, and a rule that
        # guessed from the mention would own it.
        "fn stray(i: u16) { let fid = EF_PIN_BASE + i; let _ = fs.put(fid, &[]); }\n",
        # CONTROL. A gate that masks its own PARAMETER and that nobody hands the
        # live byte to. `clientpin.rs::issue_token` and `consent_for_permissions`
        # are exactly this on the real tree: measured, 2 such gates and 0 hand-offs,
        # and the coarse rule that skipped the hand-off cost a false owner.
        "fn gate(permissions: u8) -> bool { permissions & PERM_MC != 0 }\n\n"
        "fn stray(req: &R) -> bool { gate(req.permissions) }\n",
        # CONTROL. A MAC under something that is not a token record — 4 of the
        # primitive's 5 production callers are this, MACing under an ECDH secret.
        "fn stray(s: &[u8], d: &[u8], p: &[u8]) -> bool {\n"
        "    let shared = [0u8; 32];\n    pinproto::verify(proto, &shared, d, p)\n}\n",
        # CONTROL for the mirror clause: a mask against a local that is NOT a
        # permission. Without it the clause would own every mask of the byte.
        "fn stray(s: &S) -> bool { let need = ctx.wire_mask; s.paut.permissions & need != 0 }\n",
        # CONTROL for SHADOWING, and this one is a false owner the rule had before
        # the review: the write is of EF_RP, and demanding a token disposition for
        # it would be the gate asserting something untrue about the source.
        "fn stray() { let f = EF_PIN; let f = EF_RP; let _ = fs.put(f, &[]); }\n",
        # CONTROL for the const-item clause: an alias folding to a fid this
        # projection does not own (0x1081 is OpenPGP PW1, one above EF_PIN).
        "const OTHER_FID: u16 = 0x1081;\n\nfn stray() { let _ = fs.put(OTHER_FID, &[]); }\n",
        # CONTROL for the deref clause: the same `*st = Default::default()` on a
        # name whose type is something else entirely. NOT `PinLock` — that is the
        # soft lock's own wire type and the guard axis owns every mention of it,
        # so the first draft of this control went red on a different axis and
        # would have "passed" as evidence for a clause it never exercised.
        "fn stray(gna: &RefCell<AssertionState>) {\n"
        "    let mut st = gna.borrow_mut();\n    *st = Default::default();\n}\n",
        # CONTROL for the swap clause: BUILDING a fresh state replaces nothing.
        # `firmware/src/main.rs:1170` is exactly this, and a rule reading
        # `FidoState::new` anywhere would own the boot that makes the one cell.
        "fn stray() { let cell = RefCell::new(FidoState::new()); hand(cell); }\n",
    ],
)
def test_a_control_mutant_leaves_the_row_green(tree: Tree, body: str):
    """Each of these is one token away from a case above that goes red. Without
    them the table measures spelling: every arm would still pass if the new
    clauses owned any local handed to any writer, or any masked parameter."""
    tree.append("crates/rsk-fido/src/state.rs", body)
    assert tree.findings() == []


def test_a_helper_masking_a_parameter_and_its_caller_are_both_sites(tree: Tree):
    """The mask one CALL away. Both halves, for the reason the persistent axis
    owns both halves of its fid hand-off: the helper performs the comparison and
    the caller chooses that it is the LIVE token being compared."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn gate(permissions: u8) -> bool { permissions & PERM_MC != 0 }\n\n"
        "fn stray(s: &S) -> bool { gate(s.paut.permissions) }\n",
    )
    findings = tree.findings()
    assert contains(findings, "outcome: unowned concrete site crates/rsk-fido/src/state.rs::gate")
    assert contains(findings, "outcome: unowned concrete site crates/rsk-fido/src/state.rs::stray")


def test_a_mac_over_a_token_record_is_an_outcome(tree: Tree):
    """The persistent `pcmr` grant's shape: it touches no `paut` at all, so
    neither the MAC-method clause nor the permission clause can see it. It was a
    hand-named `(file, function, callee)` triple until the primitive `verify_token`
    calls was derived and the question became what the MAC is taken OVER."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn load_grant(fs: &mut F) -> Option<[u8; 32]> { get_sealed32(fs, EF_PAUTHTOKEN) }\n\n"
        "fn stray(fs: &mut F, d: &[u8], p: &[u8]) -> bool {\n"
        "    let tok = load_grant(fs)?;\n    pinproto::verify(proto, &tok, d, p)\n}\n",
    )
    assert contains(
        tree.findings(), "outcome: unowned concrete site crates/rsk-fido/src/state.rs::stray"
    )


def test_the_mac_method_name_is_derived_and_not_spelled(tree: Tree):
    """Renaming the anchor method renames what the axis looks for, with no edit
    to the gate: `verify_token` was a hand-written name in it until the anchor
    moved to the `paut` field the MAC is taken over."""
    tree.replace("crates/rsk-fido/src/state.rs", "pub fn verify_token", "pub fn check_param")
    tree.append(
        "crates/rsk-fido/src/state.rs", "fn stray() { if !state.check_param(p, d, m) { f(); } }\n"
    )
    assert only(tree.findings(), "outcome: unowned concrete site crates/rsk-fido/src/state.rs::stray")


@pytest.mark.parametrize(
    "old,new,text",
    [
        ("pub paut: PinUvAuthToken,", "paut: PinUvAuthToken,", "declares no struct with a `pub paut`"),
        ("pinproto::verify(proto, &self.paut.token", "verify_mac(&self.paut.token", "hands no `paut` field to a MAC"),
    ],
)
def test_a_derived_anchor_moving_is_a_finding_not_a_traceback(tree: Tree, old, new, text):
    """Both new anchors, held the way `lock_vocabulary`'s already is — and with a
    reason of their own: an empty type name turns the whole-token clause into
    `\\*\\s*[\\w.]*\\w\\s*=`, which owns every dereferencing assignment in three
    crates, so a reader that stopped reading would report the tree as unowned."""
    tree.replace("crates/rsk-fido/src/state.rs", old, new)
    assert contains(tree.findings(), text), tree.findings()


def test_the_whole_token_write_is_found_outside_the_crate_that_declares_it(tree: Tree):
    """The measured hole: `crates/rsk-device/src/ctap.rs::new` replaces the whole
    session token at every power-up and was owned by nobody, invisible two
    independent ways — the clause knew only the spelling `*self`, and the writer
    axes could not see the crate at all."""
    tree.write(
        "crates/rsk-device/src/lib.rs",
        "pub mod ctap;\n\nfn stray(c: &C) { let mut st = c.borrow_mut(); "
        "*st = rsk_fido::FidoState::new(); }\n",
    )
    assert only(tree.findings(), "volatile: unowned concrete site crates/rsk-device/src/lib.rs::stray")


def test_an_array_literal_in_a_call_does_not_hide_the_hand_off(tree: Tree):
    """`([^;]*?)` cannot cross the `;` in `&[0u8; 4]`, so the caller scan lost the
    hand-off while the identical call with a named buffer was found on BOTH
    halves. `bindings()` was fixed for this exact shape and the two `calls`
    regexes were left behind — the same bug, one register over."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn helper(fid: u16, d: &[u8]) { let _ = fs.put(fid, d); }\n\n"
        "fn stray() { helper(EF_PIN, &[0u8; 4]); }\n",
    )
    findings = tree.findings()
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::stray")
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::helper")


def test_an_array_literal_does_not_invent_a_hand_off_either(tree: Tree):
    """CONTROL for the case above: the same array literal, a fid this projection
    does not own. Crossing the `;` must find the hand-off, not manufacture one."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn helper(fid: u16, d: &[u8]) { let _ = fs.put(fid, d); }\n\n"
        "fn stray() { helper(EF_ALWAYS_UV, &[0u8; 4]); }\n",
    )
    assert tree.findings() == []


def test_an_array_literal_does_not_hide_the_permission_hand_off_either(tree: Tree):
    """The outcome axis has the SAME caller scan and needed its own case: fixing
    one of the two `calls` regexes and testing only that one is how a pair like
    this stays half-repaired. Measured — reverting the outcome half alone left
    every arm in this file green."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn gate(permissions: u8, salt: &[u8]) -> bool { permissions & PERM_MC != 0 }\n\n"
        "fn stray(s: &S) -> bool { gate(s.paut.permissions, &[0u8; 4]) }\n",
    )
    findings = tree.findings()
    assert contains(findings, "outcome: unowned concrete site crates/rsk-fido/src/state.rs::gate")
    assert contains(findings, "outcome: unowned concrete site crates/rsk-fido/src/state.rs::stray")


def test_the_emulator_is_inside_the_import_scoped_sweep(tree: Tree):
    """`tools/` is walked on purpose. `tools/emu` holds a live `FidoState` and IS
    the phase-4 recording apparatus, so a token write there is the one nobody
    would ever see — and leaving a directory out in silence is exactly what let
    `crates/rsk-device` hide for as long as it did."""
    tree.write(
        "tools/emu/src/device.rs",
        "use rsk_fido::consts::EF_PIN;\n\nfn stray() { let _ = fs.delete(EF_PIN); }\n",
    )
    assert only(
        tree.findings(), "foreign: unowned concrete site tools/emu/src/device.rs::stray"
    )


def test_the_volatile_floor_this_file_ships_is_above_nothing_at_all(tree: Tree):
    """The floor is a PARAMETER, so falsify the shipped one against the real tree
    rather than a fixture-sized stand-in. 12 discriminates and 10 does not: the
    checkout derives 11, so any floor at or under it is green for a reason that
    has nothing to do with the floor being read."""
    real = token_refinement_gate.FLOORS
    assert token_refinement_gate.audit(token_refinement_gate.ROOT, real)[0] == []
    over = token_refinement_gate.audit(
        token_refinement_gate.ROOT, {**real, "volatile_writer": 12}
    )[0]
    assert contains(over, "volatile: 11 site(s) derived, under the floor of 12"), over


def test_a_permission_mask_in_a_scanned_unit_outside_the_applet_is_a_site(tree: Tree):
    """The other half of the same reach: the outcome axis could not see
    `rsk-device` either, and the crate holds the CTAP dispatcher."""
    tree.write(
        "crates/rsk-device/src/lib.rs",
        "pub mod ctap;\n\nfn stray(s: &S) -> bool { s.paut.permissions & PERM_MC != 0 }\n",
    )
    assert only(tree.findings(), "outcome: unowned concrete site crates/rsk-device/src/lib.rs::stray")


def test_a_const_fn_body_is_not_charged_to_the_function_above_it(tree: Tree):
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "const fn stray() { state.paut.in_use = false; }\n",
    )
    assert only(tree.findings(), "volatile: unowned concrete site crates/rsk-fido/src/state.rs::stray")


@pytest.mark.parametrize(
    "body",
    [
        # A commented-out write. `= TRUE \\* comment` cost this programme a green
        # run over a dead model assumption; this is the same shape in Rust.
        "fn stray() {\n    // let _ = fs.put(EF_PIN, &[]);\n    let _ = fs.put(other, &[]);\n}\n",
        # A predicate that names the fid in prose only. `reset()` really does
        # mention EF_PIN in a comment and hands predicates to `sweep`, so reading
        # comments as code invents a writer out of the pairing.
        "fn wipe(pred: fn(u16) -> bool) { fs.delete(fid); }\n\n"
        "fn owns(fid: u16) -> bool {\n    // reaches EF_PIN before the credentials\n    false\n}\n\n"
        "fn stray() { wipe(owns); }\n",
    ],
)
def test_a_fid_named_only_in_a_comment_is_not_a_writer(tree: Tree, body: str):
    tree.append("crates/rsk-fido/src/state.rs", body)
    assert tree.findings() == []


def test_a_caller_that_hands_a_token_fid_to_a_generic_writer_is_a_site(tree: Tree):
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn helper(fid: u16) { fs.put(fid, &[]); }\n\nfn stray() { helper(EF_PIN); }\n",
    )
    findings = tree.findings()
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::stray")
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::helper")


def test_a_fid_handed_through_a_free_function_reaches_every_hop(tree: Tree):
    """The shape the boot re-seal of the grant record arrives in: only the LAST
    hop is a receiver call, so a clause that stops at the first one sees none of
    it. Measured on the checkout 2026-09-16 — `migrate_keydev_boot` →
    `migrate_slot` → `put_sealed32` → `fs.put_key` was a production write the
    roster refused nothing for."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn sealer(fid: u16) { fs.put(fid, &[]); }\n\n"
        "fn relay(fid: u16) { sealer(fid); }\n\n"
        "fn stray() { relay(EF_PIN); }\n",
    )
    findings = tree.findings()
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::relay")
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::stray")


def test_the_hand_off_is_followed_through_more_than_one_relay(tree: Tree):
    """A chain, not a hop: the rule is transitive or it is a special case for the
    one depth the tree happens to have today."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn sealer(fid: u16) { fs.put(fid, &[]); }\n\n"
        "fn inner(fid: u16) { sealer(fid); }\n\n"
        "fn outer(fid: u16) { inner(fid); }\n\n"
        "fn stray() { outer(EF_PIN); }\n",
    )
    findings = tree.findings()
    # `sealer` is the SECOND hop down: assert it, or a closure that walks one link
    # and stops reads exactly like the transitive one.
    for site in ("sealer", "inner", "outer", "stray"):
        assert contains(findings, f"persistent: unowned concrete site crates/rsk-fido/src/state.rs::{site}")


def test_the_chain_is_found_with_the_caller_written_first(tree: Tree):
    """The same chain in the other source order. `catalogue()` keeps file order, so
    a single pass finds it only when each callee is already known — which is what
    the fixpoint is for, and what appending callee-first would never show."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn outer(fid: u16) { inner(fid); }\n\n"
        "fn inner(fid: u16) { sealer(fid); }\n\n"
        "fn sealer(fid: u16) { fs.put(fid, &[]); }\n\n"
        "fn stray() { outer(EF_PIN); }\n",
    )
    findings = tree.findings()
    for site in ("sealer", "inner", "outer", "stray"):
        assert contains(findings, f"persistent: unowned concrete site crates/rsk-fido/src/state.rs::{site}")


def test_a_relay_that_hands_a_fid_of_its_own_but_not_a_token_one_is_no_writer(tree: Tree):
    """The clause reads WHICH argument is handed on, not that a call happened: this
    relay has a fid parameter of its own and hands the helper a different record, so
    the token fid its own caller names reaches nothing this projection owns."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn sealer(fid: u16) { fs.put(fid, &[]); }\n\n"
        "fn relay(slot: u16) { sealer(EF_ALWAYS_UV); let _ = slot; }\n\n"
        "fn stray() { relay(EF_PIN); }\n",
    )
    assert tree.findings() == []


def test_a_nested_call_before_the_fid_does_not_break_the_chain(tree: Tree):
    """An argument list with a call in it. Stopping at the first `)` hides every
    argument after it — the fid among them — and the chain goes quiet."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn sealer(dev: &D, fid: u16) { fs.put(fid, &[]); }\n\n"
        "fn relay(fid: u16) { sealer(pick(0), fid); }\n\n"
        "fn stray() { relay(EF_PIN); }\n",
    )
    findings = tree.findings()
    for site in ("relay", "stray"):
        assert contains(findings, f"persistent: unowned concrete site crates/rsk-fido/src/state.rs::{site}")


def test_handing_something_that_is_not_a_fid_makes_no_writer(tree: Tree):
    """The other direction, and the one that keeps the clause from owning the
    tree: `relay`'s own parameter is the payload, not the fid, so reaching a
    fid-parameter helper with it writes no record — and neither does the caller
    that hands `relay` bytes which merely MENTION a token fid. Read `own` as
    "any parameter of mine" instead of "a fid one" and both become writers."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn sealer(fid: u16, data: &[u8]) { fs.put(fid, data); }\n\n"
        "fn relay(data: &[u8]) { sealer(EF_ALWAYS_UV, data); }\n\n"
        "fn stray() { relay(&[EF_PIN as u8]); }\n",
    )
    assert tree.findings() == []


def test_a_predicate_that_names_a_token_fid_reaches_the_sweep_it_selects(tree: Tree):
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn wipe(pred: fn(u16) -> bool) { fs.delete(fid); }\n\n"
        "fn owns(fid: u16) -> bool { fid == EF_PIN }\n\n"
        "fn stray() { wipe(owns); }\n",
    )
    findings = tree.findings()
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::wipe")
    assert contains(findings, "persistent: unowned concrete site crates/rsk-fido/src/state.rs::stray")


@pytest.mark.parametrize(
    ("category", "finding"),
    [
        ("volatile_writer", "volatile: stale owner"),
        ("persistent_writer", "persistent: stale owner"),
        ("outcome_producer", "outcome: stale owner"),
    ],
)
def test_a_stale_manifest_owner_fails(tree: Tree, category: str, finding: str):
    tree.own(category, "gone", 'op = "UseMc"\n')
    assert only(tree.findings(), finding)


def test_a_generic_flag_does_not_excuse_a_stale_owner(tree: Tree):
    tree.own("persistent_writer", "gone", 'op = "SetPin"\ngeneric = true\n')
    assert contains(tree.findings(), "persistent: stale owner")


def _own_the_helper_pair(tree: Tree, on_caller: str, on_helper: str) -> None:
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn helper(fid: u16) { fs.put(fid, &[]); }\n\nfn stray() { helper(EF_PIN); }\n",
    )
    tree.own("persistent_writer", "stray", f'op = "SetPin"\n{on_caller}')
    tree.own("persistent_writer", "helper", f'op = "SetPin"\n{on_helper}')


def test_a_helper_that_writes_a_handed_fid_must_say_so(tree: Tree):
    _own_the_helper_pair(tree, "", "")
    assert only(tree.findings(), "state.rs::helper does write a fid it was handed")


def test_a_caller_that_only_names_the_fid_may_not_claim_to_be_generic(tree: Tree):
    _own_the_helper_pair(tree, "generic = true\n", "generic = true\n")
    assert only(tree.findings(), "state.rs::stray does not write a fid it was handed")


def test_a_writer_the_abstraction_cannot_see_may_not_be_a_step(tree: Tree):
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { state.paut.last_used_ms = t; }\n")
    tree.own("volatile_writer", "stray", 'op = "IssueToken"\n')
    assert only(tree.findings(), "is a step over state the abstraction cannot see")


def test_a_writer_the_abstraction_does_see_may_not_be_a_stutter(tree: Tree):
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { state.paut.in_use = false; }\n")
    tree.own("volatile_writer", "stray", 'disposition = "stutter"\nwhy = "no"\n')
    assert only(tree.findings(), "writes abstract state and is not a step")


@pytest.mark.parametrize(
    ("extra", "finding"),
    [
        ('disposition = "elsewhere"\n', "carries disposition 'elsewhere'"),
        ('disposition = "stutter"\nop = "IssueToken"\nwhy = "x"\n', "and still names an op"),
        ('disposition = "stutter"\n', "is stutter with no reason"),
        ('disposition = "out-of-scope"\nwhy = "   "\n', "is out-of-scope with no reason"),
    ],
)
def test_a_disposition_must_be_answerable(tree: Tree, extra: str, finding: str):
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { state.paut.last_used_ms = t; }\n")
    tree.own("volatile_writer", "stray", extra)
    assert contains(tree.findings(), finding)


def test_a_cfg_test_module_must_declare_itself(tree: Tree):
    tree.write("crates/rsk-fido/src/harness.rs", "fn stray() { state.paut.in_use = true; }\n")
    tree.own("volatile_writer", "stray", 'op = "IssueToken"\n', file="crates/rsk-fido/src/harness.rs")
    assert only(tree.findings(), "harness.rs::stray is compiled only under cfg(test)")


def test_a_production_module_may_not_claim_to_be_test_only(tree: Tree):
    tree.replace("assurance/token_refinement.toml", 'op = "IssueToken"', 'op = "IssueToken"\ntest_only = true')
    assert only(tree.findings(), "state.rs::issue is not compiled only under cfg(test)")


def test_the_module_graph_and_not_the_file_name_decides(tree: Tree):
    """Unhooking `mod harness;` makes the same file production again."""
    tree.write("crates/rsk-fido/src/harness.rs", "fn stray() { state.paut.in_use = true; }\n")
    tree.own("volatile_writer", "stray", 'op = "IssueToken"\n', file="crates/rsk-fido/src/harness.rs")
    tree.replace("crates/rsk-fido/src/lib.rs", "#[cfg(test)]\nmod harness;", "mod harness;")
    assert tree.findings() == []


@pytest.mark.parametrize(
    ("extra", "finding"),
    [
        ('op = "IssueToken"\ncolumn = "firmware-nope"\nwhy = "x"\n', "which the matrix has no column for"),
        ('op = "IssueToken"\ncolumn = "largeblob-ext"\n', "configuration-conditional with no reason"),
    ],
)
def test_a_column_comes_from_the_matrix(tree: Tree, extra: str, finding: str):
    tree.replace("assurance/token_refinement.toml", 'op = "IssueToken"\n', extra)
    assert only(tree.findings(), finding)


def test_a_token_record_written_outside_the_scanned_units_fails(tree: Tree):
    """`rsk-display` is not one of `UNITS`, so the import-scoped sweep is all
    that reaches it. `rsk-device` used to be tested here and no longer can be —
    it is on the persistent axis proper now, one case down."""
    tree.write(
        "crates/rsk-display/src/applets.rs",
        "use rsk_fido::consts::{EF_PAUTHTOKEN, EF_PIN};\n\nfn stray() { fs.delete(EF_PIN); }\n",
    )
    assert only(
        tree.findings(), "foreign: unowned concrete site crates/rsk-display/src/applets.rs::stray"
    )


def test_a_scanned_unit_is_reported_once_and_on_the_axis_itself(tree: Tree):
    """`rsk-device` is scanned directly now, so the import-scoped sweep must not
    ALSO claim it: a write named by both rules reads as two writes, and a roster
    that counts spellings is the failure this file exists to stop."""
    tree.write("crates/rsk-device/src/lib.rs", "pub mod ctap;\n")
    tree.write(
        "crates/rsk-device/src/ctap.rs",
        "use rsk_fido::consts::{EF_PAUTHTOKEN, EF_PIN};\n\nfn stray() { fs.delete(EF_PIN); }\n",
    )
    assert only(
        tree.findings(), "persistent: unowned concrete site crates/rsk-device/src/ctap.rs::stray"
    )


def test_another_applets_like_named_record_is_not_this_one(tree: Tree):
    """`rsk-piv` defines its own `EF_PIN` (0xD180), and writes it constantly."""
    tree.write(
        "crates/rsk-piv/src/files.rs",
        "pub const EF_PIN: u16 = 0xD180;\n\nfn stray() { fs.put(EF_PIN, &[]); }\n",
    )
    assert tree.findings() == []


def test_the_store_write_api_is_read_out_of_the_store(tree: Tree):
    """A new `Fs` mutator is a new way to write a token record, with no edit here."""
    tree.append(
        "crates/rsk-fs/src/fs.rs",
        "\nimpl<S: Storage> Fs<S> {\n    pub fn scribble(&mut self, fid: u16) -> Result<()> {\n"
        "        self.storage.write(fid, &[])\n    }\n}\n",
    )
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { fs.scribble(EF_PIN); }\n")
    assert only(tree.findings(), "persistent: unowned concrete site crates/rsk-fido/src/state.rs::stray")


def test_test_kani_and_generated_files_are_not_production_axes(tree: Tree):
    body = "fn ignored() { state.paut.in_use = true; fs.delete(EF_PIN); }\n"
    tree.write("crates/rsk-fido/src/state_tests.rs", body)
    tree.write("crates/rsk-fido/src/state_kani.rs", body)
    tree.write("crates/rsk-fido/src/generated_token_edges.rs", body)
    assert tree.findings() == []


def test_main_prints_a_nonempty_success_summary(tree: Tree, monkeypatch, capsys):
    monkeypatch.setattr(token_refinement_gate, "ROOT", tree.root)
    assert token_refinement_gate.main(SCALED) == 0
    assert capsys.readouterr().out.startswith("token-refinement-gate: GREEN")


def test_main_reports_every_finding_and_exits_nonzero(tree: Tree, monkeypatch, capsys):
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { state.paut.in_use = true; }\n")
    monkeypatch.setattr(token_refinement_gate, "ROOT", tree.root)
    assert token_refinement_gate.main(SCALED) == 1
    assert "unowned concrete site" in capsys.readouterr().err


def test_replacing_the_whole_state_is_a_token_write(tree: Tree):
    """`FidoState::reset` is `*self = Self::new()` — every abstract bit at once."""
    tree.append("crates/rsk-fido/src/state.rs", "fn stray(&mut self) { *self = Self::new(); }\n")
    assert only(tree.findings(), "volatile: unowned concrete site crates/rsk-fido/src/state.rs::stray")


def test_self_means_the_token_owner_in_any_file_that_impls_it(tree: Tree):
    """`*self = Self::new()` is the same write in a second `impl FidoState`, and
    the file it may appear in is derived from the impl rather than pinned to
    `state.rs` — which is what the clause was, and what a new module would have
    walked straight past."""
    tree.write(
        "crates/rsk-fido/src/warm.rs",
        "impl FidoState {\n    fn stray(&mut self) { *self = Self::new(); }\n}\n",
    )
    assert only(tree.findings(), "volatile: unowned concrete site crates/rsk-fido/src/warm.rs::stray")


def test_self_in_an_impl_of_something_else_is_not_the_token(tree: Tree):
    """CONTROL for the case above, and the reason the impl is required at all:
    `*self = Self::new()` is an ordinary reset of whatever type owns it, and
    `rsk-fido` is full of small states that have one."""
    tree.write(
        "crates/rsk-fido/src/warm.rs",
        "impl LargeBlobState {\n    fn stray(&mut self) { *self = Self::new(); }\n}\n",
    )
    assert tree.findings() == []


def test_replacing_the_whole_state_cannot_be_a_stutter(tree: Tree):
    tree.append("crates/rsk-fido/src/state.rs", "fn stray(&mut self) { *self = Self::new(); }\n")
    tree.own("volatile_writer", "stray", 'disposition = "stutter"\nwhy = "no"\n')
    assert only(tree.findings(), "writes abstract state and is not a step")


@pytest.mark.parametrize(
    "desync",
    [
        "fn spacer() { let _b = '{'; }\n",
        "fn spacer() { /* { */ }\n",
        'fn spacer() { let _s = "}"; }\n',
    ],
)
def test_a_brace_inside_a_literal_does_not_swallow_the_next_writer(tree: Tree, desync: str):
    """One char literal desynchronises the depth counter, and every writer after
    it in the file joins the previous function's body — silently."""
    tree.append("crates/rsk-fido/src/state.rs", desync)
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { state.paut.in_use = true; }\n")
    assert only(tree.findings(), "volatile: unowned concrete site crates/rsk-fido/src/state.rs::stray")


def test_a_writer_written_inside_a_string_is_not_a_writer(tree: Tree):
    tree.append(
        "crates/rsk-fido/src/state.rs",
        'fn stray() { log("fs.put(EF_PIN, &[]) and paut.in_use = true"); }\n',
    )
    assert tree.findings() == []


def test_a_nested_fn_belongs_to_the_function_that_contains_it(tree: Tree):
    """Bodies close on brace depth, so `inner` is part of `outer` — the run-to-the-
    next-`fn` form reports `inner` instead, and this is what tells them apart."""
    tree.append(
        "crates/rsk-fido/src/state.rs",
        "fn outer() {\n    fn inner() { state.paut.in_use = true; }\n}\n",
    )
    assert only(tree.findings(), "volatile: unowned concrete site crates/rsk-fido/src/state.rs::outer")


@pytest.mark.parametrize("spelling", ["pub fn", "pub(crate) fn", "pub async fn"])
def test_every_public_spelling_of_a_store_mutator_counts(tree: Tree, spelling: str):
    """`pub(crate) fn` appears 149 times in this tree; a second, narrower `pub fn`
    pattern here would drop such a method out of the derived write API in silence."""
    tree.append(
        "crates/rsk-fs/src/fs.rs",
        f"\nimpl<S: Storage> Fs<S> {{\n    {spelling} scribble(&mut self, fid: u16) -> Result<()> {{\n"
        "        self.storage.write(fid, &[])\n    }\n}\n",
    )
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { fs.scribble(EF_PIN); }\n")
    assert only(tree.findings(), "persistent: unowned concrete site crates/rsk-fido/src/state.rs::stray")


def test_a_private_store_helper_is_not_part_of_the_write_api(tree: Tree):
    tree.append(
        "crates/rsk-fs/src/fs.rs",
        "\nimpl<S: Storage> Fs<S> {\n    fn scribble(&mut self, fid: u16) -> Result<()> {\n"
        "        self.storage.write(fid, &[])\n    }\n}\n",
    )
    tree.append("crates/rsk-fido/src/state.rs", "fn stray() { fs.scribble(EF_PIN); }\n")
    assert tree.findings() == []


def test_the_module_import_and_not_the_two_names_scopes_the_foreign_sweep(tree: Tree):
    tree.write(
        "crates/rsk-display/src/applets.rs",
        "use rsk_fido::consts;\n\nfn stray() { fs.delete(consts::EF_PIN); }\n",
    )
    assert only(
        tree.findings(), "foreign: unowned concrete site crates/rsk-display/src/applets.rs::stray"
    )


def test_a_file_reached_both_gated_and_plain_is_production(tree: Tree):
    tree.write("crates/rsk-fido/src/harness.rs", "fn stray() { state.paut.in_use = true; }\n")
    tree.replace("crates/rsk-fido/src/lib.rs", "pub mod state;", "pub mod state;\npub mod harness;")
    tree.own("volatile_writer", "stray", 'op = "IssueToken"\n', file="crates/rsk-fido/src/harness.rs")
    assert tree.findings() == []


# ---- the three guard axes ----------------------------------------------------


@pytest.mark.parametrize(
    "axis,removal",
    [
        ("walk", ("crates/rsk-fido/src/state.rs", "self.channel == channel", "true")),
        ("reset_window", ("crates/rsk-fido/src/reset.rs", "RESET_WINDOW_MS", "0")),
    ],
)
def test_a_derivation_that_finds_nothing_trips_its_own_floor(tree: Tree, axis, removal):
    """Every rule on an axis passes over an empty roster, which is the shape a
    verdict column cannot show. Run at the REAL floors, so what is falsified is
    the number this file ships and not a fixture-sized stand-in."""
    path, old, new = removal
    tree.replace(path, old, new)
    findings = token_refinement_gate.audit(tree.root)[0]
    assert contains(findings, f"{axis}: 0 site(s) derived, under the floor of"), findings


@pytest.mark.parametrize(
    "axis,file,function",
    [
        ("walk", "crates/rsk-fido/src/state.rs", "may_walk_rps"),
        ("softlock", "crates/rsk-fido/src/state.rs", "pin_lock"),
        ("reset_window", "crates/rsk-fido/src/reset.rs", "in_reset_window"),
    ],
)
def test_an_unowned_guard_site_fails(tree: Tree, axis, file, function):
    tree.replace(
        "assurance/token_refinement.toml", f'function = "{function}"', 'function = "gone"'
    )
    findings = tree.findings()
    assert contains(findings, f"{axis}: unowned concrete site {file}::{function}"), findings
    assert contains(findings, f"{axis}: stale owner {file}::gone"), findings


def test_a_caller_of_a_guard_is_a_site_of_its_family(tree: Tree):
    """The derivation is guards AND callers: `may_walk_rps` has one production
    caller and it is one frame out, in `credmgmt.rs`."""
    tree.write(
        "crates/rsk-fido/src/credmgmt.rs",
        "fn enumerate_rps() {\n    if !state.cm.may_walk_rps(state.channel) { return; }\n}\n",
    )
    assert only(
        tree.findings(),
        "walk: unowned concrete site crates/rsk-fido/src/credmgmt.rs::enumerate_rps",
    ), tree.findings()


def test_a_board_half_that_only_names_the_wire_type_is_a_site(tree: Tree):
    """`Hooks::store_pin_lock` calls neither guard — it takes the lock BY TYPE.
    Measured: `pin_lock` and `restore_pin_lock` have zero callers inside the
    applet, so a family derived from calls alone loses the whole board half."""
    tree.write(
        "crates/rsk-device/src/lib.rs",
        "pub mod ctap;\nfn store_pin_lock(&mut self, _lock: PinLock) {}\n",
    )
    assert only(
        tree.findings(),
        "softlock: unowned concrete site crates/rsk-device/src/lib.rs::store_pin_lock",
    ), tree.findings()


def test_the_soft_locks_fields_are_read_out_of_its_accessor(tree: Tree):
    """The two `FidoState` fields are named once in the tree, in `pin_lock`, and
    naming them here would be twice."""
    tree.replace(
        "crates/rsk-fido/src/state.rs",
        "engaged: self.needs_power_cycle",
        "engaged: self.other",
    )
    assert contains(tree.findings(), "the soft lock's field derivation yielded"), tree.findings()


def test_a_guard_may_not_claim_an_operation(tree: Tree):
    """A guard writes no token field, so it implements no A step: tier A carries
    no channel, no retry counter and no clock."""
    tree.replace(
        "assurance/token_refinement.toml",
        'function = "may_walk_rps"\ndisposition = "out-of-scope"',
        'function = "may_walk_rps"\nop = "UseMc"\ndisposition = "out-of-scope"',
    )
    assert contains(tree.findings(), "is out-of-scope and still names an op"), tree.findings()


def test_the_soft_lock_family_scanned_over_the_applet_alone_trips_its_floor(monkeypatch):
    """The measured reason the guard axes scan three units and not one: on the
    real tree `pin_lock` and `restore_pin_lock` have ZERO callers inside
    `rsk-fido`, so the applet-only scan derives 2 sites of 12 and loses the whole
    board half — the marshalling across the warm reset that the clause is about.
    A floor is what turns that into a red row rather than a shorter roster."""
    monkeypatch.setattr(
        token_refinement_gate, "UNITS", ((token_refinement_gate.FIDO, "lib.rs"),)
    )
    findings = token_refinement_gate.audit(token_refinement_gate.ROOT)[0]
    assert contains(findings, "softlock: 2 site(s) derived, under the floor of 8"), findings


@pytest.mark.parametrize(
    "old,new,text",
    [
        ("pub fn pin_lock(", "pub fn lock_state(", "defines no `pin_lock`"),
        ("-> PinLock", "-> &PinLock", "returns no bare type"),
    ],
)
def test_the_soft_locks_anchor_moving_is_a_finding_not_a_traceback(tree: Tree, old, new, text):
    """Both ways `lock_vocabulary`'s anchor can move used to raise, and a
    traceback here aborts all six axes before any of them is compared — so the
    other five would report nothing about a tree nobody had checked."""
    tree.replace("crates/rsk-fido/src/state.rs", old, new)
    assert contains(tree.findings(), text), tree.findings()


def test_a_floor_reports_beside_the_comparison_and_not_instead_of_it(tree: Tree):
    """Measured direction failure: with the window floor at its derived count,
    renaming the guard reported "the derivation stopped reading the tree" and
    SUPPRESSED the accurate `stale owner` line. A row that says the reader broke
    when a security guard was deleted is red for the wrong reason."""
    tree.replace("crates/rsk-fido/src/reset.rs", "RESET_WINDOW_MS", "0")
    findings = token_refinement_gate.audit(tree.root)[0]
    assert contains(findings, "reset_window: 0 site(s) derived, under the floor of"), findings
    assert contains(findings, "reset_window: stale owner"), findings


# --- the keys the file may carry ----------------------------------------------


def test_a_field_nobody_reads_is_refused(tree):
    """Six tables and no list held any of them. Measured before the rule: an
    invented key in the first record left this row at EXIT=0, so a field added
    here was read by nothing and printed by nothing."""
    tree.append(
        "assurance/token_refinement.toml",
        '\n[[walk_owner]]\nfile = "crates/rsk-fido/src/state.rs"\n'
        'function = "may_walk_rps"\nwhy = "x"\ndisposition = "owned"\n'
        'nonsense_field_nobody_holds = "x"\n',
    )
    assert contains(tree.findings(), "which nothing reads")


def test_a_table_nobody_reads_is_refused(tree):
    """And a seventh table, which was invisible in both directions."""
    tree.append(
        "assurance/token_refinement.toml", '\n[[nonsense_table]]\nname = "x"\n'
    )
    assert contains(tree.findings(), "which nothing reads")
