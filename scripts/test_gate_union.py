# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `gate_union.py` was carved out of a roster for lacking.

The guard exists because `is_oath_lock_fid` was left out of the wipe's phase-2
union for a release and nothing said so — the code compiled and the tests passed.
A guard against that failure that is itself only checked by eye is the same
mistake one layer up, and it was carved out of `test_gate_scripts.UNROSTERED`
under the honest reason "a `run` row with no mutation table".

Every case drives the row's own entry point — `python scripts/gate_union.py`, as
`check.sh` spells it — over a fixture checkout, and reads the process exit code,
because that code is the whole of what the row reads. The guard is written into
the fixture rather than imported for the same reason: a deletion arm is then the
source cut a deletion actually is, not a monkeypatched attribute.
"""

import pathlib
import subprocess
import sys

import pytest

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUARD = ROOT / "scripts/gate_union.py"

#: Where the union lives, spelled as `gate_union.UNION` derives it from its ROOT.
UNION = "crates/rsk-device/src/ccid.rs"

#: One applet per name in `gate_union.APPLETS_OWING_A_GATE`, at a DIFFERENT
#: visibility each. Requiring `pub` is what made the guard pass on the very tree
#: it recites — the missing `is_oath_lock_fid` was a bare `fn` — so the fixture
#: carries a bare one, and the arm that drops it is what says the fix holds.
APPLETS = {
    "rsk-devconf": ("pub ", "is_devconf_gate_fid"),
    "rsk-fido": ("pub ", "is_fido_gate_fid"),
    "rsk-oath": ("", "is_oath_lock_fid"),
    "rsk-openpgp": ("pub(crate) ", "is_pgp_gate_fid"),
    "rsk-piv": ("pub ", "is_piv_lock_fid"),
}

#: The union, with a nested block before the arms: `union_body` matches braces
#: rather than reading to the first `}`, and a body that ends early takes every
#: arm after it with it while reporting them as absent.
UNION_TEXT = """\
pub fn gates_wiped_last(fid: u16) -> bool {
    if fid == 0 {
        return false;
    }
    %s
}

pub fn something_after_it(fid: u16) -> bool {
    fid == 0xffff
}
"""


def arms(names):
    return " || ".join(f"{name}(fid)" for name in names)


class Tree:
    """A checkout shaped like this one: five crates that gate secrets behind a
    record, the device crate whose union deletes those records last, and a
    firmware that is scanned for predicates but holds none."""

    def __init__(self, root):
        self.root = root
        for crate, (vis, name) in APPLETS.items():
            self.write(
                f"crates/{crate}/src/lib.rs",
                f"{vis}fn {name}(fid: u16) -> bool {{\n    fid == 0x1000\n}}\n",
            )
        self.write(UNION, UNION_TEXT % arms(name for _vis, name in APPLETS.values()))
        self.write("firmware/src/main.rs", "fn main() {}\n")

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it."""
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def run(self, *cuts):
        """The row, as `check.sh` runs it, with the guard optionally cut.

        Each cut is (anchor, replacement) applied to the guard's own source with
        the anchor asserted present, so a deletion arm whose anchor moved reads
        as a moved anchor rather than as a kill. Several, because a deletion that
        actually happens takes the rule AND whatever else would have noticed.
        """
        src = GUARD.read_text()
        for old, new in cuts:
            assert src.count(old) == 1, f"anchor moved: {old!r}"
            src = src.replace(old, new)
        self.write("scripts/gate_union.py", src)
        return subprocess.run(
            [sys.executable, "scripts/gate_union.py"],
            cwd=self.root,
            capture_output=True,
            text=True,
        )


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


# --- both directions, and the wiring ------------------------------------------


def test_the_clean_fixture_is_green(tree):
    """A guard that cannot go green gets deleted as fast as one that cannot go red."""
    result = tree.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "gate-union: ok" in result.stdout


def test_this_checkout_is_green():
    """The control the fixture cannot be: the row over the tree it guards."""
    result = subprocess.run(
        [sys.executable, str(GUARD)], cwd=ROOT, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "gate-union: ok" in result.stdout


def test_check_sh_runs_the_row():
    """A guard nothing invokes can be deleted with the whole suite still green."""
    check = (ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(check, "scripts/gate_union.py")


# --- the defect the guard is named for ----------------------------------------


def test_a_predicate_the_union_does_not_name_fails_the_row(tree):
    """audit run-36, exactly: the arm goes, the tree still builds, OATH's access
    code is deleted in phase 1 and a torn reset serves every TOTP secret.

    Both findings fire, and the second is measured rather than assumed absent:
    `contributing` counts only predicates the union NAMES, so an applet whose one
    arm is missing also reports as an applet with no predicate at all.
    """
    tree.edit(UNION, " || is_oath_lock_fid(fid)", "")
    result = tree.run()
    assert result.returncode == 1
    assert "gates_wiped_last does not name:" in result.stdout
    assert "is_oath_lock_fid" in result.stdout
    assert "no gate predicate found in: ['rsk-oath']" in result.stdout


def test_a_bare_fn_is_read_like_a_pub_one(tree):
    """The case above drops the one predicate that is not `pub`. This is the half
    of it that would otherwise be silent: made `pub`, the same cut reports the
    same name, so the finding is the missing arm and not the visibility."""
    tree.edit(UNION, " || is_oath_lock_fid(fid)", "")
    tree.edit("crates/rsk-oath/src/lib.rs", "fn is_oath", "pub fn is_oath")
    result = tree.run()
    assert result.returncode == 1
    assert "is_oath_lock_fid" in result.stdout


def test_a_predicate_named_only_in_a_comment_does_not_count(tree):
    """The shape a missing arm actually takes: the call goes, the sentence that
    explained it stays behind and goes on satisfying a membership test."""
    tree.edit(
        UNION,
        " || is_oath_lock_fid(fid)",
        "\n    // is_oath_lock_fid is handled elsewhere",
    )
    result = tree.run()
    assert result.returncode == 1
    assert "gates_wiped_last does not name:" in result.stdout
    assert "is_oath_lock_fid" in result.stdout


def test_a_deleted_predicate_is_reported_by_the_roster(tree):
    """Without a roster an absent predicate is nothing at all: no export, no
    missing arm, no finding — an applet that simply has no gate records."""
    tree.write("crates/rsk-oath/src/lib.rs", "pub fn nothing_to_see(fid: u16) -> bool { false }\n")
    tree.edit(UNION, " || is_oath_lock_fid(fid)", "")
    result = tree.run()
    assert result.returncode == 1
    assert "no gate predicate found in: ['rsk-oath']" in result.stdout
    assert "does not name:" not in result.stdout


def test_the_union_function_going_missing_fails_the_row(tree):
    """Renamed away or deleted, the union is not there to be read; the arms are
    all still exported, so nothing else in the guard would say a word."""
    tree.edit(UNION, "fn gates_wiped_last", "fn wipe_gates_last")
    result = tree.run()
    assert result.returncode == 1
    assert "gates_wiped_last not found in crates/rsk-device/src/ccid.rs" in result.stdout


def test_a_name_the_union_was_extended_into_still_reads(tree):
    """Measured, not designed: the lookup is `text.find("fn gates_wiped_last")`,
    so `gates_wiped_last_v2` satisfies it and its body is read as the union. The
    guard is syntactic about WHERE the union is and says nothing about what calls
    it — a rename to a longer name is invisible here, and this is what that costs.
    """
    tree.edit(UNION, "fn gates_wiped_last", "fn gates_wiped_last_v2")
    assert tree.run().returncode == 0


def test_a_predicate_in_the_firmware_is_read_too(tree):
    """`firmware/src` stays in scope after the union moved to `crates/`: a
    predicate defined there can still be named, and a tree that stops being
    scanned is a tree whose missing arms stop being reported."""
    tree.write(
        "firmware/src/board.rs", "pub fn is_board_gate_fid(fid: u16) -> bool { fid == 1 }\n"
    )
    result = tree.run()
    assert result.returncode == 1
    assert "is_board_gate_fid" in result.stdout
    assert "firmware/src/board.rs" in result.stdout


def test_a_nested_brace_does_not_end_the_union_early(tree):
    """The fixture's union opens a block before its arms. Read to the first `}`
    the arms are outside the body, and all four report as absent — a guard that
    goes red on a reformat is one somebody switches off."""
    assert "return false;" in (tree.root / UNION).read_text()
    assert tree.run().returncode == 0


def test_a_second_function_after_the_union_is_not_part_of_it(tree):
    """The other direction of the same brace match: text past the union's `}` is
    not the union, so naming an arm there does not satisfy it."""
    tree.edit(UNION, " || is_oath_lock_fid(fid)", "")
    tree.edit(UNION, "fid == 0xffff", "is_oath_lock_fid(fid)")
    result = tree.run()
    assert result.returncode == 1
    assert "is_oath_lock_fid" in result.stdout


def test_every_missing_arm_is_reported_not_just_the_first(tree):
    """Reporting one sends you round the loop once per arm."""
    tree.edit(UNION, " || is_oath_lock_fid(fid)", "")
    tree.edit(UNION, " || is_piv_lock_fid(fid)", "")
    result = tree.run()
    assert result.returncode == 1
    assert "is_oath_lock_fid" in result.stdout and "is_piv_lock_fid" in result.stdout


# --- the controls: what the guard is right to be indifferent to ----------------


def test_a_predicate_defined_only_in_a_test_file_is_not_owed_an_arm(tree):
    """A fixture's own `is_*_gate_fid` is not a device record, and a guard that
    demanded an arm for one is a guard that gets edited around."""
    tree.write(
        "crates/rsk-oath/src/lib_tests.rs",
        "pub fn is_ghost_gate_fid(fid: u16) -> bool { fid == 0x9999 }\n",
    )
    assert tree.run().returncode == 0


def test_a_predicate_that_is_not_a_gate_or_lock_is_not_owed_an_arm(tree):
    """`is_*_gate_fid` / `is_*_lock_fid` and nothing else: the wipe's phase 2 is
    about the records that gate an applet, not every predicate over a fid. The
    same function under a gate name goes red, so the green is the suffix."""
    tree.edit(
        "crates/rsk-piv/src/lib.rs",
        "pub fn is_piv_lock_fid",
        "pub fn is_piv_cert_fid(fid: u16) -> bool { fid == 0x0500 }\npub fn is_piv_lock_fid",
    )
    assert tree.run().returncode == 0
    tree.edit("crates/rsk-piv/src/lib.rs", "is_piv_cert_fid", "is_piv_cert_gate_fid")
    result = tree.run()
    assert result.returncode == 1
    assert "is_piv_cert_gate_fid" in result.stdout


def test_an_extra_arm_the_tree_no_longer_exports_is_not_a_finding(tree):
    """The union may name a predicate that is gone — dead, not dangerous, and
    each crate's own tests own that half. Pinned so the guard is not widened into
    a compiler by someone reading the message as symmetric."""
    tree.edit(UNION, " || is_piv_lock_fid(fid)",
              " || is_piv_lock_fid(fid) || is_gone_gate_fid(fid)")
    assert tree.run().returncode == 0


# --- the deletion arms: one clause at a time ----------------------------------


def test_deleting_the_membership_test_takes_the_missing_arm_finding_with_it(tree):
    """The clause the guard is FOR. Cut, the run-36 tree above is green again."""
    tree.edit(UNION, " || is_oath_lock_fid(fid)", "")
    assert tree.run().returncode == 1
    assert tree.run(("            if name in body:", "            if True:")).returncode == 0


def test_deleting_the_comment_strip_lets_a_sentence_satisfy_the_union(tree):
    """What the strip is worth, in the one motion it was written for."""
    tree.edit(
        UNION,
        " || is_oath_lock_fid(fid)",
        "\n    // is_oath_lock_fid is handled elsewhere",
    )
    assert tree.run().returncode == 1
    cut = ('line.split("//")[0] for line in body.splitlines()',
           "line for line in body.splitlines()")
    assert tree.run(cut).returncode == 0


def test_deleting_the_roster_takes_the_absent_predicate_finding_with_it(tree):
    """The half that has no other reader: with the roster empty, a predicate that
    was renamed or deleted reads as an applet that never had one."""
    tree.write("crates/rsk-oath/src/lib.rs", "pub fn nothing_to_see(fid: u16) -> bool { false }\n")
    tree.edit(UNION, " || is_oath_lock_fid(fid)", "")
    assert tree.run().returncode == 1
    cut = ('APPLETS_OWING_A_GATE = ("rsk-devconf", "rsk-fido", "rsk-oath", "rsk-openpgp", "rsk-piv")',
           "APPLETS_OWING_A_GATE = ()")
    assert tree.run(cut).returncode == 0


def test_deleting_the_test_file_skip_makes_a_fixture_owe_an_arm(tree):
    """The clause whose deletion moves the answer the OTHER way: the control two
    cases up goes red, so the skip is load-bearing rather than tidiness."""
    tree.write(
        "crates/rsk-oath/src/lib_tests.rs",
        "pub fn is_ghost_gate_fid(fid: u16) -> bool { fid == 0x9999 }\n",
    )
    assert tree.run().returncode == 0
    cut = ('        if path.name.endswith("_tests.rs") or path.name in ("tests.rs", "kani.rs"):\n'
           "            continue\n", "")
    result = tree.run(cut)
    assert result.returncode == 1
    assert "is_ghost_gate_fid" in result.stdout


def test_requiring_pub_again_takes_the_run_37_finding_with_it(tree):
    """The repair audit run-37 made, falsified. With the visibility group back to
    mandatory the bare `fn is_oath_lock_fid` is not an export at all, so the arm
    it is missing from is the arm nothing looks for — the exact state the guard
    passed the OATH tree in."""
    tree.edit(UNION, " || is_oath_lock_fid(fid)", "")
    assert tree.run().returncode == 1
    pub = (r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+", r"^\s*(?:pub(?:\([^)]*\))?\s+)fn\s+")
    # Alone it is not a green: the predicate stops being an export, so the roster
    # reports the applet as having none. That second finding is the only thing
    # standing between this cut and silence.
    partly = tree.run(pub)
    assert partly.returncode == 1
    assert "does not name:" not in partly.stdout
    assert "no gate predicate found in: ['rsk-oath']" in partly.stdout
    roster = ('APPLETS_OWING_A_GATE = ("rsk-devconf", "rsk-fido", "rsk-oath", "rsk-openpgp", "rsk-piv")',
              "APPLETS_OWING_A_GATE = ()")
    assert tree.run(pub, roster).returncode == 0


def test_deleting_the_firmware_from_the_walk_takes_its_predicate_out_of_scope(tree):
    """The union moved to `crates/rsk-device` and the firmware stayed in the walk
    on purpose. Cut, a predicate defined there is nobody's finding."""
    tree.write(
        "firmware/src/board.rs", "pub fn is_board_gate_fid(fid: u16) -> bool { fid == 1 }\n"
    )
    assert tree.run().returncode == 1
    cut = ('sorted((ROOT / "crates").glob("*/src/**/*.rs")) + sorted(\n'
           '        (ROOT / "firmware/src").glob("**/*.rs")\n    )',
           'sorted((ROOT / "crates").glob("*/src/**/*.rs"))')
    assert tree.run(cut).returncode == 0


def test_the_missing_union_clause_survives_its_own_deletion_as_a_crash(tree):
    """The one clause with no green arm, recorded rather than claimed as a kill.

    Cut, `body` stays None and `name in body` raises — still non-zero, so the
    clause is not decorative, but a reader looking for a colour change would
    find one for the wrong reason. What it costs is the message.
    """
    tree.edit(UNION, "fn gates_wiped_last", "fn wipe_gates_last")
    assert "not found in" in tree.run().stdout
    cut = ("    if body is None:\n"
           '        print(f"gate-union: {UNION_FN} not found in {UNION.relative_to(ROOT)}")\n'
           "        return 1\n", "")
    result = tree.run(cut)
    assert result.returncode == 1
    assert "TypeError" in result.stderr
    assert "not found in" not in result.stdout
