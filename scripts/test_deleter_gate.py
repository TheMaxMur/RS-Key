# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `deleter_gate.py` was verified against, kept.

The guard exists because a caller-by-caller audit is worth exactly as much as
the roster under it, and this tree has twice found a hand-kept one wrong. So the
table below breaks the real defect shape in a fixture checkout, one at a time,
and asserts the MESSAGE rather than a count — a red for the wrong reason proves
as little as a green.

Both directions, because a guard that cannot go green is deleted as fast as one
that cannot go red: the clean fixture passes, this checkout's own ledger passes,
and `check.sh` is asserted to run the row at all. Five of the five guards this
repo shipped before this one had a hole of this family, which is why the last
two cases are about the derivation itself rather than about the ledger.
"""

import pathlib
import subprocess
import textwrap

import pytest

import deleter_gate
import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: A fixture crate with one of each shape: a caller that reads the answer, one
#: that discards it, and one on a `.method()` continuation, so the statement walk
#: is exercised rather than assumed.
CALLER = """\
fn wipe(fs: &mut Fs) -> Result<()> {
    fs.force_delete(SEED)?;
    let _ = fs.delete(INDEX);
    fs.delete_key(KEY)
        .map_err(|_| Sw::MEMORY_FAILURE)?;
    Ok(())
}
"""

MINTER = "fn head(fs: &mut Fs) { let _ = fs.meta_add(SLOT, &[0]); }\n"

#: `Fs`'s own backend removals: one that re-arms the at-rest lap and one that
#: leaves it to its callers. Line numbers matter here — the ledger below cites
#: lines 6 and 13 — so keep the shape when editing, or edit both.
FS = """\
impl<S: Storage> Fs<S> {
    pub fn factory_wipe(&mut self, keep: u16) -> Result<()> {
        let _ = crate::request_rescrub(self);
        for fid in self.keys() {
            if fid != keep {
                self.storage.remove(fid)?;
            }
        }
        self.storage.compact()
    }

    pub fn delete(&mut self, fid: u16) -> Result<()> {
        self.storage.remove(fid)?;
        Ok(())
    }
}
"""

LEDGER = """\
head_minters = ["crates/rsk-piv"]

[[site]]
file = "crates/rsk-app/src/lib.rs"
line = 2
call = "fs.force_delete(SEED)?;"
verb = "force_delete"
answer = "read"
class = "wipe-sweep"
metadata = "none"
disposition = "must-read"
why = "the sweep may not report a wipe it could not prove."

[[site]]
file = "crates/rsk-app/src/lib.rs"
line = 3
call = "let _ = fs.delete(INDEX);"
verb = "delete"
answer = "discarded"
class = "bookkeeping"
metadata = "none"
disposition = "best-effort"
why = "an index the store rebuilds."

[[site]]
file = "crates/rsk-app/src/lib.rs"
line = 4
call = "fs.delete_key(KEY)"
verb = "delete_key"
answer = "read"
class = "secret-or-gate"
metadata = "none"
disposition = "must-read"
why = "a survivor is a live key."

[[fs_removal]]
file = "crates/rsk-fs/src/fs.rs"
line = 6
method = "factory_wipe"
call = "self.storage.remove(fid)?;"
rearms = true
scrub = "re-arms"
why = "the wipe supersedes a pre-OTP-sealed verifier, so it re-arms the lap first."

[[fs_removal]]
file = "crates/rsk-fs/src/fs.rs"
line = 13
method = "delete"
call = "self.storage.remove(fid)?;"
rearms = false
scrub = "deferred-to-caller"
why = "request_rescrub is written in terms of delete; the callers decide."
"""


class Tree:
    """A checkout shaped like this one: one caller crate, one head minter."""

    def __init__(self, root):
        self.root = root
        self.write("crates/rsk-app/src/lib.rs", CALLER)
        self.write("crates/rsk-piv/src/keygen.rs", MINTER)
        self.write("crates/rsk-fs/src/fs.rs", FS)
        self.write("assurance/deleters.toml", LEDGER)
        # `sources` asks git what the tree is, so the fixture must be a checkout
        # — and one that ignores build output, like the real one.
        self.write(".gitignore", "target/\n")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)

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

    def run(self):
        return deleter_gate.run(self.root)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    # The shipped floor is about the real checkout's 43 sites. Scaled to the
    # fixture's three so the emptying case below still has one to trip.
    monkeypatch.setattr(deleter_gate, "FLOOR_SITES", 2)
    return Tree(tmp_path)


def red(tree, capsys):
    """Run the guard, require it red, and hand back what it said."""
    assert tree.run() == 1
    return capsys.readouterr().err


def tree_ledger():
    """The ledger's path inside a fixture tree, so a case can edit it by content."""
    return str(deleter_gate.LEDGER)


# --- both directions, and the wiring ------------------------------------------


def test_the_clean_fixture_passes(tree):
    assert tree.run() == 0


def test_this_checkout_passes():
    """The guard has to be green on the tree it ships in, or it is not a row."""
    assert deleter_gate.run(ROOT) == 0


def test_check_sh_runs_the_row():
    """A guard nothing invokes can have its whole table deleted, suite green."""
    text = (ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(text, "scripts/deleter_gate.py")


# --- the roster, both directions ----------------------------------------------


def test_a_new_caller_with_no_disposition_is_rejected(tree, capsys):
    tree.edit(
        "crates/rsk-app/src/lib.rs",
        "    Ok(())",
        "    let _ = fs.delete(SURPRISE);\n    Ok(())",
    )
    assert "does not dispose of it" in red(tree, capsys)


def test_a_disposition_for_a_caller_that_is_gone_is_rejected(tree, capsys):
    tree.edit("crates/rsk-app/src/lib.rs", "    let _ = fs.delete(INDEX);\n", "")
    assert "which calls nothing" in red(tree, capsys)


def test_a_moved_caller_is_reported_with_where_it_went(tree, capsys):
    """The citation-gate rule: a line that has shifted says so and says where,
    because "repair the number" and "the claim was never true" need different
    answers from the reader."""
    tree.edit(
        "crates/rsk-app/src/lib.rs",
        "fn wipe(fs: &mut Fs) -> Result<()> {",
        "// a line arrives\nfn wipe(fs: &mut Fs) -> Result<()> {",
    )
    assert "it is at :" in red(tree, capsys)


def test_a_caller_that_became_a_different_call_is_rejected(tree, capsys):
    tree.edit("crates/rsk-app/src/lib.rs", "let _ = fs.delete(INDEX);", "let _ = fs.delete(OTHER);")
    assert "reads `let _ = fs.delete(OTHER);` now" in red(tree, capsys)


# --- the judgement, held to the code ------------------------------------------


def test_a_read_answer_turned_into_a_discard_is_rejected(tree, capsys):
    """The freshness trigger §5A item 6 asks for: the disposition is a claim about
    what the site does, so quietly making a must-read site discard the answer
    has to be red rather than a label mismatch nobody looks at."""
    tree.edit("crates/rsk-app/src/lib.rs", "    fs.delete_key(KEY)\n", "    let _ = fs.delete_key(KEY)\n")
    said = red(tree, capsys)
    assert "discards the deleter's answer" in said
    assert "do not re-label it" in said


def test_relabelling_instead_of_deciding_is_rejected(tree, capsys):
    """The other half of the pair: editing the ledger to match the new code
    without changing the disposition must not buy a green either."""
    tree.edit("crates/rsk-app/src/lib.rs", "    fs.delete_key(KEY)\n", "    let _ = fs.delete_key(KEY)\n")
    tree.edit("assurance/deleters.toml", 'call = "fs.delete_key(KEY)"', 'call = "let _ = fs.delete_key(KEY)"')
    tree.edit(
        "assurance/deleters.toml",
        'answer = "read"\nclass = "secret-or-gate"',
        'answer = "discarded"\nclass = "secret-or-gate"',
    )
    assert "while the site discards the answer" in red(tree, capsys)


def test_a_wipe_sweep_on_a_conditional_verb_is_rejected(tree, capsys):
    """The VALUE half of the contract. `delete`/`delete_key` skip the backend
    removal when the present cache reads absent; a re-enumerating wipe reads the
    backend directly, so a torn-migration false-absent key is re-found on every
    pass and the sweep does not terminate. Measured on the real ledger: all five
    `wipe-sweep` sites are on `force_delete_halves` today, so this rule is a pin
    rather than a repair."""
    tree.edit("assurance/deleters.toml", 'class = "secret-or-gate"', 'class = "wipe-sweep"')
    said = red(tree, capsys)
    assert "does not terminate" in said, said
    assert "delete_key" in said, said


def test_the_removal_axis_is_derived_from_the_verb(tree, capsys):
    """And not recorded beside it: a field a caller could set independently of
    the call it describes is a second copy of the call. Driven by making the
    derivation wrong — every wipe sweep then reads as conditional."""
    tree.edit("assurance/deleters.toml", 'class = "secret-or-gate"', 'class = "wipe-sweep"')
    assert deleter_gate.REMOVAL["delete_key"] == "conditional"
    assert deleter_gate.REMOVAL["force_delete_halves"] == "unconditional"
    assert set(deleter_gate.REMOVAL) == set(deleter_gate.VERBS)
    assert tree.run() == 1
    capsys.readouterr()


def test_a_disposition_with_no_reason_is_rejected(tree, capsys):
    tree.edit("assurance/deleters.toml", 'why = "an index the store rebuilds."', 'why = "   "')
    assert "a disposition with no reason" in red(tree, capsys)


def test_an_invented_vocabulary_is_rejected(tree, capsys):
    tree.edit("assurance/deleters.toml", 'class = "bookkeeping"', 'class = "probably-fine"')
    assert "is not one of" in red(tree, capsys)


def test_two_entries_for_one_site_are_rejected(tree, capsys):
    tree.edit(
        "assurance/deleters.toml",
        'why = "an index the store rebuilds."\n',
        'why = "an index the store rebuilds."\n\n'
        + textwrap.dedent(
            """\
            [[site]]
            file = "crates/rsk-app/src/lib.rs"
            line = 3
            call = "let _ = fs.delete(INDEX);"
            verb = "delete"
            answer = "discarded"
            class = "bookkeeping"
            metadata = "none"
            disposition = "best-effort"
            why = "and again, differently."
            """
        ),
    )
    assert "same file and line" in red(tree, capsys)


# --- the metadata axis, and the premise under it -------------------------------


def test_a_head_claimed_from_a_crate_that_mints_none_is_rejected(tree, capsys):
    tree.edit("assurance/deleters.toml", 'metadata = "none"\ndisposition = "best-effort"',
              'metadata = "drops-head"\ndisposition = "best-effort"')
    assert "mints none" in red(tree, capsys)


def test_a_second_head_minter_arriving_is_rejected(tree, capsys):
    """Every `drops-head` disposition rests on one crate writing the heads. A
    second one arriving silently is how that premise stops being true while the
    entries still read as though it holds."""
    tree.write("crates/rsk-other/src/lib.rs", MINTER)
    assert "rests on that set" in red(tree, capsys)


# --- the derivation itself ------------------------------------------------------


def test_an_empty_roster_is_rejected(tree, capsys):
    """The failure a verdict column cannot show: a derivation that finds nothing
    satisfies every rule above. Driven by breaking the call matcher, which is
    what an edit to it would do."""
    tree.edit("crates/rsk-app/src/lib.rs", "fs.force_delete(SEED)?;", "")
    tree.edit("crates/rsk-app/src/lib.rs", "let _ = fs.delete(INDEX);", "")
    tree.edit("crates/rsk-app/src/lib.rs", "fs.delete_key(KEY)\n        .map_err(|_| Sw::MEMORY_FAILURE)?;", "")
    assert "under the floor of" in red(tree, capsys)


def test_the_scope_exclusions_are_the_two_the_roadmap_names():
    """A third exclusion is the rotted roster in modern spelling: nothing fails,
    the row just measures less. `BUILD_DIRS` is separate on purpose — it is
    determinism (a local `cargo build` drops generated `.rs` under the checkout),
    not scope."""
    assert deleter_gate.SKIP_DIRS == ("crates/rsk-fs", "fuzz")


def test_a_generated_source_under_a_nested_target_is_not_a_caller(tree):
    """`tools/emu` and `tools/tui` are their own workspaces with their own
    `target/`. A roster that walked into them would answer differently on a
    machine that had run cargo."""
    tree.write("tools/emu/target/debug/build/x/out/gen.rs", "fn f(fs: &mut Fs) { let _ = fs.delete(X); }\n")
    assert tree.run() == 0


def test_a_test_or_proof_sibling_is_not_a_caller(tree):
    """The cfg-gated sources by AGENTS.md's naming rule — which is what puts
    `reset_refinement_kani.rs` out, whose `reset.delete` is the refinement
    model's own verb rather than this file system's."""
    tree.write("crates/rsk-app/src/lib_tests.rs", "fn t(fs: &mut Fs) { let _ = fs.delete(X); }\n")
    tree.write("crates/rsk-app/src/reset_refinement_kani.rs", "fn p(r: &mut R) { assert!(r.delete(X)); }\n")
    assert tree.run() == 0


def test_a_continuation_line_call_is_read_against_the_let_that_owns_it():
    """A call on a `.method()` continuation has its `let _ =` lines above.
    Reading only the call's own line calls every one of those a reader, which is
    the direction that hides a discard."""
    lines = ["    let _ = ctx", "        .fs", "        .delete(X);"]
    assert deleter_gate.disposal(lines, 2) == "discarded"
    lines = ["    gate(ctx)?;", "    ctx.fs", "        .delete(X)", "        .map_err(f)?;"]
    assert deleter_gate.disposal(lines, 2) == "read"


def test_a_call_inside_a_condition_is_not_read_against_the_block_body():
    """The forward walk that finds a trailing `.ok();` must stop at a line that
    OPENS a block: `if ….is_err() {` reads the answer, and the first `;` after it
    belongs to the body. Two of the ten `force_delete` callers are that shape."""
    lines = [
        "    if fs.has_key(slot) && fs.force_delete(slot.get()).is_err() {",
        "        log(x).ok();",
        "    }",
    ]
    assert deleter_gate.disposal(lines, 0) == "read"


# --- the four spellings of "discard" -------------------------------------------


@pytest.mark.parametrize(
    "spelling",
    [
        # Rust 2021 destructuring assignment: `let`-less, and `cargo fmt --check`
        # and `clippy -D warnings` are both happy with it.
        "    _ = fs.delete_key(KEY);",
        "    fs.delete_key(KEY).ok();",
        "    drop(fs.delete_key(KEY));",
    ],
)
def test_every_spelling_of_a_discard_derives_as_one(tree, capsys, spelling):
    """A must-read site converted into any of these used to derive as `read`, so
    the ledger could be updated honestly and the row stayed green — verbatim the
    property the docstring claims. The `let _ =` spelling has its own case above;
    these are the three that were invisible."""
    tree.edit(
        "crates/rsk-app/src/lib.rs",
        "    fs.delete_key(KEY)\n        .map_err(|_| Sw::MEMORY_FAILURE)?;",
        spelling,
    )
    tree.edit(
        "assurance/deleters.toml",
        'call = "fs.delete_key(KEY)"',
        'call = "%s"' % spelling.strip(),
    )
    said = red(tree, capsys)
    assert "discards the deleter's answer" in said
    assert "do not re-label it" in said


def test_a_ufcs_caller_is_on_the_roster(tree, capsys):
    """The receiver test (`.delete(`) cannot see the same call spelled
    `Fs::force_delete(fs, x)` or `<Fs<S>>::delete(fs, x)`. Two callers were added
    that way, one of them deleting the FIDO seed, and the count did not move."""
    tree.edit(
        "crates/rsk-app/src/lib.rs",
        "    Ok(())",
        "    let _ = Fs::force_delete(fs, SEED);\n"
        "    let _ = <Fs<S>>::delete(fs, INDEX);\n    Ok(())",
    )
    said = red(tree, capsys)
    assert "Fs::force_delete(fs, SEED)" in said
    assert "<Fs<S>>::delete(fs, INDEX)" in said


# --- the second roster: what `Fs` removes on its own behalf ---------------------
# `Fs::factory_wipe` erases the device through `self.storage.remove`, from inside
# `crates/rsk-fs`. `remove` is not one of `VERBS` and `crates/rsk-fs` is not in
# scope, so the roster above cannot see it — twice over, which is what makes the
# hole invisible to a count. Each case below breaks one clause of the derivation
# that closed it.


def test_a_new_backend_removal_in_fs_with_no_disposition_is_rejected(tree, capsys):
    """The direction the whole table is for: a new way a record leaves the medium
    arrives, and nothing says whether it owes the at-rest lap a re-arm."""
    # Appended, so the two disposed-of citations do not move with it — a case that
    # shifted them would go red for the wrong reason.
    tree.edit(
        "crates/rsk-fs/src/fs.rs",
        "        Ok(())\n    }\n}",
        "        Ok(())\n"
        "    }\n"
        "\n"
        "    pub fn wipe_audit_ring(&mut self) -> Result<()> {\n"
        "        self.storage.remove(RING)?;\n"
        "        Ok(())\n"
        "    }\n"
        "}",
    )
    said = red(tree, capsys)
    assert "removes from the backend inside `wipe_audit_ring`" in said
    assert "does not dispose of it" in said


def test_a_disposition_for_a_backend_removal_that_is_gone_is_rejected(tree, capsys):
    """The other direction, and the line count is kept so the sibling entry's
    citation does not move with it."""
    tree.edit(
        "crates/rsk-fs/src/fs.rs",
        "    pub fn delete(&mut self, fid: u16) -> Result<()> {\n        self.storage.remove(fid)?;",
        "    pub fn delete(&mut self, fid: u16) -> Result<()> {\n        self.forget(fid);",
    )
    assert "removes nothing" in red(tree, capsys)


def test_deleting_the_re_arm_flips_the_derived_axis(tree, capsys):
    """`rearms` is derived from the METHOD BODY, so the fix it records cannot be
    deleted with this row green — which is the whole reason it is derived rather
    than written down beside the entry. Same line count, so the citation holds and
    the axis is the only thing that moves."""
    tree.edit(
        "crates/rsk-fs/src/fs.rs",
        "        let _ = crate::request_rescrub(self);",
        "        let _ = self.write_gen();",
    )
    said = red(tree, capsys)
    assert "`factory_wipe` does not re-arm the at-rest scrub" in said
    assert "re-decide the path, do not re-label it" in said


def test_relabelling_a_re_arm_instead_of_re_deciding_is_rejected(tree, capsys):
    """The pair that makes the judgement falsifiable by the code: `scrub` is the
    hand-written half and `rearms` the derived one, and they must agree."""
    tree.edit(tree_ledger(), 'scrub = "re-arms"', 'scrub = "deferred-to-caller"')
    assert "disposed of as `deferred-to-caller` while `rearms = true`" in red(tree, capsys)


def test_an_invented_scrub_vocabulary_is_rejected(tree, capsys):
    tree.edit(tree_ledger(), 'scrub = "re-arms"', 'scrub = "sort-of"')
    assert "is not one of" in red(tree, capsys)


def test_a_backend_removal_that_changed_method_is_rejected(tree, capsys):
    """The citation half: a removal that moved into another method is a different
    decision, and the entry must say which method it disposed of."""
    tree.edit("crates/rsk-fs/src/fs.rs", "pub fn factory_wipe(", "pub fn wipe_everything(")
    assert "is in `wipe_everything`, disposed of as `factory_wipe`" in red(tree, capsys)


def test_an_empty_fs_removal_roster_is_rejected(tree, capsys):
    """The failure a verdict column cannot show, for this roster too: a derivation
    that finds nothing satisfies every rule above it. Driven by breaking the code
    the matcher reads, which is what an edit to it would do — and the ledger's own
    entries go with it, because otherwise the row goes red on THOSE (`which removes
    nothing`) whether the floor is there or not, which is a red for another
    clause's reason wearing this one's name."""
    tree.edit("crates/rsk-fs/src/fs.rs", "                self.storage.remove(fid)?;", "                self.drop_it(fid);")
    tree.edit("crates/rsk-fs/src/fs.rs", "        self.storage.remove(fid)?;", "        self.drop_it(fid);")
    path = tree.root / deleter_gate.LEDGER
    path.write_text(path.read_text()[: path.read_text().index("[[fs_removal]]")])
    assert "under the floor of" in red(tree, capsys)


def test_a_helper_inside_a_method_does_not_steal_its_removal(tree):
    """The other direction of the same walk, end to end: a nested `fn` between a
    method's `fn` and its removal must not become the method the removal is
    attributed to. Without the indent rule this row goes red saying the wipe is
    `near` and does not re-arm — red, and about a function that removes nothing."""
    tree.edit(
        "crates/rsk-fs/src/fs.rs",
        "        let _ = crate::request_rescrub(self);",
        "        let _ = crate::request_rescrub(self);\n"
        "        fn near(x: u16) -> bool { x == 0 }",
    )
    # The insert moves the cited lines with it, so move the citations too — the
    # case is about attribution, not about a citation going stale.
    tree.edit(str(deleter_gate.LEDGER), "line = 6", "line = 7")
    tree.edit(str(deleter_gate.LEDGER), "line = 13", "line = 14")
    assert tree.run() == 0


def test_a_block_helper_that_has_already_closed_does_not_steal_it_either(tree):
    """The one-line shape above is skipped for having no closing brace to find; a
    helper with a body needs the other half of the rule, that its brace comes AFTER
    the line. Its indent is SHALLOWER than a removal nested in a loop, so an indent
    test alone hands the wipe to a two-line predicate."""
    tree.edit(
        "crates/rsk-fs/src/fs.rs",
        "        let _ = crate::request_rescrub(self);",
        "        let _ = crate::request_rescrub(self);\n"
        "        fn near(x: u16) -> bool {\n"
        "            x == 0\n"
        "        }",
    )
    tree.edit(str(deleter_gate.LEDGER), "line = 6", "line = 9")
    tree.edit(str(deleter_gate.LEDGER), "line = 13", "line = 16")
    assert tree.run() == 0


def test_an_fs_removal_field_nobody_reads_is_refused(tree, capsys):
    _insert(tree, "[[fs_removal]]\n", 'nonsense_field_nobody_holds = "x"\n')
    assert "which nothing reads" in red(tree, capsys)


def test_an_fs_removal_with_no_reason_is_rejected(tree, capsys):
    tree.edit(
        tree_ledger(),
        'why = "the wipe supersedes a pre-OTP-sealed verifier, so it re-arms the lap first."',
        'why = "   "',
    )
    assert "a disposition with no reason is not one" in red(tree, capsys)


def test_the_derivation_reads_the_method_body_not_the_next_fn(tree):
    """A nested helper must not end the span early: a re-arm standing after one
    still belongs to the method, and taking the span to the next `fn` would call
    the method un-armed."""
    lines = [
        "    pub fn wipe(&mut self) -> Result<()> {",
        "        fn near(x: u16) -> bool { x == 0 }",
        "        let _ = crate::request_rescrub(self);",
        "        self.storage.remove(FID)",
        "    }",
    ]
    assert deleter_gate.enclosing(lines, 3) == ("wipe", lines[:4])
    # And the helper's OWN removal still belongs to the helper.
    assert deleter_gate.enclosing(["    pub fn outer() {", "        fn inner() {", "            s.storage.remove(X);", "        }", "    }"], 2)[0] == "inner"


# --- the keys the file may carry ----------------------------------------------


def _insert(tree, after, line):
    path = tree.root / deleter_gate.LEDGER
    text = path.read_text()
    i = text.index(after) + len(after)
    path.write_text(text[:i] + line + text[i:])


def test_a_field_nobody_reads_is_refused(tree, capsys):
    """Measured before the rule: an invented key in the first `[[site]]` left this
    row at EXIT=0, so a field added here was held by nothing and shown to nobody."""
    _insert(tree, "[[site]]\n", 'nonsense_field_nobody_holds = "x"\n')
    assert "which nothing reads" in red(tree, capsys)


def test_a_table_nobody_reads_is_refused(tree, capsys):
    """And a whole section, invisible in both directions before this."""
    path = tree.root / deleter_gate.LEDGER
    path.write_text(path.read_text() + '\n[[nonsense_table]]\nname = "x"\n')
    assert "which nothing reads" in red(tree, capsys)


def test_a_second_copy_of_the_tree_is_not_the_tree(tree, capsys):
    """An agent worktree under `.claude/` is a whole second checkout, and the walk
    this replaced read every file of it: measured on the real tree, one worktree
    turned `deleter-gate: ok — 43 call sites` into 19 findings about paths already
    disposed of under their real names. `git ls-files --exclude-standard` answers
    what the tree is; a hand-written skip list has to remember each new directory
    and did not remember this one."""
    inner = tree.root / ".claude/worktrees/agent-x"
    tree.write(".claude/worktrees/agent-x/crates/rsk-app/src/lib.rs", CALLER)
    # A worktree carries its own `.git`, which is exactly why git does not
    # descend into it and a filesystem walk does.
    subprocess.run(["git", "init", "-q"], cwd=inner, check=True)
    assert tree.run() == 0, capsys.readouterr()


def test_a_build_directory_is_not_the_tree(tree, capsys):
    """The half the old list did get right, kept as a case so the new reader owes
    it too — `target/` is gitignored, which is why git answers the same way."""
    tree.write("target/debug/build/x/out/lib.rs", CALLER)
    assert tree.run() == 0, capsys.readouterr()


def test_there_is_one_answer_to_what_the_tree_is():
    """The walk's hand-written skip list is GONE, not kept beside the new reader:
    a constant nothing reads is a comment with a type, and a second list is a
    second answer to the question this row got wrong."""
    source = pathlib.Path(deleter_gate.__file__).read_text(encoding="utf-8")
    assert "rglob" not in source and "BUILD_DIRS" not in source
    assert "gate_lines.tree_files" in source
