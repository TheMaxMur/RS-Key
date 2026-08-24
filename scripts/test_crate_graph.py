# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `crate_graph.py` was verified against, kept.

The drawing this generator replaced was checked by eye, once, and then rotted
for a fortnight while reading as authoritative — so a generator whose failures
live only in someone's scrollback would be the same mistake one layer up. Each
case below breaks the real defect shape in a fixture workspace, one thing at a
time, and asserts the *message*, not a count.

Both directions, because a guard that cannot go green gets deleted as fast as
one that cannot go red: the clean fixture generates, this checkout's own
`--check` passes, and `check.sh` is asserted to run the row at all.
"""

import re

import pytest

import crate_graph

TIERS = [
    ("BIN", "the binary", "#000", ["firmware"]),
    ("APPLETS", "one AID each", "#111", ["rsk-a", "rsk-b"]),
    ("SHARED", "a shared codec", "#222", ["rsk-rec", "rsk-rec2"]),
    ("ALGO", "a primitive", "#333", ["rsk-alg"]),
]

MEMBERS = {
    "firmware": ["rsk-a", "rsk-b"],
    "crates/rsk-a": ["rsk-rec", "rsk-alg"],
    "crates/rsk-b": ["rsk-rec", "rsk-rec2"],
    "crates/rsk-rec": [],
    "crates/rsk-rec2": [],
    "crates/rsk-alg": [],
}

DENY = """[bans]
deny = [
    { crate = "rsk-a", wrappers = ["firmware"] },
    { crate = "rsk-b", wrappers = ["firmware"] },
]
"""


class Tree:
    """A checkout shaped like this one: a binary, two applets, three libraries."""

    def __init__(self, root, members=MEMBERS):
        self.root = root
        self.write(
            "Cargo.toml",
            "[workspace]\nmembers = [%s]\n" % ", ".join(f'"{m}"' for m in members),
        )
        for rel, deps in members.items():
            body = "".join(f'{d} = {{ path = "../{d}" }}\n' for d in deps)
            name = rel.rpartition("/")[2]
            self.write(f"{rel}/Cargo.toml", f'[package]\nname = "{name}"\n\n[dependencies]\n{body}')
        self.write("deny.toml", DENY)
        self.write("docs/architecture.md", self.page("placeholder alt"))
        self.write("docs/images/.keep", "")

    def page(self, alt, crates=MEMBERS):
        rows = "".join(f"| `{c.rpartition('/')[2]}` | what it does |\n" for c in crates)
        return f"# Architecture\n\n{alt}\n\n| Crate | Contents |\n|---|---|\n{rows}"

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

    def sync_alt(self):
        """Paste the drawing's own alt text into the page, as a contributor would."""
        try:
            crate_graph.main([])
        except SystemExit as exc:
            line = str(exc).splitlines()[-1].strip()
            self.write("docs/architecture.md", self.page(line))

    def svg(self):
        return (self.root / "docs/images/crate-graph.svg").read_text()

    def run(self, *argv):
        return crate_graph.main(list(argv))


@pytest.fixture
def tree(tmp_path, monkeypatch):
    monkeypatch.setattr(crate_graph, "ROOT", tmp_path)
    monkeypatch.setattr(crate_graph, "SVG", tmp_path / "docs/images/crate-graph.svg")
    monkeypatch.setattr(crate_graph, "ALT_PAGE", tmp_path / "docs/architecture.md")
    monkeypatch.setattr(crate_graph, "DENY", tmp_path / "deny.toml")
    monkeypatch.setattr(crate_graph, "TIERS", TIERS)
    t = Tree(tmp_path)
    t.sync_alt()
    return t


def fails(tree, *argv):
    with pytest.raises(SystemExit) as exc:
        tree.run(*argv)
    return str(exc.value)


# --- both directions, and the wiring ------------------------------------------


def test_clean_fixture_generates_and_rechecks(tree):
    assert tree.run() == 0
    assert tree.run("--check") == 0


def test_this_checkout_is_green():
    """The control the fixture cannot be: the tree these rules were written for."""
    assert crate_graph.main(["--check"]) == 0


def test_check_sh_runs_the_row():
    """A guard nothing invokes can be deleted with the whole suite still green."""
    check = (crate_graph.ROOT / "scripts/check.sh").read_text()
    assert "scripts/crate_graph.py --check" in check


# --- the roster seam: a crate the drawing would silently omit ------------------


def test_a_new_member_absent_from_the_tiers_fails(tree):
    tree.write("crates/rsk-new/Cargo.toml", '[package]\nname = "rsk-new"\n')
    tree.edit("Cargo.toml", '"crates/rsk-alg"', '"crates/rsk-alg", "crates/rsk-new"')
    assert "absent from TIERS: rsk-new" in fails(tree)


def test_a_tier_name_that_left_the_workspace_fails(tree):
    tree.edit("Cargo.toml", ', "crates/rsk-rec"', "")
    assert "not workspace members: rsk-rec" in fails(tree)


def test_a_crate_in_two_tiers_fails(tree, monkeypatch):
    doubled = [(label, sub, colour, list(crates)) for label, sub, colour, crates in TIERS]
    doubled[2][3].append("rsk-alg")
    monkeypatch.setattr(crate_graph, "TIERS", doubled)
    assert "rsk-alg is listed in two tiers" in fails(tree)


# --- R1 and R2 ----------------------------------------------------------------


def test_an_applet_to_applet_edge_fails(tree):
    tree.edit(
        "crates/rsk-a/Cargo.toml",
        "[dependencies]\n",
        '[dependencies]\nrsk-b = { path = "../rsk-b" }\n',
    )
    problem = fails(tree)
    assert "applet -> applet edges (R2)" in problem
    assert "rsk-a -> rsk-b" in problem


def test_an_upward_edge_fails(tree):
    tree.edit(
        "crates/rsk-rec/Cargo.toml",
        "[dependencies]\n",
        '[dependencies]\nrsk-a = { path = "../rsk-a" }\n',
    )
    problem = fails(tree)
    assert "do not point strictly downward (R1)" in problem
    assert "rsk-rec -> rsk-a" in problem


def test_a_same_tier_edge_fails(tree):
    """Band index only — this is why rsk-fs and rsk-sdk are in separate bands."""
    tree.edit(
        "crates/rsk-rec2/Cargo.toml",
        "[dependencies]\n",
        '[dependencies]\nrsk-rec = { path = "../rsk-rec" }\n',
    )
    problem = fails(tree)
    assert "do not point strictly downward (R1)" in problem
    assert "rsk-rec2 -> rsk-rec" in problem


def test_a_target_gated_edge_is_not_a_hiding_place(tree):
    """A `[target.'cfg(…)'.dependencies]` edge reaches the image like any other."""
    tree.edit(
        "crates/rsk-rec/Cargo.toml",
        "[dependencies]\n",
        '[dependencies]\n\n[target."cfg(target_os = \\"none\\")".dependencies]\n'
        'rsk-a = { path = "../rsk-a" }\n',
    )
    assert "rsk-rec -> rsk-a" in fails(tree)


def test_an_applet_the_ban_list_does_not_hold_fails(tree):
    """The drawing asserting R2 is not the same as cargo-deny enforcing it."""
    tree.edit("deny.toml", '    { crate = "rsk-b", wrappers = ["firmware"] },\n', "")
    assert "deny.toml does not ban rsk-b" in fails(tree)


# --- the drift the gate row exists for ----------------------------------------


def test_a_hand_edited_svg_is_stale(tree):
    tree.run()
    tree.edit("docs/images/crate-graph.svg", "GENERATED by", "HAND-EDITED by")
    assert "is stale" in fails(tree, "--check")


def test_a_deleted_svg_is_stale(tree):
    tree.run()
    (tree.root / "docs/images/crate-graph.svg").unlink()
    assert "is stale" in fails(tree, "--check")


def test_a_new_edge_makes_the_committed_svg_stale(tree):
    tree.run()
    tree.edit(
        "crates/rsk-b/Cargo.toml",
        "[dependencies]\n",
        '[dependencies]\nrsk-alg = { path = "../rsk-alg" }\n',
    )
    assert "is stale" in fails(tree, "--check")


def test_stale_alt_text_fails(tree):
    tree.write("docs/architecture.md", tree.page("![seven applets](images/crate-graph.svg)"))
    assert "does not carry the drawing's own alt text" in fails(tree, "--check")


def test_a_crate_with_no_table_row_fails(tree):
    tree.edit("docs/architecture.md", "| `rsk-alg` | what it does |\n", "")
    assert "no row for rsk-alg" in fails(tree, "--check")


def test_a_table_row_for_a_crate_that_left_fails(tree):
    tree.edit(
        "docs/architecture.md",
        "| `rsk-alg` | what it does |\n",
        "| `rsk-alg` | what it does |\n| `rsk-gone` | a crate that was deleted |\n",
    )
    assert "names rsk-gone" in fails(tree, "--check")


def test_every_problem_is_reported_not_just_the_first(tree):
    """One manifest edit moves both counts; reporting one sends you round twice."""
    tree.run()
    tree.edit(
        "crates/rsk-b/Cargo.toml",
        "[dependencies]\n",
        '[dependencies]\nrsk-alg = { path = "../rsk-alg" }\n',
    )
    problem = fails(tree, "--check")
    assert "is stale" in problem
    assert "does not carry the drawing's own alt text" in problem


# --- the notes are measurements, not prose ------------------------------------


def test_the_universal_note_names_only_what_every_applet_uses(tree):
    """rsk-rec is under both applets; rsk-alg and rsk-rec2 under one each."""
    tree.run()
    line = next(ln for ln in tree.svg().splitlines() if "All 2 applets build on" in ln)
    assert "rsk-rec<" in line and "rsk-alg" not in line and "rsk-rec2" not in line


def test_an_optional_dependency_is_daggered(tree):
    tree.edit(
        "crates/rsk-a/Cargo.toml",
        'rsk-alg = { path = "../rsk-alg" }',
        'rsk-alg = { path = "../rsk-alg", optional = true }',
    )
    tree.run()
    assert "rsk-alg †" in tree.svg()
    assert "not linked by the default image: rsk-alg" in tree.svg()


def test_a_note_never_overflows_the_card():
    """The one defect a generated drawing can still ship.

    Rendered here rather than read off the committed file, so breaking the
    wrapper fails this without anyone regenerating first. `wrap` can only
    overflow one way — a single chunk longer than the budget gets a line to
    itself — and that is what this catches.
    """
    members, edges, firm = crate_graph.read_workspace()
    svg, _desc = crate_graph.render(members, edges, firm)
    notes = [ln for ln in svg.splitlines() if 'class="note"' in ln]
    assert len(notes) >= 3, notes
    for line in notes:
        plain = re.sub(r"<[^>]+>", "", line).strip()
        assert len(plain) <= crate_graph.NOTE_BUDGET, f"{len(plain)} chars: {plain}"
