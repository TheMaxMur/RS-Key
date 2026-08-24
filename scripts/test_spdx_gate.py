# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `spdx_gate.py` is verified against.

The rule it enforces is one line of AGENTS.md that nothing had ever checked, so
the guard is the only thing standing behind it and it gets the same treatment as
its siblings: every clause mutated, both directions, and the shapes that must
stay green written down beside the ones that must not — a manifest with no
header, a vendored tree under someone else's licence, an untracked file that a
`git ls-files` without `--others` would never see.
"""

import pathlib
import subprocess

import pytest

import spdx_gate

HEADER = f"// {spdx_gate.HEADER}\n// Copyright (C) 2026 RS-Key contributors\n"


class Tree:
    """A checkout shaped like this one: sources, a vendored tree, a manifest."""

    def __init__(self, root):
        self.root = root
        self.write("crates/rsk-a/src/lib.rs", HEADER + "\npub fn a() {}\n")
        self.write("scripts/thing.py", f"#!/usr/bin/env python3\n# {spdx_gate.HEADER}\n")
        self.write("scripts/hooks/pre-commit", f"#!/usr/bin/env bash\n# {spdx_gate.HEADER}\n")
        self.write("crates/rsk-a/Cargo.toml", '[package]\nname = "rsk-a"\n')
        self.write("README.md", "# no header here, and none is asked for\n")
        self.write(".github/workflows/ci.yml", f"# {spdx_gate.HEADER}\nname: ci\n")
        for form in spdx_gate.UNHEADERED:
            self.write(form, "name: a form\n")
        self.write("LICENSE", "the licence itself\n")
        self.write("third_party/upstream/LICENSE", "MIT\n")
        self.write("third_party/upstream/test_it.py", "def test(): pass\n")
        self.write(
            "crates/rsk-rsa/csrc/bignum.c",
            "/*\n* Copyright (c) 2025 Someone Else\n*/\nint f(void) { return 0; }\n",
        )
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def problems(self, floor=1):
        """Audited with the floor lowered: the fixture is smaller than the tree."""
        was = spdx_gate.FLOOR
        spdx_gate.FLOOR = floor
        try:
            return spdx_gate.audit(self.root)[0]
        finally:
            spdx_gate.FLOOR = was


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def only(problems, needle):
    """The problems mentioning `needle`, so a message is asserted, not a count."""
    return [p for p in problems if needle in p]


# --- the clean tree, and the real one ----------------------------------------


def test_clean_tree_is_green(tree):
    assert tree.problems() == []


def test_this_checkout_is_green():
    """The control the fixture cannot be: the tree this rule was written for."""
    assert spdx_gate.audit(spdx_gate.ROOT)[0] == []


# --- files that owe a header --------------------------------------------------


def test_a_rust_file_with_no_header(tree):
    tree.write("crates/rsk-a/src/extra.rs", "pub fn extra() {}\n")
    assert only(tree.problems(), "crates/rsk-a/src/extra.rs has no")


def test_a_python_file_with_no_header(tree):
    tree.write("scripts/other.py", "print('hi')\n")
    assert only(tree.problems(), "scripts/other.py has no")


def test_a_header_below_the_window(tree):
    """Buried under code, where nobody scanning the top would ever see it."""
    tree.write(
        "crates/rsk-a/src/extra.rs",
        f"pub fn a() {{}}\npub fn b() {{}}\npub fn c() {{}}\n// {spdx_gate.HEADER}\n",
    )
    assert only(tree.problems(), "in its first 3 lines")


def test_the_wrong_licence(tree):
    tree.write("crates/rsk-a/src/extra.rs", "// SPDX-License-Identifier: MIT\n")
    assert only(tree.problems(), "crates/rsk-a/src/extra.rs has no")


def test_a_shebang_script_with_no_extension(tree):
    """The next hook beside pre-commit does not escape by having no suffix."""
    tree.write("scripts/hooks/pre-push", "#!/usr/bin/env bash\necho hi\n")
    assert only(tree.problems(), "scripts/hooks/pre-push has no")


def test_an_untracked_file_counts(tree):
    """`git ls-files` without `--others` would never see one, and new is the case."""
    subprocess.run(["git", "-C", str(tree.root), "add", "-A"], check=True, capture_output=True)
    tree.write("crates/rsk-a/src/fresh.rs", "pub fn fresh() {}\n")
    assert only(tree.problems(), "crates/rsk-a/src/fresh.rs has no")


# --- files that do not --------------------------------------------------------


def test_a_manifest(tree):
    tree.write("crates/rsk-b/Cargo.toml", '[package]\nname = "rsk-b"\n')
    assert tree.problems() == []


def test_a_markdown_page(tree):
    tree.write("docs/guide.md", "# a page\n")
    assert tree.problems() == []


def test_the_licence_itself(tree):
    """No extension and no shebang, so nothing asks it to name a licence."""
    tree.write("NOTICE", "who wrote what\n")
    assert tree.problems() == []


def test_a_vendored_file_under_its_own_licence(tree):
    tree.write("third_party/upstream/test_more.py", "def test(): pass\n")
    assert tree.problems() == []


def test_vendored_c_with_its_own_copyright_block(tree):
    """No LICENSE beside it, so the notice in the file is what excuses it."""
    assert tree.problems() == []
    assert "csrc" in " ".join(spdx_gate.EXEMPT)


# --- the exemptions are a debt, so they are checked too -----------------------


def test_an_exempt_file_with_no_notice_at_all(tree):
    (tree.root / "third_party/upstream/LICENSE").unlink()
    assert only(tree.problems(), "that is not an exemption")


def test_an_exemption_that_covers_nothing(tree):
    for rel in ("third_party/upstream/LICENSE", "third_party/upstream/test_it.py"):
        (tree.root / rel).unlink()
    assert only(tree.problems(), "is exempt any more")


def test_the_repo_licence_does_not_excuse_everything(tree):
    """A top-level LICENSE would otherwise cover every exempt file in the tree."""
    (tree.root / "third_party/upstream/LICENSE").unlink()
    assert (tree.root / "LICENSE").is_file()
    assert only(tree.problems(), "that is not an exemption")


def test_a_new_workflow_with_no_header(tree):
    """`.yml` is checked, so the next workflow is too — the three issue forms are
    excused one by one rather than by extension."""
    tree.write(".github/workflows/nightly.yml", "name: nightly\n")
    assert only(tree.problems(), ".github/workflows/nightly.yml has no")


def test_the_issue_forms_stay_excused(tree):
    assert tree.problems() == []
    assert len(spdx_gate.UNHEADERED) == 3


def test_an_excused_file_that_grew_a_header(tree):
    form = next(iter(spdx_gate.UNHEADERED))
    tree.write(form, f"# {spdx_gate.HEADER}\nname: a form\n")
    assert only(tree.problems(), "drop its UNHEADERED entry")


def test_an_excused_file_that_is_gone(tree):
    for form in spdx_gate.UNHEADERED:
        (tree.root / form).unlink()
    assert only(tree.problems(), "is listed in UNHEADERED but is not in the tree")


def test_a_file_with_no_extension_and_no_shebang(tree):
    """A Makefile has no suffix to classify, and used to fall through the gap."""
    tree.write("Makefile", "all:\n\tcargo build\n")
    assert only(tree.problems(), "this guard has never been told about")


def test_a_walk_that_finds_nothing(tree):
    """No roster to go empty, but a walk can still return nothing and exit 0."""
    assert only(tree.problems(floor=9999), "under the floor")


def test_a_stray_licensing_note_does_not_excuse_a_vendored_tree(tree):
    (tree.root / "third_party/upstream/LICENSE").unlink()
    tree.write("third_party/upstream/LICENSING-NOTES.md", "we use MIT somewhere\n")
    assert only(tree.problems(), "that is not an exemption")


# --- the set of extensions cannot go stale in silence -------------------------


def test_an_extension_nobody_has_classified(tree):
    tree.write("tools/web/app.ts", "export const a = 1;\n")
    assert only(tree.problems(), "is a `.ts` this guard has never")


def test_the_two_sets_do_not_overlap():
    assert not spdx_gate.CHECKED & set(spdx_gate.UNCHECKED)


# --- the guard's own wiring ---------------------------------------------------


def test_check_sh_still_runs_the_guard():
    check = (spdx_gate.ROOT / "scripts/check.sh").read_text()
    assert "scripts/spdx_gate.py" in check


def test_the_tests_are_named_after_the_guard():
    """`check.sh` collects `scripts` wholesale, so the name is the registration."""
    here = pathlib.Path(__file__).name
    assert here == f"test_{pathlib.Path(spdx_gate.__file__).stem}.py"
