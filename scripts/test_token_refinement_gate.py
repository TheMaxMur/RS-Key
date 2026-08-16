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
"""

STATE = """fn issue() {
    state.paut.in_use = true;
}

fn persist() {
    fs.put(EF_PIN, &[]);
}

fn authorize() {
    let authorized = state.paut.permissions & PERM_MC != 0;
}
"""


class Tree:
    def __init__(self, root: Path):
        self.root = root
        self.write("formal/generated/token_relation.txt", EXPORT)
        self.write("assurance/token_refinement.toml", MANIFEST)
        self.write("crates/rsk-fido/src/state.rs", STATE)
        self.write(
            "crates/rsk-fido/src/state_assurance.rs",
            "pub const TOKEN_PERSISTENT_FIDS: [u16; 2] = "
            "[crate::consts::EF_PIN, crate::consts::EF_PAUTHTOKEN.get()];\n",
        )

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

    def findings(self) -> list[str]:
        return token_refinement_gate.audit(self.root)[0]


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    return Tree(tmp_path)


def contains(findings: list[str], text: str) -> bool:
    return any(text in finding for finding in findings)


def test_green_fixture_passes(tree: Tree):
    assert tree.findings() == []


def test_this_checkout_passes():
    assert token_refinement_gate.audit(token_refinement_gate.ROOT)[0] == []


def test_an_owner_cannot_name_an_operation_outside_tla(tree: Tree):
    tree.replace("assurance/token_refinement.toml", 'op = "IssueToken"', 'op = "Unknown"')
    assert contains(tree.findings(), "Unknown is outside the generated TLA+ Ops domain")


def test_the_persistent_domain_is_derived_from_the_projection(tree: Tree):
    tree.replace("crates/rsk-fido/src/state_assurance.rs", "EF_PAUTHTOKEN", "EF_ALWAYS_UV")
    assert contains(tree.findings(), "TokenPersistentView key derivation yielded")


@pytest.mark.parametrize(
    ("body", "finding"),
    [
        ("fn stray() { state.paut.permissions = 0; }\n", "volatile: unowned concrete site"),
        ("fn stray() { fs.delete(EF_PIN); }\n", "persistent: unowned concrete site"),
        (
            "fn stray() { let ok = state.paut.permissions & PERM_ACFG != 0; }\n",
            "outcome: unowned concrete site",
        ),
    ],
)
def test_an_unowned_concrete_site_fails(tree: Tree, body: str, finding: str):
    tree.append("crates/rsk-fido/src/state.rs", body)
    assert contains(tree.findings(), finding)


@pytest.mark.parametrize(
    ("category", "finding"),
    [
        ("volatile_writer", "volatile: stale owner"),
        ("persistent_writer", "persistent: stale owner"),
        ("outcome_producer", "outcome: stale owner"),
    ],
)
def test_a_stale_manifest_owner_fails(tree: Tree, category: str, finding: str):
    tree.append(
        "assurance/token_refinement.toml",
        f'\n[[{category}]]\nfile = "crates/rsk-fido/src/state.rs"\n'
        'function = "gone"\nop = "UseMc"\n',
    )
    assert contains(tree.findings(), finding)


def test_test_kani_and_generated_files_are_not_production_axes(tree: Tree):
    body = "fn ignored() { state.paut.in_use = true; fs.delete(EF_PIN); }\n"
    tree.write("crates/rsk-fido/src/state_tests.rs", body)
    tree.write("crates/rsk-fido/src/state_kani.rs", body)
    tree.write("crates/rsk-fido/src/generated_token_edges.rs", body)
    assert tree.findings() == []


def test_main_prints_a_nonempty_success_summary(tree: Tree, monkeypatch, capsys):
    monkeypatch.setattr(token_refinement_gate, "ROOT", tree.root)
    assert token_refinement_gate.main() == 0
    assert capsys.readouterr().out.startswith("token-refinement-gate: GREEN")
