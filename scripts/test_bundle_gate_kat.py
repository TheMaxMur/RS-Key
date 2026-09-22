# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The `.py` half of `KAT/differential`, held to the `.rs` half's shape.

The two arms were not one rule. `.rs` demands the `#[test]` ATTRIBUTE; `.py`
demanded a `def` — any `def`, in any `.py` — so `scripts/bundle_gate.py::
method_references` discharged a KAT obligation at exit 0 while its exact Rust
twin, `testvectors.rs::KeyGenKat`, is refused for being a declaration and not a
check. That is the input the `.rs` arm refuses and the `.py` arm accepted, and
the tree carries its own instance of the shape: `scripts/rsa_vectors.py` is a
vector GENERATOR, and the check is the Rust that reproduces what it wrote.

Python has no attribute, so the analogue is the NAME its runner keys on —
`bundle_gate.PYTEST_FUNCTION`, pytest's own `python_functions` default. The
cases below carry both directions of that trade: what it now refuses, and the
honestly-run artifacts it must not, which is where two stronger shapes fell.

The arms live here rather than in `test_bundle_gate.py` so the change is one
diff; that file keeps the case whose assertion this change inverted.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import bundle_gate
import test_bundle_gate as T

#: Refused now, with the reason each is refused for. Every one resolves in the
#: tree, so the fixture carries the real file and the rule is read over real
#: source rather than a stub written to fail.
NOT_A_CASE = (
    ("scripts/bundle_gate.py::method_references", "the gate function that was the hole"),
    ("scripts/rsa_vectors.py::main", "the vector GENERATOR, not the check"),
    ("crates/rsk-mldsa/src/testvectors.rs::KeyGenKat", "the `.rs` twin of the same shape"),
)

#: Accepted, and each for a reason the rule has to keep. The last two are what
#: refuted the two stronger shapes: `card_test_reset_pw3.py` matches no
#: `python_files` pattern and its methods run anyway, because 57 of that suite's
#: 62 collected modules are `from card_test_… import *`; and no third-party
#: tree is under a pytest root `check.sh` names — `tests/third_party.py` calls
#: `pytest.main` on them instead.
A_CASE = (
    "tools/rsk/test_audit.py::test_detail_of_a_single_config_write",
    "third_party/pico-fido-tests/pico-fido/test_010_pin.py::test_set_pin",
    "third_party/openpgp-card-tests/card_test_reset_pw3.py::test_verify_pw3",
)


def kat(tmp_path, artifact):
    return T.findings(T.as_kat(T.tree(tmp_path), artifact))


@pytest.mark.parametrize("artifact,why", NOT_A_CASE)
def test_a_kat_row_naming_a_def_no_runner_collects(tmp_path, artifact, why):
    problems = kat(tmp_path, artifact)
    assert any("nothing that RAN the vectors" in p for p in problems), (why, problems)


@pytest.mark.parametrize("artifact", A_CASE)
def test_a_kat_row_naming_a_case_a_runner_really_runs(tmp_path, artifact):
    assert kat(tmp_path, artifact) == []


def test_the_tests_directory_arm_still_takes_a_file_with_no_symbol(tmp_path):
    """The asymmetry that STAYS, and the reason it is not a hole: the unit
    differs because the runner does. `scripts/emu-suites.sh` loops
    `tests/[0-9]*.py` and puts each FILE through `tests/emu.py`, where a `.rs`
    file holds many `#[test]`s and outlives any one of them. Requiring `::main`
    would require the one symbol all 65 suites have, which names nothing."""
    assert kat(tmp_path, T.KAT_RUNNER) == []


def test_the_prefix_is_what_the_runner_keys_on_and_not_a_guess(tmp_path, monkeypatch):
    """The deletion arm for [`bundle_gate.PYTEST_FUNCTION`]. Neutered to the empty
    string, every name starts with it and the arm is back to ANY `def` — which is
    the shipped hole, green on the gate function it was written against.

    Red BEFORE the mutant and green after, in one case: `== []` alone would pass
    for any reason the fixture is green."""
    artifact = NOT_A_CASE[0][0]
    assert any("nothing that RAN the vectors" in p for p in kat(tmp_path, artifact))
    monkeypatch.setattr(bundle_gate, "PYTEST_FUNCTION", "")
    assert kat(tmp_path, artifact) == []


def test_the_prefix_alone_is_not_the_rule(tmp_path):
    """The other half of the same clause: a NAME starting with `test` is not
    enough, the file must declare it. `bundle_gate.definitions` parses, so the
    name occurring in the text buys nothing — measured on this very file, which
    carries `test_set_pin` in the [`A_CASE`] roster and declares no such `def`."""
    problems = kat(tmp_path, "scripts/test_bundle_gate_kat.py::test_set_pin")
    assert any("nothing that RAN the vectors" in p for p in problems), problems
