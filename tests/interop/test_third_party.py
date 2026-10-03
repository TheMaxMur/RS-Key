# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Divergence selection must leave adjacent malformed-parameter cases active."""

import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "third_party", Path(__file__).resolve().parents[1] / "third_party.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@pytest.mark.parametrize("suffix", ["", "_type", "_alg"])
def test_missing_algorithm_list_divergence_is_exact(suffix):
    name = "test_020_register.py::test_missing_pubKeyCredParams"
    pattern, reason = runner._match(runner.DIVERGENCES["fido"], name + suffix)
    assert bool(reason) is (suffix == "")
    assert bool(pattern) is (suffix == "")


def test_substring_patterns_and_specificity_remain_available():
    patterns = {"module.py": "module", "module.py::test_case": "case"}
    assert runner._match(patterns, "module.py::test_case[param]")[1] == "case"
    assert runner._match(patterns, "module.py::test_other")[1] == "module"
