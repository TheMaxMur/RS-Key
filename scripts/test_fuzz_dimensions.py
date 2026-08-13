# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The log buckets, and the line the reporter reads.

Small, because the reporter gates nothing — but the bucketing is the whole claim
it makes, and an off-by-one in it would misdescribe a corpus rather than fail
loudly. Wasefire keeps the same handful of cases beside their `get_bucket`.
"""

import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("fuzz_dimensions", HERE / "fuzz-dimensions.py")
fd = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fd)


def test_buckets_are_powers_of_two_with_zero_its_own():
    assert [fd.bucket(n) for n in (0, 1, 2, 3, 4, 7, 8, 15, 16)] == [0, 1, 2, 2, 4, 4, 8, 8, 16]


def test_a_line_is_parsed_into_its_axes():
    found = fd.LINE.search("power-cut-stats dirty=0 ops=12 fids=9\n")
    assert found
    axes = dict(f.split("=") for f in found.group(1).split())
    assert axes == {"dirty": "0", "ops": "12", "fids": "9"}


def test_a_line_that_is_not_one_is_not_read():
    assert not fd.LINE.search("power-cut-stats\n")
    assert not fd.LINE.search("power-cut-stats dirty=\n")


def test_an_axis_the_target_adds_still_gets_a_row():
    """The order list is a preference, not a roster: an unnamed axis is shown."""
    runs = [{"dirty": 0, "brand_new": 5}]
    assert set(fd.histograms(runs)) == {"dirty", "brand_new"}
