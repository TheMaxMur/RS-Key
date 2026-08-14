# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unit tests for the pure logic in rsk.bench (no device).

Run from tools/:  python -m pytest rsk/test_bench.py
The device (rsk_bench::Summary::to_le_bytes) packs five little-endian u32 in the
order [n, cold, min, median, mad]; parse_summary must decode that exact layout,
and ab_verdict must call a layout-driven ±30 ms swing significant while ignoring
sub-MAD jitter."""
import struct

import pytest

from rsk import bench


def _summary_bytes(n, cold, mn, median, mad):
    # Same field order as rsk_bench::Summary::to_le_bytes.
    return struct.pack("<5I", n, cold, mn, median, mad)


def test_parse_summary_decodes_the_device_layout():
    got = bench.parse_summary(_summary_bytes(31, 152000, 104800, 106000, 300))
    assert got == {"n": 31, "cold": 152000, "min": 104800, "median": 106000, "mad": 300}


def test_parse_summary_rejects_wrong_length():
    with pytest.raises(ValueError):
        bench.parse_summary(b"\x00" * 19)


def test_us_to_ms_and_cold_ratio():
    assert bench.us_to_ms(106000) == 106.0
    assert bench.cold_ratio({"cold": 152000, "median": 106000}) == pytest.approx(1.433, abs=1e-3)
    # No warm data (median 0) → ratio is undefined, not a divide-by-zero.
    assert bench.cold_ratio({"cold": 5, "median": 0}) is None


def test_ab_verdict_flags_a_layout_swing_but_not_jitter():
    # The real 0.14-migration scare: an intermediate build sat at 138 ms, the
    # combs realigned it to 106 ms — a genuine 32 ms layout shift, both runs tight.
    swing = bench.ab_verdict(
        {"median": 138000, "mad": 500}, {"median": 106000, "mad": 300}
    )
    assert swing["significant"] and swing["direction"] == "improvement"

    # The same build measured twice: a fraction-of-a-MAD wobble is NOT a regression.
    noise = bench.ab_verdict(
        {"median": 106000, "mad": 300}, {"median": 106200, "mad": 300}
    )
    assert not noise["significant"] and noise["direction"] == "no change"


def test_ab_verdict_names_a_regression():
    v = bench.ab_verdict({"median": 106000, "mad": 300}, {"median": 138000, "mad": 400})
    assert v["significant"] and v["direction"] == "regression"
    assert v["delta_us"] == 32000


def test_ab_verdict_stable_runs_use_the_mad_floor():
    # Both perfectly stable (MAD 0): a 1 µs difference stays under the +1 floor.
    v = bench.ab_verdict({"median": 100000, "mad": 0}, {"median": 100001, "mad": 0})
    assert not v["significant"]


def test_fmt_latency_divides_a_batched_sample_and_switches_unit():
    # A single-op crypto selector: the sample IS the op, rendered in ms.
    assert bench.fmt_latency(106000, 1) == "106.0 ms"
    # A batch of 100 reads taking 470 µs is 4.70 µs per read — rendering that as
    # "0.5 ms" would hide the whole quantity being measured.
    assert bench.fmt_latency(470, 100) == "4.70 us"


def test_parse_response_takes_the_batch_size_from_the_device():
    body = _summary_bytes(31, 900, 460, 470, 4)
    # Plain 20-byte Summary (the crypto selectors): one op per sample.
    assert bench.parse_response(body) == (bench.parse_summary(body), 1)
    # Batched selector: the trailing u32 is the divisor, so the host holds no copy
    # of the firmware's OTP_READ_REPS to drift against it.
    summary, reps = bench.parse_response(body + struct.pack("<I", 100))
    assert reps == 100 and summary["median"] == 470


def test_parse_response_refuses_a_zero_divisor():
    # A garbled rep count must not turn the render into a divide-by-zero.
    _, reps = bench.parse_response(_summary_bytes(1, 2, 3, 4, 5) + struct.pack("<I", 0))
    assert reps == 1
