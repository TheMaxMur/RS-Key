# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unit tests for the pure logic in rsk.audit (no device).

Run from tools/:  python -m pytest rsk/test_audit.py
The device coalesces a run of config writes into one ring entry, so its detail
carries the run (`repeats(2 LE) ‖ targets(1)`) rather than eight zero bytes.
Decoding that is the only place the host interprets an entry's detail — pin it.
"""
from rsk import audit


def _entry(event, aux=0, detail=b""):
    e = bytearray(audit.ENTRY_LEN)
    e[8] = event
    e[9] = aux
    e[10:10 + len(detail)] = detail
    return bytes(e)


def test_detail_of_a_single_config_write():
    e = _entry(audit.EVT_CONFIG_WRITE, aux=2, detail=bytes([0, 0, 0b100]))
    assert audit._detail(e) == "1× write (led)"


def test_detail_counts_a_coalesced_run_over_several_targets():
    # 299 further writes folded in, touching both the phy and the LED record.
    e = _entry(audit.EVT_CONFIG_WRITE, aux=1, detail=bytes([0x2B, 0x01, 0b110]))
    assert audit._detail(e) == "300× write (phy+led)"


def test_detail_of_other_events_stays_raw_hex():
    e = _entry(audit.EVT_RESET, detail=bytes([0xAA, 0xBB]))
    assert audit._detail(e) == "aabb000000000000"
