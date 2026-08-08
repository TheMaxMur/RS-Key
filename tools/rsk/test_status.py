# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Host tests for the `rsk status` JSON shape (no device).

Run from tools/:  python -m pytest rsk/test_status.py

`gather()` is a documented machine-readable surface, so the two shapes a script
can rely on are pinned here: the serial is promoted to the top level from the
rescue SELECT, and it is `null` — never a KeyError — on the hosts where the CCID
interface is unavailable, which on Linux is the common case (docs/linux.md).
"""
import sys
import types

sys.modules.setdefault("hid", types.ModuleType("hid"))

from rsk import ccid, status

SERIAL = "a29974d3f40ac7cd"
SELECT_OK = bytes.fromhex("6f0a8408") + bytes.fromhex(SERIAL)


def test_gather_promotes_the_serial(monkeypatch):
    monkeypatch.setattr(status, "_fido", lambda: {"present": False})
    monkeypatch.setattr(status, "_secure_boot", lambda: {"available": True, "serial": SERIAL})
    assert status.gather()["serial"] == SERIAL


def test_gather_reports_no_serial_without_ccid(monkeypatch):
    monkeypatch.setattr(status, "_fido", lambda: {"present": False})
    monkeypatch.setattr(status, "_secure_boot", lambda: None)
    assert status.gather()["serial"] is None


def test_rescue_serial_reads_the_select_response():
    assert status.rescue_serial(SELECT_OK, *ccid.SW_OK) == SERIAL


def test_rescue_serial_refuses_a_short_or_failed_select():
    assert status.rescue_serial(SELECT_OK[:11], *ccid.SW_OK) is None
    assert status.rescue_serial(SELECT_OK, 0x6A, 0x82) is None
