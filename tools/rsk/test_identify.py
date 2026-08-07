# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Host tests for `rsk identify` (no real hidapi).

Run from tools/:  python -m pytest rsk/test_identify.py

Two properties matter. It must walk *every* attached authenticator rather than
refusing to guess — telling several keys apart is the whole command — and it must
not send CTAPHID_WINK to a device whose INIT reply leaves `CAPABILITY_WINK` clear,
because that bit is the device saying it has no indicator, and a wink nobody can
see is exactly the bug the command exists to avoid.
"""
import sys
import types

sys.modules.setdefault("hid", types.ModuleType("hid"))

import pytest

from rsk import ctaphid, identify

CTAPHID_INIT = 0x86
CAPS_WINK = 0x05  # WINK | CBOR
CAPS_NO_WINK = 0x04  # CBOR only — a build with no indicator


def _frame(cmd, caps=0):
    """A 64-byte init-type response frame; byte 23 is the INIT capability byte."""
    f = bytearray(64)
    f[4] = cmd
    f[7:15] = bytes(range(8))  # nonce echo
    f[15:19] = b"\x11\x22\x33\x44"  # channel id
    f[23] = caps
    return bytes(f)


class _FakeDev:
    """Answers INIT with `caps` and echoes any other command back."""

    def __init__(self, caps, log):
        self.caps = caps
        self.log = log
        self._last = None

    def open_path(self, path):
        self.log.append(("open", path))

    def write(self, payload):
        self._last = payload[5]  # payload[0] is the report id prefix
        self.log.append(("write", self._last))

    def read(self, _n, _timeout):
        return _frame(self._last, self.caps if self._last == CTAPHID_INIT else 0)

    def close(self):
        self.log.append(("close", None))


def _install(monkeypatch, devices):
    """`devices` is a list of (info, caps); returns the shared call log."""
    log = []
    monkeypatch.setattr(ctaphid, "find_all", lambda: [d[0] for d in devices])
    caps = iter(d[1] for d in devices)
    monkeypatch.setattr(
        ctaphid, "hid", types.SimpleNamespace(device=lambda: _FakeDev(next(caps), log))
    )
    monkeypatch.setattr(identify, "GAP_S", 0)
    return log


def _info(name, serial=None, path=b"/p"):
    return {"product_string": name, "serial_number": serial, "path": path}


def _winks(log):
    return [c for c in log if c == ("write", identify.CTAPHID_WINK)]


def test_walks_every_attached_device(monkeypatch, capsys):
    # The opposite of `connect_fido(exclusive=True)`: several attached keys is the
    # case this command is for, so all of them wink.
    log = _install(monkeypatch, [(_info("A", "1"), CAPS_WINK), (_info("B", "2"), CAPS_WINK)])
    identify.run(types.SimpleNamespace(repeat=1))
    assert len(_winks(log)) == 2
    out = capsys.readouterr().out
    assert "A [1]" in out and "B [2]" in out


def test_device_without_the_wink_bit_is_reported_not_winked(monkeypatch, capsys):
    log = _install(monkeypatch, [(_info("no-led"), CAPS_NO_WINK), (_info("led"), CAPS_WINK)])
    identify.run(types.SimpleNamespace(repeat=1))
    assert len(_winks(log)) == 1, "the indicator-less build must not be winked"
    assert "no indicator" in capsys.readouterr().out


def test_all_devices_lacking_an_indicator_is_an_error(monkeypatch):
    _install(monkeypatch, [(_info("no-led"), CAPS_NO_WINK)])
    with pytest.raises(SystemExit):
        identify.run(types.SimpleNamespace(repeat=1))


def test_repeat_sends_that_many_winks(monkeypatch):
    log = _install(monkeypatch, [(_info("A"), CAPS_WINK)])
    identify.run(types.SimpleNamespace(repeat=3))
    assert len(_winks(log)) == 3


def test_no_device_is_an_error(monkeypatch):
    _install(monkeypatch, [])
    with pytest.raises(SystemExit):
        identify.run(types.SimpleNamespace(repeat=1))
