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


def _frame(cmd, nonce, caps=0):
    """A 64-byte init-type response frame; byte 23 is the INIT capability byte."""
    f = bytearray(64)
    f[4] = cmd
    f[7:15] = nonce  # CTAP 2.1 §11.2.9.1.3 — the reply must carry it back
    f[15:19] = b"\x11\x22\x33\x44"  # channel id
    f[23] = caps
    return bytes(f)


class _FakeDev:
    """Answers INIT with `caps` and echoes any other command back. `answer` swaps
    in a different reply (or b"" for a device that says nothing at all)."""

    def __init__(self, caps, log, answer=None):
        self.caps = caps
        self.log = log
        self.answer = answer
        self._last = None
        self._nonce = bytes(8)

    def open_path(self, path):
        self.log.append(("open", path))

    def write(self, payload):
        self._last = payload[5]  # payload[0] is the report id prefix
        self._nonce = payload[8:16]
        self.log.append(("write", self._last))

    def read(self, _n, _timeout):
        if self._last == CTAPHID_INIT:
            return _frame(CTAPHID_INIT, self._nonce, self.caps)
        return _frame(self._last, self._nonce) if self.answer is None else self.answer

    def close(self):
        self.log.append(("close", None))


def _install(monkeypatch, devices):
    """`devices` is a list of (info, caps) or (info, caps, answer); returns the
    shared call log."""
    log = []
    monkeypatch.setattr(ctaphid, "find_all", lambda: [d[0] for d in devices])
    rest = iter(devices)

    def device():
        d = next(rest)
        return _FakeDev(d[1], log, d[2] if len(d) > 2 else None)

    monkeypatch.setattr(ctaphid, "hid", types.SimpleNamespace(device=device))
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


# --- one bad device must not end the walk (audit run-37) ----------------------

def test_a_device_that_refuses_the_wink_is_reported_not_fatal(monkeypatch, capsys):
    # A refusal used to `die`, aborting the walk — inconsistently with the
    # no-indicator case, which reports and moves on. The whole command is the walk.
    log = _install(monkeypatch, [(_info("mute"), CAPS_WINK, _frame(0xBF, bytes(8))),
                                 (_info("ok"), CAPS_WINK)])
    identify.run(types.SimpleNamespace(repeat=1))
    out = capsys.readouterr().out
    assert "mute — refused CTAPHID_WINK" in out and "ok — winking now" in out
    assert len(_winks(log)) == 2  # both were tried; only the second answered


def test_a_device_that_answers_nothing_is_reported_not_crashed(monkeypatch, capsys):
    # An empty read is what a device returns on the HID timeout; `wink` indexed
    # `r[4]` straight past the end of it and raised IndexError out of the walk.
    _install(monkeypatch, [(_info("gone"), CAPS_WINK, b""), (_info("ok"), CAPS_WINK)])
    identify.run(types.SimpleNamespace(repeat=1))
    out = capsys.readouterr().out
    assert "gone — refused CTAPHID_WINK" in out and "ok — winking now" in out


def test_init_bounds_an_empty_read():
    # Same timeout, one command earlier: `r[23]` was read with no length check.
    dev = _FakeDev(CAPS_WINK, [])
    dev.read = lambda _n, _t: b""
    with pytest.raises(OSError):
        ctaphid.ctaphid_init_caps(dev)


def test_a_device_that_cannot_be_opened_is_skipped(monkeypatch, capsys):
    log = _install(monkeypatch, [(_info("busy"), CAPS_WINK), (_info("ok"), CAPS_WINK)])
    real = ctaphid.hid.device

    def device():
        d = real()
        if len(log) == 0:  # the first device of the walk
            d.open_path = lambda path: (_ for _ in ()).throw(OSError("in use"))
        return d

    monkeypatch.setattr(ctaphid, "hid", types.SimpleNamespace(device=device))
    identify.run(types.SimpleNamespace(repeat=1))
    out = capsys.readouterr().out
    assert "busy — unreachable (in use)" in out and "ok — winking now" in out


def test_init_requires_the_nonce_to_come_back(monkeypatch):
    """The broadcast channel is shared, so an INIT reply carrying someone else's
    nonce is someone else's channel id — adopting it talks past the device."""
    log = []
    dev = _FakeDev(CAPS_WINK, log)
    dev.read = lambda _n, _t: _frame(CTAPHID_INIT, b"\xde\xad\xbe\xef" * 2, CAPS_WINK)
    with pytest.raises(OSError):
        ctaphid.ctaphid_init_caps(dev)
