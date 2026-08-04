# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""`ccid.find_reader` device selection, for the irreversible commands.

run-30 closed the no-match case (never fall back to `rs[0]`). run-32 closed the
multi-match case: the reader name is a substring test over a host-settable USB
string, so a second key left in app mode — or a planted CCID gadget — silently
won the first-match race while an OTP fuse burn reported success.
"""
import pytest

from rsk import ccid


@pytest.fixture(autouse=True)
def _no_pcsc_require(monkeypatch):
    monkeypatch.setattr(ccid, "_require", lambda: None)


def _readers(monkeypatch, names):
    monkeypatch.setattr(ccid, "readers", lambda: list(names))


def test_single_match_is_returned(monkeypatch):
    _readers(monkeypatch, ["Some Vendor CCID 00 00", "RS-Key Security Key 01 00"])
    assert ccid.find_reader(exclusive=True) == "RS-Key Security Key 01 00"


def test_multi_match_refuses_when_exclusive(monkeypatch):
    _readers(monkeypatch, ["RS-Key Security Key 00 00", "RS-Key Security Key 01 00"])
    with pytest.raises(SystemExit) as e:
        ccid.find_reader(exclusive=True)
    assert "more than one" in str(e.value)


def test_multi_match_still_guesses_for_the_read_only_callers(monkeypatch):
    # `rsk status` and friends stay non-exclusive: refusing there would be a
    # regression for anyone with two keys plugged in.
    _readers(monkeypatch, ["RS-Key A 00 00", "RS-Key B 01 00"])
    assert ccid.find_reader() == "RS-Key A 00 00"


def test_no_match_still_refuses(monkeypatch):
    _readers(monkeypatch, ["Generic Smartcard Reader 00 00"])
    with pytest.raises(SystemExit) as e:
        ccid.find_reader(exclusive=True)
    assert "no RS-Key PC/SC reader" in str(e.value)
