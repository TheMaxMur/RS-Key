# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""`rsk openpgp reset` blocks each PIN however many tries it has.

Run from tools/:  python -m pytest rsk/test_openpgp_reset.py
TERMINATE DF takes a blocked admin PIN, and SET PIN RETRIES (INS F2) gives a PIN
up to 255 tries, so a fixed number of wrong VERIFYs no longer blocks one. The card
below answers as the firmware does: 6982 per wrong try, 6983 once none is left.
"""
import sys
import types

# rsk.ctaphid sys.exits at import without hidapi; nothing here touches a device.
sys.modules.setdefault("hid", types.ModuleType("hid"))

import pytest  # noqa: E402

from rsk import openpgp  # noqa: E402

PW1, PW3 = openpgp.MODE_PW1, openpgp.MODE_PW3


class Card:
    """The OpenPGP applet's SELECT, VERIFY, TERMINATE and ACTIVATE over PINs
    nobody here knows, each with `tries` tries left."""

    def __init__(self, tries):
        self.pins = {PW1: b"owner-pw1", PW3: b"owner-admin"}
        self.left = {PW1: tries, PW3: tries}
        self.terminated = False
        self.verifies = 0

    def transmit(self, apdu):
        ins, p2, data = apdu[1], apdu[3], bytes(apdu[5:])
        if ins == 0xA4:
            return [], 0x90, 0x00
        if ins == openpgp.INS_TERMINATE:
            if self.left[PW3]:
                return [], 0x69, 0x82
            self.terminated = True
            return [], 0x90, 0x00
        if ins == openpgp.INS_ACTIVATE:
            self.pins = {PW1: openpgp.PW1_DEFAULT, PW3: openpgp.PW3_DEFAULT}
            self.left = {PW1: 3, PW3: 3}
            return [], 0x90, 0x00
        assert ins == openpgp.INS_VERIFY, apdu
        self.verifies += 1
        if self.left[p2] == 0:
            return [], 0x69, 0x83
        if data == self.pins[p2]:
            return [], 0x90, 0x00
        self.left[p2] -= 1
        return [], 0x69, 0x83 if self.left[p2] == 0 else 0x82


def reset(monkeypatch, card):
    monkeypatch.setattr(openpgp.ccid, "connect", lambda **kw: card)
    openpgp.reset(None)


@pytest.mark.parametrize("tries", [1, 3, 6, 25, 255])
def test_each_pin_is_blocked_whatever_its_tries(monkeypatch, capsys, tries):
    card = Card(tries)
    reset(monkeypatch, card)
    assert card.terminated
    assert "reset to factory defaults" in capsys.readouterr().out


def test_the_blocking_stops_at_the_first_6983(monkeypatch):
    # A factory card's three each, then the two defaults the reset checks it with.
    card = Card(3)
    reset(monkeypatch, card)
    assert card.verifies == 3 + 3 + 2
