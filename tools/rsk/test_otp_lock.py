# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""`rsk otp lock-page58`'s reading of READ 1E/07, the bits the firmware waits on.

Run from tools/:  python -m pytest rsk/test_otp_lock.py
The firmware refuses the burn with 6985 while a boot's seal passes left anything
under the pre-burn key; this is what tells the operator why, and what to do,
before the typed confirmation rather than after a refusal. The second half drives
the command against a stand-in for the rescue applet.
"""
import sys
import types

# rsk.ctaphid sys.exits at import without hidapi; nothing here touches a device.
sys.modules.setdefault("hid", types.ModuleType("hid"))

import pytest  # noqa: E402

from rsk import otp  # noqa: E402


def test_nothing_left_is_nothing_to_do():
    assert otp.pre_otp_actions(0) == []


def test_each_bit_names_its_own_remedy():
    for bit, text in otp.PRE_OTP_ACTIONS:
        assert otp.pre_otp_actions(bit) == [text]


def test_several_bits_name_several_remedies():
    both = otp.PRE_OTP_ACTIONS[0][0] | otp.PRE_OTP_ACTIONS[3][0]
    assert len(otp.pre_otp_actions(both)) == 2


def test_an_unchecked_boot_is_one_remedy_not_every_one():
    todo = otp.pre_otp_actions(otp.PRE_OTP_UNCHECKED)
    assert len(todo) == 1 and "rsk otp burn" in todo[0]


def test_an_unreadable_key_is_its_own_remedy():
    # rsk-rescue `otp_lock::PRE_OTP_KEY_UNREADABLE`: no pass ran, so no pass's remedy.
    todo = otp.pre_otp_actions(otp.PRE_OTP_KEY_UNREADABLE)
    assert len(todo) == 1 and "replug" in todo[0] and "rsk otp burn" not in todo[0]
    assert otp.PRE_OTP_KEY_UNREADABLE == 0xFFFE


def test_the_bits_are_the_firmware_s():
    # rsk-rescue `otp_lock::PRE_OTP_*`, in order: FIDO, device key, PIV, OATH, OTP.
    assert [bit for bit, _ in otp.PRE_OTP_ACTIONS] == [0x01, 0x02, 0x04, 0x08, 0x10]


# --- the command, driven against a rescue applet that answers as the firmware does

LATCH, OLD_LOCK = 0x3D3D3D, 0x3C3C3C
SERIAL = bytes.fromhex("a1b2c3d4e5f60718")


class Rescue:
    """rsk-rescue's SELECT, READ 1E/07 and OTP_LOCK, in `lock_page58`'s order: key,
    row, then the pre-burn verdict before the touch. `log` holds each APDU sent
    and each typed confirmation, in order."""

    def __init__(self, left, row=0, key=True, row_reads=True):
        self.left, self.row, self.key, self.row_reads = left, row, key, row_reads
        self.log, self.burnt = [], False

    def transmit(self, apdu):
        self.log.append(bytes(apdu))
        if apdu[:2] == [0x00, 0xA4]:
            return list(b"\x01\x02\x08\x06" + SERIAL), 0x90, 0x00
        if apdu == [0x80, 0x1E, 0x07, 0x00, 0x00]:
            return list(self.left.to_bytes(2, "big")), 0x90, 0x00
        assert apdu == otp.LOCK_APDU, apdu
        if not self.key:
            return [], 0x69, 0x85
        if not self.row_reads:
            return [], 0x64, 0x00
        if self.row == LATCH:
            return [], 0x90, 0x00
        if self.row not in (0, OLD_LOCK) or self.left != 0:
            return [], 0x69, 0x85
        self.row, self.burnt = LATCH, True
        return [], 0x90, 0x00

    def locks(self):
        return [a for a in self.log if a == bytes(otp.LOCK_APDU)]


def drive(monkeypatch, card, typed="", dry_run=False):
    monkeypatch.setattr(otp.ccid, "connect", lambda **kw: card)

    def typing(prompt=""):
        card.log.append("typed")
        return typed

    monkeypatch.setattr("builtins.input", typing)
    otp.lock_page58(types.SimpleNamespace(dry_run=dry_run))


def test_a_latched_row_exits_zero_whatever_1e07_says(monkeypatch, capsys):
    """The run-27 residual: a planted legacy OTP-PIN keeps READ 1E/07 at 0008 on a
    latched device, and the tool exited 2 as if the burn were still owed."""
    card = Rescue(left=0x0008, row=LATCH)
    drive(monkeypatch, card)
    out = capsys.readouterr().out
    assert "already locked and latched" in out and "0008" in out
    assert "typed" not in card.log and not card.burnt


def test_an_unlatched_row_with_records_left_still_exits_two(monkeypatch, capsys):
    for row in (0, OLD_LOCK):
        card = Rescue(left=0x0001, row=row)
        with pytest.raises(SystemExit) as e:
            drive(monkeypatch, card)
        assert e.value.code == 2
        assert "replug once" in capsys.readouterr().out
        assert len(card.locks()) == 1 and "typed" not in card.log and not card.burnt


def test_nothing_left_sends_no_lock_before_the_typed_confirmation(monkeypatch):
    """With 1E/07 at 0000 the firmware burns after a touch, so the only OTP_LOCK
    that may go out is the one the operator typed the serial for."""
    card = Rescue(left=0)
    with pytest.raises(SystemExit):
        drive(monkeypatch, card, typed="no")
    assert card.locks() == [] and not card.burnt
    card = Rescue(left=0)
    drive(monkeypatch, card, typed=SERIAL.hex())
    assert card.log.index("typed") < card.log.index(bytes(otp.LOCK_APDU))
    assert len(card.locks()) == 1 and card.burnt


def test_a_dry_run_sends_no_lock(monkeypatch, capsys):
    card = Rescue(left=0x0008, row=LATCH)
    with pytest.raises(SystemExit) as e:
        drive(monkeypatch, card, dry_run=True)
    assert e.value.code == 2 and card.locks() == []
    assert "cannot tell whether page 58" in capsys.readouterr().out


def test_an_unreadable_key_past_the_latch_keeps_its_remedy(monkeypatch, capsys):
    """FFFE past the latch: the firmware refuses at its key check before it reads
    the row, so the tool cannot see the latch and says what 1E/07 says."""
    card = Rescue(left=otp.PRE_OTP_KEY_UNREADABLE, row=LATCH, key=False)
    with pytest.raises(SystemExit) as e:
        drive(monkeypatch, card)
    assert e.value.code == 2
    assert "could not read the fused key" in capsys.readouterr().out


def test_a_lock_row_that_does_not_read_is_reported_not_taken_for_latched(monkeypatch, capsys):
    card = Rescue(left=0x0004, row=LATCH, row_reads=False)
    with pytest.raises(SystemExit) as e:
        drive(monkeypatch, card)
    out = capsys.readouterr().out
    assert e.value.code == 2 and "6400" in out and "EXEC_ERROR" in out
    assert "already locked" not in out
