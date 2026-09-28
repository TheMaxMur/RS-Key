# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""`rsk otp lock-page58`'s reading of READ 1E/07, the bits the firmware waits on.

Run from tools/:  python -m pytest rsk/test_otp_lock.py
The firmware refuses the burn with 6985 while a boot's seal passes left anything
under the pre-burn key; this is what tells the operator why, and what to do,
before the typed confirmation rather than after a refusal.
"""
import sys
import types

# rsk.ctaphid sys.exits at import without hidapi; nothing here touches a device.
sys.modules.setdefault("hid", types.ModuleType("hid"))

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
