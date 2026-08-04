# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unit tests for the pure logic in rsk.secureboot (no device, no picotool).

Run from tools/:  python -m pytest rsk/test_secureboot.py
The slot-row math, json re-targeting, free-slot picking, and the revoke
"don't orphan the last key" guard are the brick-risk decisions — pin them here.
"""
import pytest

from rsk import secureboot as sb


def test_slot_key_rows():
    # BOOTKEY{n}_0 = 0x80 + n*0x10, per `picotool otp list`
    assert [sb.slot_key_row(n) for n in range(4)] == [0x80, 0x90, 0xA0, 0xB0]


def test_valid_slot_range():
    for n in range(sb.N_KEY_SLOTS):
        assert sb._valid_slot(n) == n
    for bad in (-1, sb.N_KEY_SLOTS, 99):
        with pytest.raises(SystemExit):
            sb._valid_slot(bad)


def test_build_slot_json_retargets_field_and_sets_valid():
    seal = {"bootkey0": list(range(32)), "boot_flags1": {"key_valid": 1}, "crit1": {}}
    out = sb._build_slot_json(seal, 1, new_key_valid=0b11)
    assert out == {"bootkey1": list(range(32)), "boot_flags1": {"key_valid": 0b11}}
    # crit1 (enforcement) and the slot-0 field are NOT carried over
    assert "crit1" not in out and "bootkey0" not in out


def test_build_slot_json_slot0_is_backward_compatible():
    seal = {"bootkey0": list(range(32)), "boot_flags1": {"key_valid": 1}, "crit1": {}}
    assert sb._build_slot_json(seal, 0, 1) == {
        "bootkey0": list(range(32)), "boot_flags1": {"key_valid": 1}}


def test_build_slot_json_missing_fingerprint_dies():
    with pytest.raises(SystemExit):
        sb._build_slot_json({"boot_flags1": {}}, 0, 1)


def test_next_free_slot_skips_present_valid_revoked():
    # slot 0 present+valid, slot 2 revoked -> first free is slot 1
    s = {"slots_present": [True, False, False, False], "key_valid": 0b0001, "key_invalid": 0b0100}
    assert sb._next_free_slot(s) == 1
    # everything used -> None (needs a fresh board)
    full = {"slots_present": [True] * 4, "key_valid": 0b1111, "key_invalid": 0}
    assert sb._next_free_slot(full) is None


def test_revoke_leaves_valid_guard():
    # slots 0 & 1 valid, none revoked: revoking 0 leaves slot 1 -> safe (non-zero)
    assert sb._revoke_leaves_valid(0b0011, 0, 0) == 0b0010
    # only slot 0 valid: revoking it leaves nothing -> 0 (would brick)
    assert sb._revoke_leaves_valid(0b0001, 0, 0) == 0
    # slots 0 & 1 valid but slot 1 already revoked: revoking 0 leaves nothing
    assert sb._revoke_leaves_valid(0b0011, 0b0010, 0) == 0


def test_pages_locked():
    p = sb.PAGE_LOCK_BL_RO  # 0x141414 — what `secure-boot lock` writes (LOCK_BL set)
    # LOCK_BL set on either page ⇒ BOOTSEL can no longer write boot keys.
    assert sb.pages_locked({"page1_lock": p, "page2_lock": None}) is True
    assert sb.pages_locked({"page1_lock": None, "page2_lock": p}) is True
    # Unwritten / fully-unlocked pages are not a lock.
    assert sb.pages_locked({"page1_lock": None, "page2_lock": 0}) is False
    # Regression: a benign pre-existing LOCK_NS=1 with LOCK_BL=0 (0x040404) must
    # NOT read as bootloader-locked — masking the whole row would false-positive
    # and wrongly refuse `load-key` on a chip whose non-secure page is read-only.
    assert sb.pages_locked({"page1_lock": 0x040404, "page2_lock": 0x040404}) is False
    assert sb.pages_locked({"page1_lock": 0x040404, "page2_lock": None}) is False
    # LOCK_NS on one page but LOCK_BL on the other ⇒ still locked (LOCK_BL wins).
    assert sb.pages_locked({"page1_lock": 0x040404, "page2_lock": p}) is True


# --- `lock` derives its KEY_INVALID mask from live state (audit run-32) --------

def test_lock_mask_is_a_superset_of_the_current_key_invalid():
    """picotool refuses any OTP write that would clear a bit, so a mask that is not
    a superset aborts the whole lock. Exhaustive over the 256 (valid, invalid)
    pairs."""
    for kv in range(16):
        for ki in range(16):
            m = sb._lock_invalid_mask(kv, ki)
            assert m & ki == ki, f"{m:#x} would clear a fused bit from {ki:#x}"


def test_lock_mask_keeps_the_slot_the_board_actually_boots():
    # Classic slot-0 board: unchanged from the old hard-coded constant.
    assert sb._lock_invalid_mask(0b0001, 0b0000) == 0xE
    # Rotated to slot 1, old slot not yet revoked: the old constant revoked slot 1,
    # the key the board boots on. The derived mask keeps whichever slot is trusted.
    assert sb._lock_invalid_mask(0b0011, 0b0001) == 0b1101
    assert sb._trusted_slots(0b0011, 0b0001) == 0b0010
    # Both slots trusted is ambiguous — cmd_lock refuses rather than guessing.
    assert sb._trusted_slots(0b0011, 0b0000) == 0b0011
