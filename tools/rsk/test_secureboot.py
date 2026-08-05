# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unit tests for rsk.secureboot (no device, no picotool).

Run from tools/:  python -m pytest rsk/test_secureboot.py
The slot-row math, json re-targeting, free-slot picking, and the revoke
"don't orphan the last key" guard are the brick-risk decisions — pin them here.

The second half drives the four stage commands against a synthetic OTP state.
Pinning only the helpers left every guard deletable with the suite green: the
three `die("refusing: …")` brick guards and all four typed confirmations could be
removed without a red test (audit run-34 #9). A guard is only guarded once
something asserts that the command reaches it and writes nothing past it.
"""
import types

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


# --- the stage commands, driven against a synthetic OTP state -----------------

def _state(**kw):
    """A read_state() reply. Defaults describe a board mid-ritual: one key
    provisioned and valid, hardened, enforcement not yet enabled, pages open."""
    valid = kw.pop("key_valid", 0b0001)
    s = {"secure_boot_enable": False, "debug_disable": True, "glitch_enable": True,
         "glitch_sens": 3, "key_valid": valid, "key_invalid": 0,
         "slots_present": [bool(valid & (1 << n)) for n in range(sb.N_KEY_SLOTS)],
         "page1_lock": None, "page2_lock": None,
         "rollback_required": False, "boot_version": 0}
    s.update(kw)
    s.setdefault("bootkey0_present", s["slots_present"][0])
    return s


def _stage(monkeypatch, state, typed=None, after=None):
    """Run a stage command against `state`, recording every fuse write. `after` is
    what the post-write verify re-read sees. `typed` is what the operator enters at
    the confirmation — `confirm` itself runs for real, because stubbing it is what
    hid the missing coverage in the first place."""
    writes = []
    reads = iter([state, after if after is not None else state])
    monkeypatch.setattr(sb, "require_bootsel", lambda: None)
    monkeypatch.setattr(sb, "read_state", lambda: next(reads, state))
    monkeypatch.setattr(sb, "print_state", lambda s: None)
    monkeypatch.setattr(sb, "_set", lambda a, dry: writes.append(tuple(a)))
    monkeypatch.setattr("builtins.input", lambda prompt="": typed)
    return writes


def _args(**kw):
    return types.SimpleNamespace(**{"dry_run": False, **kw})


def test_revoke_refuses_to_orphan_the_last_valid_key(monkeypatch, capsys):
    # Only slot 0 is valid: revoking it leaves the board unable to validate any
    # image. The refusal must land before the typed prompt, not after it.
    writes = _stage(monkeypatch, _state(key_valid=0b0001), typed="REVOKE-BOOTKEY")
    with pytest.raises(SystemExit):
        sb.cmd_revoke(_args(slot=0))
    assert writes == []
    assert "would leave NO valid" in capsys.readouterr().err


def test_revoke_writes_nothing_when_the_confirmation_is_wrong(monkeypatch):
    writes = _stage(monkeypatch, _state(key_valid=0b0011), typed="yes")
    with pytest.raises(SystemExit):
        sb.cmd_revoke(_args(slot=0))
    assert writes == []


def test_revoke_burns_key_invalid_once_confirmed(monkeypatch):
    writes = _stage(monkeypatch, _state(key_valid=0b0011), typed="REVOKE-BOOTKEY",
                    after=_state(key_valid=0b0011, key_invalid=0b0001))
    sb.cmd_revoke(_args(slot=0))
    assert writes == [("set", "OTP_DATA_BOOT_FLAGS1.KEY_INVALID", "0x1")]


def test_harden_writes_nothing_when_the_confirmation_is_wrong(monkeypatch):
    writes = _stage(monkeypatch, _state(), typed="HARDEN")
    with pytest.raises(SystemExit):
        sb.cmd_harden(_args())
    assert writes == []


def test_enable_refuses_when_no_slot_is_trusted(monkeypatch, capsys):
    # Enforcement with every slot revoked bricks the board — RP2350's KEY_VALID
    # doc, and audit run-32's finding. A fingerprint alone is not enough.
    writes = _stage(monkeypatch, _state(key_valid=0b0001, key_invalid=0b0001),
                    typed="ENABLE-SECURE-BOOT")
    with pytest.raises(SystemExit):
        sb.cmd_enable(_args())
    assert writes == []
    assert "no slot is both KEY_VALID and non-revoked" in capsys.readouterr().err


def test_enable_writes_nothing_when_the_confirmation_is_wrong(monkeypatch):
    writes = _stage(monkeypatch, _state(), typed="ENABLE")
    with pytest.raises(SystemExit):
        sb.cmd_enable(_args())
    assert writes == []


def test_lock_refuses_when_no_slot_is_trusted(monkeypatch, capsys):
    writes = _stage(monkeypatch, _state(secure_boot_enable=True, key_valid=0b0001,
                                        key_invalid=0b0001), typed="LOCK-SECURE-BOOT")
    with pytest.raises(SystemExit):
        sb.cmd_lock(_args())
    assert writes == []
    assert "would" in capsys.readouterr().err


def test_lock_refuses_while_two_slots_are_trusted(monkeypatch, capsys):
    # Ambiguous: `lock` cannot tell which key the board boots on, so it must send
    # the operator to `revoke` (which carries the last-valid-key guard) instead.
    writes = _stage(monkeypatch, _state(secure_boot_enable=True, key_valid=0b0011),
                    typed="LOCK-SECURE-BOOT")
    with pytest.raises(SystemExit):
        sb.cmd_lock(_args())
    assert writes == []
    assert "both trusted" in capsys.readouterr().err


def test_lock_writes_nothing_when_the_confirmation_is_wrong(monkeypatch):
    writes = _stage(monkeypatch, _state(secure_boot_enable=True), typed="LOCK")
    with pytest.raises(SystemExit):
        sb.cmd_lock(_args())
    assert writes == []


def test_lock_burns_the_derived_mask_and_both_page_locks(monkeypatch):
    writes = _stage(
        monkeypatch, _state(secure_boot_enable=True, key_valid=0b0011, key_invalid=0b0001),
        typed="LOCK-SECURE-BOOT",
        after=_state(secure_boot_enable=True, key_valid=0b0011, key_invalid=0b1101))
    sb.cmd_lock(_args())
    assert writes == [
        ("set", "OTP_DATA_BOOT_FLAGS1.KEY_INVALID", "0xd"),
        ("set", "-r", "OTP_DATA_PAGE1_LOCK1", f"{sb.PAGE_LOCK_BL_RO:#x}"),
        ("set", "-r", "OTP_DATA_PAGE2_LOCK1", f"{sb.PAGE_LOCK_BL_RO:#x}"),
    ]
