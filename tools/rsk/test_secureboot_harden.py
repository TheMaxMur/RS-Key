# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Exercise hardening through the commands, with interrupted OTP writes."""
from types import SimpleNamespace

import pytest

from rsk import secureboot as sb


@pytest.fixture
def otp(monkeypatch):
    rows = {sb.BOOTKEY0_0_ROW: 1, **{sb.BOOT_FLAGS1_ROW + i: 1 for i in range(3)}}
    writes = []
    monkeypatch.setattr(sb, "require_bootsel", lambda: None)
    monkeypatch.setattr(sb, "_raw", lambda row: rows.get(row, 0))
    monkeypatch.setattr("builtins.input", lambda prompt: "HARDEN-SECURE-BOOT")

    def write(args, dry):
        if dry:
            return
        assert args[:2] == ["set", "-r"]
        row, value = int(args[2], 0), int(args[3], 0)
        assert value | rows.get(row, 0) == value, "attempted to clear OTP bits"
        writes.append((row, value))
        rows[row] = value

    monkeypatch.setattr(sb, "_set", write)
    return rows, writes


def test_harden_burns_both_debug_disables_and_preserves_other_bits(otp):
    rows, writes = otp
    for i in range(8):
        rows[sb.CRIT1_ROW + i] = 1 << 3
    sb.cmd_harden(SimpleNamespace(dry_run=False))
    assert len(writes) == 8
    assert all(rows[sb.CRIT1_ROW + i] == 0x7E for i in range(8))
    state = sb.read_state()
    assert state["debug_disable"] and state["secure_debug_disable"]
    assert not state["secure_boot_enable"]
    sb.cmd_harden(SimpleNamespace(dry_run=False))
    assert len(writes) == 8, "completed rows must not be burned again"


def test_harden_preserves_each_rows_unrelated_bits_without_replicating_them(otp):
    rows, _ = otp
    rows[sb.CRIT1_ROW] = 1
    rows[sb.CRIT1_ROW + 1] = 8
    sb.cmd_harden(SimpleNamespace(dry_run=False))
    assert rows[sb.CRIT1_ROW] == 0x77
    assert rows[sb.CRIT1_ROW + 1] == 0x7E
    assert all(rows[sb.CRIT1_ROW + i] == 0x76 for i in range(2, 8))
    assert not sb.read_state()["secure_boot_enable"]


def test_harden_is_noop_when_complete_even_after_page_lock(otp):
    rows, writes = otp
    for i in range(8):
        rows[sb.CRIT1_ROW + i] = 0x76
    rows[sb.PAGE1_LOCK1_ROW] = sb.PAGE_LOCK_BL_RO
    sb.cmd_harden(SimpleNamespace(dry_run=False))
    assert writes == []


def test_harden_can_complete_while_page_two_is_locked(otp):
    rows, _ = otp
    rows[sb.PAGE2_LOCK1_ROW] = sb.PAGE_LOCK_BL_RO
    sb.cmd_harden(SimpleNamespace(dry_run=False))
    assert sb.read_state()["harden_complete"]


def test_harden_can_resume_after_single_page_lock_copy(otp):
    rows, _ = otp
    rows[sb.PAGE1_LOCK1_ROW] = 0x10
    sb.cmd_harden(SimpleNamespace(dry_run=False))
    assert sb.read_state()["harden_complete"]


def test_lock_uses_majority_key_flags(otp, capsys):
    rows, _ = otp
    for i in range(8):
        rows[sb.CRIT1_ROW + i] = 0x77
    rows[sb.BOOT_FLAGS1_ROW] = 0x001
    rows[sb.BOOT_FLAGS1_ROW + 1] = rows[sb.BOOT_FLAGS1_ROW + 2] = 0x102
    sb.cmd_lock(SimpleNamespace(dry_run=True))
    assert "revoke every slot but 1" in capsys.readouterr().out


@pytest.mark.parametrize("cut", range(8))
def test_harden_resumes_after_each_interrupted_row(otp, monkeypatch, cut):
    rows, writes = otp
    real_write = sb._set

    def interrupted(args, dry):
        if len(writes) == cut:
            raise OSError("power cut")
        real_write(args, dry)

    monkeypatch.setattr(sb, "_set", interrupted)
    with pytest.raises(OSError, match="power cut"):
        sb.cmd_harden(SimpleNamespace(dry_run=False))
    monkeypatch.setattr(sb, "_set", real_write)
    sb.cmd_harden(SimpleNamespace(dry_run=False))
    assert all(rows[sb.CRIT1_ROW + i] == 0x76 for i in range(8))
    assert len(writes) == 8


@pytest.mark.parametrize("missing", [0x02, 0x04, 0x10, 0x20, 0x40])
def test_harden_rejects_successful_command_with_missing_bit(otp, monkeypatch, missing):
    rows, _ = otp

    def torn(args, dry):
        row, value = int(args[2], 0), int(args[3], 0)
        rows[row] = value & ~missing

    monkeypatch.setattr(sb, "_set", torn)
    with pytest.raises(SystemExit):
        sb.cmd_harden(SimpleNamespace(dry_run=False))


def test_harden_rejects_only_last_copy_torn_despite_effective_flags(otp, monkeypatch):
    rows, _ = otp
    real_write = sb._set

    def torn(args, dry):
        real_write(args, dry)
        if int(args[2], 0) == sb.CRIT1_ROW + 7:
            rows[sb.CRIT1_ROW + 7] &= ~0x02

    monkeypatch.setattr(sb, "_set", torn)
    with pytest.raises(SystemExit):
        sb.cmd_harden(SimpleNamespace(dry_run=False))
    state = sb.read_state()
    assert state["debug_disable"] and state["secure_debug_disable"]
    assert not state["harden_complete"]


@pytest.mark.parametrize("missing", [0x02, 0x04])
def test_lock_refuses_missing_debug_flag(otp, missing, capsys):
    rows, writes = otp
    for i in range(8):
        rows[sb.CRIT1_ROW + i] = 0x77 & ~missing
    with pytest.raises(SystemExit):
        sb.cmd_lock(SimpleNamespace(dry_run=False))
    assert writes == []
    assert "harden" in capsys.readouterr().err


def test_status_does_not_call_partial_redundancy_locked(otp, capsys):
    rows, _ = otp
    for i in range(8):
        rows[sb.CRIT1_ROW + i] = 0x77
    rows[sb.CRIT1_ROW + 7] &= ~0x02
    rows[sb.PAGE1_LOCK1_ROW] = sb.PAGE_LOCK_BL_RO
    rows[sb.PAGE2_LOCK1_ROW] = sb.PAGE_LOCK_BL_RO
    sb.cmd_status(None)
    output = capsys.readouterr().out
    assert "SECURE_DEBUG_DISABLE" in output
    assert "LOCKED" not in output


@pytest.mark.parametrize("count", [0, 1, 2, 3, 4, 7])
def test_status_decodes_three_of_eight_without_trusting_first_row(otp, count):
    rows, _ = otp
    for i in range(1, count + 1):
        rows[sb.CRIT1_ROW + i] = 0x77
    state = sb.read_state()
    assert state["secure_debug_disable"] == (count >= 3)
    assert state["debug_disable"] == (count >= 3)
    assert state["secure_boot_enable"] == (count >= 3)
    assert not state["harden_complete"]


@pytest.mark.parametrize("lock", [0x001010, sb.PAGE_LOCK_BL_RO])
def test_harden_refuses_locked_page_before_prompt(otp, monkeypatch, lock):
    rows, writes = otp
    rows[sb.PAGE1_LOCK1_ROW] = lock

    def unexpected(prompt):
        pytest.fail("prompted for an impossible BOOTSEL write")

    monkeypatch.setattr("builtins.input", unexpected)
    with pytest.raises(SystemExit):
        sb.cmd_harden(SimpleNamespace(dry_run=False))
    assert writes == []


@pytest.mark.parametrize("page", [sb.PAGE1_LOCK1_ROW, sb.PAGE2_LOCK1_ROW])
@pytest.mark.parametrize("lock", [0, 0x14, 0x1414, 0x101010])
def test_status_requires_complete_page_locks(otp, capsys, page, lock):
    rows, _ = otp
    rows.update({sb.CRIT1_ROW + i: 0x77 for i in range(8)})
    rows.update({sb.BOOT_FLAGS1_ROW + i: 0xE01 for i in range(3)})
    rows[sb.PAGE1_LOCK1_ROW] = rows[sb.PAGE2_LOCK1_ROW] = sb.PAGE_LOCK_BL_RO
    sb.cmd_status(None)
    assert "LOCKED" in capsys.readouterr().out
    rows[page] = lock
    sb.cmd_status(None)
    assert "LOCKED" not in capsys.readouterr().out
