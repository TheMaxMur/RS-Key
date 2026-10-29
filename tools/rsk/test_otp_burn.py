# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Provisioning must verify its own bytes and hand sealing to firmware."""
import types
from pathlib import Path

import pytest

from rsk import otp


class Bootsel:
    def __init__(self, corrupt=False):
        self.rows = {}
        self.calls = []
        self.corrupt = corrupt

    def __call__(self, *args, check=True):
        self.calls.append(args)
        if args[:2] == ("otp", "load"):
            row = int(args[args.index("-s") + 1], 0)
            blob = Path(args[-1]).read_bytes()
            size = 2 if "-e" in args else 4
            for offset in range(0, len(blob), size):
                self.rows[row + offset // size] = int.from_bytes(blob[offset:offset + size], "little")
            if self.corrupt is True or self.corrupt == "chaff" and "-r" in args:
                self.rows[row] ^= 1
            return types.SimpleNamespace(returncode=0, stdout="Mismatch", stderr="")
        if args[:2] == ("otp", "get"):
            row = int(args[-1], 0)
            return types.SimpleNamespace(returncode=0, stdout=f"VALUE 0x{self.rows.get(row, 0):06x}", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")


def drive(monkeypatch, boot, dry_run=False):
    monkeypatch.setattr(otp, "picotool", boot)
    monkeypatch.setattr(otp, "confirm", lambda token: None)
    otp.burn(types.SimpleNamespace(dry_run=dry_run))


def test_burn_reads_back_keys_and_chaff_then_reboots_without_host_lock(monkeypatch):
    boot = Bootsel()
    drive(monkeypatch, boot)
    assert not any(c[:2] == ("otp", "set") for c in boot.calls)
    assert boot.calls[-1] == ("reboot", "-a")
    for row in (otp.DEVK_ROW, otp.MKEK_ROW):
        assert ("otp", "get", "-e", "-n", hex(row)) in boot.calls


def test_zero_exit_with_mismatched_bytes_never_advances_provisioning(monkeypatch, capsys):
    boot = Bootsel(corrupt=True)
    with pytest.raises(SystemExit):
        drive(monkeypatch, boot)
    assert len([c for c in boot.calls if c[:2] == ("otp", "load")]) == 1
    assert not any(c[0] == "reboot" or c[:2] == ("otp", "set") for c in boot.calls)
    assert "written + verified" not in capsys.readouterr().out


def test_dry_run_neither_writes_nor_reboots(monkeypatch):
    boot = Bootsel()
    drive(monkeypatch, boot, dry_run=True)
    assert all(c[0] == "info" or c[:2] == ("otp", "get") for c in boot.calls)


def test_chaff_mismatch_stops_before_reboot(monkeypatch):
    boot = Bootsel(corrupt="chaff")
    with pytest.raises(SystemExit):
        drive(monkeypatch, boot)
    assert len([c for c in boot.calls if c[:2] == ("otp", "load")]) == 3
    assert not any(c[0] == "reboot" for c in boot.calls)


def test_preflight_never_prints_a_provisioned_key_word(monkeypatch, capsys):
    boot = Bootsel()
    boot.rows[otp.DEVK_ROW] = 0x123456
    with pytest.raises(SystemExit):
        drive(monkeypatch, boot)
    captured = capsys.readouterr()
    assert "123456" not in captured.out + captured.err
    assert not any(c[:2] == ("otp", "load") or c[0] == "reboot" for c in boot.calls)
