# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""`rsk lock enable` — the typed confirmation and the --key-out file mode.

Run from tools/:  python -m pytest rsk/test_lock.py
Engaging the lock erases the plaintext seed, and losing the lock key leaves a
factory reset as the only way out, so the prompt is the last thing standing
between a mistyped command and a destroyed identity. It has its own inline copy
of the typed check rather than `common.confirm`, so `test_common.py` does not
reach it; deleting it left the suite green (audit run-34 #9).

`--key-out` is the other half: the file it writes IS the lock key, so it is
created 0600 with O_EXCL rather than chmod-ed after the fact.
"""
import os
import stat
import sys
import types

# rsk.ctaphid sys.exits at import without hidapi; nothing here touches a device.
sys.modules.setdefault("hid", types.ModuleType("hid"))

import pytest  # noqa: E402

from rsk import lock  # noqa: E402

STATE = {"sealed": False, "has_seed": True, "locked": False, "unlocked": False}
LOCKED = {"sealed": False, "has_seed": False, "locked": True, "unlocked": False}


def _args(**kw):
    base = {"scheme": "hex", "threshold": 2, "shares": 3, "key_out": None, "pin": "1234"}
    return types.SimpleNamespace(**{**base, **kw})


def _drive(monkeypatch, typed, state=STATE, after=LOCKED):
    """Stub every device call `cmd_enable` makes; returns the AUT_* calls it made."""
    calls = []
    replies = iter([state, after])
    monkeypatch.setattr(lock, "connect_fido", lambda exclusive=False: (object(), b"cid"))
    monkeypatch.setattr(lock, "device_has_pin", lambda dev, cid: True)
    monkeypatch.setattr(lock, "_state", lambda dev, cid: next(replies, after))
    monkeypatch.setattr(lock, "mse_handshake", lambda dev, cid: (bytes(32), b"aad"))
    monkeypatch.setattr(lock, "_config_vendor",
                        lambda dev, cid, pin, vid, param=None: calls.append(vid) or 0)
    monkeypatch.setattr("builtins.input", lambda prompt="": typed)
    return calls


@pytest.mark.parametrize("typed", ["", "y", "yes", "lock-seed", "LOCK", "LOCK-SEED!"])
def test_enable_engages_nothing_without_the_exact_phrase(monkeypatch, typed, capsys):
    calls = _drive(monkeypatch, typed)
    with pytest.raises(SystemExit):
        lock.cmd_enable(_args())
    assert calls == []
    assert "aborted" in capsys.readouterr().err


def test_enable_engages_the_lock_once_confirmed(monkeypatch):
    calls = _drive(monkeypatch, "LOCK-SEED")
    lock.cmd_enable(_args())
    assert calls == [lock.AUT_ENABLE]


def test_enable_refuses_a_device_that_is_already_locked(monkeypatch):
    calls = _drive(monkeypatch, "LOCK-SEED", state=LOCKED)
    with pytest.raises(SystemExit):
        lock.cmd_enable(_args())
    assert calls == []


def test_key_out_is_created_private(monkeypatch, tmp_path):
    out = tmp_path / "lock.key"
    _drive(monkeypatch, "LOCK-SEED")
    lock.cmd_enable(_args(key_out=str(out)))
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert len(bytes.fromhex(out.read_text().strip())) == 32


def test_key_out_refuses_an_existing_path(monkeypatch, tmp_path, capsys):
    # O_EXCL: a pre-existing file — or a symlink planted at that path — must not be
    # followed or overwritten, and the refusal must come before the lock engages.
    out = tmp_path / "lock.key"
    out.write_text("previous\n")
    calls = _drive(monkeypatch, "LOCK-SEED")
    with pytest.raises(SystemExit):
        lock.cmd_enable(_args(key_out=str(out)))
    assert out.read_text() == "previous\n"
    assert calls == []
    assert "cannot write --key-out" in capsys.readouterr().err


def test_key_out_does_not_follow_a_symlink(monkeypatch, tmp_path):
    target = tmp_path / "victim"
    target.write_text("keep me\n")
    link = tmp_path / "lock.key"
    os.symlink(target, link)
    _drive(monkeypatch, "LOCK-SEED")
    with pytest.raises(SystemExit):
        lock.cmd_enable(_args(key_out=str(link)))
    assert target.read_text() == "keep me\n"
