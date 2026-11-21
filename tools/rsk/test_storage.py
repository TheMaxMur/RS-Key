# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Storage commands refuse ambiguous state and emit the attended rescue protocol."""
from types import SimpleNamespace

import pytest

from rsk import storage


class Connection:
    def __init__(self):
        self.disconnected = False

    def disconnect(self):
        self.disconnected = True


def wire(monkeypatch, state=b"\x02\x00", result=(b"", 0x90, 0)):
    conn = Connection()
    seen = []
    monkeypatch.setattr(storage.ccid, "connect", lambda **kwargs: (seen.append(kwargs), conn)[1])
    monkeypatch.setattr(storage.ccid, "select", lambda _, aid: (b"", 0x90, 0))

    def transmit(_, data):
        seen.append(bytes(data))
        return (state, 0x90, 0) if bytes(data) == storage.READ_STATE else result

    monkeypatch.setattr(storage.ccid, "transmit", transmit)
    return conn, seen


@pytest.mark.parametrize("action,p1,magic", [
    ("initialize", 0, b"INITV2"),
    ("import-legacy", 1, b"IMPORTV2"),
])
def test_storage_action_emits_exact_command_and_disconnects(monkeypatch, action, p1, magic):
    conn, seen = wire(monkeypatch)
    storage.run(SimpleNamespace(action=action))
    assert seen == [{"exclusive": True}, storage.READ_STATE, bytes([0x80, 0x20, p1, 0, len(magic)]) + magic]
    assert conn.disconnected


@pytest.mark.parametrize("state", [b"", b"\x02", b"\x03\x00", b"\x02\x02", b"\x02\x01", b"\x02\x00\x00"])
def test_invalid_or_active_state_cannot_emit_an_action(monkeypatch, state):
    conn, seen = wire(monkeypatch, state)
    with pytest.raises(SystemExit):
        storage.run(SimpleNamespace(action="initialize"))
    assert seen == [{"exclusive": True}, storage.READ_STATE]
    assert conn.disconnected


def test_declined_operation_does_not_claim_completion(monkeypatch):
    conn, _ = wire(monkeypatch, result=(b"", 0x69, 0x85))
    with pytest.raises(SystemExit, match="declined"):
        storage.run(SimpleNamespace(action="import-legacy"))
    assert conn.disconnected
