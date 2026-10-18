# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Interleaved INIT is consumed explicitly without hiding the owner's result."""
import pytest

from oracle_lib import hid_operations
from oracle_lib.runner import Session
from oracle_lib.trace import Trace
from oracle_lib.transport import Hid
from oracle_lib.transport_cases import reports
from test_oracle_transitions import PresenceReports


class Peer(PresenceReports):
    def write(self, report):
        frame = report[1:]
        cid, command = frame[:4], frame[4] & 127
        if cid == bytes(4) or cid == bytes([255]) * 4 and command != 6:
            self.queue.extend(reports(cid, 0x3f, b"\x0b"))
            return len(report)
        if self.defect == "INIT-during-UP-ignored" and self.owner and command == 6:
            return len(report)
        result = super().write(report)
        if self.defect == "INIT-nonce-corrupt" and command == 6 and self.owner:
            value = bytearray(self.queue.pop())
            value[7] ^= 1
            self.queue.append(bytes(value))
        return result


@pytest.mark.parametrize("defect,needle", [(None, None), ("INIT-during-UP-ignored", None),
    ("INIT-nonce-corrupt", "interleaved INIT nonce")])
def test_pending_INIT_reserved_CIDs_and_owner_recovery(tmp_path, defect, needle):
    trace = Trace(tmp_path / "INIT", {})
    peer = Peer(defect)
    hid = Hid({}, trace.now, peer)
    hid.cid = bytes.fromhex("01020304")
    session = Session(trace, hid=hid, profile="rsk")
    hid_operations.channels(session)
    hid_operations.pending_init(session)
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    assert hid.on_report is None and hid.on_keepalive is None


def test_LOCK_broadcast_INIT_foreign_WINK_CANCEL_refresh_and_owner_release(tmp_path, monkeypatch):
    trace = Trace(tmp_path / "LOCK-interactions", {})
    peer = Peer()
    hid = Hid({}, trace.now, peer)
    hid.cid = b"\x01\x02\x03\x04"
    monkeypatch.setattr(hid_operations, "wait", lambda session, seconds: setattr(peer, "now", peer.now + seconds))
    session = Session(trace, hid=hid, profile="rsk")
    hid_operations.lock_interactions(session)
    trace.finish()
    assert trace.cases[0]["verdict"] == "pass", trace.cases
