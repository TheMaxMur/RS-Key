# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Blob retirement faults are checked through authenticated fragment exchanges."""
import hashlib

import pytest

import oracle
from oracle_lib import blob_matrix, codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_fido_states import CtapPeer


class Peer(CtapPeer):
    def __init__(self, defect=None):
        super().__init__()
        self.blob_defect, self.elapsed = defect, 0

    def blobs(self, fields):
        if 3 not in fields or fields[3] == (1 << 64) - 1 or (1 in fields) == (2 in fields):
            return 2, {}
        if 1 in fields:
            if any(key in fields for key in (4, 5, 6)):
                return 2, {}
            if fields[1] > 512:
                return 3, {}
            if fields[3] > len(self.blob):
                return 2, {}
            return 0, {1: self.blob[fields[3]:fields[3] + fields[1]]}
        data, offset = fields[2], fields[3]
        if len(data) > 512:
            return 3, {}
        if offset == 0:
            total = fields.get(4, 0)
            if total > 1024:
                return 0x3E, {}
            if total < 17:
                return 2, {}
        elif 4 in fields:
            return 2, {}
        elif offset != len(self.staging):
            return 4, {}
        else:
            total = self.total
        payload = b"\xff" * 32 + b"\x0c\x00" + offset.to_bytes(4, "little") + hashlib.sha256(data).digest()
        if fields.get(5) != self.mac(payload) or not self.permissions & 16:
            return 0x33, {}
        if offset + len(data) > total:
            return 2, {}
        if offset == 0:
            self.staging, self.total = b"", total
        self.staging += data
        if self.blob_defect == "partial-commit":
            self.blob = self.staging
        if len(self.staging) == self.total:
            if hashlib.sha256(self.staging[:-16]).digest()[:16] != self.staging[-16:]:
                return 0x3D, {}
            self.blob = self.staging
            if self.blob_defect != "replay-completed":
                self.staging, self.total = b"", 0
        return 0, {}

    def transfer(self, command, wire, deadline, observe):
        if wire[0] != 12 and self.blob_defect != "unrelated-command-keeps-stage":
            self.staging, self.total = b"", 0
        if self.elapsed > 30 and self.blob_defect != "expiry-keeps-stage":
            self.staging, self.total, self.elapsed = b"", 0, 0
        if wire[0] == 4:
            output = b"\x00" + codec.encode({1: ["FIDO_2_3"], 4: {"largeBlobs": True, "clientPin": True, "pinUvAuthToken": True},
                5: 576, 6: [1, 2], 11: 1024})
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,expected", [(None, None), ("partial-commit", "only complete valid array becomes visible"),
    ("unrelated-command-keeps-stage", "fragment sequence outcome"), ("expiry-keeps-stage", "fragment sequence outcome"),
    ("replay-completed", "completed accumulator cannot be replayed")])
def test_blob_matrix_preserves_committed_array_and_retires_sequences(tmp_path, monkeypatch, defect, expected):
    peer = Peer(defect)
    def advance(session, seconds):
        peer.elapsed += seconds
        session.trace.emit("interaction", action="synthetic_wait", requested_seconds=seconds)
    monkeypatch.setattr(blob_matrix, "wait", advance)
    trace = Trace(tmp_path / "blob-matrix", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, pin="fixture-PIN", timeout=40))
    oracle.execute(session, ["blob-matrix"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures, [(row["scenario_id"], row["reason"]) for row in failures]
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert peer.blob == peer.original
