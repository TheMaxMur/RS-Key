# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Actual HID frames schedule other applets beside real ML-DSA operations."""
import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from oracle_lib.transport import Hid
from test_oracle_expanded import apdu_parts
from test_oracle_hid_processing import Reports, QuantumPeer


class ProcessingReports(Reports):
    def write(self, data):
        before = len(self.queue)
        result = super().write(data)
        if len(self.queue) > before and self.command == 0x10 and self.pending[:1] == b"\x02":
            frames = list(self.queue)
            from oracle_lib.transport_cases import reports
            self.queue.clear()
            self.queue.extend(reports(data[1:5], 0x3b, b"\x01"))
            self.queue.extend(frames)
        if self.defect == "no-PROCESSING":
            frames = [frame for frame in self.queue if not (frame[4] == 0xbb and frame[7] == 1)]
            self.queue.clear()
            self.queue.extend(frames)
        return result


class Card:
    layer = "pcsc_apdu"

    def __init__(self, backend, defect):
        self.backend, self.defect = backend, defect
        self.overlapped = 0

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        body = b"\x05\x08\x00" if ins == 0xfd else b"c" * 8 if ins == 0x84 else b""
        if self.backend.stage == 1:
            self.overlapped += 1
            if self.defect == "wrong-other-applet-result":
                body += b"wrong"
            elif self.defect == "PQC-key-lost-during-other-request":
                for record in self.backend.peer.records.values():
                    record["key"] = {-48: mldsa.MLDSA44PrivateKey, -49: mldsa.MLDSA65PrivateKey, -50: mldsa.MLDSA87PrivateKey}[record["alg"]].generate()
        if ins == 0xa4:
            body = codec.tlv(0x79, b"\x05\x08\x00") + codec.tlv(0x71, b"identity")
        output = body + b"\x90\x00"
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, status=0x9000)


@pytest.mark.parametrize("defect,needle", [(None, None), ("wrong-other-applet-result", "actual result during"),
    ("PQC-key-lost-during-other-request", "InvalidSignature")])
def test_all_PQC_algorithms_overlap_each_other_applet_and_keep_both_results(tmp_path, defect, needle):
    trace = Trace(tmp_path / "PQC-overlap", {})
    backend = ProcessingReports()
    backend.peer = QuantumPeer()
    hid = Hid({}, trace.now, backend)
    hid.cid = b"\x01\x02\x03\x04"
    card = Card(backend, defect)
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["cross-processing"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert len(trace.cases) == 18 and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert card.overlapped >= 18


def test_missing_PROCESSING_stage_cannot_be_reported_as_an_overlap(tmp_path):
    trace = Trace(tmp_path / "no-PROCESSING", {})
    backend = ProcessingReports("no-PROCESSING")
    backend.peer = QuantumPeer()
    hid = Hid({}, trace.now, backend)
    hid.cid = b"\x01\x02\x03\x04"
    card = Card(backend, None)
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["cross-processing"])
    trace.finish()
    assert len(trace.cases) == 18 and all(row["applicability"] == "excluded_by_mode" for row in trace.cases), trace.cases
    assert not card.overlapped
