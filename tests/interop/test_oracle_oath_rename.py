# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Rename grammar is checked against independent names, secret fields and moving factors."""
import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_oath_pin_matrix import Peer as PinPeer


def first_names(body):
    result, position = [], 0
    while position + 2 <= len(body) and len(result) < 2:
        tag, length = body[position:position + 2]
        position += 2
        if tag == 0x78:
            continue
        if length in (0x81, 0x82):
            width = length - 0x80
            if position + width > len(body):
                break
            length = int.from_bytes(body[position:position + width], "big")
            position += width
        if position + length > len(body):
            break
        value, position = body[position:position + length], position + length
        if tag == 0x71:
            result.append(value)
    return result


class Peer(PinPeer):
    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins != 5:
            return super().transfer(wire, deadline, observe)
        sw, names = 0x9000, first_names(body)
        if not self.validated:
            sw = 0x6982
        elif body[:1] != b"\x71" or len(names) != 2 or not 1 <= len(names[1]) <= 64:
            sw = 0x6a80
        elif names[1] in self.records or names[0] not in self.records:
            sw = 0x6984
        else:
            old, new = names
            self.records[new], self.extras[new] = self.records.pop(old), self.extras.pop(old)
            if self.defect == "rename-resets-counter":
                self.records[new]["counter"] = 0
            if self.defect == "rename-drops-password":
                self.extras[new].pop(0x84, None)
        result = sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", result)
        return Reply(result, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("rename-resets-counter", "RENAME preserves an already-used HOTP"),
    ("rename-drops-password", "RENAME preserves every private field byte")])
def test_rename_TLV_byte_boundaries_and_existing_private_state(tmp_path, defect, needle):
    trace = Trace(tmp_path / "OATH-rename", {})
    peer = Peer(defect)
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, allow_effects=("pin_change", "applet_reset", "config_change")))
    oracle.execute(session, ["oath-rename"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not peer.records and not peer.extras and peer.pin is None
