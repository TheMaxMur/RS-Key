# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Numeric vendor configuration is checked against separate PHY and live state."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_config_matrix import Peer as PolicyPeer
from test_oracle_rescue_presence import Card

IDS = {0x6fcb19b0cbe3acfa: (0, 4), 0x7b392a394de9f948: (4, 1),
       0x76a85945985d02fd: (5, 1), 0x269f3b09eceb805f: (6, 2)}


class Hid(PolicyPeer):
    def __init__(self, card, defect):
        super().__init__()
        self.card, self.fault = card, defect
        self.effective = {4: 17, 12: 3, 8: 30}

    def configuration(self, fields):
        if fields[1] != 255:
            return super().configuration(fields)
        payload = b"\xff" * 32 + b"\x0d\xff" + codec.encode(fields[2])
        if fields[4] != self.mac(payload) or not self.permissions & 32:
            return 0x33
        if self.card.management.lock is not None and self.fault != "lock-bypass":
            return 0x30
        identifier, integer = fields[2][1], fields[2].get(3, 0)
        tag, size = IDS[identifier]
        if self.fault == "rejects-overflow" and integer >= 1 << (size * 8):
            return 2
        self.card.fields[tag] = (integer & (2**(size * 8) - 1)).to_bytes(size, "big")
        if self.fault == "applies-staged-GPIO" and tag == 4:
            self.effective[4] = integer & 255
        return 0

    def transfer(self, command, wire, deadline, observe):
        if wire[0] != 0x41:
            return super().transfer(command, wire, deadline, observe)
        fields = codec.decode(wire[1:])
        if fields[1] == 13:
            body = b"".join(bytes([tag, len(value)]) + value for tag, value in sorted(self.card.fields.items()))
            result = {1: body, 2: self.effective}
        elif fields[1] == 15:
            values = [*IDS, 0x03e43f56b34285e2, 0x1831a40f04a25ed9, 0x0e6841934e719be7]
            result = {1: values[:-1] if self.fault == "missing-catalog-ID" else values}
        else:
            raise AssertionError("unprofiled numeric CONFIG control")
        output = b"\x00" + codec.encode(result)
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, status=0)


@pytest.mark.parametrize("defect,needle", [(None, None), ("lock-bypass", "lock precedes identical"),
    ("rejects-overflow", "CTAP success"), ("applies-staged-GPIO", "does not change boot-effective"),
    ("missing-catalog-ID", "every defined ID exactly once")])
def test_all_numeric_vendor_IDs_truncation_default_replay_lock_and_effective_state(tmp_path, defect, needle):
    card = Card(None)
    original = dict(card.fields)
    trace = Trace(tmp_path / "vendor-config-IDs", {})
    session = Session(trace, card=card, hid=Hid(card, defect), profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", allow_effects=("config_change",)))
    oracle.execute(session, ["config-vendor"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert card.fields == original and card.management.lock is None
