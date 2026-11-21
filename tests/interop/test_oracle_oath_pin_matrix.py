# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OTP-PIN parsing and connection persistence have independent secret storage."""
import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_oath_gates import Peer as GatePeer


def find(data, wanted):
    offset = 0
    while offset + 2 <= len(data):
        tag, length = data[offset:offset + 2]
        offset += 2
        if length & 128:
            width = length & 127
            if width not in (1, 2) or offset + width > len(data):
                return None
            length = int.from_bytes(data[offset:offset + width], "big")
            offset += width
        if offset + length > len(data):
            return None
        value, offset = data[offset:offset + length], offset + length
        if tag == wanted:
            return value
    return None


class Peer(GatePeer):
    emulated = True

    def control(self, action, deadline, observe):
        self.pin_verified, self.validated = False, self.code is None
        if self.defect == "volatile-private-fields":
            self.extras.clear()
        return Reply(b"offline ATR")

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins not in (0xb2, 0xb3, 0xb4):
            return super().transfer(wire, deadline, observe)
        old, new = find(body, 0x80), find(body, 0x81)
        sw = 0x9000
        if ins == 0xb4:
            if not self.validated:
                sw = 0x6982
            elif self.pin is not None:
                sw = 0x6985
            elif old is None:
                sw = 0x6a80
            else:
                self.pin = old[:32] if self.defect == "PIN-byte-truncation" else old
        elif self.pin is None:
            sw = 0x6985
        elif old is None or ins == 0xb3 and new is None:
            sw = 0x6a80
            if self.defect == "malformed-clears-grants":
                self.pin_verified, self.validated = False, False
        elif old != self.pin:
            self.pin_verified, self.validated = False, False
            sw = 0x6982
        elif ins == 0xb3:
            self.pin = new[:32] if self.defect == "PIN-byte-truncation" else new
            if self.defect != "change-keeps-grants":
                self.pin_verified, self.validated = False, False
        else:
            self.pin_verified = True
            self.validated = self.validated or self.code is None
        output = sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("PIN-byte-truncation", "APDU success"),
    ("change-keeps-grants", "successful PIN change drops both"), ("malformed-clears-grants", "APDU success"),
    ("volatile-private-fields", "APDU success")])
def test_OTP_PIN_TLV_binary_values_and_private_connection_persistence(tmp_path, defect, needle):
    trace = Trace(tmp_path / "OTP-PIN-matrix", {})
    peer = Peer(defect)
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, allow_effects=("pin_change", "applet_reset", "config_change", "reboot")))
    oracle.execute(session, ["oath-pin-matrix"])
    trace.finish()
    failures = [row["reason"] for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not peer.records and not peer.extras and peer.pin is None
