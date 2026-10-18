# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Code/PIN bypasses and secret leakage after reset fail independent witnesses."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_oath_access import Peer as CodePeer
from test_oracle_oath_semantics import fields


class Peer(CodePeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.pin, self.pin_verified, self.extras = None, False, {}

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        output, sw = b"", 0x9000
        if ins == 0xA4 and p1 == 4:
            self.pin_verified = False
            return super().transfer(wire, deadline, observe)
        if ins == 4:
            self.records.clear()
            self.pin, self.pin_verified, self.code, self.validated = None, False, None, True
            if self.defect != "reset-leaves-secret-fields":
                self.extras.clear()
        elif ins == 0xB4:
            if self.pin is not None:
                sw = 0x6985
            else:
                self.pin = fields(data)[0x80]
        elif ins == 0xB2:
            if self.pin is None:
                sw = 0x6985
            elif fields(data)[0x80] != self.pin:
                sw = 0x6982
            else:
                self.pin_verified = True
                self.validated = self.validated or self.code is None or self.defect == "PIN-bypasses-code"
        elif ins in (0xB1, 0xB5):
            parsed = fields(data)
            name = parsed[0x71]
            if not self.validated or self.pin is not None and not self.pin_verified and self.defect != "code-bypasses-PIN":
                sw = 0x6982
            elif ins == 0xB5:
                if name not in self.extras:
                    sw = 0x6984
                else:
                    output = codec.tlv(0x71, name) + b"".join(codec.tlv(tag, value) for tag, value in self.extras[name].items())
            elif name not in self.records:
                sw = 0x6984
            else:
                import hmac
                item = next(iter(self.records.values()))
                digest = hmac.digest(item["secret"], item["counter"].to_bytes(8, "big"), item["hash"])
                offset = digest[-1] & 15
                expected = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % (10 ** item["digits"])
                if parsed[0x75] != expected.to_bytes(4, "big"):
                    sw = 0x6A80
        elif ins == 5:
            values = codec.parse_tlv(data)
            old, new = values[0][1], values[1][1]
            if new in self.records or old not in self.records:
                sw = 0x6984
            elif len(self.records) == 255 and self.defect == "full-rename-needs-space":
                sw = 0x6A84
            else:
                self.records[new] = self.records.pop(old)
                self.extras[new] = self.extras.pop(old)
        elif ins == 1:
            parsed = fields(data)
            name = parsed[0x71]
            if name not in self.records and len(self.records) == 255:
                sw = 0x6A84
            else:
                reply = super().transfer(wire, deadline, observe)
                if reply.status == 0x9000:
                    self.extras[name] = {tag: value for tag, value in parsed.items() if tag in (0x83, 0x84, 0x85)}
                return reply
        else:
            return super().transfer(wire, deadline, observe)
        observe("tx", wire)
        output += sw.to_bytes(2, "big")
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("PIN-bypasses-code", "LIST enforces the access code independently"),
    ("code-bypasses-PIN", "secret record operation requires both"), ("reset-leaves-secret-fields", "reset removes every private record"),
    ("full-rename-needs-space", "APDU success")])
def test_OTP_PIN_access_code_reset_and_full_store_matrix(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "OATH-gates", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        allow_effects=("config_change", "pin_change", "applet_reset", "capacity")))
    oracle.execute(session, ["oath-gates"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for name, reason in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        assert not peer.records and peer.code is None and peer.pin is None
