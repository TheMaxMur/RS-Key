# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Independent PW1/PW3 retry state and real SIG keys witness reference guards."""
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_catalog import Peer as CatalogPeer
from test_oracle_openpgp_matrix import sdk_type


class Peer(CatalogPeer):
    def factory(self):
        super().factory()
        self.left, self.maximum, self.mode = {0x81: 3, 0x83: 3}, {0x81: 3, 0x83: 3}, 1

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        sw, output = 0x9000, b""
        if ins == 0xca and p2 == 0xc4:
            output = bytes([self.mode, 127, 127, 127, self.left[0x81], 0, self.left[0x83]])
        elif ins == 0xda and p2 == 0xc4:
            if 0x83 not in self.grants:
                sw = 0x6982
            elif len(body) != 1 or body[0] > 1:
                sw = 0x6a80
            else:
                self.mode = body[0]
        elif ins == 0x20:
            if p1 == 255 and body:
                sw = 0x6a80
            elif p1 not in (0, 255) or p2 not in (0x81, 0x82, 0x83):
                sw = 0x6b00
            elif p1 == 255:
                self.grants.discard(p2)
            else:
                reference = 0x83 if p2 == 0x83 else 0x81
                if not body:
                    sw = 0x9000 if p2 in self.grants else 0x63c0 | min(self.left[reference], 15)
                elif not (8 if reference == 0x83 else 6) <= len(body) <= 127:
                    sw = 0x6a80
                    if self.defect == "malformed-revokes-grant":
                        self.grants.discard(p2)
                elif self.left[reference] == 0:
                    sw = 0x6983
                elif body != self.pins[reference]:
                    self.left[reference] -= 1
                    sw = 0x6982 if self.left[reference] else 0x6983
                    if self.defect != "wrong-PW-keeps-grant":
                        self.grants.discard(p2)
                    if self.defect == "PW1-modes-have-separate-retries" and p2 == 0x82:
                        self.left[reference] += 1
                else:
                    self.left[reference] = self.maximum[reference]
                    self.grants.add(p2)
        elif ins == 0x24:
            if p1 or p2 not in (0x81, 0x83):
                sw = 0x6b00
            elif len(body) < len(self.pins[p2]):
                sw = 0x6700
            elif not body.startswith(self.pins[p2]):
                self.left[p2] -= 1
                self.grants.discard(p2)
                sw = 0x6982 if self.left[p2] else 0x6983
            else:
                new = body[len(self.pins[p2]):]
                self.left[p2] = self.maximum[p2]
                self.grants.add(p2)
                if not (6 if p2 == 0x81 else 8) <= len(new) <= 127:
                    sw = 0x6985
                else:
                    self.pins[p2] = new
        else:
            return super().transfer(wire, deadline, observe)
        output += sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


def sdk_with_errors(session):
    from yubikit.core.smartcard import ApduError
    class Sdk(sdk_type(session)):
        def signature(self, ins, p1, p2, message, algorithm):
            digest = hashes.Hash(algorithm)
            digest.update(message)
            reply = session.apdu(codec.apdu(ins, p1, p2, digest.finalize()))
            if reply.status != 0x9000:
                raise ApduError(reply.data[:-2], reply.status)
            raw = reply.data[:-2]
            return utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    return Sdk


@pytest.mark.parametrize("defect,needle", [(None, None), ("malformed-revokes-grant", "own access latch"),
    ("wrong-PW-keeps-grant", "own access latch"), ("PW1-modes-have-separate-retries", "share one counter")])
def test_OpenPGP_reference_modes_lengths_queries_and_wrong_password_state(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-references", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, openpgp_pin="123456", openpgp_admin="12345678",
        allow_effects=("config_change", "pin_attempts", "pin_change")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    oracle.execute(session, ["openpgp-references"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys and peer.left == peer.maximum
