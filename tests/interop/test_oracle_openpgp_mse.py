# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Different real DEC/AUT keys expose wrong MSE routing and policy ownership."""
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

import oracle
from oracle_lib import codec, openpgp_mse
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_catalog import Peer as CatalogPeer
from test_oracle_openpgp_matrix import sdk_type


class Peer(CatalogPeer):
    presence = True

    def factory(self):
        super().factory()
        self.mapping = {0xa4: 3, 0xb8: 2}

    def control(self, action, deadline, observe):
        self.mapping = {0xa4: 3, 0xb8: 2}
        return super().control(action, deadline, observe)

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins == 0xa4:
            previous = self.selection
            result = super().transfer(wire, deadline, observe)
            if self.selection != previous or self.defect == "reselect-clears-MSE":
                self.mapping = {0xa4: 3, 0xb8: 2}
            return result
        sw, output = 0x9000, b""
        if ins == 0x22:
            if p1 != 0x41 or p2 not in (0xa4, 0xb8):
                sw = 0x6b00
            elif len(body) < 3 or body[:2] != b"\x83\x01" or body[2] not in (2, 3):
                sw = 0x6a80
            else:
                self.mapping[p2] = body[2]
        elif ins == 0x88 or ins == 0x2a and (p1, p2) == (0x80, 0x86):
            template = 0xa4 if ins == 0x88 else 0xb8
            default = 3 if ins == 0x88 else 2
            slot = default if self.defect == "consumer-ignores-MSE" else self.mapping[template]
            policy_slot = default if self.defect == "UIF-original-slot" else slot
            if 0x82 not in self.grants and not (self.defect == "admin-overrides-PW82" and 0x83 in self.grants):
                sw = 0x6982
            elif self.data[0xd5 + policy_slot][0] and not self.presence:
                sw = 0x6600
            elif ins == 0x88:
                der = self.keys[slot].sign(body, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                r, s = utils.decode_dss_signature(der)
                output = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            else:
                point = dict(codec.parse_tlv(dict(codec.parse_tlv(dict(codec.parse_tlv(body))[0xa6]))[0x7f49]))[0x86]
                output = self.keys[slot].exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point))
        else:
            return super().transfer(wire, deadline, observe)
        output += sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("consumer-ignores-MSE", "actual reassigned private key"),
    ("reselect-clears-MSE", "actual reassigned private key"), ("UIF-original-slot", "selected password and touch policy"),
    ("admin-overrides-PW82", "selected password and touch policy")])
def test_MSE_grammar_authorization_actual_key_UIF_and_connection_lifetimes(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-MSE", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True, timeout=131, features=("display",),
        openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change", "reboot")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_type(session))
    original_cue = openpgp_mse.cue
    def operator(session, mode):
        peer.presence = mode == "accept"
        original_cue(session, mode)
    monkeypatch.setattr(openpgp_mse, "cue", operator)
    oracle.execute(session, ["openpgp-mse"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason or "InvalidSignature" in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys
