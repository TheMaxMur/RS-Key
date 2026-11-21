# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Actual RSA/EC/EdDSA private operations expose width, counter and one-shot defects."""
import math

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, utils

import oracle
from oracle_lib import codec, openpgp_operations
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_references import Peer as ReferencePeer, sdk_with_errors
from test_oracle_pgp_keys import components

ALGORITHMS = ("SECP256R1", "SECP521R1", "RSA1024", "ED25519")


class Peer(ReferencePeer):
    def transfer(self, wire, deadline, observe):
        from yubikit.openpgp import EcAttributes, KEY_REF, OID
        ins, p1, p2, body = apdu_parts(wire)
        sw, output = 0x9000, b""
        if ins == 0xca and p2 == 0xfa:
            rows = []
            for slot in (KEY_REF.SIG, KEY_REF.AUT):
                rows.extend(codec.tlv(int(slot.algorithm_attributes_do), bytes([1]) + bits.to_bytes(2, "big") + b"\x00\x20\x00") for bits in (1024, 2048, 3072, 4096))
                rows.extend(codec.tlv(int(slot.algorithm_attributes_do), bytes(EcAttributes.create(slot, OID[name]))) for name in ("SECP256R1", "SECP521R1", "Ed25519"))
            output = codec.tlv(0xfa, b"".join(rows))
        elif ins == 0xda and p2 in (0xc1, 0xc2, 0xc3):
            slot = p2 - 0xc0
            if self.attrs[slot] != body:
                self.keys.pop(slot, None)
            self.attrs[slot] = body
        elif ins == 0xdb:
            packed = dict(codec.parse_tlv(body))[0x4d]
            slot = {0xb6: 1, 0xb8: 2, 0xa4: 3}[packed[0]]
            parts = dict(codec.parse_tlv(packed[2:]))
            values = components(parts[0x7f48], parts[0x5f48])
            if self.attrs[slot][0] == 1:
                p, q, e = values[0x92], values[0x93], values[0x91]
                d = pow(e, -1, math.lcm(p - 1, q - 1))
                key = rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p), rsa.RSAPublicNumbers(e, p * q)).private_key()
            elif self.attrs[slot][0] == 0x16:
                key = ed25519.Ed25519PrivateKey.from_private_bytes(parts[0x5f48])
            else:
                curve = ec.SECP521R1() if self.attrs[slot].endswith(bytes.fromhex("2b81040023")) else ec.SECP256R1()
                key = ec.derive_private_key(values[0x92], curve)
            self.keys[slot] = key
            if slot == 1:
                self.count = 0
        elif ins == 0x88 or ins == 0x2a and (p1, p2) == (0x9e, 0x9a):
            slot, reference = (3, 0x82) if ins == 0x88 else (1, 0x81)
            if reference not in self.grants:
                sw = 0x6982
            else:
                key = self.keys[slot]
                data = body if self.defect != "wrong-message" else bytes([body[0] ^ 1]) + body[1:] if body else b"x"
                if isinstance(key, rsa.RSAPrivateKey):
                    width = key.key_size // 8
                    if len(data) > width - 11:
                        sw = 0x6581
                    else:
                        numbers = key.private_numbers()
                        encoded = b"\x00\x01" + b"\xff" * (width - len(data) - 3) + b"\x00" + data
                        output = pow(int.from_bytes(encoded, "big"), numbers.d, numbers.public_numbers.n).to_bytes(width, "big")
                elif isinstance(key, ed25519.Ed25519PrivateKey):
                    output = key.sign(data)
                else:
                    digest = data or b"\x00"
                    if key.curve.key_size == 521 and len(data) >= 66:
                        z = int.from_bytes(data[:66], "big") % (1 << 521)
                        digest = (z * 128).to_bytes(66, "big")
                    der = key.sign(digest, ec.ECDSA(utils.Prehashed(openpgp_operations.RawPrehash(len(digest)))))
                    r, s = utils.decode_dss_signature(der)
                    width = (key.curve.key_size + 7) // 8
                    output = r.to_bytes(width, "big") + s.to_bytes(width, "big")
                if slot == 1:
                    self.count += sw == 0x9000 or self.defect == "refusal-consumes-counter"
                    if self.mode == 0 and self.defect != "one-shot-reusable":
                        self.grants.discard(0x81)
        else:
            return super().transfer(wire, deadline, observe)
        output += sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("wrong-message", "InvalidSignature"),
    ("one-shot-reusable", "one-shot SIG status is spent"), ("refusal-consumes-counter", "only a successful SIG")])
def test_raw_signature_widths_all_private_key_kinds_and_one_shot_state(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    monkeypatch.setattr(openpgp_operations, "SIGN_ALGORITHMS", ALGORITHMS)
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-operations", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change",)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    oracle.execute(session, ["openpgp-operations"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys


def test_private_fixture_restores_mode_when_UIF_setup_refuses(tmp_path, monkeypatch):
    from yubikit import openpgp
    peer = Peer()
    trace = Trace(tmp_path / "OpenPGP-partial-setup", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change",)))
    base = sdk_with_errors(session)
    class Sdk(base):
        refused = False
        def put_data(self, tag, value):
            if tag == 0xd6 and not self.refused:
                self.refused = True
                raise RuntimeError("injected UIF setup refusal")
            return super().put_data(tag, value)
    monkeypatch.setattr(openpgp, "OpenPgpSession", Sdk)
    with session.case("partial-setup", ("O19",), effects=("replace_openpgp_keys", "config_change"), touch=True):
        with pytest.raises(RuntimeError, match="injected UIF setup refusal"):
            with openpgp_operations.operation_key(session, openpgp.KEY_REF.SIG, "SECP256R1", 0):
                pytest.fail("refused setup must not yield")
        session.check("partial configuration restores original PW1 mode", peer.mode, 1)
        session.check("partial configuration removes its installed private key", peer.keys, {})
    trace.finish()
    assert trace.cases[0]["verdict"] == "pass", trace.cases
