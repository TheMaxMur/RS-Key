# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Independent padding and point parsing preserves DEC grants and real private keys."""
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519

import oracle
from oracle_lib import codec, openpgp_decipher
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_operations import Peer as SignaturePeer
from test_oracle_openpgp_references import sdk_with_errors


def length(data, offset):
    if offset >= len(data):
        raise ValueError("missing length")
    value, offset = data[offset], offset + 1
    if value & 128:
        width = value & 127
        if width not in (1, 2) or offset + width > len(data):
            raise ValueError("malformed length")
        value, offset = int.from_bytes(data[offset:offset + width], "big"), offset + width
    return value, offset


def point_field(body):
    if body[:1] != b"\xa6":
        raise ValueError("missing agreement template")
    _, offset = length(body, 1)
    if body[offset:offset + 2] != b"\x7f\x49":
        raise ValueError("missing public template")
    _, offset = length(body, offset + 2)
    if body[offset:offset + 1] != b"\x86":
        raise ValueError("missing point field")
    size, offset = length(body, offset + 1)
    if offset + size > len(body):
        raise ValueError("short point")
    return body[offset:offset + size]


class Peer(SignaturePeer):
    def transfer(self, wire, deadline, observe):
        from yubikit.openpgp import EcAttributes, KEY_REF, OID
        ins, p1, p2, body = apdu_parts(wire)
        sw, output = 0x9000, b""
        if ins == 0xca and p2 == 0xfa:
            rows = [codec.tlv(0xc2, bytes([1]) + bits.to_bytes(2, "big") + b"\x00\x20\x00") for bits in (1024, 2048, 3072, 4096)]
            rows += [codec.tlv(0xc2, bytes(EcAttributes.create(KEY_REF.DEC, OID[name]))) for name in ("SECP256R1", "X25519")]
            output = codec.tlv(0xfa, b"".join(rows))
        elif ins == 0xdb and self.attrs[2] == bytes(EcAttributes.create(KEY_REF.DEC, OID.X25519)):
            packed = dict(codec.parse_tlv(body))[0x4d]
            parts = dict(codec.parse_tlv(packed[2:]))
            self.keys[2] = x25519.X25519PrivateKey.from_private_bytes(parts[0x5f48])
        elif ins == 0x2a and (p1, p2) == (0x80, 0x86):
            if 0x82 not in self.grants:
                sw = 0x6982
            else:
                key = self.keys[2]
                if isinstance(key, rsa.RSAPrivateKey):
                    width = key.key_size // 8
                    if not body:
                        sw = 0x6a80
                    elif len(body) != width + 1:
                        sw = 0x6581
                    else:
                        numbers = key.private_numbers()
                        value = int.from_bytes(body[1:], "big")
                        encoded = pow(value, numbers.d, numbers.public_numbers.n).to_bytes(width, "big")
                        delimiter = encoded.find(b"\x00", 2)
                        if value >= numbers.public_numbers.n or encoded[:2] != b"\x00\x02" or delimiter < 10:
                            sw = 0x6581
                            if self.defect == "bad-padding-decrypts":
                                output, sw = b"leaked private result", 0x9000
                        else:
                            output = encoded[delimiter + 1:]
                else:
                    try:
                        point = point_field(body)
                    except ValueError:
                        sw = 0x6a80
                    else:
                        if isinstance(key, x25519.X25519PrivateKey):
                            if len(point) != 32:
                                sw = 0x6a80
                            else:
                                try:
                                    output = key.exchange(x25519.X25519PublicKey.from_public_bytes(point))
                                except ValueError:
                                    sw = 0x6581
                        else:
                            normal = len(point) == 65 and point[:1] == b"\x04"
                            compressed = len(point) == 33 and point[:1] in (b"\x02", b"\x03") and self.defect == "compressed-point-accepted"
                            if not (normal or compressed):
                                sw = 0x6a80
                            else:
                                try:
                                    output = key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(key.curve, point))
                                except ValueError:
                                    sw = 0x6581
                if sw != 0x9000 and self.defect == "refusal-revokes-PW82":
                    self.grants.discard(0x82)
        else:
            return super().transfer(wire, deadline, observe)
        output += sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("compressed-point-accepted", "grammar, point and padding refusals"),
    ("bad-padding-decrypts", "grammar, point and padding refusals"), ("refusal-revokes-PW82", "preserves PW1.82 status")])
def test_RSA_padding_ECDH_grammar_and_X25519_low_order_points(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    monkeypatch.setattr(openpgp_decipher, "ALGORITHMS", ("RSA1024", "SECP256R1", "X25519"))
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-DECIPHER", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change",)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    oracle.execute(session, ["openpgp-decipher"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys
