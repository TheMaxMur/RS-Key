# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Advertised RSA widths reach real APDUs despite an SDK that cannot name them."""
import math

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from oracle_lib import codec, pgp_keys
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts


def components(headers, data):
    result = {}
    while headers:
        tag, width = headers[:2]
        headers = headers[2:]
        if width & 128:
            count = width & 127
            width = int.from_bytes(headers[:count], "big")
            headers = headers[count:]
        result[tag], data = int.from_bytes(data[:width], "big"), data[width:]
    assert not data
    return result


class Peer:
    layer = "pcsc_apdu"

    def __init__(self):
        self.key, self.bits, self.admin, self.pin = None, 2048, False, False

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        output, sw = b"", 0x9000
        if ins == 0xA4:
            self.admin = self.pin = False
        elif ins == 0x20:
            if p2 == 0x83:
                self.admin = data == b"12345678"
            else:
                self.pin = data == b"123456"
        elif ins == 0xCA:
            output = codec.tlv(0xFA, b"".join(codec.tlv(0xC1, bytes([1]) + bits.to_bytes(2, "big") + b"\x00\x20\x00") for bits in (1024, 2048, 3072, 4096)))
        elif ins == 0xDA:
            assert self.admin
            assert data[:1] == b"\x01" and data[-3:] == b"\x00\x20\x00"
            bits = int.from_bytes(data[1:3], "big")
            if bits != self.bits:
                self.key = None
            self.bits = bits
        elif ins == 0xDB:
            assert self.admin
            packed = dict(codec.parse_tlv(data))[0x4D]
            parts = dict(codec.parse_tlv(packed[2:]))
            values = components(parts[0x7F48], parts[0x5F48])
            p, q, e = values[0x92], values[0x93], values[0x91]
            d = pow(e, -1, math.lcm(p - 1, q - 1))
            self.key = rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p), rsa.RSAPublicNumbers(e, p * q)).private_key()
            assert self.key.key_size == self.bits
        elif ins == 0x47:
            if p1 == 0x80:
                assert self.admin
                self.key = rsa.generate_private_key(65537, self.bits)
            if self.key is None:
                sw = 0x6A88
            else:
                public = self.key.public_key().public_numbers()
                output = codec.tlv(0x7F49, codec.tlv(0x81, public.n.to_bytes(self.bits // 8, "big")) + codec.tlv(0x82, public.e.to_bytes(3, "big")))
        elif ins == 0x2A:
            assert self.pin and self.key is not None
            numbers = self.key.private_numbers()
            width = self.bits // 8
            block = b"\x00\x01" + b"\xff" * (width - len(data) - 3) + b"\x00" + data
            output = pow(int.from_bytes(block, "big"), numbers.d, numbers.public_numbers.n).to_bytes(width, "big")
        else:
            raise AssertionError("unmodelled RSA command")
        observe("tx", wire)
        output += sw.to_bytes(2, "big")
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("bits", [1024, 2048, 3072, 4096])
@pytest.mark.parametrize("origin", ["import", "generate"])
def test_all_advertised_RSA_widths_reach_the_card(tmp_path, bits, origin):
    from yubikit.openpgp import KEY_REF
    peer = Peer()
    trace = Trace(tmp_path / "RSA-wire", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True))
    class Sdk:
        def get_public_key(self, slot):
            result = session.card_value(session.apdu(codec.apdu(0x47, 0x81, data=slot.crt)))
            fields = dict(codec.parse_tlv(dict(codec.parse_tlv(result))[0x7F49]))
            return rsa.RSAPublicNumbers(int.from_bytes(fields[0x82], "big"), int.from_bytes(fields[0x81], "big")).public_key()
        def put_key(self, *args):
            raise AssertionError("SDK RSA enum must not intercept the raw path")
        generate_rsa_key = put_key
        delete_key = put_key
    sdk = Sdk()
    with session.case(f"RSA{bits}.{origin}", ("O09", "O10", "O11"), effects=("replace_openpgp_sig_key",)):
        session.select("openpgp")
        session.card_value(session.apdu(codec.apdu(0x20, p2=0x83, data=b"12345678")))
        if origin == "import":
            private = rsa.generate_private_key(65537, bits)
            pgp_keys.put_key(session, sdk, KEY_REF.SIG, private)
            public = private.public_key()
        else:
            public = pgp_keys.generate(session, sdk, KEY_REF.SIG, "RSA" + str(bits))
        assert public.public_numbers() == sdk.get_public_key(KEY_REF.SIG).public_numbers()
        session.card_value(session.apdu(codec.apdu(0x20, p2=0x81, data=b"123456")))
        message = b"independent RSA private control"
        signature = session.card_value(session.apdu(codec.apdu(0x2A, 0x9E, 0x9A, message)))
        numbers = public.public_numbers()
        block = pow(int.from_bytes(signature, "big"), numbers.e, numbers.n).to_bytes(bits // 8, "big")
        session.check("advertised RSA private signature retains its key", block, b"\x00\x01" + b"\xff" * (bits // 8 - len(message) - 3) + b"\x00" + message)
        pgp_keys.delete_key(session, sdk, KEY_REF.SIG)
        session.check("raw attribute transition deletes the key", session.apdu(codec.apdu(0x47, 0x81, data=KEY_REF.SIG.crt)).status, 0x6A88)
    trace.finish()
    assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
