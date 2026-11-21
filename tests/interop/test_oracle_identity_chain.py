# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Populated identity peers validate framing and authenticate before decrypting scalars."""
import hashlib

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_enterprise import Peer as EnterprisePeer


def split_chain(chain):
    certs = []
    if not chain or len(chain) > 2132:
        return None
    view = memoryview(chain)
    while view:
        if len(view) < 2 or view[0] != 0x30 or len(certs) == 4:
            return None
        first, header = view[1], 2
        if first < 128:
            length = first
        elif first in (0x81, 0x82) and len(view) >= 2 + (first & 127):
            header += first & 127
            length = int.from_bytes(view[2:header], "big")
        else:
            return None
        if header + length > len(view):
            return None
        certs.append(bytes(view[:header + length]))
        view = view[header + length:]
    return certs


class Peer(EnterprisePeer):
    def reply(self, wire, status, result, observe):
        output = bytes([status]) + (codec.encode(result) if status == 0 else b"")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if status == 0 else "applet_error", status)

    def transfer(self, command, wire, deadline, observe):
        if command == 3:
            body = wire[7:-2]
            challenge, application = body[:32], body[32:]
            point = ec.derive_private_key(19, ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            handle = b"owned U2F fixture"
            leaf = split_chain(self.chain)[0]
            signature = self.org.sign(b"\x00" + application + challenge + handle + point, ec.ECDSA(hashes.SHA256()))
            return Reply(b"\x05" + point + bytes([len(handle)]) + handle + leaf + signature + b"\x90\x00", status=0x9000)
        if wire[0] != 0x41:
            return super().transfer(command, wire, deadline, observe)
        fields = codec.decode(wire[1:])
        sub, params = fields[1], fields.get(2, {})
        if sub not in (6, 9, 10, 11):
            return super().transfer(command, wire, deadline, observe)
        if sub == 11:
            value = {1: self.org is not None}
            if self.org is not None:
                certs = split_chain(self.chain)
                packed = bytes([len(certs)]) + b"".join(len(cert).to_bytes(2, "little") + cert for cert in certs)
                value[2] = hashlib.sha256(packed).digest()
            return self.reply(wire, 0, value, observe)
        channel = self.vendor.channel
        self.vendor.channel = None
        if sub == 6:
            return self.reply(wire, 0x30 if channel is None else 2, {}, observe)
        status = 0
        certs = split_chain(params.get(2, b"")) if sub == 9 else None
        if sub == 9 and certs is None and self.defect != "framing-gate-after-auth":
            status = 2
        if not status:
            if 3 in fields and fields[3] not in (1, 2):
                status = 2
            elif 4 not in fields:
                status = 0x36
            elif 3 not in fields:
                status = 0x14
            else:
                payload = b"\xff" * 32 + bytes([0x41, sub]) + (codec.encode(params) if 2 in fields else b"")
                if fields[4] != self.mac(payload) or not self.permissions & 32:
                    status = 0x33
        if not status and channel is None:
            status = 0x30
        if not status and sub == 9:
            if certs is None or self.defect == "leaf-grammar-too-strict" and certs[0] == b"\x30\x00":
                status = 2
            else:
                key, aad = channel
                blob = params[1]
                try:
                    scalar = int.from_bytes(ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad), "big")
                    self.org = ec.derive_private_key(scalar, ec.SECP256R1())
                    self.chain = params[2]
                except (ValueError, InvalidTag):
                    status = 2
        elif not status and sub == 10:
            self.org = self.chain = None
        if status and self.defect == "refusal-drops-identity":
            self.org = self.chain = None
        if status and sub == 9 and self.defect == "does-not-consume-MSE":
            self.vendor.channel = channel
        return self.reply(wire, status, {}, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("leaf-grammar-too-strict", "isolates framing"),
    ("framing-gate-after-auth", "isolates framing"), ("does-not-consume-MSE", "spends its MSE channel"),
    ("refusal-drops-identity", "packed-chain commitment")])
def test_populated_identity_chain_framing_auth_scalar_and_private_key_controls(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "identity-chain", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", allow_effects=("replace_identity",)))
    oracle.execute(session, ["identity-chain"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert peer.org is None and peer.chain is None
