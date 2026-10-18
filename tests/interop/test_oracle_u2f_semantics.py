# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""U2F controls verify real attestation and signatures on both recorded transports."""
import hashlib
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_apdu_matrix import decode_apdu
from test_oracle_binding import Identity
from test_oracle_fido_properties import PropertyPeer


class Peer(PropertyPeer):
    def __init__(self, defect=None):
        super().__init__()
        self.u2f_defect, self.handles, self.u2f_counter = defect, {}, 0
        self.attestation = ec.derive_private_key(123, ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline U2F oracle")])
        self.certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.attestation.public_key()).serial_number(1).not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc)).not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc)).sign(self.attestation, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def u2f(self, wire, observe):
        ins, mode = wire[1:3]
        data, le = decode_apdu(wire)
        sw, body = 0x9000, b""
        if ins == 3:
            body = b"U2F_V2"
        elif ins == 1:
            if len(data) != 64:
                sw = 0x6700
                if self.u2f_defect == "REGISTER-error-increments":
                    self.u2f_counter += 1
            else:
                challenge, application = data[:32], data[32:]
                private = ec.derive_private_key(len(self.handles) + 1, ec.SECP256R1())
                handle = hashlib.sha256(data + len(self.handles).to_bytes(4, "big")).digest() * 2
                point = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                self.handles[handle] = {"key": private, "application": application, "counter": 0}
                signature = self.attestation.sign(b"\x00" + application + challenge + handle + point, ec.ECDSA(hashes.SHA256()))
                body = b"\x05" + point + bytes([len(handle)]) + handle + self.certificate + signature
        elif ins == 2:
            if mode not in (3, 7, 8):
                sw = 0x6A86
            elif len(data) < 65 or len(data[65:]) != data[64]:
                sw = 0x6700
            elif data[65:] not in self.handles or self.handles[data[65:]]["application"] != data[32:64]:
                sw = 0x6A80
            elif mode == 7:
                sw = 0x6985
            else:
                record = self.handles[data[65:]]
                self.u2f_counter += 1
                record["counter"] += 1
                counter = record["counter"] if self.u2f_defect == "per-handle-counter" else self.u2f_counter
                head = bytes([int(mode == 3)]) + counter.to_bytes(4, "big")
                body = head + record["key"].sign(data[32:64] + head + data[:32], ec.ECDSA(hashes.SHA256()))
        else:
            raise AssertionError("unknown U2F instruction")
        response = body + sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", response)
        return Reply(response, "success" if sw == 0x9000 else "applet_error", sw)

    def transfer(self, command, wire, deadline, observe):
        if command == 3:
            return self.u2f(wire, observe)
        if command == 0x42:
            return Identity(17).transfer(command, wire, deadline, observe)
        return super().transfer(command, wire, deadline, observe)

    def reopen(self, operator):
        return {"serial_number": "17"}

    def initialize(self, trace, timeout):
        trace.emit("session_opened", session_id="hid", backend="synthetic")


class Card(Identity):
    emulated = True

    def __init__(self, hid):
        super().__init__(17)
        self.hid = hid

    def transfer(self, wire, deadline, observe):
        if wire[1] in (1, 2, 3):
            return self.hid.u2f(wire, observe)
        return super().transfer(wire, deadline, observe)


@pytest.mark.parametrize("defect,expected", [(None, None), ("REGISTER-error-increments", "refused REGISTER does not advance"),
                                           ("per-handle-counter", "counter is global across handles")])
def test_u2f_semantics_with_independent_attestation_key_and_counter(tmp_path, defect, expected):
    peer = Peer(defect)
    trace = Trace(tmp_path / "U2F-semantics", {})
    session = Session(trace, hid=peer, card=Card(peer), profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", allow_effects=("reboot",)))
    oracle.execute(session, ["u2f-semantics"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures, [(row["scenario_id"], row["reason"]) for row in failures]
        assert any(row["scenario_id"] == "u2f.lifetime.card-transport" and row["verdict"] == "pass" for row in trace.cases)
        assert any(row["scenario_id"] == "u2f.lifetime.power_cycle" and row["verdict"] == "pass" for row in trace.cases)
