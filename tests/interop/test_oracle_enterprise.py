# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Enterprise eligibility and signing identity are checked over actual wire maps."""
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.x509.oid import NameOID

import oracle
from oracle_lib import binding, codec, enterprise
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_seed_lifecycle import Peer as SeedPeer


def identity():
    body = codec.tlv(2, (17).to_bytes(4, "big"))
    return bytes([len(body)]) + body


class Card:
    layer = "pcsc_apdu"
    emulated = True

    def control(self, action, deadline, observe):
        assert action == "power_cycle"
        return Reply(b"")

    def transfer(self, request, deadline, observe):
        assert request[1] in (0xA4, 0x1D)
        body = identity() if request[1] == 0x1D else b""
        observe("tx", request)
        observe("rx", body + b"\x90\x00")
        return Reply(body + b"\x90\x00", status=0x9000)


class Peer(SeedPeer):
    def __init__(self, defect):
        super().__init__(defect)
        self.enabled, self.rps, self.org, self.chain = False, [], None, None
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic device")])
        self.basic = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.vendor.device_key.public_key()).serial_number(2).not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc)).not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc)).sign(self.vendor.device_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def reopen(self, operator):
        return {"serial_number": "17"}

    def initialize(self, trace, timeout):
        trace.emit("session_opened", session_id="hid", backend="synthetic")

    def transfer(self, command, request, deadline, observe):
        if command == 0x42:
            observe("tx", request)
            observe("rx", identity())
            return Reply(identity())
        operation = request[0]
        fields = codec.decode(request[1:]) if len(request) > 1 else {}
        status, value, handled = 0, {}, True
        if operation == 4:
            value = {1: ["FIDO_2_3"], 4: {"clientPin": False, "ep": self.enabled, "authnrCfg": True}, 6: [1, 2]}
        elif operation == 13:
            if fields[1] == 1:
                self.enabled = self.defect != "enable-noop"
            elif fields[1] == 255:
                assert fields[2][1] == enterprise.EA_RPIDS
                self.rps = fields[2][4]
            else:
                raise AssertionError("unexpected configuration operation")
        elif operation == 0x41 and fields[1] in (9, 10, 11):
            if fields[1] == 9:
                blob = fields[2][1]
                key, aad = self.vendor.channel
                scalar = ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad)
                self.org = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())
                self.chain, self.vendor.channel = fields[2][2], None
            elif fields[1] == 10:
                self.org = self.chain = None
            else:
                value = {1: self.org is not None}
        elif operation == 7:
            self.enabled, self.rps, self.records = False, [], {}
        elif operation == 1:
            level = fields.get(10)
            if 10 in fields and not self.enabled:
                status = 2
            elif 10 in fields and level not in (1, 2):
                status = 0x2C
            else:
                status, value = super().make(fields)
                for record in self.records.values():
                    record.setdefault("seed", self.vendor.seed)
                performed = level == 2 or level == 1 and (fields[2]["id"] in self.rps or self.defect == "type-1-RP-bypass")
                if performed or fields.get(11) != ["none"]:
                    key = self.org if performed and self.defect != "wrong-org-signer" else self.vendor.device_key
                    chain = self.chain if performed else self.basic
                    value[1], value[3] = "packed", {"alg": -7, "x5c": [chain], "sig": key.sign(value[2] + fields[1], ec.ECDSA(hashes.SHA256()))}
                if performed:
                    value[4] = True
        else:
            handled = False
        if not handled:
            return super().transfer(command, request, deadline, observe)
        observe("tx", request)
        body = bytes([status]) + (codec.encode(value) if not status else b"")
        observe("rx", body)
        return Reply(body, "success" if not status else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("enable-noop", "enterprise option enabled"),
    ("type-1-RP-bypass", "enterprise RP eligibility controls ep"), ("wrong-org-signer", "InvalidSignature")])
def test_enterprise_attestation_through_normal_dispatch(tmp_path, defect, expected):
    trace = Trace(tmp_path / "enterprise", {})
    peer = Peer(defect)
    session = Session(trace, hid=peer, card=Card(), profile="rsk", options=Options(exercise=True, touch=True,
                      allow_effects=("replace_identity", "config_change", "applet_reset", "pin_change", "reboot")))
    binding.confirm(session)
    oracle.execute(session, ["enterprise-attestation"])
    trace.finish()
    row = trace.cases[-1]
    if expected is None:
        assert row["verdict"] == "pass", row
    else:
        assert row["verdict"] == "fail" and expected in row["reason"], row
    assert peer.org is None and not peer.enabled
