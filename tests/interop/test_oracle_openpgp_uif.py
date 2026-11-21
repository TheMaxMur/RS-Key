# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Real signatures and issued certificates expose UIF and one-shot ordering defects."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import codec, openpgp_uif
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_operations import Peer as SignaturePeer
from test_oracle_openpgp_references import sdk_with_errors


class Peer(SignaturePeer):
    presence = True

    def needs_touch(self, tag):
        value = self.data[tag]
        return bool(value and value[0] and not (value[0] == 2 and self.defect == "fixed-UIF-disabled"))

    def factory(self):
        super().factory()
        self.generated = set()
        self.root = ec.derive_private_key(512, ec.SECP384R1())
        self.root_cert = self.issue(self.root.public_key(), "oracle-root", True)

    def issue(self, public, name, root=False):
        now = datetime.now(timezone.utc)
        issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "oracle-root")])
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
        return x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public).serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=root, path_length=0 if root else None), True).sign(self.root, hashes.SHA384()).public_bytes(serialization.Encoding.DER)

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        sw, output = 0x9000, b""
        tag = p1 * 256 + p2
        if ins == 0xca and tag == 0xfa:
            from yubikit.openpgp import EcAttributes, KEY_REF, OID
            output = codec.tlv(0xfa, b"".join(codec.tlv(int(slot.algorithm_attributes_do), bytes(EcAttributes.create(slot, OID.SECP256R1))) for slot in (KEY_REF.SIG, KEY_REF.DEC, KEY_REF.AUT)))
        elif ins == 0xda and tag in range(0xd6, 0xda):
            if 0x83 not in self.grants:
                sw = 0x6982
            elif self.data[tag][:1] == b"\x02" and body[:1] != b"\x02":
                sw = 0x6985
            elif body and (len(body) != 2 or body[0] > 2):
                sw = 0x6a80
            else:
                self.data[tag] = body
        elif ins == 0x47 and p1 == 0x80 and p2 == 0:
            slot = {b"\xb6\x00": 1, b"\xb8\x00": 2, b"\xa4\x00": 3}[body]
            if 0x83 not in self.grants:
                sw = 0x6982
            else:
                self.keys[slot] = ec.derive_private_key(100 + slot, ec.SECP256R1())
                self.generated.add(slot)
                if slot == 1:
                    self.count = 0
                point = self.keys[slot].public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                output = codec.tlv(0x7f49, codec.tlv(0x86, point))
        elif ins == 0xfb:
            if 0x81 not in self.grants:
                sw = 0x6982
            elif wire[0] != 0x80:
                sw = 0x6e00
            elif p2 or body:
                sw = 0x6a80
            elif self.needs_touch(0xd9) and not self.presence:
                sw = 0x6600
                if self.defect == "ATTEST-decline-spends-one-shot":
                    self.grants.discard(0x81)
            else:
                if p1 not in (1, 2, 3):
                    sw = 0x6a80
                elif p1 not in self.keys or p1 not in self.generated and self.defect != "imported-origin-attests":
                    sw = 0x6985
                else:
                    occurrence = {1: 2, 2: 1, 3: 0}[p1]
                    self.certs[occurrence] = self.issue(self.keys[p1].public_key(), "owned-generated-key")
                if self.mode == 0:
                    self.grants.discard(0x81)
                if sw == 0x9000 and self.defect == "ATTEST-increments-signature-counter":
                    self.count += 1
        elif ins == 0xca and tag == 0xfc:
            output = self.root_cert
        elif ins == 0x88 or ins == 0x2a and (p1, p2) in ((0x9e, 0x9a), (0x80, 0x86)):
            reference = 0x81 if (p1, p2) == (0x9e, 0x9a) else 0x82
            slot = 1 if reference == 0x81 else 3 if ins == 0x88 else 2
            if reference not in self.grants:
                sw = 0x6982
            elif self.needs_touch(0xd5 + slot) and not self.presence:
                sw = 0x6600
                if slot == 1 and self.mode == 0 and self.defect != "SIG-decline-retains-one-shot":
                    self.grants.discard(0x81)
            else:
                return super().transfer(wire, deadline, observe)
        else:
            if ins == 0xdb:
                slot = {0xb6: 1, 0xb8: 2, 0xa4: 3}[dict(codec.parse_tlv(body))[0x4d][0]]
                self.generated.discard(slot)
            return super().transfer(wire, deadline, observe)
        output += sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("SIG-decline-retains-one-shot", "UIF decline spends one-shot SIG"),
    ("ATTEST-decline-spends-one-shot", "preserves one-shot ATTEST")])
def test_UIF_grammar_authorization_refusal_and_distinct_one_shot_boundaries(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-UIF", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        timeout=131, features=("display",), openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change",)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    def operator(session, mode):
        peer.presence = mode == "accept"
    monkeypatch.setattr(openpgp_uif, "cue", operator)
    oracle.execute(session, ["openpgp-uif"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys and peer.mode == 1


@pytest.mark.parametrize("defect", [None, "fixed-UIF-disabled"])
def test_permanent_UIF_operations_refuse_decline_and_timeout_until_reset(tmp_path, monkeypatch, defect):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-UIF-fixed", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        timeout=131, features=("display",), openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change", "applet_reset")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    monkeypatch.setattr(openpgp_uif, "cue", lambda session, mode: setattr(peer, "presence", mode == "accept"))
    oracle.execute(session, ["openpgp-uif-fixed"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert any("raw signature input has the exact" in reason or "MSE consumer enforces" in reason or "origin in order" in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys and not peer.terminated
