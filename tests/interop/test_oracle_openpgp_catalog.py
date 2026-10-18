# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""DO owners and persistence use an independent card with real signing keys."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_matrix import Peer as KeyPeer, sdk_type


class Peer(KeyPeer):
    def factory(self):
        super().factory()
        self.data = {0x5B: b"", 0x5E: b"", 0x5F2D: b"", 0x5F35: b"9", 0x5F50: b"",
                     **{tag: bytes(20) for tag in (*range(0xC7, 0xCD), 0xDB, 0xDC)},
                     **{tag: bytes(4) for tag in (*range(0xCE, 0xD1), 0xDD)},
                     **{tag: b"\x00\x20" for tag in range(0xD6, 0xDA)},
                     **{tag: b"" for tag in range(0x101, 0x105)}}

    def template(self):
        discrete = {0xC0: bytes(10), **{0xC0 + slot: body for slot, body in self.attrs.items()},
            0xC5: b"".join(self.data[tag] for tag in (0xC7, 0xC8, 0xC9, 0xDB)),
            0xC6: b"".join(self.data[tag] for tag in (0xCA, 0xCB, 0xCC, 0xDC)),
            0xCD: b"".join(self.data[tag] for tag in (0xCE, 0xCF, 0xD0, 0xDD))}
        return codec.tlv(0x6E, codec.tlv(0x4F, b"offline-aid") + codec.tlv(0x73, b"".join(codec.tlv(tag, value) for tag, value in discrete.items())))

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        tag = p1 * 256 + p2
        if self.terminated or ins not in (0xCA, 0xDA) or ins == 0xDA and tag in (0xC1, 0xC2, 0xC3) or ins == 0xCA and tag in (0x7A, 0xFA):
            return super().transfer(wire, deadline, observe)
        sw, output = 0x9000, b""
        if ins == 0xCA:
            if tag == 0x6E:
                output = self.template()
            elif tag == 0x65:
                output = codec.tlv(0x65, b"".join(codec.tlv(t, self.data[t]) for t in (0x5B, 0x5F2D, 0x5F35)))
            elif tag in (0x103, 0x104) and (0x82 if tag == 0x103 else 0x83) not in self.grants and self.defect != "admin-read-override":
                sw = 0x6982
            elif tag in (0x5E, 0x5F50, *range(0x101, 0x105), *range(0xD6, 0xDA)):
                output = self.data[tag]
            elif tag == 0x7F21:
                output = self.certs[self.certificate]
            elif tag == 0xC4:
                output = bytes([1, 127, 127, 127, self.retries, self.retries if self.code else 0, self.retries])
            elif tag == 0xF9:
                output = self.values[0xF9]
            else:
                sw = 0x6B00
        else:
            owner = 0x82 if tag in (0x101, 0x103) else 0x83
            if owner not in self.grants and self.defect != "admin-write-override":
                sw = 0x6982
            elif tag in self.data:
                self.data[tag] = data
            elif tag == 0x7F21:
                self.certs[self.certificate] = data
            else:
                sw = 0x6B00
        observe("tx", wire)
        output += sw.to_bytes(2, "big")
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)

    def control(self, action, deadline, observe):
        result = super().control(action, deadline, observe)
        if self.defect == "volatile-private-DO":
            self.data[0x101] = b""
        return result


@pytest.mark.parametrize("defect,needle", [(None, None), ("admin-write-override", "same-value PUT still enforces"),
    ("admin-read-override", "private DO has no foreign-password override"), ("volatile-private-DO", "each writable DO survives")])
def test_complete_DO_ownership_and_connection_catalog(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "DO-catalog", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("reboot",)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_type(session))
    oracle.execute(session, ["openpgp-catalog"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for name, reason in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]


def test_every_mutable_DO_returns_to_factory_default(tmp_path, monkeypatch):
    from yubikit import openpgp
    from oracle_lib import reset_witness
    peer = Peer()
    peer.certs = {index: b"" for index in range(3)}
    trace = Trace(tmp_path / "DO-reset", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True, openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("applet_reset",)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_type(session))
    monkeypatch.setattr(reset_witness, "snapshot", lambda session, excluded: None)
    original_factory = peer.factory
    def factory():
        original_factory()
        peer.certs = {index: b"" for index in range(3)}
    peer.factory = factory
    oracle.execute(session, ["openpgp-catalog-reset"])
    trace.finish()
    assert all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases]
