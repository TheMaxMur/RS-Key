# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Readback distinguishes committed/uncommitted writes and rejects partial values."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_expanded import apdu_parts
from test_oracle_piv_moves import Peer as PivPeer
from test_oracle_oath_semantics import Peer as OathPeer
from test_oracle_piv_lifecycle import DEFAULT_KEY
from test_oracle_openpgp_matrix import Peer as PgpPeer, sdk_type


class Card:
    layer = "pcsc_apdu"

    def __init__(self, commit, defect):
        self.commit, self.defect, self.applet = commit, defect, None
        self.piv, self.oath, self.losses = PivPeer(), OathPeer(), []
        self.openpgp = PgpPeer()

    def control(self, action, deadline, observe):
        self.piv.has_pin = self.piv.has_management = False
        return Reply(b"offline ATR")

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0xa4:
            self.applet = next(key for key, aid in AIDS.items() if aid.startswith(data) or data.startswith(aid))
        if self.applet == "oath" and ins == 5:
            fields = codec.parse_tlv(data)
            self.oath.records[fields[1][1]] = self.oath.records.pop(fields[0][1])
            observe("tx", wire)
            observe("rx", b"\x90\x00")
            return Reply(b"\x90\x00", status=0x9000)
        if self.applet == "piv" and ins == 0x87 and p2 != 0x9b and p2 not in self.piv.keys:
            observe("tx", wire)
            observe("rx", b"\x6a\x88")
            return Reply(b"\x6a\x88", "applet_error", 0x6a88)
        return getattr(self, self.applet).transfer(wire, deadline, observe)

    def drop_response(self, wire, deadline, observe):
        self.losses.append(bytes(wire))
        observe("tx", wire)
        if self.commit:
            result = self.transfer(wire, deadline, lambda *_: None)
            assert result.status == 0x9000
            ins, p1, p2, data = apdu_parts(wire)
            if self.applet == "piv" and ins == 0xdb and self.defect == "partial-PIV-object":
                self.piv.objects[0x5f0077] = b"partial"
            if self.applet == "oath" and ins == 1 and self.defect == "OATH-secret-corrupted":
                fields = dict(codec.parse_tlv(data))
                self.oath.records[fields[0x71]]["secret"] = b"wrong secret"
            if self.applet == "piv" and ins == 0xdb and self.defect == "lost-PIV-private-key":
                from cryptography.hazmat.primitives.asymmetric import ec
                self.piv.keys[0x82] = ec.generate_private_key(ec.SECP256R1())
        raise TransferError("synthetic answer abandoned before delivery", Outcome.CANCELLED, protocol="injected_response_loss")


@pytest.mark.parametrize("commit,defect,needle", [(False, None, None), (True, None, None),
    (True, "partial-PIV-object", "complete old or new"), (True, "OATH-secret-corrupted", "HOTP secret"),
    (True, "lost-PIV-private-key", "InvalidSignature")])
def test_each_uncertain_mutation_reads_back_without_replaying(tmp_path, monkeypatch, commit, defect, needle):
    from yubikit import openpgp
    trace = Trace(tmp_path / "uncertain-writes", {})
    card = Card(commit, defect)
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        piv_pin="123456", management_key=DEFAULT_KEY, openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change",)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_type(session))
    oracle.execute(session, ["uncertain-writes"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
        assert session.broken
        if defect == "lost-PIV-private-key":
            assert len(card.losses) == 1
            last = bytes.fromhex(trace.exchanges[-1]["request"]["hex"])
            assert (last[1], last[3]) == (0x87, 0x82), "cleanup issued another APDU after private recovery verification failed"
    else:
        assert len(trace.cases) == 12 and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert len(card.losses) == 12 and not card.piv.keys and not card.piv.objects and not card.oath.records and not card.openpgp.keys
