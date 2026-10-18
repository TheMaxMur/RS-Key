# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A refusal cannot damage private neighbors that existed before the rejected request."""
import pytest

import oracle
from oracle_lib import codec, cross_rejections
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_cross_reset import Card as ResetCard, Hid as ResetHid, DEFAULT_KEY
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_references import Peer as PgpPeer, sdk_with_errors
from test_oracle_otp_commands import Peer as OtpPeer
from test_oracle_piv_references import Peer as PivPeer
from test_oracle_vendor import VendorPeer


class Hid(ResetHid):
    def __init__(self, fault):
        super().__init__()
        self.vendor, self.fault, self.card = VendorPeer(), fault, None

    def transfer(self, command, wire, deadline, observe):
        if command == 0x10 and wire[0] == 0x41:
            return self.vendor.transfer(command, wire, deadline, observe)
        if command == 0x10 and wire[0] == 10 and codec.decode(wire[1:]) == {1: 1}:
            if self.fault == "FIDO-refusal-clears-neighbor-lock":
                self.card.management.lock = None
            observe("tx", wire)
            observe("rx", b"\x36")
            return Reply(b"\x36", "applet_error", 0x36)
        return super().transfer(command, wire, deadline, observe)


class Card(ResetCard):
    def __init__(self, hid, fault):
        super().__init__(hid, None)
        self.fault, self.piv, self.pgp, self.otp = fault, PivPeer(), PgpPeer(), OtpPeer()
        self.pgp.values.update({0x65: b"\x65\x00", 0x6e: b"\x6e\x00"})

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        selected = next((name for name, aid in AIDS.items() if aid == body), None) if ins == 0xa4 else None
        if selected in ("rescue", "vendor"):
            self.applet = selected
            return Reply(b"\x90\x00", status=0x9000)
        if ins == 0xee:
            result = Reply(b"\x6d\x00", "applet_error", 0x6d00)
        elif self.applet == "rescue" and ins == 0x10:
            result = Reply(b"\x67\x00", "applet_error", 0x6700)
        elif self.applet == "otp" and ins != 0xa4 or selected == "otp":
            self.applet = "otp"
            return self.otp.transfer(wire, deadline, observe)
        elif self.applet == "piv" and ins == 0x87 and p2 != 0x9b and p2 not in self.piv.keys:
            result = Reply(b"\x6a\x88", "applet_error", 0x6a88)
        else:
            result = super().transfer(wire, deadline, observe)
        if self.applet == "oath" and ins != 0xa4 and result.is_rejection and self.fault == "OATH-refusal-deletes-neighbor-key":
            self.piv.keys.clear()
        return result


@pytest.mark.parametrize("fault,needle", [(None, None), ("OATH-refusal-deletes-neighbor-key", "0x6a88"),
    ("FIDO-refusal-clears-neighbor-lock", "management lock")])
def test_each_applets_parser_auth_and_dispatch_refusals_keep_private_neighbors(tmp_path, monkeypatch, fault, needle):
    from yubikit import openpgp
    trace = Trace(tmp_path / "cross-rejections", {})
    hid = Hid(fault)
    card = Card(hid, fault)
    hid.card = card
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", piv_pin="123456", piv_puk="12345678", management_key=DEFAULT_KEY,
        openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change",)))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["cross-rejections"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert len(trace.cases) == 2 * len(cross_rejections.READS) and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert not card.piv.keys and not card.pgp.keys and not card.oath.records and not card.otp.slots and card.management.lock is None
