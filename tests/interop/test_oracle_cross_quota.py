# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Independent quotas cannot prevent other applets from creating real private objects."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_credential_matrix import StorePeer
from test_oracle_expanded import apdu_parts
from test_oracle_oath_semantics import Peer as OathPeer
from test_oracle_openpgp_matrix import Peer as PgpPeer, sdk_type
from test_oracle_otp_commands import Peer as OtpPeer
from test_oracle_piv_objects import Peer as PivPeer
from test_oracle_piv_lifecycle import DEFAULT_KEY
from test_oracle_states import ManagementPeer


class Card:
    layer = "pcsc_apdu"

    def __init__(self, hid, fault):
        self.hid, self.fault, self.applet = hid, fault, None
        self.piv, self.openpgp, self.oath, self.otp = PivPeer(), PgpPeer(), OathPeer(), OtpPeer()
        self.management = ManagementPeer()
        self.openpgp.values.update({0x65: b"\x65\x00", 0x6e: b"\x6e\x00"})

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins == 0xa4:
            self.applet = next(key for key, aid in AIDS.items() if aid.startswith(body) or body.startswith(aid))
        refused = self.applet == "oath" and ins == 1 and len(self.oath.records) >= 255
        if self.fault == "OATH-full-blocks-PIV" and self.applet == "piv" and ins == 0xdb and len(self.oath.records) >= 255:
            refused = True
        if self.fault == "FIDO-full-blocks-OATH" and self.applet == "oath" and ins == 1 and sum(record["resident"] for record in self.hid.records.values()) == self.hid.limit:
            refused = True
        pool = {tag: value for tag, value in self.piv.objects.items() if self.piv.pooled(tag)}
        if self.fault == "PIV-full-blocks-OpenPGP" and self.applet == "openpgp" and ins == 0xda and (len(pool) == 256 or sum(map(len, pool.values())) + 3063 > 32768):
            refused = True
        if refused:
            observe("tx", wire)
            observe("rx", b"\x6a\x84")
            return Reply(b"\x6a\x84", "applet_error", 0x6a84)
        return getattr(self, self.applet).transfer(wire, deadline, observe)


@pytest.mark.parametrize("fault,needle", [(None, None), ("OATH-full-blocks-PIV", "APDU success"),
    ("FIDO-full-blocks-OATH", "APDU success"), ("PIV-full-blocks-OpenPGP", "APDU success")])
def test_each_full_dynamic_quota_keeps_all_neighbor_writes_and_private_operations_usable(tmp_path, monkeypatch, fault, needle):
    from yubikit import openpgp
    hid = StorePeer()
    card = Card(hid, fault)
    trace = Trace(tmp_path / "cross-quota", {})
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", piv_pin="123456", piv_puk="12345678", management_key=DEFAULT_KEY,
        openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("capacity", "config_change", "applet_reset", "pin_change", "pin_attempts", "otp_both_slots", "otp_extra_slots")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_type(session))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["cross-quota"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert not hid.records and not card.piv.objects and not card.piv.keys and not card.openpgp.keys and not card.oath.records and not card.otp.slots
