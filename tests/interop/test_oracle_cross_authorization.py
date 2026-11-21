# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Independent applets enforce their own grants after every valid foreign grant."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_cursor_matrix import Peer as TokenPeer
from test_oracle_expanded import apdu_parts
from test_oracle_management_state import Peer as ManagementPeer
from test_oracle_oath_pin_matrix import Peer as OathPeer
from test_oracle_openpgp_references import Peer as PgpPeer, sdk_with_errors
from test_oracle_otp_commands import Peer as OtpPeer
from test_oracle_piv_references import Peer as PivPeer
from test_oracle_piv_lifecycle import DEFAULT_KEY


class Hid(TokenPeer):
    def __init__(self, fault):
        super().__init__()
        self.fault = fault
        self.foreign_card_auth = False

    def transfer(self, command, wire, deadline, observe):
        if wire[0] == 10 and codec.decode(wire[1:]) == {1: 1}:
            status = 0 if self.fault == "fido" and self.foreign_card_auth else 0x36
            output = bytes([status]) + (codec.encode({1: 0, 2: self.limit}) if not status else b"")
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, "success" if not status else "applet_error", status)
        if wire[0] == 0x41:
            fields = codec.decode(wire[1:])
            assert fields[1] == 7
            message = b"\xff" * 32 + bytes([0x41, 7])
            status = 0 if fields[4] == self.mac(message) and self.permissions & 32 else 0x33
            output = bytes([status]) + (codec.encode({1: 0, 2: 0, 3: bytes(32), 4: b""}) if not status else b"")
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, "success" if not status else "applet_error", status)
        return super().transfer(command, wire, deadline, observe)


class Card:
    layer = "pcsc_apdu"

    def __init__(self, hid, fault):
        self.hid, self.fault, self.applet = hid, fault, None
        self.piv, self.openpgp, self.oath, self.otp = PivPeer(), PgpPeer(), OathPeer(), OtpPeer()
        class Management(ManagementPeer):
            def write(inner, writer, wire):
                if fault == "management" and inner.lock:
                    values = dict(codec.parse_tlv(wire))
                    values[11] = inner.lock
                    wire = b"".join(codec.tlv(tag, value) for tag, value in values.items())
                return super().write(writer, wire)
        self.management = Management(False, None)

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        selected = False
        if ins == 0xa4 and p1 == 4:
            applet = next(key for key, aid in AIDS.items() if aid.startswith(body) or body.startswith(aid))
            selected = applet != self.applet
            if selected:
                if self.applet == "piv":
                    self.piv.has_pin = self.piv.has_management = False
                elif self.applet == "openpgp":
                    self.openpgp.grants.clear()
                elif self.applet == "oath":
                    self.oath.validated, self.oath.pin_verified = self.oath.code is None, False
            self.applet = applet
        reply = getattr(self, self.applet).transfer(wire, deadline, observe)
        if selected and self.fault == self.applet:
            if self.applet == "piv":
                self.piv.has_pin = self.piv.has_management = True
            elif self.applet == "openpgp":
                self.openpgp.grants = {0x81, 0x82, 0x83}
            elif self.applet == "oath":
                self.oath.validated = self.oath.pin_verified = True
        if reply.status == 0x9000 and ins in (0x20, 0x87, 0xa3, 0xb2, 1, 0x1c):
            self.hid.foreign_card_auth = True
        return reply


@pytest.mark.parametrize("fault,needle", [(None, None), ("piv", "foreign applet cannot authorize"),
    ("openpgp", "reference status query"), ("oath", "foreign applet cannot grant"),
    ("fido", "foreign applet cannot grant missing"), ("management", "configuration lock")])
def test_every_foreign_authority_has_populated_target_and_own_authority_controls(tmp_path, monkeypatch, fault, needle):
    from yubikit import openpgp
    hid = Hid(fault)
    card = Card(hid, fault)
    trace = Trace(tmp_path / "cross-auth", {})
    session = Session(trace, hid=hid, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", piv_pin="123456", management_key=DEFAULT_KEY, openpgp_pin="123456", openpgp_admin="12345678",
        allow_effects=("config_change", "pin_change", "applet_reset")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["cross-authorization"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert len(trace.cases) == 60 and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert not hid.records and not card.piv.keys and not card.openpgp.keys and not card.oath.records and not card.otp.slots and card.management.lock is None
