# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Foreign cancellation must leave actual private owners pending and usable."""
import pytest

import oracle
from oracle_lib import cross_presence
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_oath_presence import Peer as Oath
from test_oracle_openpgp_uif import Peer as Pgp
from test_oracle_openpgp_references import sdk_with_errors
from test_oracle_otp_commands import Peer as Otp
from test_oracle_otp_waits import Features as OtpFeatures
from test_oracle_piv_policies import Peer as Piv
from test_oracle_piv_lifecycle import DEFAULT_KEY


class Hid:
    layer, cid = "hid_report", b"\x01\x02\x03\x04"
    descriptor = {"serial_number": "offline-scopes"}
    on_keepalive = on_report = None
    pending = cancelled = False

    def __init__(self, defect):
        self.defect = defect

    def send_only(self, frames, deadline, observe):
        for frame in frames:
            assert frame[4] == 0x91
            observe("tx", frame)
        if self.pending:
            self.cancelled = True
        if self.defect == "HID-cancels-CCID" and self.card.pending:
            self.card.cancelled = True
        if self.defect == "HID-cancels-OTP":
            self.otp.pending = None
        return Reply(b"", "no_response_expected")

    def transfer(self, command, wire, deadline, observe):
        observe("tx", wire)
        if command == 1:
            observe("rx", wire)
            return Reply(wire)
        assert wire == b"\x0b"
        self.pending, self.cancelled = True, False
        for _ in range(4):
            self.on_keepalive(2, self.session.trace.now())
            if self.cancelled:
                break
        self.pending = False
        observe("rx", b"\x2d")
        return Reply(b"\x2d", "applet_error", 0x2d)


class Card:
    layer, on_extension = "pcsc_apdu", None
    pending = cancelled = False
    descriptor = {"serial_number": "offline-scopes", "interface_number": 0}

    def __init__(self, hid):
        self.hid, self.applet = hid, None
        self.piv, self.openpgp, self.oath, self.otp = Piv(), Pgp(), Oath(), Otp()

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0xa4 and p1 == 4:
            self.applet = next(key for key, aid in AIDS.items() if aid.startswith(data) or data.startswith(aid))
        target = getattr(self, self.applet)
        gated = self.applet == "piv" and ins == 0x87 and p2 == 0x82 or self.applet == "openpgp" and ins == 0x2a or self.applet == "oath" and ins == 0xa2 or self.applet == "otp" and ins == 1 and p1 == 0x30
        if gated and self.on_extension is not None:
            self.pending, self.cancelled = True, False
            self.on_extension(bytes.fromhex("80000000000001800000"))
            self.pending = False
            if self.cancelled:
                sw = 0x6600 if self.applet == "openpgp" else 0x6982
                output = sw.to_bytes(2, "big")
                observe("tx", wire)
                observe("rx", output)
                return Reply(output, "applet_error", sw)
        return target.transfer(wire, deadline, observe)

    def usb_control(self, request_type, request, value, index, data, deadline, observe):
        if self.hid.defect == "CCID-cancels-FIDO" and self.hid.pending:
            self.hid.cancelled = True
        if self.hid.defect == "CCID-cancels-OTP":
            self.hid.otp.pending = None
        observe("tx", data)
        return Reply(b"", "transport_error", "USB_STALL")


class Features(OtpFeatures):
    descriptor = Hid.descriptor

    def __init__(self, peer, hid):
        super().__init__(peer)
        self.hid = hid

    def raw_feature(self, report, deadline, observe):
        if report is not None and (report[-1] == 255 or report[-1] & 128 and report[-1] & 31 > 9):
            if self.hid.defect == "OTP-cancels-CCID" and self.hid.card.pending:
                self.hid.card.cancelled = True
            if self.hid.defect == "OTP-cancels-FIDO" and self.hid.pending:
                self.hid.cancelled = True
        return super().raw_feature(report, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("HID-cancels-CCID", "ApduError"),
    ("OTP-cancels-CCID", "ApduError"), ("OTP-cancels-FIDO", "owner waiting for its own cancel"),
    ("CCID-cancels-FIDO", "owner waiting for its own cancel"),
    ("HID-cancels-OTP", "cannot end or reveal"), ("CCID-cancels-OTP", "cannot end or reveal")])
def test_all_cross_transport_cancel_pairs_with_populated_owners(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    hid = Hid(defect)
    card = Card(hid)
    otp = Features(card.otp, hid)
    hid.card, hid.otp = card, otp
    trace = Trace(tmp_path / "presence-scopes", {})
    session = Session(trace, hid=hid, card=card, otp_hid=otp, profile="rsk", options=Options(exercise=True, touch=True,
        operator=True, piv_pin="123456", management_key=DEFAULT_KEY, openpgp_pin="123456", openpgp_admin="12345678",
        allow_effects=("config_change",)))
    hid.session = session
    session.values["same_instance_confirmed"] = True
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    def operator(session, action):
        card.piv.presence = card.openpgp.presence = card.oath.present = card.otp.presence = action.startswith("confirm")
    monkeypatch.setattr(cross_presence, "cue", operator)
    oracle.execute(session, ["cross-presence"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert len(trace.cases) == 12 and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert not card.piv.keys and not card.openpgp.keys and not card.oath.records and not card.otp.slots
