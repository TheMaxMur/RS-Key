# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unavailable read APIs keep unknown outcomes even when neighbors still work."""
import pytest

import oracle
from oracle_lib import keyboard
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_expanded import apdu_parts
from test_oracle_keyboard_counters import Keyboard
from test_oracle_otp_admin_matrix import Peer as Otp
from test_oracle_phy_records import Card as Rescue


class Card:
    layer = "pcsc_apdu"

    def __init__(self, commit, defect):
        self.commit, self.defect, self.applet = commit, defect, None
        self.rescue, self.otp, self.losses = Rescue(), Otp(False, None), []

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins == 0xa4 and p1 == 4:
            self.applet = next(name for name, aid in AIDS.items() if aid.startswith(body) or body.startswith(aid))
        return getattr(self, self.applet).transfer(wire, deadline, observe)

    def control(self, action, deadline, observe):
        self.otp.control(action, deadline, observe)
        return Reply(b"offline ATR")

    def drop_response(self, wire, deadline, observe):
        self.losses.append(wire)
        observe("tx", wire)
        if self.commit:
            reply = self.transfer(wire, deadline, lambda *_: None)
            assert reply.status == 0x9000
            ins, p1, p2, body = apdu_parts(wire)
            if self.defect == "partial-PHY" and self.applet == "rescue" and (ins, p1) == (0x1c, 1):
                self.rescue.fields[15] = b"partial\x00"
            if self.defect == "wrong-RTC" and self.applet == "rescue" and (ins, p1) == (0x1c, 2):
                self.rescue.seconds = 0x11223344
            if self.defect == "RTC-loses-device-key" and self.applet == "rescue" and (ins, p1) == (0x1c, 2):
                from cryptography.hazmat.primitives.asymmetric import ec
                self.rescue.key = ec.generate_private_key(ec.SECP256K1())
            if self.defect == "wrong-scan-map" and self.applet == "otp" and p1 == 0x12:
                self.otp.map = bytes([5]) * 45
        raise TransferError("offline administrative response abandoned", Outcome.CANCELLED, protocol="injected_response_loss")


@pytest.mark.parametrize("commit,defect,needle", [(False, None, None), (True, None, None),
    (True, "partial-PHY", "whole staged PHY record"), (True, "wrong-RTC", "complete old or new running clock"),
    (True, "wrong-scan-map", "whole effective OTP scan map"), (True, "RTC-loses-device-key", "InvalidSignature")])
def test_observable_readbacks_and_explicitly_unknown_opaque_records(tmp_path, monkeypatch, commit, defect, needle):
    card = Card(commit, defect)
    trace = Trace(tmp_path / "unknown-admin", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        allow_effects=("session_recovery", "config_change", "set_rtc", "replace_identity", "otp_both_slots", "otp_extra_slots", "keyboard_output")))
    session.keyboard = Keyboard(card.otp, trace)
    monkeypatch.setattr(keyboard, "gesture", lambda session, slot: setattr(card.otp, "selected_slot", slot) or "offline key press")
    oracle.execute(session, ["unknown-admin"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
        assert session.broken
        if defect == "RTC-loses-device-key":
            assert len(card.losses) == 2
    else:
        assert len(trace.cases) == 7 and not failures, failures
        assert sum(row["verdict"] == "pass" for row in trace.cases) == 3, trace.cases
        assert sum(row["applicability"] == "unknown" for row in trace.cases) == 4, trace.cases
        assert len(card.losses) == 7 and not card.otp.slots
