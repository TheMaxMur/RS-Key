# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Unknown writes distinguish private slot identities and complete locked configs."""
import pytest

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_expanded import apdu_parts
from test_oracle_otp_commands import Peer as Slots
from test_oracle_management_state import Peer as Config
from oracle_lib.runner import AIDS


class Card:
    layer = "pcsc_apdu"

    def __init__(self, committed, defect):
        self.committed, self.defect, self.applet = committed, defect, None
        self.otp, self.management, self.losses = Slots(), Config(False, None), []

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins == 0xa4:
            self.applet = next(name for name, aid in AIDS.items() if aid.startswith(body) or body.startswith(aid))
        return getattr(self, self.applet).transfer(wire, deadline, observe)

    def control(self, action, deadline, observe):
        return Reply(b"offline ATR")

    def drop_response(self, wire, deadline, observe):
        self.losses.append(wire)
        observe("tx", wire)
        if self.committed:
            ins, p1, p2, body = apdu_parts(wire)
            old = self.otp.slots.copy()
            result = self.transfer(wire, deadline, lambda *_: None)
            assert result.status == 0x9000
            if self.defect == "half-swap" and self.applet == "otp" and p1 == 6:
                self.otp.slots[body[1] + 2] = old[body[1] + 2]
            if self.defect == "corrupt-code" and self.applet == "otp" and p1 in (1, 3, 4, 5):
                slot = (2 if p1 in (3, 5) else 1) + p2
                if slot in self.otp.slots:
                    value = self.otp.slots[slot]
                    self.otp.slots[slot] = value[:38] + b"wrong!" + value[44:]
            if self.defect == "partial-configuration" and self.applet == "management" and self.management.lock:
                self.management.original[8] = b"\x23"
        raise TransferError("offline response loss", Outcome.CANCELLED, protocol="injected_response_loss")


@pytest.mark.parametrize("committed,defect,needle", [(False, None, None), (True, None, None),
    (True, "half-swap", "complete OTP swap pair"), (True, "corrupt-code", "complete old or new access code"),
    (True, "partial-configuration", "whole management configuration")])
def test_unknown_slot_and_configuration_mutations(tmp_path, committed, defect, needle):
    trace = Trace(tmp_path / "unknown-slots", {})
    card = Card(committed, defect)
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True,
        allow_effects=("otp_extra_slots", "otp_both_slots", "config_change", "session_recovery")))
    oracle.execute(session, ["unknown-slots"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:30]
    else:
        assert len(trace.cases) == 30 and all(row["verdict"] == "pass" for row in trace.cases), failures[:30]
        assert len(card.losses) == 30 and not card.otp.slots and card.management.lock is None
