# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Shared writer peers falsify lock no-op bypass and absent confirmation."""
import pytest

import oracle
from oracle_lib import codec, management_state
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_management_matrix import DeviceInfoPeer
from test_oracle_states import ManagementOtp


class Peer(DeviceInfoPeer):
    def __init__(self, strict, defect):
        super().__init__()
        self.strict, self.fault, self.confirmed = strict, defect, True

    def write(self, writer, wire):
        values = dict(codec.parse_tlv(wire))
        if self.strict and writer in ("hid", "otp") and self.fault != "strict-OTP-bypass":
            return False
        same = all(self.original.get(tag) == value for tag, value in values.items() if tag != 11)
        if self.lock is not None and values.get(11) != self.lock:
            if not (same and self.fault == "identical-bypasses-lock"):
                return False
        arming = self.lock is None and any(values.get(10, b""))
        if not self.confirmed and (arming or self.strict and writer in ("card", "fido")) and self.fault != "confirmation-bypass":
            return False
        return super().write(writer, wire)


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("defect,needle", [(None, None), ("identical-bypasses-lock", "locked identical write"),
    ("confirmation-bypass", "only confirmed enabled writers"), ("strict-OTP-bypass", "only confirmed enabled writers")])
def test_cross_writer_identical_authorization_and_confirmation(tmp_path, monkeypatch, strict, defect, needle):
    if not strict and defect == "strict-OTP-bypass":
        return
    peer = Peer(strict, defect)
    trace = Trace(tmp_path / "management-state", {})
    session = Session(trace, card=peer, hid=peer, otp_hid=ManagementOtp(peer), profile="rsk",
        options=Options(exercise=True, touch=True, operator=True, timeout=131,
            features=("display", "strict-config") if strict else ("display",), allow_effects=("config_change",)))
    session.values["fido.info"] = {4: {"clientPin": False}}
    original = peer.read()
    original_cue = management_state.cue
    def operator(session, mode):
        peer.confirmed = mode == "accept"
        original_cue(session, mode)
    monkeypatch.setattr(management_state, "cue", operator)
    oracle.execute(session, ["management-state"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert trace.cases and not failures, failures
        assert all(row["verdict"] == "pass" or strict and row["applicability"] == "excluded_by_profile" for row in trace.cases), trace.cases
        assert peer.read() == original and peer.lock is None
