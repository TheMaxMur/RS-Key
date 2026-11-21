# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Admin sequence/ACL and persisted scan maps use independent keyboard output."""
import pytest

import oracle
from oracle_lib import keyboard, otp_admin_matrix
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_keyboard_counters import Peer as CounterPeer, Keyboard
from test_oracle_otp_commands import Features


class Peer(CounterPeer):
    def __init__(self, strict, defect):
        super().__init__()
        self.strict, self.fault, self.map = strict, defect, None
        self.admin = {}

    def execute(self, command, offset, body):
        if command not in (8, 9, 0x11, 0x12):
            return super().execute(command, offset, body)
        if self.strict and self.fault != "strict-admin-bypass":
            return 0x9000, b""
        if command == 0x12 and len(body) < 45 or not body:
            return 0x9000, b""
        if command != 0x11:
            width = 45 if command == 0x12 else 64
            code = body[width:width + 6] if len(body) >= width + 6 else bytes(6)
            checks = [value[38:44] == code for value in self.slots.values()]
            if not (any(checks) if self.fault == "one-slot-authorizes-global" else all(checks)):
                return 0x6982, b""
        width = 45 if command == 0x12 else 4 if command == 0x11 else 64
        self.admin[command] = body[:width]
        if command == 0x12:
            self.map = body[:45]
        self.sequence += 1
        return 0x9000, b""

    def control(self, action, deadline, observe):
        result = super().control(action, deadline, observe)
        if self.fault == "volatile-scan-map":
            self.map = None
        return result

    def typed(self, slot):
        text = super().typed(slot)
        if self.map is not None:
            result = []
            for char in text:
                code = self.map[otp_admin_matrix.CHARSET.index(char)]
                value = keyboard.US[code & 127]
                result.append(value.upper() if code & 128 else value)
            return "".join(result)
        return text


@pytest.mark.parametrize("strict,defect,needle", [(False, None, None), (True, None, None),
    (False, "one-slot-authorizes-global", "exact applet status"), (True, "strict-admin-bypass", "admin sequence"),
    (False, "volatile-scan-map", "remains effective after the connection")])
def test_admin_lengths_all_slot_codes_strict_profile_and_map_persistence(tmp_path, monkeypatch, strict, defect, needle):
    peer = Peer(strict, defect)
    trace = Trace(tmp_path / "OTP-admin", {})
    session = Session(trace, card=peer, otp_hid=Features(peer), profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        features=("strict-config",) if strict else (), allow_effects=("config_change", "otp_both_slots", "otp_extra_slots", "reboot")))
    session.keyboard = Keyboard(peer, trace)
    monkeypatch.setattr(keyboard, "gesture", lambda session, slot: setattr(peer, "selected_slot", slot) or f"offline slot {slot}")
    if defect == "volatile-scan-map":
        monkeypatch.setattr(otp_admin_matrix, "grammar", lambda session: None)
    elif defect:
        monkeypatch.setattr(otp_admin_matrix, "scan_persistence", lambda session: None)
    oracle.execute(session, ["otp-admin-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:30]
    else:
        assert trace.cases and all(row["verdict"] == "pass" or row["applicability"] == "excluded_by_mode" for row in trace.cases), failures[:30]
        assert not peer.slots
