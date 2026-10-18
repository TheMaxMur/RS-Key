# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Shared interfaces expose stale status, disabled dispatch and actual HOTP state."""
import pytest

import oracle
from oracle_lib import codec, keyboard, otp_disabled
from oracle_lib.otp import crc16
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_expanded import apdu_parts
from test_oracle_keyboard_counters import Peer as CounterPeer, Keyboard as CounterKeyboard
from test_oracle_management_matrix import DeviceInfoPeer
from test_oracle_otp_commands import Features


class Peer(CounterPeer):
    def __init__(self, defect=None):
        super().__init__()
        self.fault, self.selected = defect, "otp"
        self.management = DeviceInfoPeer()
        self.management.original[2] = b"\x00\x00\x00\x17"
        self.cached = self.status()

    @property
    def enabled(self):
        return bool(int.from_bytes(self.management.original[3], "big") & 1)

    def transfer(self, *args):
        if len(args) == 4:
            previous = self.enabled
            reply = self.management.transfer(*args)
            if previous and not self.enabled and self.fault == "disable-deletes-slots":
                self.slots.clear()
            return reply
        wire, deadline, observe = args
        ins, p1, p2, data = apdu_parts(wire)
        if ins == 0xa4:
            name = next((name for name, aid in AIDS.items() if aid == data), None)
            if name == "otp" and not self.enabled:
                output = b"\x6a\x82"
            elif name == "otp":
                self.selected = name
                return super().transfer(wire, deadline, observe)
            else:
                self.selected, output = name, b"\x90\x00"
        elif self.selected == "management":
            return self.management.reply("card", "read" if ins == 0x1d else "write", b"" if ins == 0x1d else data[1:1 + data[0]], observe)
        elif self.selected == "otp" and (self.enabled or self.fault == "card-dispatch-bypass"):
            return super().transfer(wire, deadline, observe)
        else:
            output = b"\x6d\x00"
        observe("tx", wire)
        observe("rx", output)
        sw = int.from_bytes(output[-2:], "big")
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


class Otp(Features):
    def transfer(self, command, data, expected, deadline, observe):
        if command == -1:
            observe("rx", self.peer.cached)
            return Reply(self.peer.status() if self.peer.fault == "invented-live-cache" else self.peer.cached)
        if command == 0x13:
            body = self.peer.management.read()
            body += (~crc16(body) & 65535).to_bytes(2, "little")
            body = body.ljust(((len(body) + 6) // 7) * 7, b"\x00")
            reply = Reply(body)
        elif command == 0x15:
            accepted = self.peer.management.write("otp", data[1:1 + data[0]])
            if accepted:
                self.peer.sequence += 1
            reply = Reply(self.peer.status()) if accepted else Reply(b"", "applet_error", "CommandRejectedError")
        elif not self.peer.enabled and command in otp_disabled.FUNCTIONS and self.peer.fault != "feature-dispatch-bypass":
            reply = Reply(b"", "applet_error", "CommandRejectedError")
        else:
            reply = super().transfer(command, data, expected, deadline, observe)
        self.peer.cached = self.peer.status()
        if self.peer.fault == "disabled-hidden-mutation" and not self.peer.enabled and command in (1, 3):
            self.peer.slots.clear()
        return reply


class Keyboard(CounterKeyboard):
    def reports(self, deadline, emit):
        if not self.peer.enabled:
            if self.peer.fault == "disabled-types":
                return super().reports(deadline, emit)
            if self.peer.fault == "disabled-advances-counter":
                self.peer.typed(self.peer.selected_slot)
            raise TransferError("offline observed silent keyboard window", Outcome.DEADLINE)
        return super().reports(deadline, emit)


@pytest.mark.parametrize("defect,needle", [(None, None), ("card-dispatch-bypass", "immediately blocks card dispatch"),
    ("feature-dispatch-bypass", "feature functions are inert"), ("disable-deletes-slots", "sequence, occupancy or touch flags"),
    ("disabled-hidden-mutation", "sequence, occupancy or touch flags"), ("invented-live-cache", "does not invent a live refresh"),
    ("disabled-types", "emit no keyboard report"), ("disabled-advances-counter", "exact persisted moving factor")])
def test_disabling_all_OTP_functions_preserves_keys_counters_and_identify_routes(tmp_path, monkeypatch, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "OTP-disabled", {})
    session = Session(trace, card=peer, hid=peer, otp_hid=Otp(peer), profile="rsk",
        options=Options(exercise=True, touch=True, operator=True, allow_effects=("config_change", "otp_both_slots", "otp_extra_slots")))
    session.keyboard = Keyboard(peer, trace)
    session.values.update({"same_instance_confirmed": True, "fido.info": {4: {"clientPin": False}}})
    monkeypatch.setattr(keyboard, "gesture", lambda session, slot: setattr(peer, "selected_slot", slot) or f"offline slot {slot}")
    oracle.execute(session, ["otp-disabled"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures
        assert not peer.slots and peer.enabled
