# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Independent raw/live LED peers falsify normalization, gates and persistence."""
import pytest

import oracle
from oracle_lib import binding, codec, vendor_records
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_config_matrix import Peer as PinPeer
from test_oracle_expanded import apdu_parts
from test_oracle_rescue_presence import Card as KeyCard


def rendered(raw):
    defaults = [bytes([1, 2, 16, 0]), bytes([3, 2, 16, 0]), bytes([2, 4, 16, 0]), bytes([4, 1, 16, 0])]
    states = [bytearray(raw[index:index + 4]) for index in (1, 5, 9, 13)]
    for state in states:
        state[1] %= 8
    states[2][1] = states[2][1] or 4
    states[2][2] = max(states[2][2], 8)
    if states[2][3] == 1:
        states[2][3] = 2
    if any(states[2][1] == states[index][1] == defaults[index][1] for index in (0, 1, 3)):
        states[2] = bytearray(defaults[2])
    for index in (0, 1, 3):
        if states[index][1] == states[2][1]:
            states[index] = bytearray(defaults[index])
    return bytes([int(raw[0] != 0)]) + b"".join(states)


class Card(KeyCard):
    emulated = True

    def __init__(self, strict, fault):
        super().__init__(None)
        self.strict, self.fault = strict, fault
        self.raw = bytes([0, 1, 2, 16, 0, 3, 2, 16, 0, 2, 4, 16, 0, 4, 1, 16, 0])
        self.live = rendered(self.raw)

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        if self.selected != "vendor" or ins not in (0x10, 0x11):
            return super().transfer(wire, deadline, observe)
        status, body = 0x9000, b""
        if ins == 0x11:
            body = self.live
        elif self.management.lock is not None:
            status = 0x6986
        elif self.strict and not self.confirmed:
            status = 0x6982
        else:
            value = bytearray(self.live)
            value[0] = bool(p2 & 8)
            start = 1 + ((p2 >> 4) & 3) * 4
            value[start + 1], value[start + 2] = p2 & 7, p1
            if self.fault != "atomic-SET-LED":
                value = bytearray(rendered(bytes(value)))
            if data:
                value[start] = data[0]
                if self.fault != "atomic-SET-LED":
                    value = bytearray(rendered(bytes(value)))
            if len(data) >= 2:
                value[start + 3] = data[1]
            self.raw = self.live = rendered(bytes(value))
        output = body + status.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if status == 0x9000 else "applet_error", status)

    def control(self, action, deadline, observe):
        if self.fault == "reconnect-loses-LED":
            self.raw = bytes(17)
        self.live = rendered(self.raw)
        return Reply(b"offline ATR")


class Hid(PinPeer):
    def __init__(self, card):
        super().__init__()
        self.card = card

    def transfer(self, command, wire, deadline, observe):
        if wire[0] != 0x41:
            return super().transfer(command, wire, deadline, observe)
        fields = codec.decode(wire[1:])
        sub, parameters = fields[1], fields.get(2, {})
        target, status, result = parameters.get(1, 0), 0, {}
        if sub == 13:
            result = {1: self.card.raw if target == 2 else b"\x06\x02\x00\x00\x0b\x01\x1f"}
        else:
            assert sub == 12
            data = parameters.get(2, b"")
            if self.card.strict:
                payload = b"\xff" * 32 + b"\x41\x0c" + codec.encode(parameters)
                if 3 in fields and fields[3] not in (1, 2):
                    status = 2
                elif 4 not in fields:
                    status = 0x36
                elif 3 not in fields:
                    status = 0x14
                elif fields[4] != self.mac(payload) or not self.permissions & 32:
                    status = 0x33
            if status:
                pass
            elif self.card.strict and not self.card.confirmed and self.card.fault != "strict-consent-bypass":
                status = 0x27
            elif target == 0:
                assert parameters[2] == codec.tlv(8, self.card.management.original[8])
            elif target not in (1, 2):
                status = 2
            elif target == 2 and len(data) < 17:
                status = 3
            elif self.card.management.lock is not None and self.card.fault != "LED-lock-bypass":
                status = 0x30
            elif target == 2:
                if self.card.fault == "rejects-LED-tail" and len(data) > 17:
                    status = 3
                else:
                    self.card.raw, self.card.live = data[:17], rendered(data[:17])
                    if self.card.fault == "stores-live-instead-of-raw":
                        self.card.raw = self.card.live
        output = bytes([status]) + (codec.encode(result) if status == 0 else b"")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if status == 0 else "applet_error", status)


@pytest.mark.parametrize("strict,fault,needle", [(False, None, None), (True, None, None),
    (False, "stores-live-instead-of-raw", "retains raw input bytes"), (True, "strict-consent-bypass", "defined precedence"),
    (False, "LED-lock-bypass", "defined precedence"), (False, "rejects-LED-tail", "ignores its tail"),
    (False, "atomic-SET-LED", "optional effect/speed"),
    (False, "reconnect-loses-LED", "survives the connection action")])
def test_vendor_raw_live_LED_lengths_all_parameter_bits_gates_and_lifetimes(tmp_path, monkeypatch, strict, fault, needle):
    card = Card(strict, fault)
    original = card.raw
    trace = Trace(tmp_path / "vendor-records", {})
    session = Session(trace, card=card, hid=Hid(card), profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        timeout=131, pin="fixture-PIN", features=("display", "strict-config") if strict else ("display",), allow_effects=("config_change", "reboot")))
    monkeypatch.setattr(binding, "check_pair", lambda session: session.values.update(same_instance_confirmed=True))
    original_cue = vendor_records.cue
    def cue(session, mode):
        card.confirmed = card.management.confirmed = mode == "accept"
        original_cue(session, mode)
    monkeypatch.setattr(vendor_records, "cue", cue)
    oracle.execute(session, ["vendor-records"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert card.raw == original and card.live == rendered(original) and card.management.lock is None
