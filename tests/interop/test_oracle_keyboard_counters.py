# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Actual encrypted tickets and HOTPs witness persistent and RAM counter halves."""
from dataclasses import dataclass
import hmac

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import oracle
from oracle_lib import keyboard
from oracle_lib.otp import crc16
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_otp_commands import Peer as SlotPeer


@dataclass
class Position:
    tail: int = 0
    session: int = 0
    advanced: bool = False


class Peer(SlotPeer):
    selected_slot = 1

    def __init__(self, defect=None):
        super().__init__(defect)
        self.positions = {slot: Position() for slot in range(1, 5)}

    def execute(self, command, offset, body):
        previous = dict(self.slots)
        result = super().execute(command, offset, body)
        if result[0] == 0x9000:
            if command in (1, 3):
                slot = (1 if command == 1 else 2) + offset
                if self.defect != "CONFIGURE-keeps-old-tail":
                    self.positions[slot].tail = 0
            elif command in (4, 5) and self.defect == "UPDATE-resets-tail":
                slot = (1 if command == 4 else 2) + offset
                if slot in previous:
                    self.positions[slot].tail = 0
            elif command == 6:
                a, b = (body[0] + 1, body[1] + 2) if len(body) in (2, 8) else (1, 2)
                self.positions[a], self.positions[b] = self.positions[b], self.positions[a]
                if self.defect == "SWAP-leaves-volatile-position":
                    pa, pb = self.positions[a], self.positions[b]
                    pa.session, pb.session = pb.session, pa.session
                    pa.advanced, pb.advanced = pb.advanced, pa.advanced
        return result

    def control(self, action, deadline, observe):
        result = super().control(action, deadline, observe)
        if action == "power_cycle":
            for position in self.positions.values():
                position.session = 0
                position.advanced = self.defect == "cold-boot-replays-use-counter"
        return result

    def typed(self, slot):
        config, position = self.slots[slot], self.positions[slot]
        if config[46] & 64:
            factor = position.tail or int.from_bytes(config[20:22], "big")
            digest = hmac.digest(config[22:38] + config[16:20], factor.to_bytes(8, "big"), "sha1")
            offset = digest[-1] & 15
            digits = 8 if config[47] & 2 else 6
            value = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 10 ** digits
            position.tail = factor + 1
            text = str(value).zfill(digits)
        else:
            if not position.advanced:
                position.tail = min(position.tail + 1, 32767)
                position.advanced = True
            position.tail = position.tail or 1
            block = config[16:22] + position.tail.to_bytes(2, "little") + bytes(3) + bytes([position.session]) + b"xy"
            block += (~crc16(block) & 65535).to_bytes(2, "little")
            worker = Cipher(algorithms.AES(config[22:38]), modes.ECB()).encryptor()
            encoded = config[:6] + worker.update(block) + worker.finalize()
            alphabet = "cbdefghijklnrtuv"
            text = "".join(alphabet[byte >> 4] + alphabet[byte & 15] for byte in encoded)
            position.session = (position.session + 1) % 256
            if position.session == 0:
                if self.defect != "session-wrap-reuses-use-counter":
                    position.tail = min(position.tail + 1, 32767)
        return text + ("\r" if config[46] & 32 else "")


class Keyboard:
    def __init__(self, peer, trace):
        self.peer, self.trace = peer, trace

    def reopen(self, operator=False):
        return {"path_hex": "00", "serial_number": "offline-keyboard-fixture"}

    def reports(self, deadline, emit):
        text = self.peer.typed(self.peer.selected_slot)
        for char in text:
            code = ord(char) - ord("a") + 4 if "a" <= char <= "z" else 0x27 if char == "0" else int(char) + 29 if char.isdigit() else 0x28
            emit(bytes([0, 0, code, 0, 0, 0, 0, 0]), self.trace.now())
            emit(bytes(8), self.trace.now())


@pytest.mark.parametrize("defect,needle", [(None, None), ("UPDATE-resets-tail", "exact persisted moving factor"),
    ("SWAP-leaves-volatile-position", "exact profiled lifetime"), ("cold-boot-replays-use-counter", "exact profiled lifetime"),
    ("CONFIGURE-keeps-old-tail", "exact persisted moving factor"), ("session-wrap-reuses-use-counter", "exact profiled lifetime")])
def test_typed_counters_update_swap_power_cycle_and_partial_observation(tmp_path, monkeypatch, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "OTP-typed-counters", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, operator=True,
        allow_effects=("otp_both_slots", "otp_extra_slots", "reboot")))
    session.keyboard = Keyboard(peer, trace)
    original = keyboard.gesture
    def operator(session, slot):
        peer.selected_slot = slot
        return original(session, slot)
    monkeypatch.setattr(keyboard, "gesture", operator)
    oracle.execute(session, ["keyboard-counters"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.slots
