# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A slot model independently checks every mode/flag route with real crypto."""
import hmac

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import oracle
from oracle_lib import codec
from oracle_lib.otp import crc16
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts


class Peer:
    layer, emulated = "pcsc_apdu", True
    presence = True

    def __init__(self, defect=None):
        self.defect, self.slots, self.sequence = defect, {}, 0

    @staticmethod
    def challenge(config):
        ticket, flags = config[46:48]
        return bool(ticket & 64 and (flags & 0x22 == 0x22 or flags & 0x20 and not flags & 2))

    def status(self):
        flags = 0
        for slot in (1, 2):
            config = self.slots.get(slot)
            if config is not None:
                flags |= 1 << (slot - 1)
                if not self.challenge(config) or config[47] & 8:
                    if self.defect != "status-omits-touch":
                        flags |= 4 << (slot - 1)
        return b"\x05\x08\x00" + bytes([self.sequence & 255, flags, 0])

    def execute(self, command, offset, body):
        if command == 0x10:
            return 0x9000, b"\x00\x00\x00\x17"
        if command == 6:
            if len(body) not in (0, 2, 6, 8):
                return 0x6700, b""
            a, b = (body[0] + 1, body[1] + 2) if len(body) in (2, 8) else (1, 2)
            if a > 4 or b > 4:
                return 0x6a86, b""
            presented = body[-6:] if len(body) in (6, 8) else bytes(6)
            previous = {slot: self.slots.get(slot) for slot in (a, b)}
            if self.defect != "SWAP-code-bypass" and any(config is not None and config[38:44] != presented for config in previous.values()):
                return 0x6982, b""
            if self.defect != "SWAP-noop":
                for slot, config in ((a, previous[b]), (b, previous[a])):
                    if config is None:
                        self.slots.pop(slot, None)
                    else:
                        self.slots[slot] = config
            self.sequence += 1
            return 0x9000, self.status()
        if command in (4, 5):
            slot = (1 if command == 4 else 2) + offset
            if command == 5 and offset or slot > 4:
                return 0x6a86, b""
            config = body[:52]
            if len(config) != 52 or config[48:50] != bytes(2) or crc16(config) != 0xf0b8:
                return 0x6700, b""
            previous = self.slots.get(slot)
            if previous is not None:
                if len(body) < 58:
                    return 0x6700, b""
                if body[52:58] != previous[38:44]:
                    return 0x6982, b""
                value = bytearray(config)
                if self.defect != "UPDATE-replaces-secret":
                    value[:38] = previous[:38]
                value[44] = previous[44]
                value[46] = previous[46] & 0xc0 | config[46] & 0x3f
                value[47] = previous[47] if previous[46] & 64 else previous[47] & 0xf3 | config[47] & 0x0c
                self.slots[slot] = bytes(value)
                self.sequence += 1
            return 0x9000, self.status()
        if command in (1, 3):
            if command == 3 and offset or (1 if command == 1 else 2) + offset > 4:
                return 0x6a86, b""
            slot = (1 if command == 1 else 2) + offset
            if len(body) < 52:
                return 0x6700, b""
            config, previous = body[:52], self.slots.get(slot)
            if previous is not None:
                if len(body) < 58:
                    return 0x6700, b""
                if body[52:58] != previous[38:44]:
                    return 0x6982, b""
            if any(config):
                if config[48:50] != bytes(2) or crc16(config) != 0xf0b8:
                    return 0x6700, b""
                self.slots[slot] = config
            else:
                self.slots.pop(slot, None)
            self.sequence += 1
            return 0x9000, self.status()
        if command == 0x14:
            output = []
            for slot, config in sorted(self.slots.items()):
                fields = codec.tlv(0xa0, config[46:48])
                if not config[46] & 64 and not config[47] & 0x22:
                    fields += codec.tlv(0xc0, config[:6])
                output.append(codec.tlv(0xaf + slot, fields))
            return 0x9000, b"".join(output)
        if command in (0x20, 0x28, 0x30, 0x38):
            if command in (0x28, 0x38) and offset:
                return 0x6a86, b""
            slot = (2 if command in (0x28, 0x38) else 1) + offset
            if slot > 4:
                return 0x6a86, b""
            config = self.slots.get(slot)
            if config is None:
                return 0x9000, b""
            if not self.challenge(config) and self.defect != "typing-slot-leaks-HMAC":
                return 0x6700, b""
            if config[47] & 8 and not self.presence and self.defect != "touch-bypass":
                return 0x6985, b""
            if command in (0x30, 0x38):
                if config[47] & 0x22 != 0x22 and self.defect != "typing-slot-leaks-HMAC":
                    return 0x6700, b""
                if len(body) < 64:
                    return 0x6700, b""
                challenge = body if self.defect == "HMAC-includes-trailing-data" else body[:64]
                if config[47] & 4:
                    challenge = challenge[:-1] if self.defect == "trim-only-one-padding-byte" else challenge.rstrip(challenge[-1:])
                key = config[22:38] + config[16:22]
                if self.defect == "HMAC-key-corrupt":
                    key = bytes(len(key))
                return 0x9000, hmac.digest(key, challenge, "sha1")
            if not config[47] & 0x20 or config[47] & 2 or len(body) < 6:
                return 0x6700, b""
            worker = Cipher(algorithms.AES(config[22:38]), modes.ECB()).encryptor()
            return 0x9000, worker.update(body[:6] + b"0011223344") + worker.finalize()
        if self.defect == "unknown-command-changes-secret" and 1 in self.slots:
            value = self.slots[1]
            self.slots[1] = value[:22] + bytes(16) + value[38:]
        return 0x9000, b""

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        if ins == 0xa4:
            self.sequence = int(1 in self.slots or 2 in self.slots)
            status, result = 0x9000, self.status()
        elif ins == 3:
            status, result = 0x9000, self.status()
        elif ins == 1:
            status, result = self.execute(p1, p2, body)
        else:
            status, result = 0x6d00, b""
        response = result + status.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", response)
        return Reply(response, "success" if status == 0x9000 else "applet_error", status)

    def control(self, action, deadline, observe):
        self.sequence = int(1 in self.slots or 2 in self.slots)
        if self.defect == "connection-forgets-access-code":
            self.slots = {slot: value[:38] + bytes(6) + value[44:] for slot, value in self.slots.items()}
        return Reply(b"synthetic ATR")


class Features:
    layer, broken = "otp_hid_feature", False

    def __init__(self, peer):
        self.peer = peer

    def reopen(self, operator=False):
        return {"path_hex": "00", "serial_number": "offline-OTP-fixture"}

    def transfer(self, command, body, expected_len, deadline, observe):
        observe("tx", bytes([command & 255]) + body)
        if command == -1:
            output = self.peer.status()
        else:
            before = self.peer.sequence & 255
            sw, output = self.peer.execute(command, 0, body.ljust(64, b"\x00"))
            if command in (1, 3, 4, 5, 6):
                current = self.peer.status()
                acknowledged = current[3] == before + 1 or current[3] == 0 and before > 0 and not current[4] & 3
                if not acknowledged:
                    return Reply(b"", "applet_error", "CommandRejectedError")
                output = current
            if sw != 0x9000 or not output and before == self.peer.sequence & 255:
                return Reply(b"", "applet_error", "CommandRejectedError")
            if command == 0x14:
                output += (~crc16(output) & 65535).to_bytes(2, "little")
                output = output.ljust(((len(output) + 6) // 7) * 7, b"\x00")
        observe("rx", output)
        return Reply(output)


@pytest.mark.parametrize("defect,needle", [(None, None), ("status-omits-touch", "actual slot mode and touch"),
    ("HMAC-key-corrupt", "secret survives exact flag"), ("typing-slot-leaks-HMAC", "exact applet status"),
    ("UPDATE-replaces-secret", "secret survives exact flag")])
def test_slot_mode_flag_products_are_executed_on_both_routes(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "OTP-commands", {})
    session = Session(trace, card=peer, otp_hid=Features(peer), profile="rsk", options=Options(exercise=True, touch=True,
        allow_effects=("otp_extra_slots",)))
    oracle.execute(session, ["otp-commands"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        applicable = [row for row in trace.cases if row["applicability"] != "excluded_by_mode"]
        assert not failures and all(row["verdict"] == "pass" for row in applicable), [(row["scenario_id"], row["reason"]) for row in applicable if row["verdict"] != "pass"]
        assert not peer.slots
