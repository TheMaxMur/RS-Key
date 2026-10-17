# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OTP state cases verify secrets after updates, swaps, and refused writes."""
import hmac

import pytest

import oracle
from oracle_lib import codec
from oracle_lib.otp import crc16
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace


class SlotPeer:
    layer = "pcsc_apdu"

    def __init__(self, defect=None):
        self.defect = defect
        self.slots = {}
        self.sequence = 0

    def status(self):
        bits = sum(1 << (slot - 1) for slot in (1, 2) if slot in self.slots)
        return b"\x05\x08\x00" + bytes([self.sequence & 255, bits, 0])

    def transfer(self, request, deadline, observe):
        observe("tx", request)
        ins, command, offset = request[1:4]
        data = request[5:5 + request[4]] if len(request) > 4 else b""
        status, body = 0x9000, b""
        if ins == 0xA4:
            body = self.status()
        elif command in (1, 3, 4, 5):
            slot = (2 if command in (3, 5) else 1) + offset
            previous = self.slots.get(slot)
            config, presented = data[:52], data[52:58]
            if previous is not None and presented != previous[38:44]:
                status = 0x6982
            elif not any(config):
                self.slots.pop(slot, None)
            elif len(config) != 52 or crc16(config) != 0xF0B8:
                if self.defect != "CRC-accepted":
                    status = 0x6101 if self.defect == "CRC-continuation" else 0x6A80
            elif command in (4, 5) and previous is not None:
                value = bytearray(config)
                if self.defect != "UPDATE-replaces-key":
                    value[:38] = previous[:38]
                    value[44], value[46], value[47] = previous[44], previous[46], previous[47]
                self.slots[slot] = bytes(value)
            else:
                self.slots[slot] = config
            if status == 0x9000:
                self.sequence += 1
                body = self.status()
        elif command in (0x30, 0x38):
            slot = (1 if command == 0x30 else 2) + offset
            config = self.slots.get(slot)
            if config is None:
                status = 0x6985
            else:
                key = config[22:38] + config[16:20]
                body = hmac.digest(key, data, "sha1")
        elif command == 6:
            if self.defect != "SWAP-noop":
                first, second = self.slots.pop(1, None), self.slots.pop(2, None)
                if first:
                    self.slots[2] = first
                if second:
                    self.slots[1] = second
            body = self.status()
        elif command == 0x14:
            body = b"".join(codec.tlv(0xB0 + slot - 1, b"\xa0\x02" + config[46:48]) for slot, config in self.slots.items())
        else:
            raise AssertionError(f"unexpected OTP command {command:02x}")
        response = body + status.to_bytes(2, "big")
        observe("rx", response)
        return Reply(response, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("defect,assertion", [(None, None), ("CRC-accepted", "bad config CRC refused"),
    ("CRC-continuation", "bad config CRC refused"), ("UPDATE-replaces-key", "UPDATE preserves original secret"),
    ("SWAP-noop", "key moved to other slot")])
def test_OTP_state_checks_run_through_dispatch_and_notice_the_defect(tmp_path, defect, assertion):
    trace = Trace(tmp_path / "slots", {})
    peer = SlotPeer(defect)
    session = Session(trace, card=peer, profile="rsk",
                      options=Options(exercise=True, allow_effects=("otp_both_slots", "otp_extra_slots")))
    oracle.execute(session, ["otp-states"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if assertion is None:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases)
    else:
        assert any(assertion in row["reason"] for row in failures), failures
    assert not peer.slots
