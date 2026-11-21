# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Native USB endpoints wrap a real-key applet peer through control/removal faults."""
import builtins

import pytest
import usb.core
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import usb_ccid, usb_ccid_cases
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_operation_state import Peer as PgpPeer
from test_oracle_openpgp_references import sdk_with_errors
from test_oracle_usb_ccid import DESCRIPTOR, Device, Endpoint, install, response


class BridgeEndpoint(Endpoint):
    def write(self, wire, timeout):
        if self.device.removed:
            raise usb.core.USBError("selected test device removed", error_code=-4, errno=19)
        self.device.writes.append((bytes(wire), timeout))
        sequence, kind = wire[6], 0x80 if wire[0] in (0x62, 0x6f) else 0x81
        if wire[0] == 0x6f:
            apdu = bytes(wire[10:])
            ins, p1, p2, _ = apdu_parts(apdu)
            uif = self.device.peer.data[0xd6]
            if ins == 0x2a and (p1, p2) == (0x9e, 0x9a) and uif and uif[0]:
                self.device.pending = (sequence, apdu)
                self.device.cancelled = False
                self.device.enqueue(response(0x80, sequence, b"", 0x80))
                return len(wire)
            result = self.device.execute(apdu)
        else:
            self.device.peer.control("card_reset", 0, lambda *args: None)
            result = b"\x3b\x00" if wire[0] == 0x62 else b""
        self.device.enqueue(response(kind, sequence, result))
        return len(wire)

    def read(self, size, timeout):
        if self.device.removed:
            raise usb.core.USBError("selected test device removed", error_code=-4, errno=19)
        if not self.device.queue and self.device.pending is not None:
            sequence, apdu = self.device.pending
            self.device.pending = None
            body = b"\x66\x00" if self.device.cancelled else self.device.execute(apdu)
            self.device.enqueue(response(0x80, sequence, body))
        return super().read(size, timeout)


class Bridge(Device):
    def __init__(self, peer, fault):
        super().__init__()
        self.peer, self.fault = peer, fault
        self.removed, self.cancelled, self.repeat_next = False, False, False
        self.pending = None
        self.configuration.interface.endpoints = [BridgeEndpoint(self, 0x81), BridgeEndpoint(self, 0x02)]

    def enqueue(self, wire):
        self.queue.extend(wire[offset:offset + 64] for offset in range(0, len(wire), 64))

    def execute(self, apdu):
        result = self.peer.transfer(apdu, 0, lambda *args: None).data
        if self.repeat_next and self.fault == "lost-operation-replayed":
            self.peer.transfer(apdu, 0, lambda *args: None)
        self.repeat_next = False
        return result

    def ctrl_transfer(self, *args, **kwargs):
        if self.fault == "ABORT-cancels-current-command" and self.pending:
            self.cancelled = True
        if self.fault == "stalled-control-revokes-PW1":
            self.peer.grants.discard(0x81)
        return super().ctrl_transfer(*args, **kwargs)


@pytest.mark.parametrize("fault,needle", [(None, None), ("ABORT-cancels-current-command", "raw signature input has the exact"),
    ("stalled-control-revokes-PW1", "raw signature input has the exact"), ("removal-replaces-private-key", "InvalidSignature"),
    ("lost-operation-replayed", "at most one committed counter")])
def test_native_USB_ABORT_wait_removal_and_lost_response_have_retained_key_controls(tmp_path, monkeypatch, fault, needle):
    from yubikit import openpgp
    peer = PgpPeer()
    device = Bridge(peer, fault)
    install(monkeypatch, device)
    monkeypatch.setattr(usb_ccid, "inventory", lambda: {"interfaces": [dict(DESCRIPTOR)], "errors": []})
    trace = Trace(tmp_path / "USB-CCID-cases", {})
    card = usb_ccid.UsbCard(DESCRIPTOR, trace.now, backend=device, operator=True)
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, operator=True,
        openpgp_pin="123456", openpgp_admin="12345678", allow_effects=("config_change", "reboot")))
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    def cue(session, action):
        peer.presence = action == "accept"
    monkeypatch.setattr(usb_ccid_cases, "cue", cue)
    monkeypatch.setattr(usb_ccid_cases, "remove", lambda session: setattr(device, "removed", True))
    def operator(prompt):
        assert "unplug and replug" in prompt
        device.removed, device.pending, device.queue = False, None, []
        peer.control("power_cycle", 0, lambda *args: None)
        if fault == "removal-replaces-private-key":
            peer.keys[1] = ec.derive_private_key(65535, ec.SECP256R1())
        return ""
    monkeypatch.setattr(builtins, "input", operator)
    original = card.drop_response
    def drop(request, deadline, observe):
        device.repeat_next = True
        return original(request, deadline, observe)
    monkeypatch.setattr(card, "drop_response", drop)
    oracle.execute(session, ["usb-ccid"])
    trace.finish()
    card.close()
    failures = [(row["scenario_id"], row["reason"], row.get("causes", [])) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in " ".join([reason, *causes]) for _, reason, causes in failures), failures
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.keys and not session.broken
