# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Native fake endpoints distinguish acknowledgment, physical-loss error and timeout."""
import builtins

import pytest
import usb.core
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import usb_ccid
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_phy_records import Card as KeyPeer
from test_oracle_usb_ccid import DESCRIPTOR, Device, Endpoint, install, response


class Peer(KeyPeer):
    def transfer(self, wire, deadline, observe):
        if apdu_parts(wire)[0] == 0x1f:
            return Reply(b"\x90\x00", status=0x9000)
        return super().transfer(wire, deadline, observe)


class NativeEndpoint(Endpoint):
    def write(self, wire, timeout):
        wire = bytes(wire)
        self.device.writes.append((wire, timeout))
        if wire[0] == 0x6f:
            body = self.device.peer.transfer(wire[10:], 0, lambda *args: None).data
            if wire[11] == 0x1f:
                self.device.rebooting = True
        else:
            body = b"\x3b\x00" if wire[0] == 0x62 else b""
        packet = response(0x80 if wire[0] in (0x6f, 0x62) else 0x81, wire[6], body)
        self.device.queue.extend(packet[offset:offset + 64] for offset in range(0, len(packet), 64))
        return len(wire)

    def read(self, size, timeout):
        if self.device.rebooting and (not self.device.queue or self.device.fault == "disconnect-before-ack"):
            if self.device.fault == "reboot-does-not-disconnect":
                raise usb.core.USBTimeoutError("offline no disconnect in host observation window", error_code=-7, errno=110)
            raise usb.core.USBError("offline device disconnected after reboot", error_code=-4, errno=19)
        return super().read(size, timeout)


class Native(Device):
    def __init__(self, fault):
        super().__init__()
        self.peer, self.fault, self.rebooting = Peer(), fault, False
        self.configuration.interface.endpoints = [NativeEndpoint(self, 0x81), NativeEndpoint(self, 0x02)]


@pytest.mark.parametrize("fault,needle", [(None, None), ("disconnect-before-ack", "offline device disconnected"),
    ("reboot-does-not-disconnect", "actual USB disconnect"), ("reboot-replaces-device-key", "InvalidSignature")])
def test_reboot_reply_precedes_observed_USB_disconnect_and_retains_device_key(tmp_path, monkeypatch, fault, needle):
    device = Native(fault)
    install(monkeypatch, device)
    trace = Trace(tmp_path / "native-reboot", {})
    card = usb_ccid.UsbCard(dict(DESCRIPTOR), trace.now, operator=True)
    def replug():
        device.rebooting = False
        device.queue.clear()
        if fault == "reboot-replaces-device-key":
            device.peer.key = ec.derive_private_key(43, ec.SECP256K1())
        return {"interfaces": [dict(DESCRIPTOR)]}
    monkeypatch.setattr(usb_ccid, "inventory", replug)
    monkeypatch.setattr(builtins, "input", lambda prompt: "")
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, operator=True, allow_effects=("reboot",)))
    oracle.execute(session, ["rescue-reboot"])
    card.close()
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures
        observations = [row for row in trace.exchanges if row["command"] == "reboot.await-USB-disconnect"]
        assert observations and all(row["execution_outcome"] == "disconnected" and row["response"] is None for row in observations)
