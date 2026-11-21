# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Every writer's actual dispatch mask and lock persist across nine boundaries."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from test_oracle_expanded import apdu_parts
from test_oracle_management_state import Peer as Config
from test_oracle_states import ManagementOtp
from test_oracle_token_matrix import Peer as Tokens


class Hid(Tokens):
    def __init__(self, config):
        super().__init__()
        self.config = config

    def transfer(self, command, wire, deadline, observe):
        if command in (0x42, 0x43) or wire[:1] == b"\x41":
            return self.config.transfer(command, wire, deadline, observe)
        return super().transfer(command, wire, deadline, observe)

    def reopen(self, operator):
        return {"serial_number": "offline-config"}

    def initialize(self, trace, timeout):
        trace.emit("session_opened", session_id="hid", backend="offline")


class Card:
    layer, emulated = "pcsc_apdu", True

    def __init__(self, config, defect):
        self.config, self.defect, self.applet = config, defect, None

    def boundary(self):
        if self.defect == "lock-lost":
            self.config.lock = None
        if self.defect == "mask-lost":
            self.config.original[3] = self.config.original[1]

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        sw, output = 0x9000, b""
        if ins == 0xa4 and p1 == 4:
            applet = next((name for name, aid in AIDS.items() if aid.startswith(body) or body.startswith(aid)), None)
            if applet is None or applet == "oath" and not int.from_bytes(self.config.original[3], "big") & 32:
                sw = 0x6a82
            else:
                self.applet = applet
                if applet == "oath":
                    output = codec.tlv(0x71, b"offline-id")
        elif self.applet == "management":
            return self.config.transfer(wire, deadline, observe)
        elif self.applet == "piv" and ins == 0xfd:
            output = b"\x05\x08\x00"
        elif self.applet == "rescue" and ins == 0x1f:
            self.boundary()
        output += sw.to_bytes(2, "big")
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)

    def control(self, action, deadline, observe):
        self.boundary()
        return Reply(b"offline ATR")

    def usb_reset(self, deadline, observe):
        self.boundary()
        return Reply(b"")

    def wait_disconnect(self, deadline, observe):
        raise TransferError("offline warm disconnect", Outcome.DISCONNECTED)


class Otp(ManagementOtp):
    def reopen(self, operator):
        return {"serial_number": "offline-config"}


@pytest.mark.parametrize("defect,needle", [(None, None), ("lock-lost", "complete persistent configuration"),
    ("mask-lost", "complete persistent configuration")])
def test_actual_shared_mask_flags_and_lock_lifetime_product(tmp_path, defect, needle):
    config = Config(False, None)
    hid = Hid(config)
    trace = Trace(tmp_path / "configuration-lifetimes", {})
    original = config.read()
    session = Session(trace, hid=hid, card=Card(config, defect), otp_hid=Otp(config), profile="rsk",
        options=Options(exercise=True, touch=True, pin="fixture-PIN", allow_effects=("config_change", "reboot", "session_recovery")))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["config-lifetimes"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert len(trace.cases) == 36 and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert config.read() == original and config.lock is None
