# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Reported capabilities do not substitute for actual per-applet dispatch checks."""
import pytest

import oracle
from oracle_lib import codec, management_cases
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_states import ManagementPeer, ManagementOtp


class Peer(ManagementPeer):
    def __init__(self, defect=None):
        super().__init__()
        self.defect = defect

    def write(self, writer, fields):
        parsed = dict(codec.parse_tlv(fields))
        if self.lock and parsed.get(11) != self.lock:
            return False
        if any(tag not in (3, 10, 11) for tag in parsed):
            return False
        if 3 in parsed:
            self.original[3] = parsed[3]
        return super().write(writer, b"".join(codec.tlv(tag, value) for tag, value in parsed.items() if tag != 3))

    def transfer(self, *args):
        mask = int.from_bytes(self.original[3], "big")
        if len(args) == 3:
            request, deadline, observe = args
            ins = request[1]
            if ins == 0xA4:
                aid = request[5:5 + request[4]]
                applet = next((name for name, value in AIDS.items() if value == aid), None)
                bit = next((bit for bit, name in management_cases.APPLICATIONS if name == applet), 0)
                available = applet == "management" or bool(mask & bit) or self.defect == "reported-mask-only"
                if self.defect == "management-disabled" and not mask:
                    available = False
                status = 0x9000 if available else 0x6A82
                observe("tx", request)
                return Reply(status.to_bytes(2, "big"), "success" if available else "applet_error", status)
            if ins in (0x1E, 0x1F, 0, 0x7F, 255):
                status = 0x9000 if ins == 0x1E else 0x6D00
                observe("tx", request)
                return Reply(status.to_bytes(2, "big"), "success" if status == 0x9000 else "applet_error", status)
        else:
            command, data, deadline, observe = args
            if command == 0x10 and data[:1] == b"\x04":
                status = 0 if mask & 512 or self.defect == "reported-mask-only" else 0x30
                observe("tx", data)
                return Reply(bytes([status]) + (codec.encode({1: ["FIDO_2_1"]}) if status == 0 else b""), "success" if status == 0 else "applet_error", status)
            if command == 3:
                status = 0x9000 if mask & 2 or self.defect == "reported-mask-only" else 0x6986
                observe("tx", data)
                return Reply(b"U2F_V2" + status.to_bytes(2, "big"), "success" if status == 0x9000 else "applet_error", status)
        return super().transfer(*args)


@pytest.mark.parametrize("defect,expected", [(None, None), ("reported-mask-only", "actual dispatch enforcement"),
                                           ("management-disabled", "remains selectable")])
def test_all_application_masks_across_selected_writers(tmp_path, defect, expected):
    trace = Trace(tmp_path / "applications", {})
    peer = Peer(defect)
    session = Session(trace, card=peer, hid=peer, otp_hid=ManagementOtp(peer), profile="rsk",
                      options=Options(exercise=True, touch=True, allow_effects=("config_change",)))
    session.values["fido.info"] = {4: {"clientPin": False}}
    oracle.execute(session, ["management-enforcement"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected is None:
        assert not failures, failures
        masks = [row for row in trace.cases if row["scenario_id"].startswith("management.enforcement.")]
        assert masks and all(row["verdict"] == "pass" for row in masks)
    else:
        assert any(expected in " ".join([row["reason"], *row.get("causes", [])]) for row in failures), failures
    assert peer.lock is None
    if defect != "management-disabled":
        assert peer.original[3] == b"\x02\x3b"
