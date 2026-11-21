# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""All DeviceInfo writers use one independent validator and preserve deltas."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_states import ManagementPeer, ManagementOtp


class DeviceInfoPeer(ManagementPeer):
    def __init__(self, defect=None):
        super().__init__()
        self.defect = defect
        self.original[8] = b"\x00"

    def write(self, writer, wire):
        widths = {3: 2, 6: 2, 7: 2, 8: 1, 10: 16, 11: 16, 12: 0, 14: 2, 23: 1}
        try:
            items = codec.parse_tlv(wire)
        except ValueError:
            return False
        if len(wire) > 128 or len({tag for tag, value in items}) != len(items):
            return False
        for tag, value in items:
            if tag not in widths:
                return False
            if tag in (3, 10, 11) and len(value) != widths[tag] or len(value) > widths[tag]:
                return False
        if self.defect == "replace-instead-of-merge" and any(tag not in (10, 11) for tag, value in items):
            self.original = {tag: value for tag, value in self.original.items() if tag in (1, 2, 4, 5)}
        for tag, value in items:
            if tag == 10:
                self.lock = value if any(value) else None
            elif tag == 11:
                continue
            else:
                if tag == 3 and self.defect != "reserved-bit-enabled":
                    value = (int.from_bytes(value, "big") & int.from_bytes(self.original[1], "big")).to_bytes(2, "big")
                self.original[tag] = value
        return True


@pytest.mark.parametrize("defect,expected", [(None, None), ("replace-instead-of-merge", "partial update preserves all other fields"),
                                           ("reserved-bit-enabled", "reserved capability bit is never reported enabled")])
def test_management_tag_matrix_uses_every_selected_writer(tmp_path, defect, expected):
    peer = DeviceInfoPeer(defect)
    trace = Trace(tmp_path / "management-fields", {})
    session = Session(trace, hid=peer, card=peer, otp_hid=ManagementOtp(peer), profile="rsk",
                      options=Options(exercise=True, touch=True, allow_effects=("config_change",)))
    session.values["fido.info"] = {4: {"clientPin": False}}
    oracle.execute(session, ["management-matrix"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" or row["applicability"] == "excluded_by_profile" for row in trace.cases), trace.cases
        assert {writer for writer, kind, data in peer.calls if kind == "write"} == {"card", "hid", "otp", "fido"}
