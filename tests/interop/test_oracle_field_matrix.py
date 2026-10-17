# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A separate typed reader detects acceptance and retry side effects on malformed fields."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace


def read(value, shape):
    if isinstance(shape, type):
        if type(value) is not shape:
            raise TypeError("field type")
    elif isinstance(shape, list):
        if type(value) is not list:
            raise TypeError("array")
        for item in value:
            read(item, shape[0])
    else:
        if type(value) is not dict:
            raise TypeError("map")
        for key, item in value.items():
            if key in shape:
                read(item, shape[key])


class Peer:
    layer = "hid_report"

    def __init__(self, defect=None):
        self.defect, self.retries = defect, 8

    def transfer(self, command, data, deadline, observe):
        fields = codec.decode(data[1:]) if len(data) > 1 else {}
        operation, value, status = data[0], {}, 0
        if operation == 4:
            value = {1: ["FIDO_2_3"], 4: {"credMgmt": True, "largeBlobs": True, "authnrCfg": True}, 6: [1, 2]}
        elif operation == 6 and fields == {1: 2, 2: 1}:
            value = {3: self.retries}
        else:
            descriptor = {"id": bytes, "type": str, "transports": [str]}
            user = {"id": bytes, "name": str, "displayName": str}
            point = {-2: bytes, -3: bytes}
            if operation == 1:
                shape = {1: bytes, 2: {"id": str, "name": str}, 3: user, 4: [{"type": str, "alg": int}],
                         5: [descriptor], 6: {}, 7: {"rk": bool, "up": bool, "uv": bool}, 8: bytes, 9: int, 10: int, 11: [str]}
            elif operation == 2:
                shape = {1: str, 2: bytes, 3: [descriptor], 4: {}, 5: {"rk": bool, "up": bool, "uv": bool}, 6: bytes, 7: int}
            elif operation == 6:
                shape = {1: int, 2: int, 3: point, 4: bytes, 5: bytes, 6: bytes, 9: int, 10: str}
            elif operation == 10:
                shape = {1: int, 2: {1: bytes, 2: {"id": bytes, "transports": [str]}, 3: user}, 3: int, 4: bytes}
            elif operation == 12:
                shape = {1: int, 2: bytes, 3: int, 4: int, 5: bytes, 6: int}
            elif operation == 13:
                sub = fields.get(1) if isinstance(fields, dict) else None
                params = {1: int, 2: [str], 3: bool, 4: bool} if sub == 3 else {1: int, 2: bytes, 3: int, 4: [str]} if sub == 255 else {}
                shape = {1: int, 2: params, 3: int, 4: bytes}
            else:
                assert operation == 0x41
                sub = fields.get(1) if isinstance(fields, dict) else None
                params = {1: point, 2: bytes} if sub == 1 else {1: bytes, 2: bytes} if sub == 9 else {1: bytes} if sub in (3, 6, 8) else {1: int, 2: bytes} if sub == 12 else {1: int} if sub in (13, 14) else {}
                shape = {1: int, 2: params, 3: int, 4: bytes}
            try:
                read(fields, shape)
            except TypeError:
                status = 0 if self.defect == "accept-invalid-type" else 0x11
                if self.defect == "consume-PIN-retry":
                    self.retries -= 1
            else:
                raise AssertionError("generator sent a type-valid request to a mutating command")
        observe("tx", data)
        response = bytes([status]) + (codec.encode(value) if not status else b"")
        observe("rx", response)
        return Reply(response, "success" if not status else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("accept-invalid-type", "rejected before command execution"),
                                           ("consume-PIN-retry", "preserves PIN retry state")])
def test_every_parsed_field_type_variant_through_normal_dispatch(tmp_path, defect, expected):
    trace = Trace(tmp_path / "fields", {})
    session = Session(trace, hid=Peer(defect), profile="rsk", options=Options(exercise=True))
    oracle.execute(session, ["field-matrix"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected:
        assert any(expected in row["reason"] for row in failures), failures
        assert session.broken and len(failures) == 1
        if defect == "consume-PIN-retry":
            assert session.broken and session.hid.retries == 7
            assert len(failures) == 1
            assert all(row["reason"] == "malformed field changed PIN retries; explicit recovery required" for row in trace.cases[1:])
    else:
        assert not failures and all(row["verdict"] == "pass" for row in trace.cases), trace.cases
        deletion = next(row for row in trace.cases if row["scenario_id"] == "fields.credentialManagement-6.2.2.id.null")
        update = next(row for row in trace.cases if row["scenario_id"] == "fields.credentialManagement-7.2.3.name.null")
        assert deletion["families"] == ["G02", "G14", "F17"]
        assert update["families"] == ["G02", "G14", "F18"]


def test_wallet_profile_excludes_mutating_field_corpus_without_io(tmp_path):
    trace = Trace(tmp_path / "wallet", {})
    session = Session(trace, hid=Peer(), profile="trezor", options=Options(exercise=True))
    oracle.execute(session, ["field-matrix", "rescue-matrix", "apdu-matrix", "oath-matrix"])
    trace.finish()
    assert not trace.exchanges
    assert all(row["applicability"] == "excluded_by_profile" for row in trace.cases)
