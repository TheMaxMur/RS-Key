# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Encoding corpus reaches normal capture dispatch and checks surviving keys."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_pin_matrix import PinPeer


def map_keys(raw):
    count = raw[0] & 31
    offset = 1
    if count == 24:
        count, offset = raw[1], 2
    keys = []
    for _ in range(count):
        key, size = codec.decode(raw[offset:], prefix=True)
        offset += size
        value, size = codec.decode(raw[offset:], prefix=True, lossless=True)
        offset += size
        keys.append(key)
    return keys


def normalize_indefinite(raw, command):
    at, refusal = 0, None
    def item(path=()):
        nonlocal at, refusal
        start, initial = at, raw[at]
        major, size = initial >> 5, initial & 31
        at += 1
        if size in (24, 25, 26, 27):
            width = 1 << (size - 24)
            size = int.from_bytes(raw[at:at + width], "big")
            at += width
        indefinite = initial & 31 == 31
        ignored = command in (1, 2) and "transports" in path or command == 1 and path == (2, "name")
        if indefinite and major in (2, 3):
            chunks = []
            while raw[at] != 255:
                value, width = codec.decode(raw[at:], prefix=True)
                at += width
                chunks.append(value)
            at += 1
            if not ignored:
                refusal = 0x11
            return codec.encode((b"" if major == 2 else "").join(chunks))
        if major in (4, 5):
            if indefinite and not ignored:
                refusal = 0x12
            values = []
            count = 0
            while raw[at] != 255 if indefinite else count < size:
                if major == 5:
                    key, width = codec.decode(raw[at:], prefix=True)
                    at += width
                    values.extend((codec.encode(key), item((*path, key))))
                else:
                    values.append(item((*path, count)))
                count += 1
            if indefinite:
                at += 1
            return codec._head(major, count) + b"".join(values)
        value, width = codec.decode(raw[start:], prefix=True)
        at = start + width
        return codec.encode(value)
    packed = item()
    if at != len(raw):
        raise ValueError("trailing CBOR")
    return packed, refusal


class Peer(PinPeer):
    def transfer(self, command, wire, deadline, observe):
        if command == 0x42:
            return super().transfer(command, wire, deadline, observe)
        if wire[0] == 4:
            value = {1: ["FIDO_2_3"], 4: {"clientPin": True, "rk": True, "credMgmt": True, "pinUvAuthToken": True, "largeBlobs": True, "authnrCfg": True}, 6: [1, 2], 13: 4}
            output = b"\x00" + codec.encode(value)
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0)
        parsed, status = None, None
        try:
            normalized, status = normalize_indefinite(wire[1:], wire[0])
            def materialize(value):
                if isinstance(value, dict) and value.get("type") == "cbor_map":
                    return {key: materialize(child) for key, child in value["entries"]}
                return [materialize(child) for child in value] if isinstance(value, list) else value
            parsed = materialize(codec.decode(normalized, lossless=True))
            keys = map_keys(normalized)
            if wire[0] != 0x41 and any(left >= right for left, right in zip(keys, keys[1:])):
                raise ValueError("nonascending outer key")
            if isinstance(parsed.get(100), dict) and parsed[100].get("type") == "cbor_tag":
                raise ValueError("tag on skipped value")
        except (ValueError, IndexError):
            if wire[0] == 0x41:
                try:
                    pairs = codec.decode(wire[1:], lossless=True)
                    if pairs.get("type") == "cbor_map" and len({key for key, value in pairs["entries"]}) != len(pairs["entries"]):
                        status = 0x33
                except (ValueError, IndexError):
                    pass
            if status is None:
                status = 0x33 if self.defect == "trailing-accepted" and wire[-1:] == b"\x00" else 0x12
        if status is None:
            if wire[0] == 6 and (len(parsed) <= 2 or parsed.get(3, {}).get(-2) not in (None, bytes(32))):
                return super().transfer(command, wire, deadline, observe)
            if wire[0] in (1, 2) and parsed.get(8 if wire[0] == 1 else 6) not in (None, bytes(32)):
                return super().transfer(command, wire, deadline, observe)
            status = 0x33
        observe("tx", wire)
        output = bytes([status])
        observe("rx", output)
        return Reply(output, "success" if status == 0 else "applet_error", status)


@pytest.mark.parametrize("defect", [None, "trailing-accepted"])
def test_all_request_schemas_reach_the_encoding_gate(tmp_path, defect):
    peer = Peer(defect)
    trace = Trace(tmp_path / "CBOR-matrix", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN"))
    oracle.execute(session, ["cbor-matrix"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if defect:
        assert any("trailing-00" in name and "exact parser refusal" in reason for name, reason in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" or row["applicability"] == "unknown" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]


def test_generic_encoding_controls_stop_before_fixture_or_mutator_on_unset_PIN(tmp_path, monkeypatch):
    from oracle_lib import cbor_matrix
    class Unset(Peer):
        def transfer(self, command, wire, deadline, observe):
            assert wire == b"\x04", "unset-PIN generic control issued a fixture or a mutator"
            output = b"\x00" + codec.encode({4: {"clientPin": False}})
            observe("tx", wire)
            observe("rx", output)
            return Reply(output, status=0)
    monkeypatch.setattr(cbor_matrix, "commands", lambda: iter((("FINALIZE", 0x41, {1: 4, 2: {}, 3: 2, 4: bytes(32)}, "V04", ()),)))
    trace = Trace(tmp_path / "unset-PIN-CBOR", {})
    session = Session(trace, hid=Unset(), profile="rsk", options=Options(exercise=True, touch=True))
    oracle.execute(session, ["cbor-matrix"])
    trace.finish()
    assert trace.cases and all(row["applicability"] == "blocked_by_precondition" and "known host PIN" in row["reason"] for row in trace.cases), trace.cases
    assert len(trace.exchanges) == 1
