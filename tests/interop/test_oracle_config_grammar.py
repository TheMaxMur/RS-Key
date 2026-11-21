# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""An independent byte walker checks raw CONFIG MACs and directed parser faults."""
from dataclasses import dataclass
import hmac

import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_config_matrix import Peer as PolicyPeer


class Refusal(Exception):
    def __init__(self, status):
        self.status = status


@dataclass
class Item:
    major: int
    value: object
    raw: bytes
    indefinite: bool = False


class Reader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, size):
        if self.offset + size > len(self.data):
            raise Refusal(0x12)
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def item(self):
        start = self.offset
        header = self.take(1)[0]
        major, argument = header >> 5, header & 31
        indefinite = argument == 31
        if argument in (24, 25, 26, 27):
            argument = int.from_bytes(self.take({24: 1, 25: 2, 26: 4, 27: 8}[argument]), "big")
        elif argument >= 28 and not indefinite:
            raise Refusal(0x12)
        if major in (0, 1):
            value = argument if major == 0 else -1 - argument
        elif major in (2, 3):
            if indefinite:
                raise Refusal(0x12)
            value = self.take(argument)
            if major == 3:
                try:
                    value = value.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise Refusal(0x12) from error
        elif major in (4, 5):
            value = []
            count = 0
            while count < argument or indefinite:
                if indefinite and self.data[self.offset:self.offset + 1] == b"\xff":
                    self.take(1)
                    break
                child = self.item()
                value.append((child, self.item()) if major == 5 else child)
                count += 1
        elif major == 6:
            value = self.item()
        elif major == 7 and argument in (20, 21, 22):
            value = {20: False, 21: True, 22: None}[argument]
        else:
            raise Refusal(0x12)
        return Item(major, value, self.data[start:self.offset], indefinite)


def typed(item, major, bits=None):
    if item.major != major:
        raise Refusal(0x11)
    if item.indefinite or bits is not None and item.value >= 1 << bits:
        raise Refusal(0x12)
    return item.value


class Peer(PolicyPeer):
    def raw_configuration(self, data):
        try:
            outer = dict((typed(key, 0, 32), value) for key, value in typed(Reader(data).item(), 5))
            sub = typed(outer[1], 0, 32)
            params = outer.get(2)
            values = {}
            if params is not None:
                for key, value in typed(params, 5):
                    key = typed(key, 0, 32)
                    kind = ({1: 0, 2: 4, 3: 7, 4: 7} if sub == 3 else {1: 0, 2: 2, 3: 0, 4: 4}).get(key)
                    if kind is None:
                        if value.major == 6:
                            raise Refusal(0x12)
                        continue
                    extracted = typed(value, kind, (32 if sub == 3 else 64) if kind == 0 else None)
                    if kind == 7 and type(extracted) is not bool:
                        raise Refusal(0x11)
                    if kind == 4:
                        extracted = [typed(child, 3) for child in extracted]
                        if self.defect == "rejects-opaque-RP" and any("\x00" in child or not child for child in extracted):
                            raise Refusal(2)
                    values[key] = extracted
            raw = params.raw if params is not None else b""
            if len(raw) > 384 and self.defect != "raw-limit-ignored":
                return 0x39
            if self.defect == "canonical-MAC" and params is not None:
                raw = codec.encode(values)
            message = b"\xff" * 32 + bytes([13, sub]) + raw
            expected = hmac.digest(self.token, message, "sha256")[:16 if self.protocol == 1 else 32]
            if typed(outer[4], 2) != expected or not self.permissions & 32:
                return 0x33
            if sub == 255:
                return 0x3e
            if len(values.get(2, [])) > 8:
                return 0x28
            floor = values.get(1) or self.floor
            return 0 if self.floor <= floor <= 63 else 0x37
        except Refusal as error:
            return error.status

    def transfer(self, command, wire, deadline, observe):
        if wire[0] != 13:
            return super().transfer(command, wire, deadline, observe)
        # A typed integer reader rejects a bytes header before reading its missing body.
        status = 0x11 if b"\xa1\x01\x58\x20" in wire else self.raw_configuration(wire[1:])
        if status == 0x12 and self.defect == "integer-overflow-type-error":
            status = 0x11
        output = bytes([status])
        observe("tx", wire)
        observe("rx", output)
        return Reply(output, "success" if status == 0 else "applet_error", status)


@pytest.mark.parametrize("defect,needle", [(None, None), ("canonical-MAC", "isolated parser/policy outcome"),
    ("raw-limit-ignored", "isolated parser/policy outcome"), ("rejects-opaque-RP", "isolated parser/policy outcome"),
    ("integer-overflow-type-error", "isolated parser/policy outcome")])
def test_raw_config_original_bytes_uint_widths_strings_and_grant_controls(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "raw-config", {})
    session = Session(trace, hid=peer, profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN",
        allow_effects=("config_change",)))
    oracle.execute(session, ["config-grammar"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert peer.floor == 4 and not peer.force and not peer.complexity
