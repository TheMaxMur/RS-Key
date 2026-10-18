# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Single type defects cover parsed fields, independently of authorization gates."""
import copy

from . import codec
from .fido import info


def paths(value, prefix=()):
    yield prefix, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from paths(child, (*prefix, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from paths(child, (*prefix, index))


def replace(value, path, replacement):
    result = copy.deepcopy(value)
    if not path:
        return replacement
    parent = result
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = replacement
    return result


def read_path(command, path):
    return not (command in (1, 2) and "transports" in path or command == 1 and path == (2, "name"))


def commands():
    point = {-2: bytes(32), -3: bytes(32)}
    make = {1: bytes(32), 2: {"id": "fields.oracle.invalid", "name": "Oracle"},
            3: {"id": b"oracle", "name": "Oracle", "displayName": "Oracle Fixture"},
            4: [{"type": "public-key", "alg": -7}], 5: [{"type": "public-key", "id": b"unknown", "transports": ["usb"]}],
            6: {}, 7: {"rk": False, "up": True, "uv": False}, 8: bytes(32), 9: 2, 10: 1, 11: ["packed"]}
    yield "makeCredential", 1, make, "F11", ()
    yield "getAssertion", 2, {1: "fields.oracle.invalid", 2: bytes(32),
        3: [{"type": "public-key", "id": b"unknown", "transports": ["usb"]}], 4: {},
        5: {"rk": False, "up": True, "uv": False}, 6: bytes(32), 7: 2}, "F12", ()
    for subcommand in (1, 2, 3, 4, 5, 6, 7, 9):
        yield f"clientPIN-{subcommand}", 6, {1: 2, 2: subcommand, 3: point, 4: bytes(32), 5: bytes(80), 6: bytes(32),
            9: 2, 10: "fields.oracle.invalid"}, {1: "F02", 2: "F03", 3: "F04", 4: "F05", 5: "F06", 6: "F07", 7: "F08", 9: "F06"}[subcommand], ()
    for subcommand in range(1, 8):
        yield f"credentialManagement-{subcommand}", 10, {1: subcommand, 2: {1: bytes(32),
            2: {"id": b"unknown", "transports": ["usb"]}, 3: {"id": b"user", "name": "Oracle", "displayName": "Fixture"}},
            3: 2, 4: bytes(32)}, {1: "F14", 2: "F15", 3: "F15", 4: "F16", 5: "F16", 6: "F17", 7: "F18"}[subcommand], ("credMgmt",)
    yield "largeBlobs-read", 12, {1: 1, 3: 0}, "F19", ("largeBlobs",)
    yield "largeBlobs-write", 12, {2: b"x", 3: 0, 4: 17, 5: bytes(32), 6: 2}, "F20", ("largeBlobs",)
    for subcommand in (1, 2, 3, 255):
        parameters = {1: 4, 2: ["fields.oracle.invalid"], 3: False, 4: False} if subcommand == 3 else {
            1: 0x0E6841934E719BE7, 2: b"x", 3: 1, 4: ["fields.oracle.invalid"]} if subcommand == 255 else {}
        yield f"authenticatorConfig-{subcommand}", 13, {1: subcommand, 2: parameters, 3: 2, 4: bytes(32)}, "F21", ("authnrCfg",)
    for subcommand in range(1, 16):
        parameters = {1: point, 2: bytes(1184)} if subcommand == 1 else {1: b"blob", 2: b"chain"} if subcommand == 9 else {
            1: b"blob"} if subcommand in (3, 6, 8) else {1: 3, 2: b"config"} if subcommand == 12 else {
            1: 3 if subcommand == 14 else 1} if subcommand in (13, 14) else {}
        yield f"vendor-{subcommand}", 0x41, {1: subcommand, 2: parameters, 3: 2, 4: bytes(32)}, {
            1: "V01", 2: "V02", 3: "V03", 4: "V04", 5: "V02", 6: "V05", 7: "V07", 8: "V08", 9: "V06",
            10: "V06", 11: "V06", 12: "V09", 13: "V09", 14: "V07", 15: "V10"}[subcommand], ()


def inputs():
    alternatives = (("null", None), ("bool", False), ("integer", 1), ("bytes", b"x"), ("text", "x"), ("array", []), ("map", {}))
    for label, command, base, family, required in commands():
        for path, value in paths(base):
            if not read_path(command, path):
                continue
            for kind, other in alternatives:
                if type(value) is type(other):
                    continue
                location = ".".join(map(str, path)) or "body"
                yield f"{label}.{location}.{kind}", command, replace(base, path, other), family, required, path


def halt(session, reason):
    session.broken = True
    session.values["halt_reason"] = reason


def run(session):
    for label, command, fields, family, required, path in inputs():
        with session.case("fields." + label, ("G02", "G14", family), effects=("malformed_known_command",),
                          parameters={"command": command, "field_path": list(path), "defect": "single wrong CBOR type"}):
            session.require(session.profile == "rsk", "field readers here follow the confirmed RS-Key catalog", "excluded_by_profile")
            session.require(all(info(session).get(4, {}).get(option) for option in required), "optional command not advertised", "unknown")
            session.observe("input_basis", "parser template with invalid crypto/auth placeholders; exact type error is required, not a semantic-command success claim")
            before = session.ctap_value(session.ctap(4))
            retries = session.ctap_value(session.ctap(6, {1: 2, 2: 1}))
            reply = session.ctap(command, raw=codec.encode(fields))
            if (reply.protocol, reply.status) != ("applet_error", 0x11):
                halt(session, "unexpected malformed-command result; explicit recovery required")
            session.check("single wrong field type rejected before command execution", (reply.protocol, reply.status), ("applet_error", 0x11))
            remaining = session.ctap_value(session.ctap(6, {1: 2, 2: 1}))
            if remaining != retries:
                halt(session, "malformed field changed PIN retries; explicit recovery required")
            session.check("typed-field refusal preserves PIN retry state", remaining, retries)
            after = session.ctap_value(session.ctap(4))
            actual, expected = ({k: v for k, v in value.items() if k not in (25, 30)} for value in (after, before))
            if actual != expected:
                halt(session, "malformed field changed public FIDO state; explicit recovery required")
            session.check("typed-field refusal preserves public FIDO state", actual, expected)
