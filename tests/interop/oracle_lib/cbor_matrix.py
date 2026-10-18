# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Encoding gates are isolated from semantic refusals on every parsed schema."""
from . import codec
from .field_matrix import commands, halt, paths, read_path
from .fido import info
from .fido_fixtures import credential


def map_wire(items, header=None):
    return (codec._head(5, len(items)) if header is None else header) + b"".join(codec.encode(key) + value for key, value in items)


def encoded_path(value, path, replacement):
    if not path:
        return replacement
    key, *rest = path
    if isinstance(value, list):
        return codec._head(4, len(value)) + b"".join(encoded_path(child, rest, replacement) if index == key else codec.encode(child) for index, child in enumerate(value))
    items = sorted(value, key=lambda item: (len(codec.encode(item)), codec.encode(item)))
    return codec._head(5, len(value)) + b"".join(codec.encode(item) + (encoded_path(value[item], rest, replacement) if item == key else codec.encode(value[item])) for item in items)


def variants(command, fields):
    items = [(key, codec.encode(value)) for key, value in sorted(fields.items())]
    body = map_wire(items)
    for length in range(len(body)):
        yield "truncated-" + str(length), body[:length], 0x12
    for suffix in (b"\x00", b"\xa0", b"\xc0\x00"):
        yield "trailing-" + suffix.hex(), body + suffix, 0x12
    yield "indefinite-map", map_wire(items, b"\xbf") + b"\xff", 0x12
    yield "duplicate-last-key", map_wire([*items, items[-1]]), None if command == 0x41 else 0x12
    yield "reordered-last-keys", map_wire([*items[:-2], *reversed(items[-2:])]), None if command == 0x41 else 0x12
    yield "wide-map-length", map_wire(items, b"\xb8" + bytes([len(items)])), None
    yield "wide-outer-keys", codec._head(5, len(items)) + b"".join(b"\x1b" + key.to_bytes(8, "big") + value for key, value in items), None
    yield "unknown-key", map_wire([*items, (100, codec.encode({1: [0, b"x", "valid UTF-8"]}))]), None
    yield "tagged-unknown-value", map_wire([*items, (100, b"\xc0\x00")]), 0x12
    for index, (key, value) in enumerate(items):
        if isinstance(fields[key], dict):
            nested = fields[key]
            packed = b"\xbf" + b"".join(codec.encode(k) + codec.encode(v) for k, v in nested.items()) + b"\xff"
            yield f"indefinite-nested-map-{key}", map_wire([*items[:index], (key, packed), *items[index + 1:]]), 0x12
    for path, value in paths(fields):
        if not path:
            continue
        label = ".".join(map(str, path))
        packed = codec.encode(value)
        major = packed[0] >> 5
        if type(value) is int:
            integer = value if value >= 0 else -1 - value
            if len(packed) < 9:
                yield "non-shortest-value-" + label, encoded_path(fields, path, bytes([(major << 5) | 27]) + integer.to_bytes(8, "big")), None
        elif isinstance(value, (bytes, str, list, dict)):
            size = len(value.encode()) if isinstance(value, str) else len(value)
            header = len(codec._head(major, size))
            yield "wide-value-length-" + label, encoded_path(fields, path, bytes([(major << 5) | 27]) + size.to_bytes(8, "big") + packed[header:]), None
            yield "incorrect-declared-length-" + label, encoded_path(fields, path, codec._head(major, len(body) + size + 1) + packed[header:]), 0x12
            if isinstance(value, str) and read_path(command, path):
                yield "invalid-UTF8-" + label, encoded_path(fields, path, b"\x61\xff"), 0x12
            elif isinstance(value, dict):
                pairs = sorted(value.items(), key=lambda pair: (len(codec.encode(pair[0])), codec.encode(pair[0])))
                if pairs:
                    duplicate = map_wire([(key, codec.encode(child)) for key, child in (*pairs, pairs[-1])])
                    yield "nested-duplicate-same-value-" + label, encoded_path(fields, path, duplicate), None
                if len(pairs) > 1:
                    reordered = map_wire([(key, codec.encode(child)) for key, child in reversed(pairs)])
                    yield "nested-reordered-" + label, encoded_path(fields, path, reordered), None
            if isinstance(value, list):
                indefinite = b"\x9f" + b"".join(codec.encode(child) for child in value) + b"\xff"
                yield "indefinite-array-" + label, encoded_path(fields, path, indefinite), 0x12 if read_path(command, path) else None
            elif isinstance(value, (bytes, str)):
                ignored = not read_path(command, path)
                indefinite = bytes([(major << 5) | 31]) + packed + b"\xff"
                yield "indefinite-string-" + label, encoded_path(fields, path, indefinite), None if ignored else 0x11


def run(session):
    for label, command, fields, family, required in commands():
        for defect, body, expected in variants(command, fields):
            with session.case("CBOR." + label + "." + defect, ("G05", "G06", "G14", family),
                              effects=("malformed_known_command", "create_fido_credential"), touch=True,
                              parameters={"command": command, "defect": defect}, method="per-schema-encoding-gate"):
                session.require(session.profile == "rsk", "encoding contracts require the confirmed RS-Key parser profile", "excluded_by_profile")
                session.require(info(session).get(4, {}).get("clientPin") and session.options.pin,
                    "generic semantic controls require a known host PIN so FINALIZE and other consumers cannot execute on an unset-PIN device")
                session.require(all(info(session).get(4, {}).get(option) for option in required), "optional command not advertised", "unknown")
                with credential(session, session.current.name) as fixture:
                    baseline = session.ctap(command, fields)
                    session.check("parser control reaches a semantic result", baseline.status != 0x12)
                    session.observe("control_scope", "correct CBOR parser template with crypto placeholders; semantic success is tested in the command's separate owned-fixture suite")
                    retries = session.ctap_value(session.ctap(6, {1: 2, 2: 1}))
                    before = session.ctap_value(session.ctap(4))
                    result = session.ctap(command, raw=body)
                    if result.protocol == "success" and baseline.protocol != "success":
                        halt(session, "encoding mutation unexpectedly executed a formerly refused semantic command")
                    if expected is None:
                        session.check("accepted encoding preserves the same semantic outcome", (result.protocol, result.status, result.data),
                                      (baseline.protocol, baseline.status, baseline.data))
                    else:
                        session.check("encoding defect has the exact parser refusal", (result.protocol, result.status), ("applet_error", expected))
                    session.check("encoding probe preserves PIN retries", session.ctap_value(session.ctap(6, {1: 2, 2: 1})), retries)
                    after = session.ctap_value(session.ctap(4))
                    session.check("encoding probe preserves public state", {k: v for k, v in after.items() if k not in (25, 30)},
                                  {k: v for k, v in before.items() if k not in (25, 30)})
                    fixture.assertion(session)
