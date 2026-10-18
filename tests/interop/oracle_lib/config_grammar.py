# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""CONFIG parser controls authenticate the original nested CBOR byte span."""
from . import codec
from .config_matrix import public, request
from .fido import info, pin_token, token_mac
from .fido_fixtures import credential

RAW_LIMIT = 384
UNKNOWN_VENDOR = 0


def mapping(pairs):
    return codec._head(5, len(pairs)) + b"".join(codec.encode(key) + value for key, value in pairs)


def wire(version, token, subcommand, parameters, *, auth=None):
    message = b"\xff" * 32 + bytes([13, subcommand]) + (parameters or b"")
    pairs = [(1, codec.encode(subcommand))]
    if parameters is not None:
        pairs.append((2, parameters))
    pairs += [(3, codec.encode(version)), (4, codec.encode(token_mac(version, token, message) if auth is None else auth))]
    return mapping(pairs)


def vectors():
    for raw, name in ((None, "omitted"), (b"\xa0", "empty"), (codec.encode({1: UNKNOWN_VENDOR}), "unknown-id")):
        yield name, 255, raw, 0x3e
    for key in (1, 3):
        for value in (0, 1, 23, 24, 255, 256, 65535, 65536, 2**32 - 1, 2**32, 2**64 - 1):
            yield f"vendor.uint64.key-{key}.{value}", 255, codec.encode({1: UNKNOWN_VENDOR, key: value}), 0x3e
        yield f"vendor.negative.key-{key}", 255, codec.encode({1: UNKNOWN_VENDOR, key: -1}), 0x11
    for value in (0, 1, 63, 64, 255, 256, 65535, 2**32 - 1, 2**32, 2**64 - 1, -1):
        # The out-of-policy floor avoids modifying a preexisting RP authorization list.
        if value in (0, 1, 63):
            continue
        yield f"minimum.uint32.{value}", 3, codec.encode({1: value}), 0x12 if value > 2**32 - 1 else 0x11 if value < 0 else 0x37
    for key in (1, 2, 3, 4):
        for value in (None, b"", "", [], {}, False, -1):
            valid = (key == 1 and type(value) is int and value >= 0 or key == 2 and isinstance(value, bytes)
                     or key == 3 and type(value) is int and value >= 0 or key == 4 and isinstance(value, list))
            yield f"vendor.type.key-{key}.{type(value).__name__}", 255, codec.encode({1: UNKNOWN_VENDOR, key: value}), 0x3e if valid else 0x11
    for key in (1, 2, 3, 4):
        for value in (None, b"", "", [], {}, False, -1):
            valid = key in (3, 4) and type(value) is bool or key == 2 and isinstance(value, list)
            fields = {1: 64, key: value}
            expected = 0x37 if valid else 0x11
            yield f"minimum.type.key-{key}.{type(value).__name__}", 3, codec.encode(fields), expected
    for size in (0, 1, 31, 32, 33, 63, 64, 127, 128, 255, 256, 375, 376, 377, 378, 379, 384, 385):
        for kind in ("bytes", "ascii", "utf8"):
            value = bytes(size) if kind == "bytes" else "r" * size if kind == "ascii" else "é" * size
            fields = {1: UNKNOWN_VENDOR, 2: value} if kind == "bytes" else {1: UNKNOWN_VENDOR, 4: [value]}
            raw = codec.encode(fields)
            yield f"vendor.{kind}.length-{size}", 255, raw, 0x39 if len(raw) > RAW_LIMIT else 0x3e
    for count in (0, 1, 7, 8, 9, 16):
        for sub, key in ((3, 2), (255, 4)):
            fields = {1: 64 if sub == 3 else UNKNOWN_VENDOR, key: ["r"] * count}
            yield f"RP-count.sub-{sub}.{count}", sub, codec.encode(fields), 0x28 if sub == 3 and count > 8 else 0x37 if sub == 3 else 0x3e
    for text in ("", "a\x00b", "éΩ", "a" * 253, "a" * 254):
        yield "vendor.RP." + text.encode().hex(), 255, codec.encode({1: UNKNOWN_VENDOR, 4: [text]}), 0x3e
    for text in (b"\x61\xff", b"\x62\xc0\xaf", b"\x63\xed\xa0\x80", b"\x64\xf4\x90\x80\x80"):
        yield "RP.invalid-utf8." + text.hex(), 255, b"\xa2\x01\x00\x04\x81" + text, 0x12
    for sub in (3, 255):
        prefix = [(1, codec.encode(64 if sub == 3 else UNKNOWN_VENDOR))]
        expected = 0x37 if sub == 3 else 0x3e
        yield f"sub-{sub}.nested-out-of-order", sub, mapping([(99, b"\x00")] + prefix), expected
        yield f"sub-{sub}.duplicate-known", sub, mapping(prefix + prefix), expected
        yield f"sub-{sub}.duplicate-unknown", sub, mapping(prefix + [(99, b"\x00"), (99, b"\x01")]), expected
        yield f"sub-{sub}.unknown-indefinite-array", sub, mapping(prefix + [(99, b"\x9f\x00\xff")]), expected
        yield f"sub-{sub}.unknown-tag", sub, mapping(prefix + [(99, b"\xc0\x00")]), 0x12
        yield f"sub-{sub}.key-overflow", sub, b"\xa1\x1b\x00\x00\x00\x01\x00\x00\x00\x00\x00", 0x12
        yield f"sub-{sub}.indefinite-map", sub, b"\xbf\x01\x00\xff", 0x12
        array_key = 2 if sub == 3 else 4
        yield f"sub-{sub}.indefinite-RPs", sub, mapping(prefix + [(array_key, b"\x9f\xff")]), 0x12
        for raw in (b"\xa1", b"\xa1\x01", b"\xa1\x01\x1b\x00", b"\xa1\x18"):
            yield f"sub-{sub}.truncated.{raw.hex()}", sub, raw, 0x12
        yield f"sub-{sub}.wrong-type-truncated-body", sub, b"\xa1\x01\x58\x20", 0x11


def run(session):
    for version in (1, 2):
        for label, sub, raw, expected in vectors():
            with session.case(f"fido.CONFIG.raw.protocol-{version}.{label}", ("F21", "G01", "G02", "G03", "G04", "G05", "G06", "G08", "G13", "G14"),
                effects=("config_change", "create_fido_credential"), touch=True,
                parameters={"subcommand": sub, "raw_subparameter_length": len(raw) if raw is not None else None, "auth_covers_original_bytes": True}):
                session.require(session.profile == "rsk", "raw CONFIG grammar requires RS-Key", "excluded_by_profile")
                session.require(info(session).get(4, {}).get("authnrCfg"), "configuration is not advertised", "unknown")
                session.require(not info(session).get(12), "raw grammar controls require no pending forced PIN change")
                with credential(session, session.current.name) as retained:
                    before = session.ctap_value(session.ctap(4))
                    retries = session.ctap_value(session.ctap(6, {1: version, 2: 1}))[3]
                    _, token = pin_token(session, 32, version=version)
                    result = session.ctap(13, raw=wire(version, token, sub, raw))
                    session.check("CONFIG raw grammar has the isolated parser/policy outcome", result.status, expected)
                    session.check("CONFIG raw refusal has no result bytes", result.data[1:], b"")
                    session.ctap_value(session.ctap(13, request(session, version, token, 3, {1: before.get(13, 4)})))
                    session.check("the same config grant survives the rejected command", public(session.ctap_value(session.ctap(4))), public(before))
                    session.check("CONFIG grammar cannot consume PIN comparisons", session.ctap_value(session.ctap(6, {1: version, 2: 1}))[3], retries)
                    retained.assertion(session)
