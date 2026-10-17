# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Strict primitive codecs; trace decoding retains map order and duplicates."""
import struct

MAX_DEPTH = 32


def _head(major, value):
    for limit, width, tag in ((24, 0, 0), (256, 1, 24), (65536, 2, 25), (2**32, 4, 26), (2**64, 8, 27)):
        if value < limit:
            return bytes([(major << 5) | (value if not width else tag)]) + (value.to_bytes(width, "big") if width else b"")
    raise ValueError("CBOR integer outside uint64")


def encode(value):
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return _head(3, len(data)) + data
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(encode(v) for v in value)
    if isinstance(value, dict):
        pairs = sorted(((encode(k), encode(v)) for k, v in value.items()), key=lambda kv: (len(kv[0]), kv[0]))
        return _head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise TypeError(f"unsupported CBOR type {type(value).__name__}")


def decode(data, lossless=False, *, prefix=False):
    offset = 0

    def take(length):
        nonlocal offset
        if length < 0 or length > len(data) - offset:
            raise ValueError("truncated CBOR")
        value = data[offset:offset + length]
        offset += length
        return value

    def item(depth=0):
        if depth > MAX_DEPTH:
            raise ValueError("CBOR nesting too deep")
        initial = take(1)[0]
        major, info = initial >> 5, initial & 31
        if major == 7 and info in (25, 26, 27):
            return struct.unpack({25: ">e", 26: ">f", 27: ">d"}[info], take({25: 2, 26: 4, 27: 8}[info]))[0]
        if info < 24:
            value = info
        elif info in (24, 25, 26, 27):
            value = int.from_bytes(take({24: 1, 25: 2, 26: 4, 27: 8}[info]), "big")
        else:
            raise ValueError("indefinite or reserved CBOR length")
        if major == 0:
            return value
        if major == 1:
            return -1 - value
        if major == 2:
            return take(value)
        if major == 3:
            return take(value).decode("utf-8")
        if major == 4:
            if value > len(data) - offset:
                raise ValueError("impossible CBOR array length")
            return [item(depth + 1) for _ in range(value)]
        if major == 5:
            if value > (len(data) - offset) // 2:
                raise ValueError("impossible CBOR map length")
            pairs = [(item(depth + 1), item(depth + 1)) for _ in range(value)]
            if lossless:
                return {"type": "cbor_map", "entries": pairs}
            result = {}
            for key, child in pairs:
                if key in result:
                    raise ValueError("duplicate CBOR map key")
                result[key] = child
            return result
        if major == 6:
            return {"type": "cbor_tag", "tag": value, "value": item(depth + 1)}
        if major == 7:
            return {20: False, 21: True, 22: None}.get(value, {"type": "cbor_simple", "value": value})
        raise ValueError("invalid CBOR major type")

    value = item()
    if prefix:
        return value, offset
    if offset != len(data):
        raise ValueError("trailing CBOR bytes")
    return value


def tlv(tag, value):
    if isinstance(tag, int):
        tag = tag.to_bytes(max(1, (tag.bit_length() + 7) // 8), "big")
    length = len(value)
    encoded_length = bytes([length]) if length < 128 else bytes([0x80 | ((length.bit_length() + 7) // 8)]) + length.to_bytes((length.bit_length() + 7) // 8, "big")
    return tag + encoded_length + value


def parse_tlv(data):
    elements, offset = [], 0
    while offset < len(data):
        start = offset
        offset += 1
        if data[start] & 31 == 31:
            while True:
                if offset >= len(data) or offset - start > 4:
                    raise ValueError("invalid TLV tag")
                byte = data[offset]
                offset += 1
                if not byte & 128:
                    break
        tag = int.from_bytes(data[start:offset], "big")
        if offset >= len(data):
            raise ValueError("missing TLV length")
        length = data[offset]
        offset += 1
        if length & 128:
            width = length & 127
            if not 1 <= width <= 4 or offset + width > len(data):
                raise ValueError("invalid TLV length")
            length = int.from_bytes(data[offset:offset + width], "big")
            offset += width
        if length > len(data) - offset:
            raise ValueError("truncated TLV value")
        elements.append((tag, data[offset:offset + length]))
        offset += length
    return elements


def apdu(ins, p1=0, p2=0, data=b"", cla=0, le=None):
    header = bytes([cla, ins, p1, p2])
    if len(data) > 65535 or (le is not None and not 0 <= le <= 65536):
        raise ValueError("APDU length outside extended encoding")
    extended = len(data) > 255 or (le is not None and le > 256)
    if data:
        result = header + (b"\x00" + len(data).to_bytes(2, "big") if extended else bytes([len(data)])) + data
        return result + ((le % 65536).to_bytes(2, "big") if extended else bytes([le % 256])) if le is not None else result
    if le is not None:
        return header + (b"\x00" + (le % 65536).to_bytes(2, "big") if extended else bytes([le % 256]))
    return header
