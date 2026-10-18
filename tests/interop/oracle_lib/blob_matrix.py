# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Array fragmentation, bounds and retirement preserve the committed value."""
import hashlib

from . import codec
from .fido import info, pin_token, token_mac
from .fido_manage import blob_read, blob_write, restore_blob
from .timers import wait


def available(session):
    session.require(session.profile == "rsk", "largeBlobs limits and sequence retirement require RS-Key", "excluded_by_profile")
    session.require(info(session).get(4, {}).get("largeBlobs"), "serialized blob arrays not advertised", "unknown")


def array_bytes(session, label, length=64):
    body = codec.encode([session.fixture(label, length)])
    return body + hashlib.sha256(body).digest()[:16]


def array_length(length):
    target = length - 16
    if target == 1:
        body = codec.encode([])
    else:
        for count in range(max(1, target - 9), target):
            values = [None] * count
            missing = target - len(codec.encode(values))
            if 0 <= missing <= 8:
                if missing:
                    values[0] = bytes(missing)
                body = codec.encode(values)
                if len(body) == target:
                    break
        else:
            raise ValueError("bounded array length cannot be represented")
    return body + hashlib.sha256(body).digest()[:16]


def fragment(session, version, token, offset, data, total=None, extra=None):
    message = b"\xff" * 32 + b"\x0c\x00" + (offset & 0xFFFFFFFF).to_bytes(4, "little") + hashlib.sha256(data).digest()
    fields = {2: data, 3: offset, 5: token_mac(version, token, message), 6: version}
    if total is not None:
        fields[4] = total
    if extra:
        fields.update(extra)
    return session.ctap(12, fields)


def reads(session):
    for offset_label in ("zero", "last-byte", "end", "past-end", "u32-overflow", "u64-maximum"):
        for size_label in ("zero", "one", "maximum-minus-one", "maximum", "maximum-plus-one"):
            with session.case(f"fido.largeBlobs.read.{offset_label}.{size_label}", ("F19", "G03", "G04", "G14"), parameters={"offset": offset_label, "size": size_label}):
                available(session)
                original = blob_read(session)
                maximum = info(session).get(5, 7609) - 64
                session.require(1 <= maximum <= 16384, "fragment bound exceeds bounded generator")
                offset = {"zero": 0, "last-byte": max(0, len(original) - 1), "end": len(original), "past-end": len(original) + 1,
                          "u32-overflow": 1 << 32, "u64-maximum": (1 << 64) - 1}[offset_label]
                size = {"zero": 0, "one": 1, "maximum-minus-one": maximum - 1, "maximum": maximum, "maximum-plus-one": maximum + 1}[size_label]
                response = session.ctap(12, {1: size, 3: offset})
                if offset <= len(original) and size <= maximum:
                    session.check("fragment reads exact bounded slice", session.ctap_value(response)[1], original[offset:offset + size])
                else:
                    session.check("invalid fragment bound refused", response.protocol, "applet_error")
                session.check("fragment read/refusal preserves committed array", blob_read(session), original)
    for field, value in ((4, 17), (5, b""), (6, 1), (2, b"")):
        with session.case(f"fido.largeBlobs.read.forbidden-field-{field}", ("F19", "G01", "G14")):
            available(session)
            original = blob_read(session)
            response = session.ctap(12, {1: 1, 3: 0, field: value})
            session.check("read forbids write-only parameters", response.status, 2)
            session.check("forbidden read parameter preserves array", blob_read(session), original)


def sequences(session):
    for interruption in ("complete", "read-committed", "getInfo", "token-issuance", "timeout", "restart", "gap", "overlap", "repeated-length", "overshoot", "bad-digest", "past-completion"):
        with session.case("fido.largeBlobs.sequence." + interruption, ("F19", "F20", "G09", "G11", "G12", "G14"),
                          effects=("replace_and_restore_large_blob_array",), parameters={"interruption": interruption}):
            available(session)
            session.require(interruption != "timeout" or session.options.timeout > 31, "increase --timeout above blob idle-expiry window")
            original = blob_read(session)
            replacement = array_bytes(session, "blob.staged")
            version, token = pin_token(session, 16)
            with restore_blob(session, original):
                session.ctap_value(fragment(session, version, token, 0, replacement[:8], len(replacement)))
                if interruption == "read-committed":
                    session.check("partial write cannot publish new bytes", blob_read(session), original)
                elif interruption == "getInfo":
                    session.ctap_value(session.ctap(4))
                elif interruption == "token-issuance":
                    version, token = pin_token(session, 16)
                elif interruption == "timeout":
                    wait(session, 30.25)
                elif interruption == "restart":
                    session.ctap_value(fragment(session, version, token, 0, replacement[:8], len(replacement)))
                offset = 9 if interruption == "gap" else 7 if interruption == "overlap" else 8
                tail = replacement[8:] + b"x" if interruption == "overshoot" else replacement[8:]
                if interruption == "bad-digest":
                    tail = tail[:-1] + bytes([tail[-1] ^ 1])
                response = fragment(session, version, token, offset, tail, total=len(replacement) if interruption == "repeated-length" else None)
                success = interruption in ("complete", "read-committed", "restart", "past-completion")
                session.check("fragment sequence outcome", response.protocol, "success" if success else "applet_error")
                if interruption == "past-completion":
                    session.check("completed accumulator cannot be replayed", fragment(session, version, token, len(replacement), b"").protocol, "applet_error")
                session.check("only complete valid array becomes visible", blob_read(session), replacement if success else original)
                version, token = pin_token(session, 16)
                session.ctap_value(blob_write(session, version, token, replacement, fragment_size=7))
                session.check("fresh fragmented write recovers after any interruption", blob_read(session), replacement)


def write_bounds(session):
    for field in ("total", "fragment"):
        for label in ("zero", "minimum-minus-one", "minimum", "maximum-minus-one", "maximum", "maximum-plus-one", "u32-overflow", "u64-maximum"):
            if field == "fragment" and label in ("u32-overflow", "u64-maximum"):
                continue
            with session.case(f"fido.largeBlobs.write.{field}.{label}", ("F20", "G03", "G04", "G14"), effects=("replace_and_restore_large_blob_array",)):
                available(session)
                original = blob_read(session)
                maximum = info(session).get(11, 1024) if field == "total" else info(session).get(5, 7609) - 64
                session.require(17 <= maximum <= 16384, "advertised blob bound exceeds bounded generator")
                length = {"zero": 0, "minimum-minus-one": 16, "minimum": 17, "maximum-minus-one": maximum - 1,
                          "maximum": maximum, "maximum-plus-one": maximum + 1, "u32-overflow": 1 << 32, "u64-maximum": (1 << 64) - 1}[label]
                version, token = pin_token(session, 16)
                with restore_blob(session, original):
                    committed = original
                    if field == "total":
                        response = fragment(session, version, token, 0, b"\x80", total=length)
                        valid = 17 <= length <= maximum
                    else:
                        storage_maximum = info(session).get(11, 1024)
                        if 17 <= length <= min(maximum, storage_maximum):
                            value = array_length(length)
                            response = fragment(session, version, token, 0, value, total=length)
                            committed, valid = value, True
                        else:
                            response = fragment(session, version, token, 0, session.fixture("blob.fragment.bound", length), total=17)
                            valid = length <= maximum and length < 17
                            session.observe("fragment_limit_context", {"fragment_maximum": maximum, "array_maximum": storage_maximum,
                                "refusal_before_digest": "fragment limit" if length > maximum else "array overrun"})
                    if field == "total" and valid:
                        session.ctap_value(response)
                    elif field == "fragment" and valid:
                        session.ctap_value(response)
                    else:
                        session.check("invalid blob length or digest refused", response.protocol, "applet_error")
                    session.check("only valid complete boundary array is committed", blob_read(session), committed)
    for label in ("minimum", "maximum-minus-one", "maximum"):
        with session.case("fido.largeBlobs.array-capacity." + label, ("F20", "G03", "G14"), effects=("replace_and_restore_large_blob_array",)):
            available(session)
            original = blob_read(session)
            maximum = info(session).get(11, 1024)
            session.require(17 <= maximum <= 16384, "array bound exceeds bounded generator")
            value = array_length(17 if label == "minimum" else maximum - (label == "maximum-minus-one"))
            with restore_blob(session, original):
                version, token = pin_token(session, 16)
                session.ctap_value(blob_write(session, version, token, value, fragment_size=17))
                session.check("array capacity boundary accepts complete valid digest", blob_read(session), value)


def run(session):
    reads(session)
    sequences(session)
    write_bounds(session)
