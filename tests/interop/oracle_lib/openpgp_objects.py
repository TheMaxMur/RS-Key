# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Read nested DOs through their templates and exercise each writable object's ACL."""
from . import codec
from .openpgp_lifecycle import fixture_session

PERSONAL = {0x5B: 39, 0x5E: 2048, 0x5F2D: 8, 0x5F35: 1, 0x5F50: 2048}
FINGERPRINTS = {**{tag: (0xC5, (tag - 0xC7) * 20, 20) for tag in range(0xC7, 0xCA)},
                **{tag: (0xC6, (tag - 0xCA) * 20, 20) for tag in range(0xCA, 0xCD)},
                **{tag: (0xCD, (tag - 0xCE) * 4, 4) for tag in range(0xCE, 0xD1)},
                0xDB: (0xC5, 60, 20), 0xDC: (0xC6, 60, 20), 0xDD: (0xCD, 12, 4)}


def read_do(sdk, tag):
    if tag in (0x5B, 0x5F2D, 0x5F35):
        outer = dict(codec.parse_tlv(sdk.get_data(0x65)))
        return dict(codec.parse_tlv(outer[0x65]))[tag]
    if tag in FINGERPRINTS or tag in (0xC1, 0xC2, 0xC3):
        outer = dict(codec.parse_tlv(sdk.get_data(0x6E)))
        nested = dict(codec.parse_tlv(dict(codec.parse_tlv(outer[0x6E]))[0x73]))
        if tag in FINGERPRINTS:
            aggregate, offset, length = FINGERPRINTS[tag]
            value = nested[aggregate]
            if len(value) < offset + length:
                raise ValueError("profile does not expose this aggregate occurrence")
            return value[offset:offset + length]
        return nested[tag]
    return sdk.get_data(tag)


def run(session):
    from yubikit.core.smartcard import ApduError
    tags = {**PERSONAL, **{tag: length for tag, (_, _, length) in FINGERPRINTS.items()},
            0x101: 2048, 0x102: 2048, 0x103: 2048, 0x104: 2048}
    for tag, maximum in tags.items():
        fixed = tag in FINGERPRINTS
        lengths = sorted({0, 1, maximum - 1, maximum, maximum + 1})
        for length in lengths:
            with session.case(f"openpgp.DO-catalog.{tag:04x}.length-{length}", ("O01", "O07", "G03", "G10", "G14"), effects=("write_and_restore_openpgp_DO",)):
                sdk = fixture_session(session)
                owner_is_user = tag in (0x101, 0x103)
                if owner_is_user or tag == 0x103:
                    sdk.verify_pin(session.options.openpgp_pin, extended=True)
                original = read_do(sdk, tag)
                value = b"9" if tag == 0x5F35 and length == 1 else b"x" * length
                attempted = False
                try:
                    attempted = True
                    reply = session.apdu(codec.apdu(0xDA, tag >> 8, tag & 255, value), "openpgp.DO-catalog.PUT")
                    valid_length = length == maximum if fixed else length <= maximum
                    if not valid_length and session.profile == "rsk":
                        session.check("DO length boundary refusal", reply.status, 0x6A80)
                        session.check("refused DO length preserves original", read_do(sdk, tag), original)
                    elif reply.protocol == "success":
                        readback = read_do(sdk, tag)
                        session.check("DO catalog exact write/read", readback, b"9" if tag == 0x5F35 and not value else value)
                        for ref in (0x81, 0x82, 0x83):
                            session.card_value(session.apdu(codec.apdu(0x20, 0xFF, ref)))
                        denied = session.apdu(codec.apdu(0xDA, tag >> 8, tag & 255, value), "openpgp.DO-catalog.unauthorized-PUT")
                        session.check("unauthorized same valid body refused by ACL", denied.status, 0x6982)
                        if tag in (0x103, 0x104):
                            denied_read = session.apdu(codec.apdu(0xCA, tag >> 8, tag & 255), "openpgp.DO-catalog.unauthorized-GET")
                            session.check("private DO read owner enforced", denied_read.status, 0x6982)
                        if owner_is_user:
                            sdk.verify_pin(session.options.openpgp_pin, extended=True)
                        else:
                            sdk.verify_admin(session.options.openpgp_admin)
                        session.check("ACL refusal preserves DO", read_do(sdk, tag), readback)
                    else:
                        session.check("DO boundary refusal is an applet error", reply.protocol, "applet_error")
                        session.observe("profile_boundary_refusal", reply.status)
                        session.check("DO refusal preserves original", read_do(sdk, tag), original)
                finally:
                    if attempted and not session.broken:
                        session.trace.phase = "cleanup"
                        if owner_is_user:
                            sdk.verify_pin(session.options.openpgp_pin, extended=True)
                        else:
                            sdk.verify_admin(session.options.openpgp_admin)
                        sdk.put_data(tag, original)
                        session.check("DO catalog original restored", read_do(sdk, tag), original)
    opaque_text(session)


def opaque_text(session):
    from .card_pin_matrix import pgp_key, pgp_sign
    tags = {**{tag: maximum for tag, maximum in PERSONAL.items() if tag != 0x5f35}, **{tag: 2048 for tag in range(0x101, 0x105)}}
    for tag, maximum in tags.items():
        vectors = [("ASCII", b"Oracle"), ("multibyte", "é😀".encode()), ("invalid-UTF8", b"\xff\x80"),
            ("embedded-NUL", b"a\x00b"), ("leading-NUL", b"\x00tail"), ("partial-codepoint-at-byte-bound", b"x" * (maximum - 1) + b"\xc3")]
        for size in (maximum - 1, maximum, maximum + 1):
            vectors.append(("multibyte-byte-bound-" + str(size), ("é" * (size // 2)).encode() + b"x" * (size % 2)))
        for label, value in vectors:
            with session.case(f"openpgp.DO-opaque-text.{tag:04x}.{label}", ("O07", "O11", "O22", "G03", "G08", "G14"),
                    effects=("write_and_restore_openpgp_DO", "replace_openpgp_sig_key"), touch=True,
                    parameters={"tag": tag, "byte_length": len(value), "text_semantics": "opaque bytes, no UTF-8/NUL normalization"}):
                session.require(session.profile == "rsk", "opaque DO byte semantics require RS-Key", "excluded_by_profile")
                with pgp_key(session) as (sdk, key):
                    sdk.verify_pin(session.options.openpgp_pin, extended=True)
                    original = read_do(sdk, tag)
                    try:
                        response = session.apdu(codec.apdu(0xda, tag >> 8, tag & 255, value))
                        accepted = len(value) <= maximum
                        session.check("OpenPGP text DO is byte-bounded rather than Unicode-normalized", response.status, 0x9000 if accepted else 0x6a80)
                        session.check("OpenPGP DO retains every opaque byte or the original on refusal", read_do(sdk, tag), value if accepted else original)
                        pgp_sign(session, sdk, key)
                    finally:
                        if not session.broken:
                            session.trace.phase = "cleanup"
                            sdk.verify_admin(session.options.openpgp_admin)
                            sdk.verify_pin(session.options.openpgp_pin, extended=True)
                            sdk.put_data(tag, original)
                            session.check("opaque DO fixture restores the exact original bytes", read_do(sdk, tag), original)
    for value in range(256):
        with session.case(f"openpgp.DO-sex.byte-{value:02x}", ("O07", "O11", "G04", "G14"),
                effects=("write_and_restore_openpgp_DO", "replace_openpgp_sig_key"), touch=True):
            session.require(session.profile == "rsk", "sex DO uses its explicit profile value set", "excluded_by_profile")
            with pgp_key(session) as (sdk, key):
                original = read_do(sdk, 0x5f35)
                try:
                    response = session.apdu(codec.apdu(0xda, 0x5f, 0x35, bytes([value])))
                    accepted = value in b"129"
                    session.check("sex DO accepts exactly its three profiled byte values", response.status, 0x9000 if accepted else 0x6a80)
                    session.check("reserved sex byte cannot change the prior value", read_do(sdk, 0x5f35), bytes([value]) if accepted else original)
                    pgp_sign(session, sdk, key)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.verify_admin(session.options.openpgp_admin)
                        sdk.put_data(0x5f35, original)
