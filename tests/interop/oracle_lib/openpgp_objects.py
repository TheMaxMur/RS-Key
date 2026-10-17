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
                changed = False
                try:
                    reply = session.apdu(codec.apdu(0xDA, tag >> 8, tag & 255, value), "openpgp.DO-catalog.PUT")
                    valid_length = length == maximum if fixed else length <= maximum
                    if not valid_length and session.profile == "rsk":
                        session.check("DO length boundary refusal", reply.status, 0x6A80)
                        session.check("refused DO length preserves original", read_do(sdk, tag), original)
                    elif reply.protocol == "success":
                        changed = True
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
                        session.observe("profile_boundary_refusal", reply.status)
                finally:
                    if changed and not session.broken:
                        session.trace.phase = "cleanup"
                        if owner_is_user:
                            sdk.verify_pin(session.options.openpgp_pin, extended=True)
                        else:
                            sdk.verify_admin(session.options.openpgp_admin)
                        sdk.put_data(tag, original)
                        session.check("DO catalog original restored", read_do(sdk, tag), original)
