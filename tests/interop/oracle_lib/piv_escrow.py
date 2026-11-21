# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Escrow is an explicit ADMIN-DATA opt-in, never a stored host key copy."""
from . import codec
from .card_pin_matrix import piv_sign
from .piv_matrix import key_fixture

ADMIN, PRINTED, FACTORY_CERT, DISCOVERY = 0x5fff00, 0x5fc109, 0x5fff01, 0x7e


def read(session, object_id):
    width = 1 if object_id == DISCOVERY else 3
    result = session.apdu(codec.apdu(0xcb, 0x3f, 0xff, codec.tlv(0x5c, object_id.to_bytes(width, "big"))))
    session.check("escrow object read has an explicit result", result.status in (0x9000, 0x6a82))
    return result.data[:-2] if object_id == DISCOVERY else dict(codec.parse_tlv(result.data[:-2]))[0x53] if result.status == 0x9000 else None


def put(session, object_id, value):
    return session.apdu(codec.apdu(0xdb, 0x3f, 0xff, codec.tlv(0x5c, object_id.to_bytes(3, "big")) + codec.tlv(0x53, value or b"")))


def flags(value):
    if value is None:
        return 0
    outer = dict(codec.parse_tlv(value))
    return dict(codec.parse_tlv(outer[0x80])).get(0x81, b"\x00")[0]


def run(session):
    for protected in (False, True):
        with session.case(f"piv.escrow.protected-{protected}.ACL-storage-and-rotation", ("P06", "P07", "P13", "P17", "G09", "G10", "G14"),
                effects=("config_change", "replace_piv_keys", "write_and_restore_piv_objects"), touch=True):
            session.require(session.profile == "rsk", "factory-certificate and escrow semantics are RS-Key-specific", "excluded_by_profile")
            with key_fixture(session) as (sdk, key):
                original_admin, original_printed = read(session, ADMIN), read(session, PRINTED)
                session.require(not flags(original_admin) & 2, "escrow fixture requires initially unprotected management key")
                ordinary = session.fixture("piv.ordinary-printed", 24)
                try:
                    sdk.put_object(PRINTED, ordinary)
                    sdk.put_object(ADMIN, codec.tlv(0x80, codec.tlv(0x81, bytes([2 if protected else 0])) + codec.tlv(0x83, b"oracle")))
                    expected = codec.tlv(0x88, codec.tlv(0x89, session.options.management_key)) if protected else ordinary
                    session.check("PIN-readable escrow uses the live management key only after opt-in", read(session, PRINTED), expected)
                    for width in (16, 24, 32):
                        forged = codec.tlv(0x88, codec.tlv(0x89, session.fixture("forged.management-key", width)))
                        session.card_value(put(session, PRINTED, forged))
                        session.check("acknowledged host escrow bytes are never persisted", read(session, PRINTED), expected)
                    for body in (b"ordinary", codec.tlv(0x53, codec.tlv(0x88, codec.tlv(0x89, bytes(24)))),
                            codec.tlv(0x88, codec.tlv(0x89, bytes(24))) + b"\x00", b"\x88\x03\x89\x01x"):
                        result = put(session, PRINTED, body)
                        session.check("live escrow refuses unrelated nonempty PRINTED overwrite", result.status, 0x6985 if protected else 0x9000)
                        if not protected:
                            expected = body
                        session.check("escrow discrimination preserves the visible object", read(session, PRINTED), expected)
                    session.select("openpgp")
                    session.select("piv")
                    sdk.authenticate(session.options.management_key)
                    denied = session.apdu(codec.apdu(0xcb, 0x3f, 0xff, codec.tlv(0x5c, PRINTED.to_bytes(3, "big"))))
                    session.check("management grant cannot replace PIN for PRINTED", denied.status, 0x6982)
                    sdk.verify_pin(session.options.piv_pin)
                    session.check("PIN recovers the same visible object", read(session, PRINTED), expected)
                    if protected:
                        session.card_value(put(session, PRINTED, b""))
                        session.check("deleting ordinary PRINTED backing cannot delete synthesized escrow", read(session, PRINTED), expected)
                    sdk.set_management_key(sdk.management_key_type, session.options.management_key)
                    sdk.authenticate(session.options.management_key)
                    session.check("even identical explicit key rotation revokes escrow opt-in", bool(flags(read(session, ADMIN)) & 2), False)
                    session.check("rotation cannot disclose the replacement key as escrow", read(session, PRINTED), None if protected else expected)
                    sdk.verify_pin(session.options.piv_pin)
                    piv_sign(session, sdk, key)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.authenticate(session.options.management_key)
                        sdk.put_object(ADMIN, original_admin)
                        sdk.put_object(PRINTED, original_printed)
                        sdk.verify_pin(session.options.piv_pin)
                        session.check("escrow fixture restores ADMIN", read(session, ADMIN), original_admin)
                        session.check("escrow fixture restores ordinary PRINTED", read(session, PRINTED), original_printed)
    for object_id in (DISCOVERY, FACTORY_CERT):
        for authorized in (False, True):
            with session.case(f"piv.readonly-object.{object_id:06x}.management-{authorized}", ("P01", "P13", "P14", "G10", "G14"),
                    effects=("replace_piv_keys", "write_and_restore_piv_objects"), touch=True):
                session.require(session.profile == "rsk", "RS-Key refuses host factory-attestation replacement", "excluded_by_profile")
                with key_fixture(session) as (sdk, key):
                    original = read(session, object_id)
                    if not authorized:
                        session.select("openpgp")
                        session.select("piv")
                    result = put(session, object_id, b"must-not-replace-factory-object")
                    session.check("read-only object refusal follows management then object validation", result.status, 0x6a80 if authorized else 0x6982)
                    session.check("read-only object is exactly preserved", read(session, object_id), original)
                    sdk.verify_pin(session.options.piv_pin)
                    piv_sign(session, sdk, key)
