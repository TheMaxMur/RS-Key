# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Read and write each public/private DO under its actual owner and lifetime."""
from . import codec
from .card_pin_matrix import pgp_key, pgp_sign
from .lifecycle import Action, change
from .openpgp_objects import PERSONAL, FINGERPRINTS, read_do
from .openpgp_lifecycle import fixture_session

WRITABLE = {**{tag: (b"9" if tag == 0x5F35 else b"en" if tag == 0x5F2D else b"oracle-DO") for tag in PERSONAL},
            **{tag: bytes([tag & 255]) * width for tag, (_, _, width) in FINGERPRINTS.items()},
            **{tag: b"oracle-private-DO" for tag in (0x101, 0x102, 0x103, 0x104)},
            **{tag: b"\x00\x20" for tag in (0xD6, 0xD7, 0xD8, 0xD9)}, 0x7F21: b"oracle-certificate"}
NESTED = (0x5B, 0x5F2D, 0x5F35, 0x73, 0x93, 0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xCD,
          *range(0xC7, 0xD1), 0xDA, 0xDB, 0xDC, 0xDD)
INTERNAL = (0xD3, 0xD5, *range(0x1081, 0x1084), *range(0x1099, 0x10A3),
            *range(0x10C1, 0x10C6), *range(0x10D1, 0x10D8), 0x10DA, 0x10DE, 0x1F21, 0x1F22, 0x1F23)
READ_ONLY = (0x4F, 0x5F52, 0x65, 0x6E, 0x73, 0x7A, 0x7F66, 0x7F74, 0xC0, 0xC5, 0xC6, 0xCD, 0xDA, 0xDE, 0xFA, 0xFC)


def grants(session, sdk, references):
    for reference in (0x81, 0x82, 0x83):
        session.card_value(session.apdu(codec.apdu(0x20, 0xFF, reference)))
    for reference in references:
        if reference == 0x83:
            sdk.verify_admin(session.options.openpgp_admin)
        else:
            sdk.verify_pin(session.options.openpgp_pin, extended=reference == 0x82)


def owner(sdk, session, tag):
    if tag in (0x101, 0x103):
        sdk.verify_pin(session.options.openpgp_pin, extended=True)
    else:
        sdk.verify_admin(session.options.openpgp_admin)
    if tag == 0x103:
        sdk.verify_pin(session.options.openpgp_pin, extended=True)


def acl(session):
    for tag, value in WRITABLE.items():
        for label, references in (("none", ()), ("PW1-81", (0x81,)), ("PW1-82", (0x82,)), ("PW3", (0x83,)), ("both", (0x82, 0x83))):
            with session.case(f"openpgp.DO-owner.{tag:04x}.{label}", ("O01", "O07", "O02", "G10", "G14"),
                              effects=("write_and_restore_openpgp_DO", "replace_openpgp_sig_key"), touch=True):
                session.require(session.profile == "rsk", "complete DO ownership table requires RS-Key", "excluded_by_profile")
                with pgp_key(session) as (sdk, key):
                    sdk.verify_pin(session.options.openpgp_pin, extended=True)
                    original = read_do(sdk, tag)
                    session.require(tag not in range(0xD6, 0xDA) or not original or original[0] != 2,
                                    "fixed UIF cannot be restored without resetting the applet")
                    written = False
                    try:
                        owner(sdk, session, tag)
                        sdk.put_data(tag, value)
                        written = True
                        grants(session, sdk, references)
                        can_write = (0x82 if tag in (0x101, 0x103) else 0x83) in references
                        reply = session.apdu(codec.apdu(0xDA, tag >> 8, tag & 255, value))
                        session.check("same-value PUT still enforces the DO owner", reply.status, 0x9000 if can_write else 0x6982)
                        can_read = tag not in (0x103, 0x104) or (0x82 if tag == 0x103 else 0x83) in references
                        if tag in (0x103, 0x104):
                            result = session.apdu(codec.apdu(0xCA, tag >> 8, tag & 255))
                            session.check("private DO has no foreign-password override", result.status, 0x9000 if can_read else 0x6982)
                        if not can_read:
                            owner(sdk, session, tag)
                        session.check("DO owner checks preserve the complete value", read_do(sdk, tag), value)
                        sdk.verify_pin(session.options.openpgp_pin)
                        pgp_sign(session, sdk, key)
                    finally:
                        if written and not session.broken:
                            session.trace.phase = "cleanup"
                            owner(sdk, session, tag)
                            sdk.put_data(tag, original)
                            session.check("DO owner fixture restored", read_do(sdk, tag), original)


def catalog(session):
    for kind, tags in (("nested", NESTED), ("internal", INTERNAL), ("unknown", (0, 1, 0x42, 0xFF, 0x100, 0x105, 0x7F22, 0xFFFF))):
        for tag in dict.fromkeys(tags):
            for authenticated in (False, True):
                with session.case(f"openpgp.GET-catalog.{kind}.{tag:04x}.PW3-{authenticated}", ("O01", "O07", "G04", "G10", "G14")):
                    session.require(session.profile == "rsk", "GET DATA visibility catalog requires RS-Key", "excluded_by_profile")
                    sdk = fixture_session(session)
                    grants(session, sdk, (0x83,) if authenticated else ())
                    before = sdk.get_data(0x6E)
                    result = session.apdu(codec.apdu(0xCA, tag >> 8, tag & 255))
                    session.check("nested/internal/unknown DO is not independently readable", result.status, 0x6B00)
                    session.check("refused GET DATA preserves public template", sdk.get_data(0x6E), before)
    for tag in READ_ONLY:
        for references in ((), (0x82,), (0x83,)):
            with session.case(f"openpgp.PUT-read-only.{tag:04x}.grants-{'-'.join(map(str, references)) or 'none'}", ("O01", "O07", "G10", "G14")):
                session.require(session.profile == "rsk", "PUT DATA read-only catalog requires RS-Key", "excluded_by_profile")
                sdk = fixture_session(session)
                grants(session, sdk, references)
                before = sdk.get_data(0x6E)
                response = session.apdu(codec.apdu(0xDA, tag >> 8, tag & 255, b"invalid-write"))
                session.check("read-only PUT validates authentication before visibility", response.status, 0x6B00 if 0x83 in references else 0x6982)
                session.check("read-only PUT preserves public template", sdk.get_data(0x6E), before)


def persistence(session):
    for tag, value in WRITABLE.items():
        for action in Action:
            with session.case(f"openpgp.DO-lifetime.{tag:04x}.{action.value}", ("O01", "O07", "X11", "G14"),
                              effects=("write_and_restore_openpgp_DO", "reboot") if action == Action.POWER_CYCLE else ("write_and_restore_openpgp_DO",)):
                session.require(session.profile == "rsk", "DO lifetime catalog requires RS-Key", "excluded_by_profile")
                session.require(session.card is not None and hasattr(session.card, "control"), "DO lifetime requires an explicit connection backend", "excluded_by_mode")
                sdk = fixture_session(session)
                sdk.verify_pin(session.options.openpgp_pin, extended=True)
                original = read_do(sdk, tag)
                session.require(tag not in range(0xD6, 0xDA) or not original or original[0] != 2, "fixed UIF cannot be overwritten")
                written = False
                try:
                    owner(sdk, session, tag)
                    sdk.put_data(tag, value)
                    written = True
                    change(session, action)
                    sdk = fixture_session(session)
                    sdk.verify_pin(session.options.openpgp_pin, extended=True)
                    session.check("each writable DO survives connection change", read_do(sdk, tag), value)
                finally:
                    if written and not session.broken:
                        session.trace.phase = "cleanup"
                        session.select("openpgp")
                        owner(sdk, session, tag)
                        sdk.put_data(tag, original)
                        session.check("persistent DO fixture restored", read_do(sdk, tag), original)


def run(session):
    acl(session)
    catalog(session)
    persistence(session)


def reset_defaults(session):
    from .openpgp_lifecycle import lifecycle
    ready = False
    with session.namespace("openpgp.DO-reset."):
        with session.case("populate-catalog", ("O01", "O07", "O21", "X06"), effects=("write_and_restore_openpgp_DO",)):
            session.require(session.profile == "rsk", "DO reset defaults require RS-Key", "excluded_by_profile")
            sdk = fixture_session(session)
            sdk.verify_pin(session.options.openpgp_pin, extended=True)
            for tag, value in WRITABLE.items():
                owner(sdk, session, tag)
                sdk.put_data(tag, value)
                session.check("reset fixture has populated DO", read_do(sdk, tag), value)
            ready = True
        if ready or session.planning:
            lifecycle(session)
        with session.case("verify-each-default", ("O01", "O07", "O21", "X06")):
            session.require(ready, "reset defaults need a populated DO catalog")
            sdk = fixture_session(session)
            sdk.verify_pin(session.options.openpgp_pin, extended=True)
            for tag in WRITABLE:
                expected = bytes(FINGERPRINTS[tag][2]) if tag in FINGERPRINTS else b"\x00\x20" if tag in range(0xD6, 0xDA) else b"9" if tag == 0x5F35 else b""
                session.check(f"DO {tag:04x} reset default", read_do(sdk, tag), expected)
            session.check("reset KDF is disabled", sdk.get_data(0xF9), b"\x81\x01\x00")
            session.check("reset retry/PIN mode defaults", sdk.get_data(0xC4), bytes([1, 127, 127, 127, 3, 0, 3]))
