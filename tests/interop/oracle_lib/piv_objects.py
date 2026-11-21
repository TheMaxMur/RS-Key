# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PIV object ACLs, pool quotas and chaining have separate populated controls."""
from . import codec
from .card_pin_matrix import piv_sign
from .piv_matrix import key_fixture
from .piv_lifecycle import fixture_session
from .lifecycle import Action, change
from .apdu_matrix import collect

MAX_OBJECT = 3063
CHAIN_LIMIT = 3072
POOL_BYTES = 32768
POOL_SLOTS = 256
CHUID = 0x5FC102
CCC = 0x5FC107
DEFAULT_CCC = bytes.fromhex("f000f100f200f50110")
OBJECTS = (*range(0x5FC100, 0x5FC1F0), 0x5FC1F0, 0x5FC1F1, 0x5FFF00, *range(0x5FFF10, 0x5FFF16), 0x5F0077)
PIN_OBJECTS = (0x5FC103, 0x5FC108, 0x5FC109, 0x5FC121)


def read(session, identifier):
    body = codec.tlv(0x5C, identifier.to_bytes(max(1, (identifier.bit_length() + 7) // 8), "big"))
    reply = session.apdu(codec.apdu(0xCB, 0x3F, 0xFF, body))
    if reply.status == 0x9000 or reply.status >> 8 == 0x61:
        return dict(codec.parse_tlv(collect(session, reply)))[0x53]
    session.check("object is present or absent after authorized read", reply.status, 0x6A82)
    return None


def write(session, identifier, value, chunk=255):
    data = codec.tlv(0x5C, identifier.to_bytes(3, "big")) + codec.tlv(0x53, value or b"")
    parts = [data[offset:offset + chunk] for offset in range(0, len(data), chunk)]
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        response = session.apdu(codec.apdu(0xDB, 0x3F, 0xFF, part, cla=0 if last else 0x10), "piv.object.PUT-chunk")
        if not last and response.status != 0x9000:
            return response
    return response


def owners(session):
    for identifier in OBJECTS:
        for grants in ("none", "PIN", "management", "both"):
            with session.case(f"piv.object.owner.{identifier:06x}.{grants}", ("P13", "P03", "P06", "G09", "G10", "G14"),
                              effects=("write_and_restore_piv_object", "replace_piv_slot_82"), touch=True):
                session.require(session.profile == "rsk", "complete fixed/pool object map requires RS-Key", "excluded_by_profile")
                with key_fixture(session) as (sdk, key):
                    sdk.verify_pin(session.options.piv_pin)
                    original = read(session, identifier)
                    value = b"\x80\x03\x81\x01\x00" if identifier == 0x5FFF00 else b"oracle-PIV-object"
                    changed = False
                    try:
                        result = write(session, identifier, value)
                        session.card_value(result)
                        changed = True
                        session.check("owned PIV object exists", read(session, identifier), value)
                        session.select("openpgp")
                        session.select("piv")
                        if grants in ("PIN", "both"):
                            sdk.verify_pin(session.options.piv_pin)
                        if grants in ("management", "both"):
                            sdk.authenticate(session.options.management_key)
                        body = codec.tlv(0x5C, identifier.to_bytes(3, "big"))
                        reply = session.apdu(codec.apdu(0xCB, 0x3F, 0xFF, body))
                        session.check("PIV read ACL cannot be replaced by management authentication", reply.status,
                                      0x6982 if identifier in PIN_OBJECTS and grants not in ("PIN", "both") else 0x9000)
                        reply = write(session, identifier, value)
                        session.check("identical PIV PUT still requires management grant", reply.status, 0x9000 if grants in ("management", "both") else 0x6982)
                        sdk.verify_pin(session.options.piv_pin)
                        session.check("PIV ACL checks preserve complete object", read(session, identifier), value)
                        piv_sign(session, sdk, key)
                        sdk.authenticate(session.options.management_key)
                        session.card_value(write(session, identifier, None))
                        deleted = read(session, identifier)
                        if identifier == CHUID:
                            session.check("deleted CHUID falls back to synthesized default", deleted is not None and deleted != value)
                        elif identifier == CCC:
                            session.check("deleted CCC falls back to synthesized default", deleted, DEFAULT_CCC)
                        else:
                            session.check("empty PUT deletes the object", deleted, None)
                        session.card_value(write(session, identifier, None))
                    finally:
                        if changed and not session.broken:
                            session.trace.phase = "cleanup"
                            sdk.authenticate(session.options.management_key)
                            session.card_value(write(session, identifier, original))
                            sdk.verify_pin(session.options.piv_pin)
                            session.check("PIV object semantic value restored", read(session, identifier), original)
                            if identifier in (CHUID, CCC):
                                session.observe("cleanup_limit", "a synthesized read cannot distinguish absent storage from the identical stored object")


def persistence(session):
    for identifier in OBJECTS:
        for action in Action:
            with session.case(f"piv.object.lifetime.{identifier:06x}.{action.value}", ("P13", "X11", "G14"),
                              effects=("write_and_restore_piv_object", "reboot") if action == Action.POWER_CYCLE else ("write_and_restore_piv_object",)):
                session.require(session.profile == "rsk", "PIV object lifetime map requires RS-Key", "excluded_by_profile")
                session.require(session.card is not None and hasattr(session.card, "control"), "PIV lifetime requires a defined connection backend", "excluded_by_mode")
                sdk = fixture_session(session)
                original = read(session, identifier)
                value = b"\x80\x03\x81\x01\x00" if identifier == 0x5FFF00 else b"oracle-persistent-PIV"
                changed = False
                try:
                    session.card_value(write(session, identifier, value))
                    changed = True
                    change(session, action)
                    sdk = fixture_session(session)
                    session.check("PIV object survives connection change", read(session, identifier), value)
                finally:
                    if changed and not session.broken:
                        session.trace.phase = "cleanup"
                        session.select("piv")
                        sdk.authenticate(session.options.management_key)
                        session.card_value(write(session, identifier, original))
                        sdk.verify_pin(session.options.piv_pin)
                        session.check("persistent PIV object restored", read(session, identifier), original)


def boundaries(session):
    for size in (0, 1, MAX_OBJECT - 1, MAX_OBJECT, MAX_OBJECT + 1, CHAIN_LIMIT, CHAIN_LIMIT + 1):
        for chunk in (127, 255):
            with session.case(f"piv.object.chained-boundary.size-{size}.chunk-{chunk}", ("P13", "T11", "T12", "G03", "G12", "G14"), effects=("write_and_restore_piv_object",)):
                session.require(session.profile == "rsk", "PIV chain/object ceilings require RS-Key", "excluded_by_profile")
                sdk = fixture_session(session)
                identifier = 0x5F0077
                original = read(session, identifier)
                try:
                    value = session.fixture("PIV.object.boundary", size)
                    reply = write(session, identifier, value, chunk)
                    if size <= MAX_OBJECT:
                        session.card_value(reply)
                        session.check("bounded PIV object roundtrips completely", read(session, identifier), value or None)
                    else:
                        session.check("chain overflow is refused before object storage", reply.protocol, "applet_error")
                        session.observe("observable_limit", "MAX_OBJECT + its 9-byte PUT envelope equals the chain limit; a larger object cannot independently reach the object's own length guard")
                        session.select("piv")
                        sdk.authenticate(session.options.management_key)
                        session.check("overflow chain preserves previous object", read(session, identifier), original)
                    session.card_value(write(session, identifier, b"oracle-after-overflow"))
                    session.check("fresh command works after abandoned/overflow chain", read(session, identifier), b"oracle-after-overflow")
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        session.select("piv")
                        sdk.authenticate(session.options.management_key)
                        session.card_value(write(session, identifier, original))


def capacity(session):
    from .piv_lifecycle import reset
    for kind, width in (("bytes", MAX_OBJECT), ("records", 1)):
        empty, prepared = False, False
        with session.namespace("piv.pool." + kind + "."):
            with session.case("prepare-reset", ("P13", "P16", "X07"), effects=("capacity", "applet_reset")):
                session.require(session.profile == "rsk", "independent pool quota measurements require RS-Key", "excluded_by_profile")
                prepared = True
                session.observe("quota_setup", "PIV reset establishes an empty fixed/pool store before either independent limit")
            if prepared or session.planning:
                before = len(session.trace.cases)
                reset(session)
                empty = any(row["verdict"] == "pass" for row in session.trace.cases[before:])
            with session.case("fill-reclaim", ("P13", "X07", "G09", "G14"), effects=("capacity", "write_piv_fixture_objects")):
                session.require(empty, "independent pool quota measurement requires a witnessed PIV reset")
                sdk = fixture_session(session)
                owned, full = [], False
                value = session.fixture("PIV.pool.capacity", width)
                try:
                    for index in range(POOL_SLOTS + 1):
                        identifier = 0x5F8000 + index
                        session.check("reset pool fixture ID is vacant", read(session, identifier), None)
                        reply = write(session, identifier, value)
                        if reply.status != 0x9000:
                            session.check("pool exhaustion has storage cause", reply.status, 0x6A84)
                            full = True
                            break
                        owned.append(identifier)
                    session.check("pool reaches the independently bounded quota", full)
                    expected = POOL_BYTES // width if kind == "bytes" else POOL_SLOTS
                    session.check("byte and record quotas are measured independently", len(owned), expected)
                    for identifier in owned:
                        session.check("exhaustion preserves every owned record", read(session, identifier), value)
                    removed = owned.pop()
                    session.card_value(write(session, removed, None))
                    replacement = 0x5F9000
                    session.card_value(write(session, replacement, value))
                    owned.append(replacement)
                    session.check("deletion reclaims exactly enough quota", read(session, replacement), value)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.authenticate(session.options.management_key)
                        for identifier in owned:
                            session.card_value(write(session, identifier, None))
                            session.check("pool fixture removed", read(session, identifier), None)


def run(session):
    owners(session)
    persistence(session)
    boundaries(session)
