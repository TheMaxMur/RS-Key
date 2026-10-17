# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Card ACLs, one-shot grants, object rollback, and populated-key controls."""
from cryptography.hazmat.primitives import hashes

from . import codec
from .cards import connection, encoded_public, fixture_key, sdk_supported
from .fido import verified
from .runner import AIDS

PIV_FIXTURE_OBJECT = 0x5F0077
PGP_PERSONAL_DOS = ((0x5B, b"Oracle<<Fixture"), (0x5E, b"oracle@example.invalid"),
                    (0x5F2D, b"en"), (0x5F35, b"9"), (0x5F50, b"https://oracle.invalid/key"))


def sdk_refused(session, operation, label, expected_status):
    from yubikit.core.smartcard import ApduError
    start = len(session.trace.exchanges)
    try:
        operation()
    except ApduError as error:
        session.check(label + " reached the card", len(session.trace.exchanges) > start)
        session.check(label + " refused by card", session.trace.exchanges[-1]["protocol_outcome"], "applet_error")
        session.observe(label + ".status", error.sw)
        session.check(label + " refusal cause", error.sw, expected_status)
        return session.evidence()
    session.check(label + " must be refused", False)


def selection(session):
    for applet in ("piv", "openpgp", "oath"):
        for transition in ("same", "different", "invalid", "prefix", "suffix"):
            with session.case(f"card.selection.{applet}.{transition}", ("P01" if applet == "piv" else "O01" if applet == "openpgp" else "A01", "X02", "G09")):
                session.select(applet)
                initial = session.evidence()
                if transition == "different":
                    session.select("openpgp" if applet != "openpgp" else "piv")
                else:
                    aid = AIDS[applet]
                    selected = aid if transition == "same" else aid[:5] if transition == "prefix" else aid + b"\x00" if transition == "suffix" else b"\xf0\xff\xff\xff\xff"
                    reply = session.apdu(codec.apdu(0xA4, 4, data=selected), "select.transition." + transition)
                    session.observe("transition.status", reply.status)
                    if transition == "invalid":
                        session.check("unknown AID refused", reply.protocol, "applet_error")
                trigger = session.evidence()
                session.select(applet)
                session.transition("card.selection", "selected:" + applet, "selected:" + applet,
                                   trigger, [initial, trigger, session.evidence()])


def piv_grants(session):
    from yubikit.piv import KEY_TYPE, PIN_POLICY, SLOT, PivSession
    for policy in (PIN_POLICY.ONCE, PIN_POLICY.ALWAYS, PIN_POLICY.NEVER):
        with session.case("piv.transition.pin-policy." + policy.name.lower(), ("P03", "P09", "P10", "P11", "P17", "G10", "G14"),
                          effects=("replace_piv_slot_82",), touch=True):
            session.require(session.options.management_key is not None and session.options.piv_pin is not None,
                            "PIV policy fixtures require management key and PIN")
            piv = PivSession(connection(session))
            piv.authenticate(session.options.management_key)
            key = fixture_key(session, "ECCP256")
            created = False
            try:
                sdk_supported(session, lambda: piv.put_key(SLOT(0x82), key, pin_policy=policy))
                created = True
                message = session.fixture("piv.policy.message")

                def sign():
                    return piv.sign(SLOT(0x82), KEY_TYPE.ECCP256, message, hashes.SHA256())

                piv.verify_pin(session.options.piv_pin)
                signature = sign()
                verified(session, "authorized populated PIV signature", key.public_key(), -7, signature, message)
                initial = session.evidence()
                if policy == PIN_POLICY.ALWAYS:
                    trigger = sdk_refused(session, sign, "consumed one-shot PIN grant", 0x6982)
                    piv.verify_pin(session.options.piv_pin)
                    verified(session, "PIV valid control after refusal", key.public_key(), -7, sign(), message)
                    session.transition("piv.PIN_grant", "consumed", "new_grant_consumed", trigger, [initial, trigger, session.evidence()])
                else:
                    verified(session, "PIV repeated signature", key.public_key(), -7, sign(), message)
                    session.observe("repeat_policy", policy.name)
                metadata = sdk_supported(session, lambda: piv.get_slot_metadata(SLOT(0x82)))
                session.check("metadata PIN policy", metadata.pin_policy, policy)
                session.check("metadata public key", encoded_public(metadata.public_key), encoded_public(key.public_key()))
            finally:
                if created and not session.broken:
                    session.trace.phase = "cleanup"
                    if piv.version >= (5, 7, 0):
                        piv.authenticate(session.options.management_key)
                        piv.delete_key(SLOT(0x82))
                    else:
                        session.observe("cleanup", "fixture remains; DELETE KEY unavailable")


def piv_objects(session):
    from yubikit.piv import PivSession
    for size in (0, 1, 127, 128, 254, 255, 256, 1024, 2048):
        with session.case(f"piv.transition.object.{size}", ("P06", "P13", "T12", "T13", "G03", "G14"), effects=("write_piv_fixture_object",)):
            session.require(session.options.management_key is not None, "PIV objects require --management-key-env")
            piv = PivSession(connection(session))
            piv.authenticate(session.options.management_key)
            request = codec.apdu(0xCB, 0x3F, 0xFF, codec.tlv(0x5C, PIV_FIXTURE_OBJECT.to_bytes(3, "big")))
            existing = session.apdu(request)
            session.require(existing.status == 0x6A82, "PIV fixture object is occupied or its absence is unconfirmed")
            changed = False
            try:
                value = session.fixture("piv.object", size)
                piv.put_object(PIV_FIXTURE_OBJECT, value)
                changed = True
                if size:
                    session.check("PIV object readback", piv.get_object(PIV_FIXTURE_OBJECT), value)
                    initial = session.evidence()
                    malformed = codec.tlv(0x5C, PIV_FIXTURE_OBJECT.to_bytes(3, "big")) + b"\x53\x82\xff"
                    reply = session.apdu(codec.apdu(0xDB, 0x3F, 0xFF, malformed))
                    session.check("truncated object TLV refused", reply.protocol, "applet_error")
                    trigger = session.evidence()
                    session.check("object survived malformed replacement", piv.get_object(PIV_FIXTURE_OBJECT), value)
                    session.transition("piv.object", "present", "unchanged", trigger, [initial, trigger, session.evidence()])
                else:
                    session.check("empty PUT deletes object", session.apdu(request).status, 0x6A82)
            finally:
                if changed and not session.broken:
                    session.trace.phase = "cleanup"
                    piv.authenticate(session.options.management_key)
                    piv.put_object(PIV_FIXTURE_OBJECT, None)
                    session.check("fixture object absent after cleanup", session.apdu(request).status, 0x6A82)


def pgp_grants(session):
    from yubikit.openpgp import KEY_REF, OpenPgpSession
    for reference in (KEY_REF.SIG, KEY_REF.AUT):
        with session.case("openpgp.transition.PW-scope." + reference.name.lower(), ("O02", "O10", "O11", "O12", "O22", "G10", "G14"),
                          effects=("replace_openpgp_" + reference.name.lower() + "_key",), touch=True):
            session.require(session.options.openpgp_pin is not None and session.options.openpgp_admin is not None,
                            "OpenPGP grants require user and admin PINs")
            pgp = OpenPgpSession(connection(session))
            pgp.verify_admin(session.options.openpgp_admin)
            key = fixture_key(session, "ECCP256")
            created = False
            try:
                pgp.put_key(reference, key)
                created = True
                message = session.fixture("pgp.PW-scope.message")
                operation = pgp.sign if reference == KEY_REF.SIG else pgp.authenticate
                right, wrong = (0x81, 0x82) if reference == KEY_REF.SIG else (0x82, 0x81)
                # Explicit logout avoids attributing a pre-existing grant to this VERIFY.
                for pw in (0x81, 0x82):
                    reply = session.apdu(codec.apdu(0x20, 0xFF, pw))
                    session.require(reply.status == 0x9000, "profile does not support explicit VERIFY logout")
                pgp.verify_pin(session.options.openpgp_pin, extended=wrong == 0x82)
                before = pgp.get_signature_counter()
                trigger = sdk_refused(session, lambda: operation(message, hashes.SHA256()), "wrong PW1 reference on populated key", 0x6982)
                session.check("rejected operation does not increment SIG counter", pgp.get_signature_counter(), before)
                pgp.verify_pin(session.options.openpgp_pin, extended=right == 0x82)
                verified(session, "correct PW1 reference control", key.public_key(), -7, operation(message, hashes.SHA256()), message)
                session.check("successful operation counter scope", pgp.get_signature_counter() - before, 1 if reference == KEY_REF.SIG else 0)
                session.transition("openpgp.authorization", "wrong_PW1_mode", "right_PW1_mode_usable", trigger, [trigger, session.evidence()])
            finally:
                if created and not session.broken:
                    session.trace.phase = "cleanup"
                    pgp.verify_admin(session.options.openpgp_admin)
                    sdk_supported(session, lambda: pgp.delete_key(reference))


def pgp_objects(session):
    from yubikit.openpgp import OpenPgpSession
    for tag, replacement in PGP_PERSONAL_DOS:
        with session.case(f"openpgp.transition.DO.{tag:04x}", ("O01", "O02", "O07", "G10", "G14"), effects=("write_and_restore_openpgp_DO",)):
            session.require(session.options.openpgp_admin is not None, "DO write requires --openpgp-admin-env")
            pgp = OpenPgpSession(connection(session))
            original = pgp.get_data(tag)
            pgp.verify_admin(session.options.openpgp_admin)
            changed = False
            try:
                pgp.put_data(tag, replacement)
                changed = True
                session.check("DO write readback", pgp.get_data(tag), replacement)
                logout = session.apdu(codec.apdu(0x20, 0xFF, 0x83))
                session.require(logout.status == 0x9000, "profile does not support explicit admin logout")
                trigger = sdk_refused(session, lambda: pgp.put_data(tag, replacement), "unauthenticated DO replacement", 0x6982)
                session.check("DO unchanged after ACL refusal", pgp.get_data(tag), replacement)
                session.transition("openpgp.DO", "written_authenticated", "unchanged_unauthenticated", trigger, [trigger, session.evidence()])
            finally:
                if changed and not session.broken:
                    session.trace.phase = "cleanup"
                    pgp.verify_admin(session.options.openpgp_admin)
                    pgp.put_data(tag, original)
                    session.check("original DO restored", pgp.get_data(tag), original)


def pin_changes(session):
    from yubikit.piv import PivSession
    from yubikit.openpgp import OpenPgpSession
    for applet in ("piv", "openpgp"):
        with session.case("card.transition.PIN-change." + applet, ("P04" if applet == "piv" else "O03", "G14"), effects=("pin_change",)):
            old = session.options.piv_pin if applet == "piv" else session.options.openpgp_pin
            session.require(old is not None, "PIN change requires the existing PIN environment option")
            sdk = PivSession(connection(session)) if applet == "piv" else OpenPgpSession(connection(session))
            new = "864209" if old != "864209" else "975310"
            changed = False
            try:
                sdk.change_pin(old, new)
                changed = True
                trigger = session.evidence()
                sdk.verify_pin(new)
                session.transition(applet + ".PIN", "original_PIN", "replacement_PIN_verified", trigger, [trigger, session.evidence()])
            finally:
                if changed and not session.broken:
                    session.trace.phase = "cleanup"
                    sdk.change_pin(new, old)
                    sdk.verify_pin(old)
                    session.observe("cleanup", "original PIN restored and verified")


def cross_applet(session):
    bad = {"oath": codec.apdu(0xA1, p1=1), "piv": codec.apdu(0xCB, 0x3F, 0xFF, b"\x5c\x03\x00"),
           "openpgp": codec.apdu(0xCA, 0xFF, 0xFF)}
    controls = {"oath": None, "piv": codec.apdu(0xFD), "openpgp": codec.apdu(0x84, le=8)}
    for first in bad:
        for second in controls:
            if first == second:
                continue
            with session.case(f"card.cross-applet.recovery.{first}.{second}", ("X12", "G14")):
                session.select(first)
                refused = session.apdu(bad[first])
                session.check("first applet refused malformed command", refused.protocol, "applet_error")
                trigger = session.evidence()
                selected = session.select(second)
                if controls[second] is not None:
                    body = session.card_value(session.apdu(controls[second]))
                    session.check("second applet control length", len(body), 3 if second == "piv" else 8)
                else:
                    session.check("OATH SELECT after foreign refusal", len(selected) > 0)
                session.transition("card.shared_session", "first_applet_rejected", "second_applet_usable", trigger, [trigger, session.evidence()])


def run(session):
    selection(session)
    cross_applet(session)
    piv_grants(session)
    piv_objects(session)
    pgp_grants(session)
    pgp_objects(session)
    pin_changes(session)
