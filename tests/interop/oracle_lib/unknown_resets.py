# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""A lost lifecycle answer is resolved before reset recovery or neighbor cleanup."""
from . import codec
from .binding import require_pair
from .cards import encoded_public
from .cross_reset import Fixtures
from .fido import cm, info, pin_token
from .fido_fixtures import provision_after_reset
from .lifecycle import Action, change, require_action
from .otp import oath_names, oath_open
from .runner import AIDS, CtapRoute
from .uncertain_writes import classify, lose, require_loss

TARGETS = ("oath", "openpgp-terminate", "openpgp-activate", "piv", "fido")


def oath(session, fixtures):
    oath_open(session)
    original = oath_names(session)
    session.check("unknown OATH reset starts with its owned populated reference", fixtures.oath_name in original)
    lose(session, 4, lambda: session.apdu(codec.apdu(4, 0xde, 0xad)))
    oath_open(session)
    current = oath_names(session)
    classify(session, "whole OATH reset name set", current, original, set())
    return "oath" if not current else None


def openpgp(session, target, fixtures):
    from .openpgp_reset_profile import activate
    session.select("openpgp")
    fixtures.pgp.verify_admin(session.options.openpgp_admin)
    marker = b"oracle-unknown-lifecycle"
    original = fixtures.pgp.get_data(0x5e)
    fixtures.pgp.put_data(0x5e, marker)
    if target == "openpgp-activate":
        session.card_value(session.apdu(codec.apdu(0xe6)))
    lose(session, 0xe6 if target == "openpgp-terminate" else 0x44,
        lambda: session.apdu(codec.apdu(0xe6 if target == "openpgp-terminate" else 0x44)))
    selected = session.apdu(codec.apdu(0xa4, 4, data=AIDS["openpgp"]))
    session.check("OpenPGP lifecycle readback is active or explicitly terminated", selected.status in (0x9000, 0x6285))
    terminated = selected.status == 0x6285
    session.observe("OpenPGP_lost_lifecycle_readback", {"request": target, "terminated": terminated,
        "committed": terminated if target == "openpgp-terminate" else not terminated, "unknown_request_replayed": False})
    if target == "openpgp-terminate" and not terminated:
        session.check("uncommitted termination preserves its exact existing object", fixtures.pgp.get_data(0x5e), marker)
        fixtures.pgp.verify_admin(session.options.openpgp_admin)
        fixtures.pgp.put_data(0x5e, original)
        return None
    if terminated:
        session.observe("explicit_recovery", "ACTIVATE after observed terminated state; a lost TERMINATE is never repeated, and a lost ACTIVATE is recovered only after decisive readback shows it did not commit")
        activate(session)
    else:
        session.options.openpgp_pin, session.options.openpgp_admin, session.options.openpgp_reset_code = "123456", "12345678", ""
        for reference in (0x81, 0x83, "reset_code"):
            session.failed_auth.discard(("openpgp", reference))
    session.select("openpgp")
    session.check("readback-confirmed activation clears the old personal object", fixtures.pgp.get_data(0x5e), b"")
    session.check("readback-confirmed activation restores factory retry state", fixtures.pgp.get_data(0xc4)[4:], b"\x03\x00\x03")
    return "openpgp"


def piv(session, fixtures):
    from yubikit.piv import DEFAULT_MANAGEMENT_KEY, PIN_POLICY, SLOT
    from .card_pin_matrix import piv_sign
    from .piv_lifecycle import recovered, wire_pin
    from .piv_matrix import key_fixture
    sdk = fixtures.piv
    session.select("piv")
    sdk.authenticate(session.options.management_key)
    marker = 0x5f0077
    sdk.put_object(marker, b"oracle-unknown-reset")
    old_public = encoded_public(sdk.get_slot_metadata(SLOT(0x82)).public_key)
    for reference, secret, metadata in ((0x80, session.options.piv_pin, sdk.get_pin_metadata()), (0x81, session.options.piv_puk, sdk.get_puk_metadata())):
        session.require(1 <= metadata.attempts_remaining <= 16, "PIV reset preparation needs bounded independently available PIN/PUK budgets")
        wrong = "00000000" if secret != "00000000" else "11111111"
        with session.attempts(("piv", reference), metadata.attempts_remaining):
            for _ in range(metadata.attempts_remaining):
                reply = session.apdu(codec.apdu(0x20, p2=0x80, data=wire_pin(wrong)) if reference == 0x80 else codec.apdu(0x2c, p2=0x80, data=wire_pin(wrong) + wire_pin("123456")))
                session.check("PIV reset preparation performs an actual refused comparison", reply.is_rejection)
    session.check("both reference budgets are blocked before the unknown reset", (sdk.get_pin_metadata().attempts_remaining, sdk.get_puk_metadata().attempts_remaining), (0, 0))
    lose(session, 0xfb, lambda: session.apdu(codec.apdu(0xfb)))
    session.select("piv")
    counts = sdk.get_pin_metadata().attempts_remaining, sdk.get_puk_metadata().attempts_remaining
    object_reply = session.apdu(codec.apdu(0xcb, 0x3f, 0xff, codec.tlv(0x5c, marker.to_bytes(3, "big"))))
    key_reply = session.apdu(codec.apdu(0xf7, p2=0x82))
    old = counts == (0, 0) and object_reply.status == key_reply.status == 0x9000
    new = counts == (3, 3) and object_reply.status == 0x6a82 and key_reply.status == 0x6a88
    session.check("unknown PIV reset has a complete blocked old state or complete factory deletion", old != new)
    if old:
        session.check("readback of uncommitted reset retains the exact old object", sdk.get_object(marker), b"oracle-unknown-reset")
        session.check("blocked old slot retains its exact public metadata", encoded_public(sdk.get_slot_metadata(SLOT(0x82)).public_key), old_public)
        session.observe("blocked_key_evidence_limit", "private operation cannot be re-tested while both references are blocked; public metadata is not proof of private-key integrity")
        session.observe("explicit_recovery", "both budgets and exact old object/key metadata prove no reset committed; a new factory-reset recovery is now sent from that known blocked state")
        session.card_value(session.apdu(codec.apdu(0xfb), "piv.reset.recover-confirmed-uncommitted"))
    for reference in (0x80, 0x81):
        recovered(session, ("piv", reference), "readback-confirmed factory state followed by known-credential controls")
    session.options.piv_pin, session.options.piv_puk, session.options.management_key = "123456", "12345678", DEFAULT_MANAGEMENT_KEY
    sdk.verify_pin(session.options.piv_pin)
    sdk.authenticate(session.options.management_key)
    session.card_value(session.apdu(codec.apdu(0x24, p2=0x81, data=wire_pin(session.options.piv_puk) * 2), "piv.factory-PUK-known-value-control"))
    phase = session.trace.phase
    try:
        with key_fixture(session, policy=PIN_POLICY.ONCE) as (fresh, key):
            fresh.verify_pin(session.options.piv_pin)
            piv_sign(session, fresh, key)
    finally:
        session.trace.phase = phase
    return "piv"


def fido(session, fixtures):
    session.require(info(session).get(4, {}).get("clientPin") and session.options.pin, "unknown reset needs a known configured host PIN before its attempt")
    readonly = pin_token(session, 64)
    before = session.ctap_value(cm(session, *readonly, 1))
    change(session, Action.POWER_CYCLE)
    session.select("fido")
    with session.route(CtapRoute.CARD):
        lose(session, 0x10, lambda: session.ctap(7))
    current = session.ctap_value(session.ctap(4))
    configured = current.get(4, {}).get("clientPin")
    session.check("unknown reset has a decisive configured/unset PIN observation", type(configured) is bool)
    session.bind("fido.info", current)
    if configured:
        fixtures.fido.assertion(session)
        session.check("uncommitted reset preserves the actual persistent grant", session.ctap_value(cm(session, *readonly, 1)), before)
        return None
    session.options.pin = None
    session.check("readback-confirmed FIDO reset revokes the exact old private reference", session.ctap(2, fixtures.fido.query(session, authenticate=False, options={"up": False, "uv": False})).status, 0x2e)
    session.check("readback-confirmed reset revokes the old persistent grant", cm(session, *readonly, 1).status, 0x33)
    provision_after_reset(session, current)
    session.check("reprovisioning the known PIN cannot revive the old persistent grant", cm(session, *readonly, 1).status, 0x33)
    return "fido"


def run(session):
    for target in TARGETS:
        effects = ("session_recovery", "applet_reset", "pin_attempts", "pin_change", "config_change", "reboot",
            "replace_piv_slot_82", "replace_openpgp_sig_key", "create_fido_credential", "create_oath_record", "replace_otp_slot_" + str(session.options.otp_slot))
        with session.case("cross.unknown-write.lifecycle." + target, ("X06", "X10", "F23", "P16", "O21", "A12", "G09", "G10", "G11", "G12", "G14"), effects=effects, touch=True):
            require_loss(session)
            require_pair(session)
            if target == "fido":
                require_action(session, Action.POWER_CYCLE)
            fixtures, reset = Fixtures(session), None
            try:
                fixtures.prepare()
                reset = oath(session, fixtures) if target == "oath" else openpgp(session, target, fixtures) if target.startswith("openpgp") else piv(session, fixtures) if target == "piv" else fido(session, fixtures)
                fixtures.verify(reset)
            finally:
                if fixtures.config is not None and not session.broken:
                    session.trace.phase = "cleanup"
                    fixtures.cleanup(reset)
