# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PIN freshness and touch refusals are witnessed by actual private operations."""
import sys
from itertools import product

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from . import codec
from .card_keys import PIV_SLOTS
from .cards import fixture_key
from .lifecycle import Action, change
from .piv_lifecycle import fixture_session
from .timers import wait


def cue(session, action):
    session.trace.emit("interaction", action="PIV-touch-" + action, stage="requested", source="runner", observed_touch_ns=None)
    print("oracle: PIV private operation: " + action, file=sys.stderr)


def operate(session, sdk, slot, private, agreement=False, expected=0x9000):
    from yubikit.core.smartcard import ApduError
    from yubikit.piv import KEY_TYPE
    peer = ec.derive_private_key(392, ec.SECP256R1())
    message = session.fixture("piv.policy.message")
    try:
        result = sdk.calculate_secret(slot, peer.public_key()) if agreement else sdk.sign(slot, KEY_TYPE.ECCP256, message, hashes.SHA256())
        status = 0x9000
    except ApduError as error:
        status, result = error.sw, None
    session.check("PIV policy controls the private operation", status, expected)
    if status == 0x9000:
        if agreement:
            session.check("policy-gated ECDH has the independent secret", result, peer.exchange(ec.ECDH(), private.public_key()))
        else:
            private.public_key().verify(result, message, ec.ECDSA(hashes.SHA256()))
            session.check("policy-gated signature verifies with retained key", True)


def run(session):
    from yubikit.piv import SLOT, PIN_POLICY, TOUCH_POLICY
    actions = ("repeat", "decline", "timeout", "bad-algorithm", "bad-point", "idle", "same-SELECT", "other-SELECT", *Action)
    for number, pin, touch, agreement, action in product(PIV_SLOTS, PIN_POLICY, TOUCH_POLICY, (False, True), actions):
        label = action.value if isinstance(action, Action) else action
        with session.case(f"piv.policy.{number:02x}.{pin.name}.{touch.name}.ECDH-{agreement}.{label}",
                ("P01", "P03", "P11", "P12", "P17", "X01", "X11", "G10", "G14"),
                effects=("replace_piv_keys", "reboot") if action == Action.POWER_CYCLE else ("replace_piv_keys",), touch=True,
                parameters={"slot": number, "PIN_policy": pin.name, "touch_policy": touch.name, "interruption": label}):
            session.require(session.profile == "rsk", "cached touch is deliberately strict on RS-Key", "excluded_by_profile")
            session.require(session.options.operator, "touch refusal/confirmation requires a controlled operator action")
            touches = touch not in (TOUCH_POLICY.DEFAULT, TOUCH_POLICY.NEVER)
            session.require(action not in ("decline", "timeout") or touches, "NEVER touch policy has no ceremony to refuse", "excluded_by_mode")
            session.require(action != "timeout" or session.options.timeout > 130, "touch timeout needs the full presence window")
            sdk = fixture_session(session)
            private, slot, installed = fixture_key(session, "ECCP256"), SLOT(number), False
            resolved = pin if pin != PIN_POLICY.DEFAULT else PIN_POLICY.ALWAYS if number == 0x9c else PIN_POLICY.NEVER if number == 0x9e else PIN_POLICY.ONCE
            try:
                if pin in (PIN_POLICY.MATCH_ONCE, PIN_POLICY.MATCH_ALWAYS):
                    sdk.put_key(slot, private, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
                    installed = True
                    scalar = private.private_numbers().private_value.to_bytes(32, "big")
                    effective_touch = TOUCH_POLICY.NEVER if touch == TOUCH_POLICY.DEFAULT else touch
                    result = session.apdu(codec.apdu(0xfe, 0x11, number, codec.tlv(6, scalar) + codec.tlv(0xaa, bytes([pin])) + codec.tlv(0xab, bytes([effective_touch]))))
                    session.check("unsupported biometric PIV policy is refused on the actual wire", result.status, 0x6a80)
                    sdk.verify_pin(session.options.piv_pin)
                    cue(session, "accept")
                    operate(session, sdk, slot, private, agreement)
                    continue
                sdk.put_key(slot, private, pin, touch)
                installed = True
                session.select("openpgp")
                session.select("piv")
                cue(session, "accept")
                operate(session, sdk, slot, private, agreement, 0x9000 if resolved == PIN_POLICY.NEVER else 0x6982)
                sdk.verify_pin(session.options.piv_pin)
                if action == "repeat":
                    operate(session, sdk, slot, private, agreement)
                    operate(session, sdk, slot, private, agreement, 0x6982 if resolved == PIN_POLICY.ALWAYS else 0x9000)
                elif action in ("decline", "timeout"):
                    cue(session, action)
                    operate(session, sdk, slot, private, agreement, 0x6982)
                    cue(session, "accept")
                    operate(session, sdk, slot, private, agreement)
                elif action in ("bad-algorithm", "bad-point"):
                    body = codec.tlv(0x7c, codec.tlv(0x82, b"") + codec.tlv(0x85 if action == "bad-point" else 0x81, b"\x04" + bytes(64) if action == "bad-point" else bytes(32)))
                    response = session.apdu(codec.apdu(0x87, 0x11 if action == "bad-point" else 0xff, number, body))
                    session.check("private defect refused before producing key material", response.is_rejection)
                    operate(session, sdk, slot, private, agreement, 0x6982 if action == "bad-point" and resolved == PIN_POLICY.ALWAYS else 0x9000)
                elif action == "idle":
                    operate(session, sdk, slot, private, agreement)
                    sdk.verify_pin(session.options.piv_pin)
                    wait(session, 16.25)
                    if touches:
                        cue(session, "decline")
                        operate(session, sdk, slot, private, agreement, 0x6982)
                        cue(session, "accept")
                    operate(session, sdk, slot, private, agreement)
                else:
                    if isinstance(action, Action):
                        change(session, action)
                    elif action == "other-SELECT":
                        session.select("openpgp")
                    session.select("piv", required=True)
                    operate(session, sdk, slot, private, agreement, 0x9000 if resolved == PIN_POLICY.NEVER or action == "same-SELECT" else 0x6982)
                sdk.verify_pin(session.options.piv_pin)
                cue(session, "accept")
                operate(session, sdk, slot, private, agreement)
            finally:
                if installed and not session.broken:
                    session.trace.phase = "cleanup"
                    sdk.authenticate(session.options.management_key)
                    sdk.delete_key(slot)
