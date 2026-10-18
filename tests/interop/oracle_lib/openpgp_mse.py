# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""MSE changes the selected key; its password and UIF remain separate policies."""
from itertools import product
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import codec, pgp_keys
from .lifecycle import Action, change
from .openpgp_lifecycle import fixture_session


def cue(session, mode):
    session.trace.emit("interaction", source="runner", stage="requested", action="OpenPGP-UIF-" + mode, observed_touch_ns=None)
    print("oracle: OpenPGP reassigned-key touch: " + mode, file=sys.stderr)


def fixture_keys(session, references):
    return {slot: ec.derive_private_key(int.from_bytes(session.fixture("OpenPGP.MSE." + slot.name, 24), "big") + 1, ec.SECP256R1()) for slot in references}


def operate(session, template, key, expected=0x9000):
    digest = session.fixture("OpenPGP.MSE.message")
    peer = ec.derive_private_key(312, ec.SECP256R1())
    point = peer.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    wire = codec.apdu(0x88, data=digest) if template == 0xa4 else codec.apdu(0x2a, 0x80, 0x86, codec.tlv(0xa6, codec.tlv(0x7f49, codec.tlv(0x86, point))))
    reply = session.apdu(wire)
    session.check("MSE consumer enforces the selected password and touch policy", reply.status, expected)
    if expected != 0x9000:
        session.check("refused MSE consumer returns no private-operation bytes", reply.data[:-2], b"")
        return
    output = session.card_value(reply)
    if template == 0xa4:
        session.check("MSE EC signature has both scalar halves", len(output), 64)
        signature = utils.encode_dss_signature(int.from_bytes(output[:32], "big"), int.from_bytes(output[32:], "big"))
        key.public_key().verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        session.check("MSE signature identifies the actual reassigned private key", True)
    else:
        session.check("MSE ECDH identifies the actual reassigned private key", output, peer.exchange(ec.ECDH(), key.public_key()))


def inputs(reference):
    base = bytes([0x83, 1, reference])
    yield "valid", 0x41, None, base, True, 0x9000
    for size in (0, 1, 2):
        yield f"truncated-{size}", 0x41, None, base[:size], False, 0x6a80
    for value in (0, 1, 2, 4, 127, 128, 255):
        if value not in (2, 3):
            yield f"wrong-reference-{value}", 0x41, None, bytes([0x83, 1, value]), False, 0x6a80
    for tag in (0, 0x80, 0x81, 0x84, 0xff):
        yield f"wrong-tag-{tag}", 0x41, None, bytes([tag, 1, reference]), False, 0x6a80
    for size in (0, 2, 127, 128, 255):
        yield f"wrong-length-byte-{size}", 0x41, None, bytes([0x83, size, reference]), False, 0x6a80
    for p1 in (0, 1, 0x40, 0x42, 0xff):
        yield f"wrong-P1-{p1}", p1, None, base, False, 0x6b00
    for p2 in (0, 1, 0xa3, 0xa5, 0xb7, 0xb9, 0xff):
        yield f"wrong-P2-{p2}", 0x41, p2, base, False, 0x6b00
    for suffix in (b"\xff", b"\x83\x01\x01", b"\x53\x01x", bytes(255)):
        yield "ignored-tail-" + suffix.hex(), 0x41, None, base + suffix, True, 0x9000


def run(session):
    from yubikit.openpgp import KEY_REF
    for template, reference, granted in product((0xa4, 0xb8), (2, 3), (False, True)):
        for label, p1, p2, body, accepted, status in inputs(reference):
            with session.case(f"openpgp.MSE.{template:02x}.reference-{reference}.PW82-{granted}.{label}", ("O02", "O11", "O12", "O13", "O14", "O19", "O22", "G01", "G03", "G04", "G07", "G09", "G10", "G13", "G14"),
                    effects=("replace_openpgp_keys",), touch=True, parameters={"template": template, "reference": reference, "PW82": granted, "defect": label}):
                session.require(session.profile == "rsk", "MSE grammar and reassignment require RS-Key", "excluded_by_profile")
                session.select("piv")
                sdk = fixture_session(session)
                keys, installed = fixture_keys(session, (KEY_REF.DEC, KEY_REF.AUT)), []
                try:
                    for slot, key in keys.items():
                        pgp_keys.put_key(session, sdk, slot, key)
                        installed.append(slot)
                    sdk.verify_pin(session.options.openpgp_pin, extended=True)
                    counter = sdk.get_signature_counter()
                    default = KEY_REF.AUT if template == 0xa4 else KEY_REF.DEC
                    operate(session, template, keys[default])
                    if not granted:
                        session.card_value(session.apdu(codec.apdu(0x20, 0xff, 0x82)))
                    session.check("MSE authorization is independent of the consumer", session.apdu(codec.apdu(0x22, p1, template if p2 is None else p2, body)).status, status)
                    actual = KEY_REF(reference) if accepted else default
                    operate(session, template, keys[actual], 0x9000 if granted else 0x6982)
                    sdk.verify_pin(session.options.openpgp_pin, extended=True)
                    operate(session, template, keys[actual])
                    opposite = 0xb8 if template == 0xa4 else 0xa4
                    operate(session, opposite, keys[KEY_REF.DEC if opposite == 0xb8 else KEY_REF.AUT])
                    session.check("MSE and its consumers never increment SIG counter", sdk.get_signature_counter(), counter)
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        sdk.verify_admin(session.options.openpgp_admin)
                        for slot in installed:
                            pgp_keys.delete_key(session, sdk, slot)
    lifetimes(session)
    policies(session)


def lifetimes(session):
    from yubikit.openpgp import KEY_REF
    for template, action in product((0xa4, 0xb8), ("same-SELECT", "invalid-SELECT", "other-SELECT", *Action)):
        label = action.value if isinstance(action, Action) else action
        with session.case(f"openpgp.MSE.lifetime.{template:02x}.{label}", ("O01", "O02", "O12", "O13", "O14", "X11", "G10", "G11", "G14"), effects=("replace_openpgp_keys", "reboot") if action == Action.POWER_CYCLE else ("replace_openpgp_keys",), touch=True):
            session.require(session.profile == "rsk", "MSE lifetime contract requires RS-Key", "excluded_by_profile")
            session.select("piv")
            sdk = fixture_session(session)
            keys, installed = fixture_keys(session, (KEY_REF.DEC, KEY_REF.AUT)), []
            try:
                for slot, key in keys.items():
                    pgp_keys.put_key(session, sdk, slot, key)
                    installed.append(slot)
                selected = KEY_REF.DEC if template == 0xa4 else KEY_REF.AUT
                session.card_value(session.apdu(codec.apdu(0x22, 0x41, template, bytes([0x83, 1, selected]))))
                sdk.verify_pin(session.options.openpgp_pin, extended=True)
                operate(session, template, keys[selected])
                if isinstance(action, Action):
                    change(session, action)
                elif action == "other-SELECT":
                    session.select("piv")
                elif action == "invalid-SELECT":
                    session.check("unknown AID is refused without selecting a different DF", session.apdu(codec.apdu(0xa4, 4, data=b"\xf0\xff\xff\xff\xff")).status, 0x6a82)
                session.select("openpgp")
                retained = action in ("same-SELECT", "invalid-SELECT")
                actual = selected if retained else KEY_REF.AUT if template == 0xa4 else KEY_REF.DEC
                operate(session, template, keys[actual], 0x9000 if retained else 0x6982)
                sdk.verify_pin(session.options.openpgp_pin, extended=True)
                operate(session, template, keys[actual])
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    sdk.verify_admin(session.options.openpgp_admin)
                    for slot in installed:
                        pgp_keys.delete_key(session, sdk, slot)


def policies(session):
    from yubikit.openpgp import KEY_REF
    for template, target, touched, mode in product((0xa4, 0xb8), (KEY_REF.DEC, KEY_REF.AUT), (KEY_REF.DEC, KEY_REF.AUT), ("accept", "decline", "timeout")):
        with session.case(f"openpgp.MSE.UIF.{template:02x}.target-{target.name}.touch-{touched.name}.{mode}", ("O02", "O12", "O13", "O14", "O19", "O22", "G10", "G14"), effects=("replace_openpgp_keys", "config_change"), touch=True):
            session.require(session.profile == "rsk", "reassigned UIF semantics require RS-Key", "excluded_by_profile")
            session.require(session.options.operator, "MSE touch outcomes need a controlled operator action")
            session.require(mode != "decline" or "display" in session.options.features, "decline needs a declared display")
            session.require(mode != "timeout" or session.options.timeout > 130, "UIF timeout needs the full device window")
            session.select("piv")
            sdk = fixture_session(session)
            originals = {slot: sdk.get_data(0xd5 + int(slot)) for slot in (KEY_REF.DEC, KEY_REF.AUT)}
            session.require(all(value[:1] != b"\x02" for value in originals.values()), "fixed UIF cannot be restored without applet reset")
            keys, installed = fixture_keys(session, (KEY_REF.DEC, KEY_REF.AUT)), []
            try:
                for slot, key in keys.items():
                    pgp_keys.put_key(session, sdk, slot, key)
                    installed.append(slot)
                    sdk.put_data(0xd5 + int(slot), bytes([slot == touched, 0x20]))
                session.card_value(session.apdu(codec.apdu(0x22, 0x41, template, bytes([0x83, 1, target]))))
                sdk.verify_pin(session.options.openpgp_pin, extended=True)
                before = sdk.get_signature_counter()
                cue(session, mode)
                operate(session, template, keys[target], 0x6600 if target == touched and mode != "accept" else 0x9000)
                cue(session, "accept")
                operate(session, template, keys[target])
                session.check("UIF refusal and reassigned operation leave the SIG counter alone", sdk.get_signature_counter(), before)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    cue(session, "accept")
                    sdk.verify_admin(session.options.openpgp_admin)
                    for slot in installed:
                        sdk.put_data(0xd5 + int(slot), originals[slot])
                        pgp_keys.delete_key(session, sdk, slot)
