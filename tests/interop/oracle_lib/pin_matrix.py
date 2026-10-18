# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Encrypted PIN semantics use real ECDH, owned keys and bounded recovery."""
import hashlib

from .fido import info, pin_protocol, pin_token
from .fido_fixtures import credential, provision_after_reset
from .fido_states import change_pin
from .lifecycle import Action, change


def pin_bytes(label, minimum):
    if label == "minimum-ascii":
        return ("A7!b" + "x" * max(0, minimum - 4)).encode()
    if label == "minimum-unicode":
        return ("A7!" + "é" * max(1, minimum - 3)).encode()
    if label == "maximum-bytes":
        return b"A7!" + b"x" * 60
    if label == "maximum-unicode":
        return b"A7!" + "é".encode() * 30
    if label == "minimum-plus-one":
        return ("A7!b" + "x" * max(0, minimum - 3)).encode()
    if label == "maximum-minus-one":
        return b"A7!" + b"x" * 59
    if label == "embedded-NUL-tail":
        return ("A7!b" + "x" * max(0, minimum - 4)).encode() + b"\x00ignored\xfftail"
    if label == "whitespace-PIN":
        return b"A7!\t" + b"x" * max(0, minimum - 4)
    raise ValueError("unknown PIN boundary")


def request(session, version, new, old=None):
    protocol = pin_protocol(session, version)
    encrypted = protocol.encrypt(new)
    fields = {1: version, 2: 3 if old is None else 4, 3: protocol.cose, 5: encrypted}
    if old is not None:
        fields[6] = protocol.encrypt(hashlib.sha256(old.encode()).digest()[:16])
    fields[4] = protocol.authenticate(encrypted + fields.get(6, b""))
    return protocol, fields


def malformed(protocol, fields, defect, minimum):
    # Recompute the MAC for ciphertext defects so each case reaches its own gate.
    if defect == "missing-MAC":
        fields.pop(4)
    elif defect == "bad-MAC":
        fields[4] = bytes([fields[4][0] ^ 1]) + fields[4][1:]
    elif defect in ("empty-MAC", "one-byte-MAC", "short-MAC", "long-MAC"):
        fields[4] = b"" if defect == "empty-MAC" else fields[4][:1] if defect == "one-byte-MAC" else fields[4][:-1] if defect == "short-MAC" else fields[4] + b"x"
    elif defect.startswith("coordinate-"):
        _, axis, shape = defect.split("-")
        key = -2 if axis == "x" else -3
        fields[3] = dict(fields[3])
        if shape == "absent":
            fields[3].pop(key)
        else:
            value = fields[3][key]
            fields[3][key] = b"" if shape == "empty" else value[:1] if shape == "one" else value[:-1] if shape == "short" else b"\x00" + value
    elif defect == "off-curve":
        fields[3] = {**fields[3], -2: bytes(32), -3: bytes(32)}
    elif defect in ("short-x", "long-y"):
        key = -2 if defect == "short-x" else -3
        fields[3] = {**fields[3], key: bytes(31 if key == -2 else 33)}
    elif defect == "missing-point":
        fields.pop(3)
    elif defect == "missing-new":
        fields.pop(5)
    elif defect in ("empty-ciphertext", "unaligned-ciphertext", "oversized-ciphertext"):
        fields[5] = b"" if defect == "empty-ciphertext" else fields[5][:-1] if defect == "unaligned-ciphertext" else fields[5] + bytes(32)
        fields[4] = protocol.authenticate(fields[5] + fields.get(6, b""))
    elif defect.startswith("cipher-length-"):
        length = int(defect.removeprefix("cipher-length-"))
        fields[5] = (fields[5] + bytes(length))[:length]
        fields[4] = protocol.authenticate(fields[5] + fields.get(6, b""))
    elif defect in ("short-plaintext", "long-plaintext", "no-terminator", "invalid-UTF8", "below-codepoint-minimum", "empty-PIN", "leading-NUL-with-tail", "embedded-NUL-below-minimum"):
        plain = {"short-plaintext": b"A7!b" + bytes(12), "long-plaintext": b"A7!b" + bytes(76),
                 "no-terminator": b"A7!" + b"x" * 61, "invalid-UTF8": b"A7!\xff" + bytes(60),
                 "below-codepoint-minimum": ("é" * (minimum - 1)).encode().ljust(64, b"\x00"), "empty-PIN": bytes(64),
                 "leading-NUL-with-tail": b"\x00A7!b" + bytes(59),
                 "embedded-NUL-below-minimum": (b"x" * (minimum - 1) + b"\x00A7!b").ljust(64, b"\x00")}[defect]
        fields[5] = protocol.encrypt(plain)
        fields[4] = protocol.authenticate(fields[5] + fields.get(6, b""))
    elif defect in ("missing-old", "short-old", "long-old"):
        if defect == "missing-old":
            fields.pop(6)
        else:
            fields[6] = fields[6][:-1] if defect == "short-old" else fields[6] + b"x"
        fields[4] = protocol.authenticate(fields[5] + fields.get(6, b""))
    elif defect.startswith("old-length-"):
        length = int(defect.removeprefix("old-length-"))
        fields[6] = (fields[6] + bytes(length))[:length]
        fields[4] = protocol.authenticate(fields[5] + fields[6])
    else:
        raise ValueError("unknown PIN defect")


DEFECTS = ("missing-MAC", "bad-MAC", "empty-MAC", "one-byte-MAC", "short-MAC", "long-MAC", "missing-point", "off-curve", "short-x", "long-y",
           "missing-new", "empty-ciphertext", "unaligned-ciphertext", "oversized-ciphertext", "short-plaintext",
           "long-plaintext", "no-terminator", "invalid-UTF8", "below-codepoint-minimum", "empty-PIN", "leading-NUL-with-tail", "embedded-NUL-below-minimum",
           *(f"coordinate-{axis}-{shape}" for axis in ("x", "y") for shape in ("absent", "empty", "one", "short", "long")),
           *(f"cipher-length-{length}" for length in (0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 79, 80, 81)))
BOUNDARIES = ("minimum-ascii", "minimum-unicode", "minimum-plus-one", "maximum-minus-one", "maximum-bytes", "maximum-unicode", "embedded-NUL-tail", "whitespace-PIN")


def refusal_status(defect, version):
    if defect.startswith("old-length-"):
        length = int(defect.removeprefix("old-length-"))
        return 0x33 if length in (16, 32) else 2
    if defect.startswith("coordinate-"):
        return 0x14 if defect.endswith(("-absent", "-empty")) else 2
    if defect.startswith("cipher-length-"):
        length = int(defect.removeprefix("cipher-length-"))
        return 2 if 0 < length <= 80 and length % 16 == 0 else 0x37
    if defect.startswith("missing-"):
        return 0x14
    if defect in ("bad-MAC", "empty-MAC", "one-byte-MAC", "short-MAC", "long-MAC"):
        return 0x33
    if defect in ("off-curve", "short-x", "long-y", "short-old", "long-old", "short-plaintext"):
        return 0x02
    if defect == "long-plaintext":
        return 0x02 if version == 1 else 0x37
    return 0x31 if defect == "wrong-old" else 0x37


def retries(session, version):
    return session.ctap_value(session.ctap(6, {1: version, 2: 1}))[3]


def configured(session):
    session.require(session.profile == "rsk", "PIN semantic status catalog requires the RS-Key profile", "excluded_by_profile")
    session.require(session.options.pin is not None and info(session).get(4, {}).get("clientPin"), "known configured fixture PIN required")
    session.require(not info(session).get(27, False), "complexity-enabled profile uses the dedicated complexity-policy scenarios")


def changes(session):
    for version in (1, 2):
        for defect in (*DEFECTS, "missing-old", "short-old", "long-old", *(f"old-length-{length}" for length in (0, 1, 15, 16, 17, 31, 32, 33)), "wrong-old", "same-PIN", *BOUNDARIES):
            if defect in (f"cipher-length-{64 if version == 1 else 80}", f"old-length-{16 if version == 1 else 32}"):
                continue
            with session.case(f"fido.PIN.change.protocol-{version}.{defect}", ("F01", "F02", "F03", "F05", "F09", "G03", "G08", "G10", "G14"),
                              effects=("pin_change", "pin_attempts", "create_fido_credential"), touch=True,
                              parameters={"protocol": version, "defect": defect, "single_defect": True}):
                configured(session)
                minimum = info(session).get(13, 4)
                session.require(4 <= minimum <= 31, "Unicode codepoint boundaries require an encodable policy minimum")
                old = session.options.pin
                pin_token(session, 4, version=version)
                with credential(session, session.current.name) as fixture:
                    fixture.assertion(session)
                    before = retries(session, version)
                    session.require(before > 1, "wrong-old control needs at least two retries")
                    raw = old.encode() if defect == "same-PIN" else pin_bytes(defect if defect in BOUNDARIES else "minimum-ascii", minimum)
                    protocol, fields = request(session, version, raw.ljust(64, b"\x00"), old + "!" if defect == "wrong-old" else old)
                    if defect in (*DEFECTS, "missing-old", "short-old", "long-old") or defect.startswith("old-length-"):
                        malformed(protocol, fields, defect, minimum)
                    accepted = False
                    with session.attempts("fido.pin", 8):
                        try:
                            reply = session.ctap(6, fields)
                            accepted = reply.protocol == "success"
                            if accepted and defect not in (*BOUNDARIES, "same-PIN"):
                                session.broken = True
                                session.values["halt_reason"] = "invalid encrypted PIN accepted; PIN identity is uncertain and requires explicit recovery"
                            if accepted:
                                session.options.pin = raw.split(b"\x00", 1)[0].decode()
                            if defect in BOUNDARIES or defect == "same-PIN":
                                session.ctap_value(reply)
                                session.check("PIN change clears force-change", session.ctap_value(session.ctap(4)).get(12, False), False)
                            else:
                                session.check("single encrypted PIN defect refused", reply.protocol, "applet_error")
                                session.check("encrypted PIN defect reports its own cause", reply.status, refusal_status(defect, version))
                                session.check("PIN retry cost matches defect", retries(session, version), before - (defect == "wrong-old"))
                            pin_token(session, 4, version=version)
                            fixture.assertion(session)
                            session.check("valid verification restores retry budget", retries(session, version), before)
                        finally:
                            if accepted and not session.broken:
                                session.trace.phase = "cleanup"
                                change_pin(session, session.options.pin, old)
                                session.options.pin = old
                                session.bind("fido.info", session.ctap_value(session.ctap(4)))
                            if not session.broken:
                                pin_token(session, 4, version=version)
                                fixture.assertion(session)
        agreement_lifetimes(session, version)


def agreement_lifetimes(session, version):
    with session.case(f"fido.key-agreement.protocol-{version}.retry-and-selection", ("F03", "F06", "G10", "G14"), effects=("pin_attempts",)):
        configured(session)
        pin_token(session, 4, version=version)
        first = session.ctap_value(session.ctap(6, {1: version, 2: 2}))[1]
        session.check("key agreement stable on repeated read", session.ctap_value(session.ctap(6, {1: version, 2: 2}))[1], first)
        session.ctap_value(session.ctap(4))
        session.check("getInfo does not rotate agreement key", session.ctap_value(session.ctap(6, {1: version, 2: 2}))[1], first)
        protocol = pin_protocol(session, version)
        session.require(retries(session, version) > 1, "agreement rotation control needs recovery retry")
        with session.attempts("fido.pin", 3):
            try:
                reply = session.ctap(6, {1: version, 2: 9, 3: protocol.cose, 6: protocol.encrypt(bytes(16)), 9: 4})
                session.check("wrong PIN rotates agreement only after comparison failure", reply.status, 0x31)
                session.check("agreement key changes after failed comparison", session.ctap_value(session.ctap(6, {1: version, 2: 2}))[1] != first)
            finally:
                if not session.broken:
                    pin_token(session, 4, version=version)


def setup(session):
    for version in (1, 2):
        for defect in (*DEFECTS, *BOUNDARIES):
            if defect == f"cipher-length-{64 if version == 1 else 80}":
                continue
            with session.case(f"fido.PIN.set.protocol-{version}.{defect}", ("F01", "F02", "F03", "F04", "G03", "G08", "G14"),
                              effects=("pin_change", "applet_reset", "reboot", "create_fido_credential"), touch=True,
                              parameters={"protocol": version, "defect": defect, "initial_state": "factory PIN unset"}):
                session.require(session.profile == "rsk", "factory PIN boundary catalog is RS-Key only", "excluded_by_profile")
                session.require(session.card is not None and hasattr(session.card, "control") and (session.options.operator or getattr(session.card, "emulated", False)),
                                "PIN setup matrix requires explicit power-cycle and reset recovery")
                session.require(session.initial_pin is not None, "original fixture PIN required for final reprovisioning")
                reset_started = False
                try:
                    change(session, Action.POWER_CYCLE)
                    session.ctap_value(session.ctap(7))
                    reset_started = True
                    session.options.pin = None
                    current = session.ctap_value(session.ctap(4))
                    session.check("PIN initially unset", current[4]["clientPin"], False)
                    session.bind("fido.info", current)
                    with credential(session, session.current.name) as fixture:
                        raw = pin_bytes(defect if defect in BOUNDARIES else "minimum-ascii", 4)
                        protocol, fields = request(session, version, raw.ljust(64, b"\x00"))
                        if defect in DEFECTS:
                            malformed(protocol, fields, defect, 4)
                        reply = session.ctap(6, fields)
                        if reply.protocol == "success":
                            session.options.pin = raw.split(b"\x00", 1)[0].decode()
                        if defect in BOUNDARIES:
                            session.ctap_value(reply)
                            session.bind("fido.info", session.ctap_value(session.ctap(4)))
                            session.check("PIN now configured", info(session)[4]["clientPin"], True)
                            pin_token(session, 4, version=version)
                            session.check("setPIN cannot replace configured PIN", session.ctap(6, fields).status, 0x30)
                        else:
                            session.check("invalid setPIN refused", reply.protocol, "applet_error")
                            session.check("setPIN defect reports its own cause", reply.status, refusal_status(defect, version))
                            session.check("refused setPIN leaves PIN unset", session.ctap_value(session.ctap(4))[4]["clientPin"], False)
                        fixture.assertion(session)
                finally:
                    if reset_started and not session.broken:
                        session.trace.phase = "cleanup"
                        change(session, Action.POWER_CYCLE)
                        session.ctap_value(session.ctap(7))
                        provision_after_reset(session, session.ctap_value(session.ctap(4)))
