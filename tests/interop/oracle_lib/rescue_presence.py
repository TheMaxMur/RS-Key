# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Rescue consent refusals retain the device key, staged PHY and reachable session."""
from itertools import product
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import codec
from .management_cases import read as management_read, write as management_write
from .phy_records import read, tlv
from .rescue_cases import active, request, device_certificate_fixture


def cue(session, mode):
    session.trace.emit("interaction", action="rescue-confirmation-" + mode, stage="requested", source="runner", observed_touch_ns=None)
    print("oracle: selected test key rescue confirmation: " + mode, file=sys.stderr)


def require(session, mode):
    session.require(session.options.operator, "rescue consent/refusal needs a controlled operator action")
    session.require(mode not in ("decline", "panel-cancel") or "display" in session.options.features,
        "explicit refusal requires the positively declared display profile", "excluded_by_profile")
    session.require(mode != "timeout" or session.options.timeout > 130, "rescue timeout needs the full presence window")


def private_control(session, public):
    cue(session, "accept")
    digest = session.fixture("rescue.consent.retained-key")
    raw = request(session, 0x10, 1, data=digest)
    session.check("rescue control has both signature scalars", len(raw), 64)
    der = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public).verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    session.check("rescue refusal preserves the device-key identity", request(session, 0x10, 2), public)


def consent(session):
    for operation, mode in product(("sign", "certificate", "PHY", "BOOTSEL"), ("accept", "decline", "panel-cancel", "timeout", "malformed-withheld")):
        if operation == "BOOTSEL" and mode == "accept":
            continue
        with session.case(f"rescue.consent.{operation}.{mode}", ("R02", "R03", "R05", "G03", "G10", "G12", "G13", "G14"),
                effects=("config_change", "replace_identity") if operation == "certificate" else ("config_change",), touch=True):
            active(session)
            require(session, mode)
            public, before = request(session, 0x10, 2), read(session)
            try:
                cue(session, "withhold" if mode == "malformed-withheld" else mode)
                malformed = mode == "malformed-withheld"
                expected = 0x6700 if malformed else 0x9000 if mode == "accept" else 0x6985
                if operation == "sign":
                    request(session, 0x10, 1, data=bytes(31 if malformed else 32), expected=expected)
                elif operation == "certificate":
                    # This command stores opaque bytes; it has no DER or key-binding parser.
                    certificate = device_certificate_fixture(session, ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public))
                    request(session, 0x10, 3, data=b"" if malformed else certificate, expected=expected)
                    session.observe("certificate_visibility", "no certificate export exists; refusal status and retained signing key are observable, prior certificate bytes are not")
                    if mode == "accept":
                        session.observe("cleanup_limit", "valid fixture device certificate retained; the prior certificate cannot be exported or restored")
                elif operation == "PHY":
                    value = (int.from_bytes(before[6], "big") ^ 8).to_bytes(2, "big")
                    request(session, 0x1c, 1, data=b"\x06" if malformed else tlv(6, value), expected=expected)
                    session.check("declined PHY cannot partially change the staged record", read(session), {**before, 6: value} if mode == "accept" else before)
                else:
                    request(session, 0x1f, 1, data=b"x" if malformed else b"", expected=expected)
                session.check("refused or completed rescue command leaves active storage", request(session, 0x1e, 8), b"\x02\x01")
                private_control(session, public)
                if operation != "PHY":
                    session.check("non-PHY rescue commands preserve all staged PHY fields", read(session), before)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    cue(session, "accept")
                    active(session)
                    if read(session) != before:
                        request(session, 0x1c, 1, data=tlv(6, before[6]))
                    session.check("rescue consent fixture restores its staged PHY field", read(session), before)


def locked_phy(session):
    for same in (False, True):
        with session.case(f"rescue.PHY.locked.identical-{same}", ("R03", "M04", "M05", "V09", "G10", "G11", "G14"), effects=("config_change",), touch=True):
            active(session)
            session.require(session.options.operator, "controlled lock setting needs the selected key's operator")
            original, before = management_read(session, "card"), read(session)
            session.require(original.get(10) == b"\x00", "known unlocked device configuration required")
            code, armed = session.fixture("rescue.PHY.shared-lock", 16), False
            try:
                cue(session, "accept")
                management_write(session, "card", codec.tlv(10, code))
                armed = management_read(session, "card").get(10) == b"\x01"
                session.check("shared configuration lock is actually armed", armed)
                active(session)
                public = request(session, 0x10, 2)
                value = before[6] if same else (int.from_bytes(before[6], "big") ^ 8).to_bytes(2, "big")
                cue(session, "withhold")
                request(session, 0x1c, 1, data=tlv(6, value), expected=0x6986)
                session.check("locked PHY rejects even an identical request before any write", read(session), before)
                private_control(session, public)
            finally:
                if armed and not session.broken:
                    session.trace.phase = "cleanup"
                    cue(session, "accept")
                    management_write(session, "card", codec.tlv(11, code) + codec.tlv(10, bytes(16)))
                    session.check("rescue shared-lock fixture is removed with its known code", management_read(session, "card"), original)


def run(session):
    consent(session)
    locked_phy(session)
