# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Rescue mutations use profiled selectors; fuse payloads never enter the writer."""
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import codec
from .lifecycle import Action, change
from .vendor_cases import rsk

RTC_MAX = 0xFFFFFFFF


def request(session, ins, p1=0, p2=0, data=b"", expected=0x9000):
    reply = session.apdu(codec.apdu(ins, p1, p2, data, cla=0x80), f"rescue.{ins:02x}.{p1:02x}.{p2:02x}")
    session.check("rescue response cause", (reply.protocol, reply.status),
                  ("success" if expected == 0x9000 else "applet_error", expected))
    return reply.data[:-2]


def active(session):
    rsk(session)
    session.select("rescue")
    session.require(request(session, 0x1E, 8) == b"\x02\x01", "scenario requires active v2 storage")


def phy(session):
    variants = ((5, b"\x00"), (5, b"\x01"), (5, b"\xff"), (6, b"\x00\x00"), (6, b"\x00\x08"),
                (8, b"\x00"), (8, b"\x01"), (8, b"\x09"), (8, b"\x0a"), (8, b"\xff"))
    for tag, value in variants:
        with session.case(f"rescue.PHY.tag-{tag}.{value.hex()}", ("R03", "V09", "G03", "G14"), effects=("config_change",), touch=True):
            active(session)
            original = request(session, 0x1E, 1)
            initial = dict(codec.parse_tlv(original))
            changed = None
            try:
                request(session, 0x1C, 1, data=codec.tlv(tag, value))
                changed = dict(codec.parse_tlv(request(session, 0x1E, 1)))
                session.check("PHY selected field written", changed[tag], value)
                for other, before in initial.items():
                    if other != tag:
                        session.check(f"PHY preserves untouched tag {other}", changed.get(other), before)
                request(session, 0x1C, 0xFF, data=codec.tlv(tag, value), expected=0x6A86)
                session.check("invalid selector preserves PHY", dict(codec.parse_tlv(request(session, 0x1E, 1))), changed)
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    restore = dict(changed) if changed is not None else dict(initial)
                    for written in set(restore) - set(initial):
                        restore[written] = b""
                    restore.update(initial)
                    request(session, 0x1C, 1, data=b"".join(codec.tlv(key, val) for key, val in restore.items()))
                    restored = dict(codec.parse_tlv(request(session, 0x1E, 1)))
                    for key, val in initial.items():
                        session.check("PHY original field restored", restored.get(key), val)


def clock(session):
    values = (0, 1, 951782400, 0x7FFFFFFF, 0x80000000, RTC_MAX)
    for seconds in values:
        with session.case(f"rescue.RTC.unix.{seconds}", ("R04", "G04", "G14"), effects=("set_rtc",)):
            active(session)
            request(session, 0x1C, 2, 2, seconds.to_bytes(4, "big"))
            start = session.trace.now()
            got = int.from_bytes(request(session, 0x1E, 4, 2), "big")
            elapsed = (session.trace.now() - start) // 1000000000 + 2
            session.check("RTC epoch readback within measured interval", (got - seconds) & RTC_MAX <= elapsed)
            civil = request(session, 0x1E, 4, 1)
            session.check("RTC civil response length", len(civil), 8)
            instant = datetime(int.from_bytes(civil[:2], "big"), civil[2] + 1, civil[3], civil[5], civil[6], civil[7], tzinfo=timezone.utc)
            elapsed = (session.trace.now() - start) // 1000000000 + 2
            session.check("RTC civil calendar", (int(instant.timestamp()) - seconds) & RTC_MAX <= elapsed)
            session.check("RTC civil weekday", civil[4], (instant.weekday() + 1) % 7)
            for bad in (b"", bytes(1), bytes(3), bytes(5)):
                result = session.apdu(codec.apdu(0x1C, 2, 2, bad, cla=0x80), "rescue.RTC.invalid-length")
                session.check("RTC malformed write refused", result.protocol, "applet_error")


def device_key(session):
    with session.case("rescue.device-key.sign-and-bind", ("R02", "G03", "G14"), touch=True):
        active(session)
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), request(session, 0x10, 2))
        digest = session.fixture("rescue.digest")
        signature = request(session, 0x10, 1, data=digest)
        session.check("rescue signature raw length", len(signature), 64)
        der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        public.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        session.check("rescue digest signature independent verification", True)
        for length in (0, 1, 31, 33, 64):
            result = session.apdu(codec.apdu(0x10, 1, data=bytes(length), cla=0x80), "rescue.sign.invalid-length")
            session.check("invalid digest refused", result.protocol, "applet_error")
        session.check("key unchanged after refused signing", request(session, 0x10, 2), public.public_bytes_raw() if hasattr(public, "public_bytes_raw") else public_bytes(public))


def public_bytes(public):
    from cryptography.hazmat.primitives import serialization
    return public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def device_certificate_fixture(session, public):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    issuer = ec.derive_private_key(int.from_bytes(session.fixture("rescue.certificate.issuer", 24), "big") + 1, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Oracle fixture CA")])
    leaf = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Oracle rescue device")])).issuer_name(name).public_key(public).serial_number(1).not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc)).not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc)).sign(issuer, hashes.SHA256())
    return leaf.public_bytes(serialization.Encoding.DER)


def device_certificate(session):
    with session.case("rescue.device-key.certificate-install", ("R02", "G03", "G14"), effects=("replace_identity",), touch=True):
        active(session)
        encoded = request(session, 0x10, 2)
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), encoded)
        request(session, 0x10, 3, data=device_certificate_fixture(session, public))
        request(session, 0x10, 3, expected=0x6700)
        session.check("certificate upload preserves device signing key", request(session, 0x10, 2), encoded)
        session.observe("certificate_visibility", "upload acknowledged; certificate record has no read/export command")
        session.observe("cleanup_limit", "fixture certificate retained; previous certificate cannot be exported for restoration")


def recovery(session):
    with session.case("rescue.storage-setup.active-refusals", ("R06", "G13", "G14"), effects=("storage_setup",), touch=True):
        rsk(session)
        session.select("rescue")
        initial = request(session, 0x1E, 8)
        session.require(initial == b"\x02\x01", "active-media refusal case requires active v2 storage")
        for p1, magic in ((0, b"INITV2"), (1, b"IMPORTV2")):
            request(session, 0x20, p1, data=magic, expected=0x6985)
            session.check("refused setup leaves active storage", request(session, 0x1E, 8), initial)
            request(session, 0x20, p1, data=b"invalid", expected=0x6A80)
        for applet in ("piv", "openpgp", "oath"):
            session.check("active storage still serves " + applet, bool(session.select(applet)))


def fuses(session):
    with session.case("rescue.OTP-fuses.invalid-selectors-only", ("R07", "G04", "G14")):
        active(session)
        initial = request(session, 0x1E, 3)
        for selector in (0, 1, 0x47, 0x49, 0x57, 0x59, 255):
            request(session, 0x1B, selector, data=b"invalid", expected=0x6A86)
        session.check("fuse refusal preserves reported secure-boot state", request(session, 0x1E, 3), initial)
        session.observe("positive_fuse_writes", "excluded from ordinary capture; no matching fuse selector and magic pair is transmitted")


def reboot(session):
    for selector in (0, 1):
        with session.case(f"rescue.reboot.{selector}", ("R05", "X11", "T01"), effects=("reboot",), touch=selector == 1):
            rsk(session)
            session.require(session.options.operator, "reboot rediscovery requires an operator and exact rebinding")
            session.select("rescue")
            request(session, 0x1F, selector)
            session.trace.emit("interaction", action="exit_bootsel" if selector else "await_normal_USB", stage="requested", source="runner")
            input("oracle: wait for ONLY the selected key in normal mode, then press Enter: ")
            change(session, Action.USB_RECONNECT)
            session.check("rescue identity after reboot", len(session.select("rescue")), 12)


def recovery_states(session):
    from .runner import AIDS
    for layout, selector, magic in (("empty", 0, b"INITV2"), ("legacy", 1, b"IMPORTV2")):
        with session.case("rescue.storage-setup.recovery-to-active." + layout, ("R06", "R05", "X11", "G14"),
                          effects=("storage_setup", "reboot"), touch=True):
            rsk(session)
            session.require(session.options.recovery_layout == layout, "supply a matching --recovery-layout for an independently prepared recovery fixture")
            session.require(session.card is not None and (session.options.operator or getattr(session.card, "emulated", False)), "recovery reboot requires explicit reconnect control and operator on hardware")
            session.select("rescue")
            session.require(request(session, 0x1E, 8) == b"\x02\x00", "positive storage setup requires recovery mode; active storage is never reformatted")
            session.observe("prepared_layout_basis", "operator assertion; storage readiness does not identify empty versus legacy layout")
            for applet in ("piv", "openpgp", "oath"):
                result = session.apdu(codec.apdu(0xA4, 4, data=AIDS[applet]), "rescue.recovery.neighbor-select")
                session.check("recovery prevents ordinary applet use", result.protocol, "applet_error")
            session.select("rescue", required=True)
            request(session, 0x20, selector, data=magic + b"\x00", expected=0x6A80)
            session.check("invalid setup magic preserves recovery", request(session, 0x1E, 8), b"\x02\x00")
            request(session, 0x20, selector, data=magic)
            if not getattr(session.card, "emulated", False):
                session.trace.emit("interaction", action="await_recovery_reboot", stage="requested", source="runner")
                input("oracle: wait for the selected recovery fixture to reappear, then press Enter: ")
            change(session, Action.USB_RECONNECT)
            session.select("rescue", required=True)
            session.check("storage setup transitions to active v2", request(session, 0x1E, 8), b"\x02\x01")
            request(session, 0x20, selector, data=magic, expected=0x6985)
            for applet in ("piv", "openpgp", "oath"):
                result = session.apdu(codec.apdu(0xA4, 4, data=AIDS[applet]), "rescue.active.neighbor-select")
                session.check("active storage permits dispatch or preserved applet policy", result.status in ((0x9000,) if layout == "empty" else (0x9000, 0x6A82)))
                session.observe("active_applet." + applet, result.status)
            session.observe("cleanup_limit", "initialized or imported active v2 store retained; recovery fixture is consumed")


def measurement(session):
    for ins in (0x12, 0x13, 0x14, 0x15):
        with session.case(f"rsk.measurement.shipping-exclusion.{ins}", ("V13",)):
            active(session)
            feature = {0x12: "core1-stats", 0x13: "keygen-bench", 0x14: "bench", 0x15: "bench"}[ins]
            session.require(feature not in session.options.features, "shipping exclusion does not apply to declared measurement build", "excluded_by_profile")
            session.select("vendor")
            result = session.apdu(codec.apdu(ins), "vendor.measurement.shipping")
            session.check("shipping build excludes measurement command", result.status, 0x6D00)


def run(session):
    device_key(session)
    device_certificate(session)
    phy(session)
    clock(session)
    recovery(session)
    recovery_states(session)
    fuses(session)
    measurement(session)
    reboot(session)
