# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Seed gates distinguish refused mutations, sealed export and RAM-only unlocks."""
from itertools import product

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import codec
from .fido import info, u2f_apdu, verified
from .fido_fixtures import credential
from .rescue_presence import cue, require as require_consent
from .vendor_cases import handshake, vendor
from .vendor_lifecycle import export_seed, wrap
from .vendor_matrix import authenticated, exportable

ORDER = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
AUTH = ("valid", "missing-auth", "missing-protocol", "unknown-protocol", "unsupported-protocol",
        "empty-auth", "short-auth", "long-auth", "wrong-permission", "readonly", "bad-MAC")


def auth_status(defect):
    return 0 if defect == "valid" else 0x36 if defect == "missing-auth" else 0x14 if defect == "missing-protocol" else 2 if defect in ("unknown-protocol", "unsupported-protocol") else 0x33


def channel_spent(session):
    session.check("parsed seed consumer spends the channel on every outcome", vendor(session, 6).status, 0x30)


def gates(session):
    for sub, version, defect in product((2, 3, 4), (1, 2), AUTH):
        # FINALIZE's successful irreversible path belongs to sealed(), after these controls.
        if sub == 4 and defect == "valid":
            continue
        with session.case(f"rsk.seed.gate.sub-{sub}.protocol-{version}.{defect}",
                ("V01", "V02", "V03", "V04", "G10", "G11", "G13", "G14"),
                effects=("read_encrypted_seed", "seed_change", "create_fido_credential"), touch=True):
            exportable(session)
            session.require(info(session).get(4, {}).get("clientPin") and session.options.pin,
                "host authorization products require a configured known PIN")
            original = export_seed(session)
            identity = session.ctap_value(vendor(session, 11))
            before = session.ctap_value(vendor(session, 5))
            with credential(session, session.current.name) as retained:
                if sub == 3:
                    params = {1: wrap(session, original)}
                    key = aad = None
                else:
                    key, aad = handshake(session)
                    params = None
                result = authenticated(session, 0x41, sub, params, defect, version=version)
                session.check("seed authorization has its specific refusal", result.status, auth_status(defect))
                if sub == 2 and defect == "valid":
                    blob = session.ctap_value(result)[1]
                    session.check("authorized export decrypts the exact seed", ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad), original)
                if sub != 4:
                    channel_spent(session)
                else:
                    # FINALIZE never takes the channel, even when its PIN gate refuses.
                    blob = session.ctap_value(vendor(session, 2, authenticated=True))[1]
                    session.check("FINALIZE authorization refusal retains the original usable MSE", ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad), original)
                session.check("seed gate preserves backup flags", session.ctap_value(vendor(session, 5)), before)
                session.check("seed gate preserves organization identity", session.ctap_value(vendor(session, 11)), identity)
                session.check("seed gate retains the exact seed", export_seed(session), original)
                retained.assertion(session)


def loads(session):
    for mode in ("short-blob", "long-blob", "bad-tag", "zero-scalar", "curve-order", "valid-scalar"):
        for hybrid in (False, True):
            with session.case(f"rsk.seed.LOAD.{mode}.hybrid-{hybrid}", ("V01", "V02", "V03", "G03", "G04", "G09", "G13", "G14"),
                    effects=("read_encrypted_seed", "seed_change", "create_fido_credential"), touch=True):
                exportable(session)
                original = export_seed(session)
                identity = session.ctap_value(vendor(session, 11))
                session.require(not identity[1], "LOAD attestation checks require no pre-existing organization identity")
                replacement = (int.from_bytes(session.fixture("seed.LOAD.scalar"), "big") % (ORDER - 1) + 1).to_bytes(32, "big")
                raw = bytes(32) if mode == "zero-scalar" else ORDER.to_bytes(32, "big") if mode == "curve-order" else replacement
                changed = False
                with credential(session, session.current.name) as old:
                    try:
                        blob = wrap(session, raw, hybrid)
                        if mode == "short-blob":
                            blob = blob[:-1]
                        elif mode == "long-blob":
                            blob += b"x"
                        elif mode == "bad-tag":
                            blob = blob[:-1] + bytes([blob[-1] ^ 1])
                        result = vendor(session, 3, {1: blob}, authenticated=True)
                        changed = result.status == 0
                        expected = 0x14 if mode in ("short-blob", "long-blob") else 0x3d if mode == "bad-tag" else 2 if mode in ("zero-scalar", "curve-order") else 0
                        session.check("LOAD distinguishes length, integrity, scalar and success", result.status, expected)
                        channel_spent(session)
                        session.check("LOAD result has the exact seed", export_seed(session), replacement if expected == 0 else original)
                        session.check("LOAD does not create an organization identity", session.ctap_value(vendor(session, 11)), identity)
                        if expected == 0:
                            session.check("new seed revokes the populated old wrapped reference", session.ctap(2, old.query(session, options={"up": False})).status, 0x2e)
                            with credential(session, session.current.name + ".replacement") as fresh:
                                fresh.assertion(session)
                        else:
                            old.assertion(session)
                    finally:
                        if changed and not session.broken:
                            session.trace.phase = "cleanup"
                            session.ctap_value(vendor(session, 3, {1: wrap(session, original)}, authenticated=True))
                            session.check("LOAD cleanup restores the exact original seed", export_seed(session), original)
                            old.assertion(session)
                            session.observe("cleanup_limit", "seed restored; persistent credential-store tag and removed device certificate cannot be rolled back")


def consent(session):
    for sub, mode in product((2, 3, 4), ("decline", "panel-cancel", "timeout")):
        with session.case(f"rsk.seed.consent.sub-{sub}.{mode}", ("V02", "V03", "V04", "G10", "G11", "G12", "G14"),
                effects=("read_encrypted_seed", "seed_change", "create_fido_credential"), touch=True):
            exportable(session)
            require_consent(session, mode)
            original = export_seed(session)
            before = session.ctap_value(vendor(session, 5))
            with credential(session, session.current.name) as retained:
                params = {1: wrap(session, original)} if sub == 3 else None
                if sub != 3:
                    key, aad = handshake(session)
                cue(session, mode)
                result = vendor(session, sub, params, authenticated=True)
                session.check("seed confirmation refusal has operation-denied status", result.status, 0x27)
                cue(session, "accept")
                if sub != 4:
                    channel_spent(session)
                else:
                    blob = session.ctap_value(vendor(session, 2, authenticated=True))[1]
                    session.check("declined FINALIZE preserves the live channel", ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad), original)
                session.check("refused seed confirmation preserves all flags", session.ctap_value(vendor(session, 5)), before)
                session.check("refused seed confirmation preserves the exact seed", export_seed(session), original)
                retained.assertion(session)


def no_pin(session):
    for sub in (2, 3):
        with session.case(f"rsk.seed.no-host-or-device-PIN.sub-{sub}", ("V02", "V03", "G10", "G13", "G14"),
                effects=("read_encrypted_seed", "seed_change"), touch=True):
            exportable(session)
            session.require(not info(session).get(4, {}).get("clientPin") and session.options.device_pin_state == "unset",
                "PIN-less controls require explicit absence of both independent PINs")
            session.require(session.options.operator, "PIN-less LOAD requires both named confirmations")
            original = export_seed(session)
            cue(session, "accept both Replace device seed and Load seed prompts" if sub == 3 else "accept Export secret seed")
            if sub == 2:
                session.check("PIN-less export still decrypts the seed after consent", export_seed(session), original)
            else:
                session.ctap_value(vendor(session, 3, {1: wrap(session, original)}))
                session.check("PIN-less two-confirmation LOAD preserves the chosen seed", export_seed(session), original)

    for prompt, mode in product(("replace", "load"), ("decline", "panel-cancel", "timeout")):
        with session.case(f"rsk.seed.no-PIN.LOAD.{prompt}.{mode}", ("V03", "G10", "G12", "G13", "G14"),
                effects=("read_encrypted_seed", "seed_change", "create_fido_credential"), touch=True):
            exportable(session)
            session.require(not info(session).get(4, {}).get("clientPin") and session.options.device_pin_state == "unset",
                "two-prompt LOAD controls require explicit absence of both PINs")
            require_consent(session, mode)
            original = export_seed(session)
            with credential(session, session.current.name, authenticate=False) as retained:
                blob = wrap(session, original)
                cue(session, f"{mode} at Replace device seed" if prompt == "replace" else f"accept Replace device seed, then {mode} at Load seed")
                session.check("either named PIN-less LOAD refusal denies replacement", vendor(session, 3, {1: blob}).status, 0x27)
                cue(session, "accept")
                channel_spent(session)
                session.check("either prompt refusal preserves the original seed", export_seed(session), original)
                retained.assertion(session, authenticate=False)


def fips(session):
    with session.case("rsk.seed.FIPS.import-only-policy", ("V01", "V02", "V03", "V04", "U02", "G10", "G13", "G14"),
            effects=("seed_change", "create_fido_credential"), touch=True):
        session.require(session.profile == "rsk" and "fips-profile" in session.options.features,
            "import-only control requires the positively declared FIPS build", "excluded_by_profile")
        session.require(session.hid is not None and not info(session).get(4, {}).get("alwaysUv"), "seed binding uses U2F's default attestation key")
        session.require(info(session).get(4, {}).get("clientPin") and session.options.pin, "FIPS authorization products require a configured known host PIN")
        session.require(not session.ctap_value(vendor(session, 5))[3] and not session.ctap_value(vendor(session, 11))[1],
            "FIPS import binding requires no soft lock or organization identity")
        scalar = (int.from_bytes(session.fixture("FIPS.seed"), "big") % (ORDER - 1) + 1).to_bytes(32, "big")
        private = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())
        with credential(session, session.current.name) as old:
            session.ctap_value(vendor(session, 3, {1: wrap(session, scalar)}, authenticated=True))
            session.check("FIPS LOAD revokes the previous seed's private reference", session.ctap(2, old.query(session, options={"up": False})).status, 0x2e)
        challenge, application = session.fixture("FIPS.challenge"), session.fixture("FIPS.application")
        raw = session.card_value(session.hid_call(3, u2f_apdu(1, data=challenge + application)))
        session.check("FIPS U2F binding has its registration marker and point", raw[:2], b"\x05\x04")
        key_end = 67 + raw[66]
        rest = raw[key_end:]
        width = rest[1] & 127 if rest[1] & 128 else 0
        certificate_len = 2 + width + int.from_bytes(rest[2:2 + width], "big") if width else 2 + rest[1]
        certificate = x509.load_der_x509_certificate(rest[:certificate_len])
        encoded = lambda key: key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        session.check("FIPS seed import rebuilds a certificate over the exact imported public key", encoded(certificate.public_key()), encoded(private.public_key()))
        verified(session, "FIPS LOAD binds the actual attestation signer to the imported scalar", private.public_key(), -7,
            rest[certificate_len:], b"\x00" + application + challenge + raw[67:key_end] + raw[1:66])
        for live in (False, True):
            for defect in AUTH:
                if live:
                    handshake(session)
                session.check("FIPS export refuses before channel, PIN and confirmation gates", authenticated(session, 0x41, 2, None, defect).status, 0x30)
                channel_spent(session)
        with credential(session, session.current.name + ".new") as fresh:
            fresh.assertion(session)
        session.observe("cleanup_limit", "non-exportable FIPS seed cannot be restored; the known fixture seed and derived identity are retained")


def run(session):
    gates(session)
    loads(session)
    consent(session)
    no_pin(session)
    fips(session)
