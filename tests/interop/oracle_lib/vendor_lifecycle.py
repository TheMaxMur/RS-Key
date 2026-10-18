# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Seed replacement, export sealing, soft lock and organization identity fixtures."""
import hashlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.x509.oid import NameOID

from . import codec
from .fido import info, pin_token, token_mac, u2f_apdu, verified
from .fido_fixtures import credential
from .vendor_cases import rsk, vendor, handshake, audit

AUT_ENABLE, AUT_DISABLE = 0x03E43F56B34285E2, 0x1831A40F04A25ED9


def config(session, subcommand, parameters=None):
    session.require(info(session).get(4, {}).get("clientPin") and session.options.pin,
                    "positive CONFIG requires a known configured host PIN; absence never grants ACFG")
    request = {1: subcommand}
    if parameters is not None:
        request[2] = parameters
    version, token = pin_token(session, 32)
    request.update({3: version, 4: token_mac(version, token, bytes([255]) * 32 + bytes([13, subcommand]) + (codec.encode(parameters) if parameters is not None else b""))})
    return session.ctap(13, request)


def wrap(session, secret, hybrid=False):
    key, aad = handshake(session, hybrid)
    nonce = session.fixture("vendor.wrap.nonce", 12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, secret, aad)


def export_seed(session):
    key, aad = handshake(session)
    blob = session.ctap_value(vendor(session, 2, authenticated=True))[1]
    return ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad)


def seeds(session):
    for hybrid in (False, True):
        with session.case("rsk.seed.load." + ("hybrid" if hybrid else "classical"), ("V01", "V02", "V03", "U06", "FE14", "G14"), effects=("seed_change", "create_fido_credential"), touch=True):
            rsk(session)
            original_state = session.ctap_value(vendor(session, 5))
            session.require(not original_state[1] and not original_state[3], "seed fixture requires an open export window and no soft lock")
            original = export_seed(session)
            fixture = ec.derive_private_key(int.from_bytes(session.fixture("vendor.fixture.seed", 24), "big") + 1, ec.SECP256R1()).private_numbers().private_value.to_bytes(32, "big")
            changed = False
            with credential(session, session.current.name + ".before-load") as old:
                old.assertion(session)
                try:
                    damaged = bytearray(wrap(session, fixture, hybrid))
                    damaged[-1] ^= 1
                    result = vendor(session, 3, {1: bytes(damaged)}, authenticated=True)
                    session.check("bad seed AEAD has integrity failure", result.status, 0x3D)
                    session.check("failed load preserves exact seed", export_seed(session), original)
                    old.assertion(session)
                    session.ctap_value(vendor(session, 3, {1: wrap(session, fixture, hybrid)}, authenticated=True))
                    changed = True
                    session.check("installed fixture seed exports exactly", export_seed(session), fixture)
                    session.check("seed replacement rejects old wrapped credential", session.ctap(2, old.query(session, options={"up": False})).status, 0x2E)
                    previous = session.values.get("u2f.fixture")
                    if previous is not None:
                        data = previous["challenge"] + previous["application"] + bytes([len(previous["handle"])]) + previous["handle"]
                        session.check("seed replacement rejects old U2F handle", session.hid_call(3, u2f_apdu(2, 7, data)).status, 0x6A80)
                    again = vendor(session, 3, {1: bytes(60)}, authenticated=True)
                    session.check("consumed MSE cannot load again", again.protocol, "applet_error")
                    session.check("rejected replay preserves fixture seed", export_seed(session), fixture)
                finally:
                    if changed and not session.broken:
                        session.trace.phase = "cleanup"
                        session.ctap_value(vendor(session, 3, {1: wrap(session, original)}, authenticated=True))
                        session.check("original seed restored", export_seed(session), original)
                        old.assertion(session)
                        session.observe("cleanup_limit", "seed restored; credential-store state and removed device certificate cannot be rolled back")


def finalize(session):
    with session.case("rsk.seed.finalize", ("V04", "V02", "G11", "G14"), effects=("seed_change",), touch=True):
        rsk(session)
        session.ctap_value(vendor(session, 4, authenticated=True))
        session.check("finalize seals export window", session.ctap_value(vendor(session, 5))[1], True)
        session.ctap_value(vendor(session, 4, authenticated=True))
        handshake(session)
        result = vendor(session, 2, authenticated=True)
        session.check("sealed export refused", result.protocol, "applet_error")
        session.check("export refusal leaves window sealed", session.ctap_value(vendor(session, 5))[1], True)
        session.observe("cleanup_limit", "export window stays sealed until authenticatorReset")


def soft_lock(session):
    with session.case("rsk.soft-lock.enable-unlock-disable", ("V05", "V01", "G10", "G14"), effects=("config_change",), touch=True):
        rsk(session)
        initial = session.ctap_value(vendor(session, 5))
        session.require(not initial[3], "existing soft lock is not replaced")
        lock_key = session.fixture("vendor.soft-lock")
        engaged = False
        try:
            session.ctap_value(config(session, 255, {1: AUT_ENABLE, 2: wrap(session, lock_key)}))
            engaged = True
            state = session.ctap_value(vendor(session, 5))
            session.check("soft-lock removes plaintext seed", (state[2], state[3], state[4]), (False, True, False))
            wrong = lock_key[:-1] + bytes([lock_key[-1] ^ 1])
            result = vendor(session, 6, {1: wrap(session, wrong)})
            session.check("wrong soft-lock key refused", result.protocol, "applet_error")
            session.check("wrong unlock leaves lock engaged", session.ctap_value(vendor(session, 5))[4], False)
            session.ctap_value(vendor(session, 6, {1: wrap(session, lock_key)}))
            session.check("correct key unlocks current boot", session.ctap_value(vendor(session, 5))[4], True)
            session.ctap_value(session.ctap(4))
        finally:
            if engaged and not session.broken:
                session.trace.phase = "cleanup"
                if not session.ctap_value(vendor(session, 5))[4]:
                    session.ctap_value(vendor(session, 6, {1: wrap(session, lock_key)}))
                session.ctap_value(config(session, 255, {1: AUT_DISABLE}))
                state = session.ctap_value(vendor(session, 5))
                session.check("soft-lock disabled and seed restored", (state[2], state[3]), (True, False))


def identity_fixture(session):
    private = ec.derive_private_key(int.from_bytes(session.fixture("org.identity", 24), "big") + 1, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Oracle fixture identity")])
    certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key()).serial_number(1).not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc)).not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc)).sign(private, hashes.SHA256())
    return private, certificate.public_bytes(serialization.Encoding.DER)


def attestation(session):
    with session.case("rsk.organization-attestation.import-clear", ("V06", "FE12", "G14"), effects=("replace_identity",), touch=True):
        rsk(session)
        session.require(not info(session).get(4, {}).get("alwaysUv"), "organization U2F witness needs U2F enabled by the current verification policy")
        session.require(not session.ctap_value(vendor(session, 11))[1], "existing organization identity cannot be exported for restoration")
        private, chain = identity_fixture(session)
        scalar = private.private_numbers().private_value.to_bytes(32, "big")
        installed = False
        try:
            session.ctap_value(vendor(session, 9, {1: wrap(session, scalar), 2: chain}, authenticated=True))
            installed = True
            state = session.ctap_value(vendor(session, 11))
            session.check("organization identity installed", state[1], True)
            challenge, application = session.fixture("organization.challenge"), session.fixture("organization.application")
            body = session.card_value(session.hid_call(3, u2f_apdu(1, data=challenge + application), "u2f.organization-register"))
            session.check("organization registration marker", body[:1], b"\x05")
            handle = body[67:67 + body[66]]
            leaf = body[67 + body[66]:67 + body[66] + len(chain)]
            session.check("U2F uses installed organization certificate", leaf, chain)
            verified(session, "organization U2F attestation signature", private.public_key(), -7,
                     body[67 + body[66] + len(chain):], b"\x00" + application + challenge + handle + body[1:66])
            # A one-certificate packed chain has the profile's SHA-256 commitment.
            session.observe("chain_commitment", state.get(2), "presence")
            invalid = vendor(session, 9, {1: wrap(session, scalar), 2: b"\x30\x82\xff"}, authenticated=True)
            session.check("malformed identity chain refused", invalid.protocol, "applet_error")
            session.check("refused import preserves identity", session.ctap_value(vendor(session, 11)), state)
        finally:
            if installed and not session.broken:
                session.trace.phase = "cleanup"
                handshake(session)
                session.ctap_value(vendor(session, 10, authenticated=True))
                session.check("fixture organization identity cleared", session.ctap_value(vendor(session, 11))[1], False)


def audit_configuration(session):
    with session.case("rsk.audit.enable-disable-invalid", ("V07", "V08", "G14"), effects=("config_change",), touch=True):
        rsk(session)
        original = session.ctap_value(vendor(session, 14, {1: 2}))[1]
        try:
            for enabled in (False, True):
                session.check("audit configuration write", session.ctap_value(vendor(session, 14, {1: int(enabled)}, authenticated=True))[1], enabled)
                session.check("audit status readback", session.ctap_value(vendor(session, 14, {1: 2}))[1], enabled)
                result = vendor(session, 14, {1: 3}, authenticated=True)
                session.check("unknown audit operation refused", result.protocol, "applet_error")
                session.check("refusal preserves audit policy", session.ctap_value(vendor(session, 14, {1: 2}))[1], enabled)
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                session.ctap_value(vendor(session, 14, {1: int(original)}, authenticated=True))
                session.check("audit policy restored", session.ctap_value(vendor(session, 14, {1: 2}))[1], original)


def run(session):
    seeds(session)
    soft_lock(session)
    attestation(session)
    audit_configuration(session)
    finalize(session)
