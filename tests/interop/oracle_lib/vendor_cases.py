# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Profile-bound RS-Key MSE, config rollback, and independently verified audit evidence."""
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import codec
from .fido import info, pin_token, token_mac, verified

VENDOR_COMMAND = 0x41
MSE_PQ_SALT = b"RSK-MSE-PQ-v1"
AUDIT_ENTRY_BYTES = 20
AUDIT_CHECKPOINT_DOMAIN = b"RSK-AUDIT-CKPT-v1"


def rsk(session):
    session.require(session.profile == "rsk", "RS-Key command catalog requires the RS-Key profile", "excluded_by_profile")


def vendor(session, subcommand, parameters=None, authenticated=False):
    rsk(session)
    request = {1: subcommand}
    if parameters is not None:
        request[2] = parameters
    if authenticated and info(session).get(4, {}).get("clientPin"):
        version, token = pin_token(session, 32)
        message = b"\xff" * 32 + bytes([VENDOR_COMMAND, subcommand]) + (codec.encode(parameters) if parameters is not None else b"")
        request.update({3: version, 4: token_mac(version, token, message)})
    return session.ctap(VENDOR_COMMAND, request)


def handshake(session, hybrid=False):
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    parameters = {1: {1: 2, 3: -25, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}}
    kem = None
    if hybrid:
        from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
        kem = MLKEM768PrivateKey.generate()
        parameters[2] = kem.public_key().public_bytes_raw()
    result = session.ctap_value(vendor(session, 1, parameters))
    point = result[1]
    session.check("MSE peer shape", (point[1], point[3], point[-1], len(point[-2]), len(point[-3])), (2, -25, 1, 32, 32))
    peer = ec.EllipticCurvePublicNumbers(int.from_bytes(point[-2], "big"), int.from_bytes(point[-3], "big"), ec.SECP256R1()).public_key()
    shared = private.exchange(ec.ECDH(), peer)
    aad = b"\x04" + point[-2] + point[-3]
    if 2 in result:
        session.check("hybrid reply was requested", hybrid)
        session.check("ML-KEM ciphertext length", len(result[2]), 1088)
        shared += kem.decapsulate(result[2])
        key = HKDF(hashes.SHA256(), 32, MSE_PQ_SALT, aad + result[2]).derive(shared)
        session.observe("channel", "hybrid_P256_MLKEM768")
    else:
        key = HKDF(hashes.SHA256(), 32, b"", aad).derive(shared)
        session.observe("channel", "classical_P256")
    return key, aad


def mse(session):
    for hybrid in (False, True):
        with session.case("rsk.transition.MSE." + ("hybrid" if hybrid else "classical"), ("V01", "V02", "G11", "G14"),
                          effects=("read_encrypted_seed",), touch=True):
            rsk(session)
            state = session.ctap_value(vendor(session, 5))
            session.require(not state[1], "export window is sealed; this case does not reset it")
            handshake(session, hybrid)
            generator = ec.derive_private_key(1, ec.SECP256R1()).public_key().public_numbers()
            valid_point = {1: 2, 3: -25, -1: 1, -2: generator.x.to_bytes(32, "big"), -3: generator.y.to_bytes(32, "big")}
            refused = vendor(session, 1, {1: valid_point})
            session.check("repeated MSE refused", refused.protocol, "applet_error")
            trigger = session.evidence()
            key, aad = handshake(session, hybrid)
            exported = session.ctap_value(vendor(session, 2, authenticated=True))[1]
            exported_at = session.evidence()
            seed = ChaCha20Poly1305(key).decrypt(exported[:12], exported[12:], aad)
            session.check("decrypted seed length", len(seed), 32)
            session.observe("fixture_seed_sha256", hashlib.sha256(seed).digest(), "presence")
            again = vendor(session, 2, authenticated=True)
            session.check("consumed channel cannot export again", again.protocol, "applet_error")
            session.transition("rsk.MSE", "active", "consumed_after_export", exported_at, [trigger, exported_at, session.evidence()])
    for defect in ("missing-point", "short-x", "short-y", "off-curve", "short-KEM"):
        with session.case("rsk.negative.MSE." + defect, ("V01", "G01", "G03", "G14")):
            rsk(session)
            generator = ec.derive_private_key(1, ec.SECP256R1()).public_key().public_numbers()
            point = {1: 2, 3: -25, -1: 1, -2: generator.x.to_bytes(32, "big"), -3: generator.y.to_bytes(32, "big")}
            params = {1: point}
            if defect == "missing-point":
                params = {}
            elif defect == "short-x":
                point[-2] = bytes(31)
            elif defect == "short-y":
                point[-3] = bytes(31)
            elif defect == "short-KEM":
                params[2] = bytes(1183)
            elif defect == "off-curve":
                point[-2], point[-3] = bytes(32), bytes(32)
            reply = vendor(session, 1, params)
            session.observe("status", reply.status)
            session.check("invalid MSE refused", reply.protocol, "applet_error")
            session.check("getInfo after MSE refusal", isinstance(session.ctap_value(session.ctap(4))[1], list))


def configuration(session):
    for target in (1, 2):
        with session.case(f"rsk.transition.config.{target}", ("V09", "M05", "G14"), effects=("config_change",), touch=True):
            rsk(session)
            original = session.ctap_value(vendor(session, 13, {1: target}))[1]
            session.require(original, "no stored config to rewrite and restore without changing absence semantics")
            session.ctap_value(vendor(session, 12, {1: target, 2: original}, authenticated=True))
            session.check("identical write preserves stored config", session.ctap_value(vendor(session, 13, {1: target}))[1], original)
            malformed = {1: target, 2: b"\x04\x82\xff"} if target != 2 else {1: target, 2: original[:-1]}
            reply = vendor(session, 12, malformed, authenticated=True)
            session.observe("malformed.status", reply.status)
            session.check("malformed config refused", reply.protocol, "applet_error")
            trigger = session.evidence()
            session.check("refusal preserved stored config", session.ctap_value(vendor(session, 13, {1: target}))[1], original)
            session.transition("rsk.config", "original", "unchanged_after_refusal", trigger, [trigger, session.evidence()])


def audit(session):
    with session.case("rsk.audit.checkpoint", ("V07", "V08"), touch=True):
        rsk(session)
        window = session.ctap_value(vendor(session, 7, authenticated=True))
        start, end, epoch, entries = (window[key] for key in (1, 2, 3, 4))
        session.check("audit epoch length", len(epoch), 32)
        session.check("audit window bounds", 0 <= start <= end)
        session.check("audit entry count", len(entries), (end - start) * AUDIT_ENTRY_BYTES)
        head = epoch
        for offset in range(0, len(entries), AUDIT_ENTRY_BYTES):
            head = hashlib.sha256(head + entries[offset:offset + AUDIT_ENTRY_BYTES]).digest()
        nonce = session.fixture("audit.nonce")
        checkpoint = session.ctap_value(vendor(session, 8, {1: nonce}, authenticated=True))
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), checkpoint[4])
        session.check("audit checkpoint head length", len(checkpoint[1]), 32)
        session.check("audit checkpoint does not precede exported window", checkpoint[2] >= end)
        if checkpoint[2] == end:
            session.check("audit hash chain", checkpoint[1], head)
        else:
            session.observe("chain_continuity", "intervening journal entries; exported window is not the checkpoint prefix")
        message = AUDIT_CHECKPOINT_DOMAIN + checkpoint[1] + checkpoint[2].to_bytes(4, "little") + nonce
        verified(session, "audit checkpoint signature", public, -7, checkpoint[3], message)
        session.observe("identity_binding", "response-provided key; manufacturer identity is not pinned")
    for length in (0, 1, 31, 32, 33):
        with session.case(f"rsk.audit.nonce.{length}", ("V08", "G03"), touch=True):
            rsk(session)
            nonce = session.fixture("audit.nonce", length)
            reply = vendor(session, 8, {1: nonce}, authenticated=True)
            if length > 32:
                session.check("oversized audit nonce refused", reply.protocol, "applet_error")
            else:
                checkpoint = session.ctap_value(reply)
                key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), checkpoint[4])
                message = AUDIT_CHECKPOINT_DOMAIN + checkpoint[1] + checkpoint[2].to_bytes(4, "little") + nonce
                verified(session, "audit nonce binding", key, -7, checkpoint[3], message)


def run(session):
    mse(session)
    configuration(session)
    audit(session)
