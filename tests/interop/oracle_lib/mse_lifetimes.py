# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Every MSE consumer spends the owner channel, including foreign-CID refusals."""
from itertools import product

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import codec
from .binding import require_pair
from .fido import info
from .fido_fixtures import credential
from .hid_sequences import allocate, hooks
from .runner import CtapRoute
from .vendor_cases import handshake, vendor
from .vendor_lifecycle import AUT_ENABLE, config, export_seed, identity_fixture
from .vendor_matrix import exportable, vacant, point

CONSUMERS = (2, 3, 6, 9, 10, AUT_ENABLE)


def ready(session):
    exportable(session)
    session.require(session.hid is not None and session.card is not None, "MSE route scope needs both explicit FIDO transports", "excluded_by_mode")
    require_pair(session)
    session.require(info(session).get(4, {}).get("clientPin") and session.options.pin, "controlled MSE consumer scope requires a known host PIN")
    session.require(not session.ctap_value(vendor(session, 11))[1], "ATT_CLEAR scope control must not erase a preexisting organization identity")
    session.select("fido", required=True)


def consumed(session):
    session.check("consumer spends MSE before any later request can use it", vendor(session, 2, authenticated=True).status, 0x30)


def consumers(session):
    routes = ((CtapRoute.HID, CtapRoute.HID, False), (CtapRoute.HID, CtapRoute.HID, True),
              (CtapRoute.HID, CtapRoute.CARD, False), (CtapRoute.CARD, CtapRoute.HID, False), (CtapRoute.CARD, CtapRoute.CARD, False))
    for sub, (owner, caller, foreign) in product(CONSUMERS, routes):
        with session.case(f"rsk.MSE.consume-{sub}.owner-{owner.value}.caller-{caller.value}.foreign-CID-{foreign}",
                ("V01", "V02", "V03", "V05", "V06", "X03", "G09", "G10", "G11", "G13", "G14"),
                effects=("read_encrypted_seed", "seed_change", "replace_identity", "config_change", "create_fido_credential"), touch=True):
            ready(session)
            other = None
            if foreign:
                with hooks(session):
                    other = allocate(session)
            with session.route(owner):
                vacant(session)
                seed = export_seed(session)
                state = session.ctap_value(vendor(session, 5))
                with credential(session, session.current.name) as retained:
                    key, aad = handshake(session)
                    nonce = session.fixture("MSE.lifetime.nonce", 12)
                    bad_blob = nonce + ChaCha20Poly1305(key).encrypt(nonce, seed, aad)
                    bad_blob = bad_blob[:-1] + bytes([bad_blob[-1] ^ 1])
                    params = {1: bad_blob} if sub in (3, 6, 9) else None
                    if sub == 9:
                        params[2] = identity_fixture(session)[1]
                    original_cid = session.hid.cid
                    try:
                        if foreign:
                            session.hid.cid = other
                        with session.route(caller):
                            result = config(session, 255, {1: AUT_ENABLE, 2: bad_blob}) if sub == AUT_ENABLE else vendor(session, sub, params, authenticated=True)
                    finally:
                        session.hid.cid = original_cid
                    same_owner = owner == caller and not foreign
                    expected = (0 if sub in (2, 10) else 0x3d if sub == 3 else 2) if same_owner else 0x30
                    session.check("each MSE consumer has its exact owner/foreign-channel outcome", result.status, expected)
                    if same_owner and sub == 2:
                        blob = session.ctap_value(result)[1]
                        session.check("owner export is encrypted under the original handshake", ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad), seed)
                    consumed(session)
                    session.check("consumer or refusal preserves complete seed/lock state", session.ctap_value(vendor(session, 5)), state)
                    session.check("fresh owner handshake recovers the exact seed", export_seed(session), seed)
                    session.check("scope controls preserve the absent organization identity", session.ctap_value(vendor(session, 11))[1], False)
                    retained.assertion(session)


def parse_boundary(session):
    for sub, defect in product((1, 2, 3, 6, 9, 10), ("subcommand-type", "params-type", "outer-protocol-type", "outer-auth-type", "trailing-item", "truncated-map")):
        with session.case(f"rsk.MSE.parser-boundary.consumer-{sub}.{defect}", ("V01", "V02", "V03", "V05", "V06", "G02", "G05", "G11", "G13", "G14"),
                effects=("read_encrypted_seed",), touch=True):
            exportable(session)
            vacant(session)
            seed = export_seed(session)
            key, aad = handshake(session)
            fields = {1: sub, 2: {}}
            if defect == "subcommand-type":
                fields[1] = b"subcommand"
            elif defect == "params-type":
                fields[2] = []
            elif defect == "outer-protocol-type":
                fields[3] = b"protocol"
            elif defect == "outer-auth-type":
                fields[4] = 0
            raw = codec.encode(fields) + (b"\x00" if defect == "trailing-item" else b"")
            if defect == "truncated-map":
                raw = b"\xa2\x01" + codec.encode(sub) + b"\x02"
            result = session.ctap(0x41, raw=raw)
            session.check("parser refusal happens before the MSE consumer boundary", result.status, 0x12 if defect in ("trailing-item", "truncated-map") else 0x11)
            exported = session.ctap_value(vendor(session, 2, authenticated=True))[1]
            session.check("unparsed consumer retains the original usable channel", ChaCha20Poly1305(key).decrypt(exported[:12], exported[12:], aad), seed)
            consumed(session)


def metadata(session):
    for variant in ("coordinates-only", "empty-KEM", "ignored-kty", "ignored-alg", "ignored-curve", "unknown-key"):
        with session.case("rsk.MSE.ignored-metadata-and-fresh-ephemeral." + variant,
                ("V01", "V02", "G01", "G02", "G03", "G04", "G09", "G11", "G14"), effects=("read_encrypted_seed",), touch=True):
            exportable(session)
            vacant(session)
            original = export_seed(session)
            previous = None
            for repeat in range(2):
                parameters = {1: point()}
                if variant == "coordinates-only":
                    parameters[1] = {key: value for key, value in parameters[1].items() if key in (-2, -3)}
                elif variant == "empty-KEM":
                    parameters[2] = b""
                elif variant == "unknown-key":
                    parameters[1][99] = ["ignored", None]
                else:
                    parameters[1][{"ignored-kty": 1, "ignored-alg": 3, "ignored-curve": -1}[variant]] = "ignored metadata"
                result = session.ctap_value(vendor(session, 1, parameters))
                session.check("empty or omitted KEM uses the classical channel", 2 not in result)
                own = result[1]
                aad = b"\x04" + own[-2] + own[-3]
                if previous is not None:
                    session.check("a completed MSE cannot reuse its device ephemeral public point", aad != previous)
                previous = aad
                peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), aad)
                shared = ec.derive_private_key(1, ec.SECP256R1()).exchange(ec.ECDH(), peer)
                key = HKDF(hashes.SHA256(), 32, b"", aad).derive(shared)
                blob = session.ctap_value(vendor(session, 2, authenticated=True))[1]
                session.check("ignored COSE metadata still uses the actual supplied P-256 coordinates", ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad), original)
                consumed(session)


def live_semantic_refusals(session):
    for defect in ("missing-point", "missing-x", "short-x", "off-curve", "invalid-KEM"):
        with session.case("rsk.MSE.live-channel.semantic-precedence." + defect, ("V01", "V02", "G03", "G11", "G13", "G14"), effects=("read_encrypted_seed",), touch=True):
            exportable(session)
            vacant(session)
            seed = export_seed(session)
            handshake(session)
            params = {1: point()}
            if defect == "missing-point":
                params = {}
            elif defect == "missing-x":
                params[1].pop(-2)
            elif defect == "short-x":
                params[1][-2] = bytes(31)
            elif defect == "off-curve":
                params[1][-2], params[1][-3] = bytes(32), bytes(32)
            else:
                params[2] = b"invalid KEM"
            session.check("a live channel is vacated before semantic MSE validation", vendor(session, 1, params).status, 0x30)
            consumed(session)
            session.check("semantic MSE refusal can recover with the exact prior seed", export_seed(session), seed)


def run(session):
    consumers(session)
    parse_boundary(session)
    metadata(session)
    live_semantic_refusals(session)
