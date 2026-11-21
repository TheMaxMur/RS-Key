# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""MSE rejection and consumer failures must spend the channel without changing identity."""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import codec
from .fido import info, pin_token, token_mac
from .fido_fixtures import credential
from .hid_sequences import allocate, hooks
from .vendor_cases import rsk, vendor, handshake
from .vendor_lifecycle import export_seed, identity_fixture, config, AUT_ENABLE


def point():
    public = ec.derive_private_key(1, ec.SECP256R1()).public_key().public_numbers()
    return {1: 2, 3: -25, -1: 1, -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")}


def vacant(session):
    response = vendor(session, 1, {1: point()})
    if response.protocol == "success":
        response = vendor(session, 1, {1: point()})
    session.check("explicit channel retirement", response.status, 0x30)


def exportable(session):
    rsk(session)
    state = session.ctap_value(vendor(session, 5))
    session.require(not state[1] and not state.get(3, False), "open export window and no soft lock required")
    session.require("fips-profile" not in session.options.features, "FIPS seed is non-exportable", "excluded_by_profile")


def mse_inputs(session):
    defects = ("missing-point", "empty-x", "empty-y", "one-x", "one-y", "missing-x", "missing-y", "short-x", "short-y", "long-x", "long-y",
               "off-curve", "KEM-one", "KEM-short", "KEM-long", "KEM-noncanonical", "already-live", "other-CID")
    for defect in defects:
        with session.case("rsk.MSE.semantic." + defect, ("V01", "V02", "G01", "G03", "G09", "G11", "G14"),
                          effects=("read_encrypted_seed",), touch=True):
            exportable(session)
            if defect == "other-CID":
                session.require(session.hid is not None and hasattr(session.hid, "send_only"), "raw CID allocator required", "excluded_by_mode")
            vacant(session)
            original = export_seed(session)
            parameters = {1: point()}
            if defect == "missing-point":
                parameters = {}
            elif defect.startswith("missing-"):
                parameters[1].pop(-2 if defect.endswith("x") else -3)
            elif defect in ("empty-x", "empty-y", "one-x", "one-y", "short-x", "short-y", "long-x", "long-y"):
                parameters[1][-2 if defect.endswith("x") else -3] = bytes(0 if defect.startswith("empty") else 1 if defect.startswith("one") else 31 if defect.startswith("short") else 33)
            elif defect == "off-curve":
                parameters[1][-2], parameters[1][-3] = bytes(32), bytes(32)
            elif defect.startswith("KEM-"):
                parameters[2] = b"\xff" * (1 if defect == "KEM-one" else 1183 if defect == "KEM-short" else 1185 if defect == "KEM-long" else 1184)
            elif defect == "already-live":
                handshake(session)
            elif defect == "other-CID":
                with hooks(session):
                    other = allocate(session)
                handshake(session)
                owner = session.hid.cid
                try:
                    session.hid.cid = other
                    session.check("other CID cannot consume owner MSE", vendor(session, 2, authenticated=True).status, 0x30)
                finally:
                    session.hid.cid = owner
                session.check("foreign consumer also spends one-shot channel", vendor(session, 2, authenticated=True).status, 0x30)
                session.check("new handshake exports original seed after foreign consumer", export_seed(session), original)
                continue
            reply = vendor(session, 1, parameters)
            session.check("MSE semantic defect refused", reply.protocol, "applet_error")
            expected = 0x30 if defect == "already-live" else 0x14 if defect in ("missing-point", "missing-x", "missing-y", "empty-x", "empty-y") else 0x02
            session.check("MSE semantic refusal cause", reply.status, expected)
            session.check("failed MSE leaves no usable channel", vendor(session, 2, authenticated=True).status, 0x30)
            session.check("fresh handshake works and preserves seed after rejection", export_seed(session), original)


def authenticated(session, command, subcommand, parameters, defect, version=None):
    permission = 2 if defect == "wrong-permission" else 64 if defect == "readonly" else 32
    version, token = pin_token(session, permission, "vendor-gate.oracle.invalid" if permission == 2 else None, version=version)
    fields = {1: subcommand}
    if parameters is not None:
        fields[2] = parameters
    payload = b"\xff" * 32 + bytes([command, subcommand]) + (codec.encode(parameters) if parameters is not None else b"")
    fields.update({3: version, 4: token_mac(version, token, payload)})
    if defect == "missing-auth":
        fields.pop(4)
    elif defect == "missing-protocol":
        fields.pop(3)
    elif defect == "unknown-protocol":
        fields[3] = 0
    elif defect == "unsupported-protocol":
        fields[3] = 3
    elif defect == "empty-auth":
        fields[4] = b""
    elif defect == "short-auth":
        fields[4] = fields[4][:-1]
    elif defect == "long-auth":
        fields[4] += b"x"
    elif defect == "bad-MAC":
        fields[4] = bytes([fields[4][0] ^ 1]) + fields[4][1:]
    return session.ctap(command, fields)


def consumers(session):
    for subcommand in (2, 3, 9, 10):
        for defect in ("missing-auth", "missing-protocol", "unknown-protocol", "wrong-permission", "bad-MAC"):
            with session.case(f"rsk.MSE.consumer-{subcommand}.{defect}", ("V01", "V02", "V03", "V05", "V06", "G10", "G11", "G14"),
                              effects=("read_encrypted_seed", "seed_change", "replace_identity", "create_fido_credential"), touch=True):
                exportable(session)
                session.require(session.options.pin and info(session).get(4, {}).get("clientPin"), "PIN-gate failures require a known configured PIN")
                vacant(session)
                original = export_seed(session)
                identity = session.ctap_value(vendor(session, 11))
                private, chain = identity_fixture(session)
                raw = private.private_numbers().private_value.to_bytes(32, "big") if subcommand == 9 else original
                with credential(session, session.current.name) as fixture:
                    key, aad = handshake(session)
                    nonce = session.fixture("vendor.semantic.nonce", 12)
                    blob = nonce + ChaCha20Poly1305(key).encrypt(nonce, raw, aad)
                    params = {1: blob, 2: chain} if subcommand == 9 else {1: blob} if subcommand in (3, 6) else None
                    reply = authenticated(session, 0x41, subcommand, params, defect)
                    session.check("MSE consumer refuses authorization defect", reply.protocol, "applet_error")
                    session.check("authorization refusal spends one-shot MSE", vendor(session, 2, authenticated=True).status, 0x30)
                    session.check("failed consumer preserves exact identity", session.ctap_value(vendor(session, 11)), identity)
                    session.check("failed consumer preserves exact seed", export_seed(session), original)
                    fixture.assertion(session)


def blob_lengths(session):
    for subcommand in (3, 6, 9):
        for size in (0, 1, 11, 12, 43, 44, 59, 60, 61):
            with session.case(f"rsk.MSE.consumer-{subcommand}.blob-length-{size}", ("V01", "V03", "V05", "V06", "G03", "G14"),
                              effects=("read_encrypted_seed", "seed_change", "replace_identity", "create_fido_credential"), touch=True):
                exportable(session)
                vacant(session)
                seed = export_seed(session)
                identity = session.ctap_value(vendor(session, 11))
                _, chain = identity_fixture(session)
                with credential(session, session.current.name) as fixture:
                    handshake(session)
                    params = {1: session.fixture("vendor.invalid-blob", size)}
                    if subcommand == 9:
                        params[2] = chain
                    result = vendor(session, subcommand, params, authenticated=True)
                    session.check("malformed wrapped payload refused", result.protocol, "applet_error")
                    session.check("payload refusal spends channel", vendor(session, 2, authenticated=True).status, 0x30)
                    session.check("payload refusal preserves identity", session.ctap_value(vendor(session, 11)), identity)
                    session.check("payload refusal preserves seed", export_seed(session), seed)
                    fixture.assertion(session)


def config_catalog(session):
    from .vendor_lifecycle import AUT_DISABLE
    from .enterprise import EA_RPIDS
    with session.case("rsk.CONFIG-COMMANDS.advertised-and-dispatch", ("V09", "V10", "F01", "F21", "G04", "G14")):
        rsk(session)
        response = session.ctap_value(vendor(session, 15))[1]
        session.check("vendor command list has unique integer IDs", isinstance(response, list) and len(set(response)) == len(response) and all(type(value) is int for value in response))
        session.check("vendor command list contains lock and enterprise controls", {AUT_ENABLE, AUT_DISABLE, EA_RPIDS}.issubset(response))
        session.observe("advertised_vendor_config_IDs", response)
        for identifier in (0, 1, 0xFFFFFFFFFFFFFFFF):
            session.check("unknown vendor config ID is refused", config(session, 255, {1: identifier}).status, 0x3E)
        session.check("unknown ID leaves advertised command list unchanged", session.ctap_value(vendor(session, 15))[1], response)


def run(session):
    mse_inputs(session)
    consumers(session)
    blob_lengths(session)
    config_catalog(session)
