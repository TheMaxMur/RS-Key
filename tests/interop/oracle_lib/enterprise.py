# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Enterprise attestation checks both RP eligibility and the actual signing key."""
from cryptography import x509

from . import codec
from .fido import authorize, info, pin_token, verified
from .fido_fixtures import credential, provision_after_reset
from .lifecycle import Action, change
from .config_matrix import request as config_request
from .config_grammar import RAW_LIMIT
from .vendor_cases import rsk, vendor, handshake
from .vendor_lifecycle import config, identity_fixture, wrap

EA_RPIDS = 0x0E6841934E719BE7
MAX_EA_RPIDS = 8


def rp_probe(session, label, rp, allowed, chain):
    size = len(rp.encode())
    if not rp or size > 253 or any(value in b" \t\r\n\v\f" for value in rp.encode()):
        query = {1: session.fixture("EA.invalid-RP.hash"), 2: {"id": rp}, 3: {"id": b"EA.invalid-RP"},
            4: [{"type": "public-key", "alg": -7}], 10: 1}
        authorize(session, query, 1, rp, query[1], 8, 9)
        session.check("CONFIG accepts opaque RP hashes without changing makeCredential's separate RP grammar",
            session.ctap(1, query).status, 0x14 if not rp else 3 if size > 253 else 2)
        return
    with credential(session, label, rp=rp, extra={10: 1}) as owned:
        session.check("enterprise RP eligibility controls ep after exact list replacement", owned.registration.get(4, False), allowed)
        statement = owned.registration[3]
        session.check("RP eligibility selects the actual organization chain", statement["x5c"][0] == chain, allowed)
        leaf = x509.load_der_x509_certificate(statement["x5c"][0])
        verified(session, "RP-list attestation signs the actual retained credential", leaf.public_key(), statement["alg"],
            statement["sig"], owned.registration[2] + owned.challenge)
        owned.assertion(session)


def rp_matrix(session, chain, eligible, unrelated):
    vectors = [("count-" + str(count), [f"r{index}.oracle.invalid" for index in range(count)]) for count in (0, 1, 7, 8, 9, 16)]
    vectors += [("duplicates-" + str(count), [eligible] * count) for count in (8, 9)]
    vectors += [("text-" + str(index), [text]) for index, text in enumerate(("", "r", "a\x00b", "éΩ.oracle.invalid",
        "é" * 126, "é" * 127, "r" * 253, "r" * 254, "r" * 367, "r" * 368, "r" * 369, "space RP"))]
    current = [eligible]
    for version in (1, 2):
        for label, proposed in vectors:
            parameters = {1: EA_RPIDS, 4: proposed}
            owner_version, token = pin_token(session, 32, version=version)
            fields = config_request(session, owner_version, token, 255, parameters)
            expected = 0x39 if len(codec.encode(parameters)) > RAW_LIMIT else 0x28 if len(proposed) > MAX_EA_RPIDS else 0
            for repeat in range(2):
                result = session.ctap(13, fields)
                session.check("vendor enterprise RP count/raw-byte limit has its exact refusal and repeat result", result.status, expected)
            if not expected:
                current = proposed
            for rp in dict.fromkeys((eligible, unrelated, *(proposed[:1] + proposed[-1:]), *(current[:1] + current[-1:]))):
                rp_probe(session, f"EA.RP-matrix.protocol-{version}.{label}.{rp}", rp, rp in current, chain)
        params = {1: EA_RPIDS, 4: [unrelated]}
        version, token = pin_token(session, 32, version=version)
        rejected = config_request(session, version, token, 255, params)
        rejected[4] = bytes([rejected[4][0] ^ 1]) + rejected[4][1:]
        session.check("vendor RP-list change is MAC-protected on both protocols", session.ctap(13, rejected).status, 0x33)
        rp_probe(session, "EA.RP-matrix.refused-auth", eligible, eligible in current, chain)
        rp_probe(session, "EA.RP-matrix.refused-auth.unrelated", unrelated, unrelated in current, chain)
    session.ctap_value(config(session, 255, {1: EA_RPIDS, 4: [eligible]}))
    for action in Action:
        change(session, action)
        session.check("enterprise opt-in survives every connection action", session.ctap_value(session.ctap(4))[4]["ep"], True)
        rp_probe(session, "EA.RP-matrix.persistence." + action.value, eligible, True, chain)
        rp_probe(session, "EA.RP-matrix.persistence.unrelated." + action.value, unrelated, False, chain)


def run(session):
    with session.case("fido.enterprise-attestation.enable-RPs-formats-and-identity", ("F21", "FE12", "V06", "G03", "G04", "G08", "G10", "G11", "G14"),
                      effects=("replace_identity", "config_change", "applet_reset", "pin_change", "reboot", "create_fido_credential"), touch=True):
        rsk(session)
        current = info(session)
        session.require("ep" in current.get(4, {}) and current.get(4, {}).get("authnrCfg"), "enterprise attestation configuration not advertised", "unknown")
        session.require(current.get(4, {}).get("clientPin") and session.options.pin, "enterprise CONFIG fixtures require a known configured host PIN")
        session.require(session.card is not None and hasattr(session.card, "control") and (session.options.operator or getattr(session.card, "emulated", False)),
                        "enterprise policy fixture requires explicit power/reset recovery")
        session.require(not session.ctap_value(vendor(session, 11))[1], "existing organization identity cannot be restored")
        private, chain = identity_fixture(session)
        eligible, unrelated = "enterprise.oracle.invalid", "unrelated.oracle.invalid"
        installed = configured = False
        try:
            session.ctap_value(vendor(session, 9, {1: wrap(session, private.private_numbers().private_value.to_bytes(32, "big")), 2: chain}, authenticated=True))
            installed = True
            if not current[4]["ep"]:
                for level in (0, 1, 2, 3):
                    request = {1: session.fixture("EA.disabled.hash"), 2: {"id": eligible}, 3: {"id": b"oracle-EA"},
                               4: [{"type": "public-key", "alg": -7}], 10: level}
                    authorize(session, request, 1, eligible, request[1], 8, 9)
                    session.check("disabled enterprise request refused", session.ctap(1, request).status, 2)
            session.ctap_value(config(session, 1))
            configured = True
            session.ctap_value(config(session, 255, {1: EA_RPIDS, 4: [eligible]}))
            session.bind("fido.info", session.ctap_value(session.ctap(4)))
            session.check("enterprise option enabled", info(session)[4]["ep"], True)
            rp_matrix(session, chain, eligible, unrelated)
            for level in (1, 2):
                for rp in (eligible, unrelated):
                    for formats in (None, ["none"], ["packed"], ["unknown", "packed"]):
                        extra = {10: level, **({11: formats} if formats is not None else {})}
                        with credential(session, f"EA.{level}.{rp}.{formats}", rp=rp, extra=extra) as fixture:
                            performed = level == 2 or rp == eligible
                            session.check("enterprise RP eligibility controls ep", fixture.registration.get(4, False), performed)
                            if not performed and formats == ["none"]:
                                session.check("none preference suppresses ordinary attestation", (fixture.registration[1], fixture.registration[3]), ("none", {}))
                                continue
                            session.check("requested packed attestation format", fixture.registration[1], "packed")
                            statement = fixture.registration[3]
                            leaf = x509.load_der_x509_certificate(statement["x5c"][0])
                            if performed:
                                session.check("enterprise attestation uses fixture chain", statement["x5c"], [chain])
                            else:
                                session.check("unrelated type-1 RP does not receive org identity", statement["x5c"][0] != chain)
                            verified(session, "enterprise/basic attestation signature", leaf.public_key(), statement["alg"],
                                     statement["sig"], fixture.registration[2] + fixture.challenge)
                            fixture.assertion(session)
            for level in (0, 3, 255):
                query = {1: session.fixture("EA.invalid.hash"), 2: {"id": eligible}, 3: {"id": b"oracle-EA"},
                         4: [{"type": "public-key", "alg": -7}], 10: level}
                authorize(session, query, 1, eligible, query[1], 8, 9)
                session.check("unknown enterprise type refused after enable", session.ctap(1, query).status, 0x2C)
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                if installed:
                    handshake(session)
                    session.ctap_value(vendor(session, 10, authenticated=True))
                    session.check("enterprise fixture identity removed", session.ctap_value(vendor(session, 11))[1], False)
                if configured:
                    change(session, Action.POWER_CYCLE)
                    session.ctap_value(session.ctap(7))
                    provision_after_reset(session, session.ctap_value(session.ctap(4)))
                    session.check("factory enterprise policy disabled", info(session)[4]["ep"], False)
                    session.observe("cleanup_limit", "factory FIDO store retained; fixture PIN reprovisioned when supplied")
