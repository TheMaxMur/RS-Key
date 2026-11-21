# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""previewSign v4 signatures are verified with an independently derived ARKG key."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import arkg, codec
from .fido import auth_data, authorize, info, public_key
from .fido_fixtures import credential

SPLIT_ARKG = -65539


def registration_defects():
    yield "missing-algs", {4: 1}, 0x14
    for value in ([], [-7], [-65538]):
        yield "unsupported-algs-" + codec.encode(value).hex(), {3: value, 4: 1}, 0x26
    for value in ([0], [1], [SPLIT_ARKG, 0], [False], [None], [b"alg"], ["alg"], {}, False):
        yield "wrong-algs-" + codec.encode(value).hex(), {3: value, 4: 1}, 0x11
    for value in (2, 3, 4, 6, 255, 256, 0xffffffffffffffff):
        yield f"reserved-flags-{value}", {3: [SPLIT_ARKG], 4: value}, 0x2c
    for value in (None, False, -1, b"", [], {}):
        yield "wrong-flags-" + codec.encode(value).hex(), {3: [SPLIT_ARKG], 4: value}, 0x11


def assertion_defects(fields, handle, context):
    for key in (2, 6, 7):
        value = dict(fields)
        del value[key]
        yield f"missing-{key}", value, 0x14 if key == 7 else 0x2c
        for wrong in (None, False, 0, "bytes", [], {}):
            yield f"wrong-type-{key}-" + codec.encode(wrong).hex(), {**fields, key: wrong}, 0x11
    for length in (0, 1, len(fields[2]) - 1, len(fields[2]) + 1, 255):
        yield f"credential-handle-length-{length}", {**fields, 2: fields[2][:length].ljust(length, b"x")}, 0x22
    base = {3: SPLIT_ARKG, -1: handle, -2: context}
    for key in (3, -1, -2):
        value = dict(base)
        del value[key]
        yield f"missing-argument-{key}", {**fields, 7: codec.encode(value)}, 0x22 if key == 3 else 0x14
        for wrong in (None, False, 0, "bytes", [], {}):
            if key == 3 and wrong == 0 and type(wrong) is int:
                expected = 0x22
            else:
                expected = 0x11
            yield f"wrong-argument-{key}-" + codec.encode(wrong).hex(), {**fields, 7: codec.encode({**base, key: wrong})}, expected
    for label, encoded in (("empty-args", b""), ("truncated-args", fields[7][:-1]), ("trailing-args", fields[7] + b"\x00"), ("wrong-args-shape", b"\x80")):
        yield label, {**fields, 7: encoded}, 0x12 if label != "wrong-args-shape" else 0x11
    for length in (0, 1, len(handle) - 1, len(handle) + 1):
        yield f"derivation-handle-length-{length}", {**fields, 7: codec.encode({**base, -1: handle[:length].ljust(length, b"x")})}, 0x22
    for value in (-7, -65538, 0, 1):
        yield f"foreign-argument-alg-{value}", {**fields, 7: codec.encode({**base, 3: value})}, 0x22
    yield "unknown-argument", {**fields, 7: codec.encode({**base, 99: b"ignored"})}, 0


def run(session):
    for flags in (None, 0, 1, 5):
        for context_size in (0, 1, 63, 64):
            with session.case(f"fido.previewSign.flags-{flags}.ctx-{context_size}", ("FE10", "G03", "G09", "G14"), effects=("create_fido_credential",), touch=True):
                session.require("previewSign" in info(session).get(2, []), "previewSign build not advertised", "unknown")
                session.require(flags != 5 or session.options.pin is not None or info(session).get(4, {}).get("uv"), "UV-required preview key needs configured verification")
                policy = 1 if flags is None else flags
                with credential(session, session.current.name, extensions={"previewSign": {3: [-7, SPLIT_ARKG, SPLIT_ARKG], **({4: flags} if flags is not None else {})}}) as fixture:
                    attestation = codec.decode(fixture.registration[6]["previewSign"][7])
                    attested = auth_data(attestation["authData"])
                    session.check("preview key RP binding", attested["rp_hash"], fixture.parsed["rp_hash"])
                    seed = attested["cose"]
                    session.check("ARKG public seed profile", (seed[1], seed[3], seed[-3]), (-65537, -65700, -9))
                    context = session.fixture("preview.ctx", context_size)
                    derived, handle = arkg.derive(public_key(seed[-1]), public_key(seed[-2]), session.fixture("preview.ikm"), context)
                    digest = session.fixture("preview.digest")
                    args = codec.encode({3: SPLIT_ARKG, -1: handle, -2: context})
                    fields = {2: attested["credential_id"], 6: digest, 7: args}
                    def check_signature():
                        _, signed = fixture.assertion(session, extensions={"previewSign": fields})
                        signature = signed["extensions"]["previewSign"][6]
                        derived.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                        session.check("previewSign independent ARKG signature", True)
                        try:
                            derived.verify(signature, bytes([digest[0] ^ 1]) + digest[1:], ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                        except InvalidSignature:
                            session.check("previewSign altered digest refused", True)
                        else:
                            session.check("previewSign altered digest refused", False)
                    check_signature()
                    for up in (False, True):
                        for authenticated in (False, True):
                            query = fixture.query(session, extensions={"previewSign": fields}, options={"up": up, "uv": False}, authenticate=authenticated)
                            result = session.ctap(2, query)
                            expected = 0x3b if policy & 1 and not up else 0x36 if policy & 4 and not authenticated else 0
                            session.check("preview key UP/UV policy survives a changed assertion option", result.status, expected)
                            if expected == 0:
                                value = session.ctap_value(result)
                                derived.verify(auth_data(value[2])["extensions"]["previewSign"][6], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                    for omitted in (False, True):
                        query = fixture.query(session, extensions={"previewSign": fields}, allow=[])
                        if omitted:
                            del query[3]
                        session.check("preview signing requires an explicit usable allow list", session.ctap(2, query).status, 0x2c)
                    check_signature()
                    for label, invalid, expected in assertion_defects(fields, handle, context):
                        result = session.ctap(2, fixture.query(session, extensions={"previewSign": invalid}))
                        session.check("previewSign malformed parameter has its isolated refusal: " + label, result.status, expected)
                        if expected == 0:
                            value = session.ctap_value(result)
                            signature = auth_data(value[2])["extensions"]["previewSign"][6]
                            derived.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                        check_signature()
                    if flags == 1 and context_size == 0:
                        for label, invalid, expected in registration_defects():
                            query = {1: fixture.challenge, 2: {"id": fixture.rp}, 3: {"id": b"preview-refused-key"},
                                4: [{"type": "public-key", "alg": -7}], 6: {"previewSign": invalid}}
                            authorize(session, query, 1, fixture.rp, fixture.challenge, 8, 9)
                            session.check("previewSign registration negotiation refuses a single defect: " + label, session.ctap(1, query).status, expected)
                            check_signature()
                    for defect in ("short-digest", "long-digest", "damaged-handle", "damaged-derivation", "missing-args", "oversize-context"):
                        invalid = dict(fields)
                        if defect == "short-digest":
                            invalid[6] = digest[:-1]
                        elif defect == "long-digest":
                            invalid[6] = digest + b"\x00"
                        elif defect == "damaged-handle":
                            invalid[2] = bytes([invalid[2][0] ^ 1]) + invalid[2][1:]
                        elif defect == "damaged-derivation":
                            invalid[7] = codec.encode({3: SPLIT_ARKG, -1: handle[:-1] + bytes([handle[-1] ^ 1]), -2: context})
                        elif defect == "missing-args":
                            del invalid[7]
                        else:
                            invalid[7] = codec.encode({3: SPLIT_ARKG, -1: handle, -2: bytes(65)})
                        result = session.ctap(2, fixture.query(session, extensions={"previewSign": invalid}))
                        session.check("invalid previewSign " + defect + " refused", result.protocol, "applet_error")
                        check_signature()
